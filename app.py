from flask import Flask, render_template, request, redirect, session, jsonify, Response
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, ImageDraw, ImageFont
from email.message import EmailMessage
import hashlib
import hmac
import io
import json
import os
import random
import re
import secrets
import smtplib
import threading
import time
import urllib.request

app = Flask(__name__)

# ---------------- CONFIG ---------------- #

# On Render: set SECRET_KEY as an environment variable.
app.secret_key = os.environ.get("SECRET_KEY") or "directline_demo_secret_change_me"
if app.secret_key == "directline_demo_secret_change_me":
    print("WARNING: SECRET_KEY env var is not set. Set it on Render before going live.")

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Render sets RENDER=true; cookies are HTTPS-only there, plain http still works locally
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("RENDER") is not None

USERS_FILE = "users.json"
MESSAGES_FILE = "messages.json"

# captcha
CAPTCHA_TTL = 300            # seconds a captcha stays valid
CAPTCHA_MAX_STORED = 5000    # safety cap so nobody can fill memory
CAPTCHA_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"  # no 0/O/1/l/I

# email verification
CODE_TTL = 600               # code valid for 10 minutes
RESEND_COOLDOWN = 60         # seconds between "resend" requests
MAX_CODE_ATTEMPTS = 5        # wrong tries before a new code is needed
UNVERIFIED_TTL = 3600        # signup not verified within 1 hour -> userid is released

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

users_lock = threading.RLock()


# ---------------- USERS ---------------- #

def _is_stale(u):
    """Signup that never verified its email (frees the userid again)."""
    return (
        not u.get("email_verified")
        and u.get("email")
        and time.time() - u.get("created_at", time.time()) > UNVERIFIED_TTL
    )


def load_users():
    with users_lock:
        if not os.path.exists(USERS_FILE):
            with open(USERS_FILE, "w") as f:
                json.dump([], f)

        with open(USERS_FILE, "r") as f:
            users = json.load(f)

        fresh = [u for u in users if not _is_stale(u)]
        if len(fresh) != len(users):
            save_users(fresh)
        return fresh


def save_users(users):
    with users_lock:
        tmp = USERS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(users, f, indent=4)
        os.replace(tmp, USERS_FILE)  # atomic, no half-written file


def find_user(users, userid):
    for u in users:
        if u.get("userid") == userid:
            return u
    return None


def email_in_use(users, email, exclude_userid=None):
    for u in users:
        if u.get("userid") != exclude_userid and u.get("email") == email:
            return True
    return False


def mask_email(email):
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked = local[:1] + "*"
    else:
        masked = local[0] + "*" * (len(local) - 2) + local[-1]
    return masked + "@" + domain


# ---------------- MESSAGES ---------------- #

def load_messages():
    if not os.path.exists(MESSAGES_FILE):
        with open(MESSAGES_FILE, "w") as f:
            json.dump([], f)

    with open(MESSAGES_FILE, "r") as f:
        return json.load(f)


def save_messages(messages):
    with open(MESSAGES_FILE, "w") as f:
        json.dump(messages, f, indent=4)


# ---------------- IMAGE CAPTCHA ---------------- #
# The text is generated on the server, drawn into a PNG, and the answer is
# kept ONLY in server memory (never in the cookie). Each captcha is single use.
# NOTE: run gunicorn with ONE worker (see README) so memory is shared.

_captcha_store = {}          # captcha_id -> (answer_lowercase, expires_at)
_captcha_lock = threading.Lock()
_font_cache = {}

FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    "arialbd.ttf",
    "/Library/Fonts/Arial Bold.ttf",
]


def get_font(size):
    if size in _font_cache:
        return _font_cache[size]

    font = None
    for path in FONT_CANDIDATES:
        try:
            font = ImageFont.truetype(path, size)
            break
        except OSError:
            continue

    if font is None:
        try:
            font = ImageFont.load_default(size=size)   # Pillow >= 10.1
        except TypeError:
            font = ImageFont.load_default()

    _font_cache[size] = font
    return font


def _cleanup_captchas():
    now = time.time()
    for cid in [c for c, (_, exp) in _captcha_store.items() if exp < now]:
        _captcha_store.pop(cid, None)
    while len(_captcha_store) > CAPTCHA_MAX_STORED:
        _captcha_store.pop(next(iter(_captcha_store)), None)


def new_captcha():
    text = "".join(secrets.choice(CAPTCHA_CHARS) for _ in range(5))
    cid = secrets.token_urlsafe(16)
    with _captcha_lock:
        _cleanup_captchas()
        _captcha_store[cid] = (text.lower(), time.time() + CAPTCHA_TTL)
    return cid, text


def drop_captcha(cid):
    if cid:
        with _captcha_lock:
            _captcha_store.pop(cid, None)


def check_captcha(cid, answer):
    """Single use: the captcha is destroyed whether the answer is right or wrong."""
    if not cid:
        return False
    with _captcha_lock:
        entry = _captcha_store.pop(cid, None)
    if not entry:
        return False
    expected, expires = entry
    if time.time() > expires:
        return False
    return hmac.compare_digest(expected, (answer or "").strip().lower())


def make_captcha_image(text):
    W, H = 200, 70
    img = Image.new("RGB", (W, H), (238, 241, 250))
    font = get_font(44)

    # letters: each one rotated and jittered separately
    x = 14
    for ch in text:
        layer = Image.new("RGBA", (60, 70), (0, 0, 0, 0))
        ImageDraw.Draw(layer).text((10, 8), ch, font=font, fill=(20, 25, 45, 255))
        layer = layer.rotate(random.uniform(-25, 25), resample=Image.BICUBIC)
        img.paste(layer, (x + random.randint(-2, 2), random.randint(-4, 4)), layer)
        x += 34

    draw = ImageDraw.Draw(img)

    # crossing lines
    for _ in range(3):
        draw.line(
            [(random.randint(0, 30), random.randint(5, H - 5)),
             (random.randint(W - 30, W), random.randint(5, H - 5))],
            fill=(80, 90, 125), width=1
        )

    # speckle noise
    for _ in range(450):
        px, py = random.randint(0, W - 1), random.randint(0, H - 1)
        shade = random.randint(30, 120)
        draw.point((px, py), fill=(shade, shade, shade + 20))
        if random.random() < 0.3:
            draw.point((px + 1, py), fill=(shade, shade, shade + 20))

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@app.route("/captcha.png")
def captcha_image():
    # a new image replaces the previous one for this browser
    drop_captcha(session.pop("captcha_id", None))

    cid, text = new_captcha()
    session["captcha_id"] = cid

    resp = Response(make_captcha_image(text), mimetype="image/png")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    return resp


# ---------------- EMAIL SENDING ---------------- #

def send_email(to_email, subject, text_body, html_body):
    """
    Returns True if the email was handed to a provider.
    1) Brevo HTTP API  (BREVO_API_KEY + MAIL_FROM)  -> works on Render free plan
    2) SMTP            (SMTP_HOST ...)              -> blocked on Render free plan
    3) EMAIL_DEV_MODE=1 prints the mail to the console (local testing only)
    """
    sender_name = os.environ.get("MAIL_FROM_NAME", "DirectLine")

    api_key = os.environ.get("BREVO_API_KEY")
    sender = os.environ.get("MAIL_FROM")

    if api_key and sender:
        payload = json.dumps({
            "sender": {"name": sender_name, "email": sender},
            "to": [{"email": to_email}],
            "subject": subject,
            "htmlContent": html_body,
            "textContent": text_body,
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.brevo.com/v3/smtp/email",
            data=payload,
            method="POST",
            headers={
                "api-key": api_key,
                "content-type": "application/json",
                "accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return 200 <= r.status < 300
        except Exception as e:
            print("Brevo email error:", repr(e))
            return False

    smtp_host = os.environ.get("SMTP_HOST")
    if smtp_host:
        smtp_user = os.environ.get("SMTP_USER")
        from_addr = sender or smtp_user
        try:
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = f"{sender_name} <{from_addr}>"
            msg["To"] = to_email
            msg.set_content(text_body)
            msg.add_alternative(html_body, subtype="html")

            port = int(os.environ.get("SMTP_PORT", "587"))
            if port == 465:
                server = smtplib.SMTP_SSL(smtp_host, port, timeout=15)
            else:
                server = smtplib.SMTP(smtp_host, port, timeout=15)
                server.starttls()
            with server:
                if smtp_user:
                    server.login(smtp_user, os.environ.get("SMTP_PASS", ""))
                server.send_message(msg)
            return True
        except Exception as e:
            print("SMTP email error:", repr(e))
            return False

    if os.environ.get("EMAIL_DEV_MODE") == "1":
        print(f"\n[EMAIL_DEV_MODE] To: {to_email}\n{subject}\n{text_body}\n")
        return True

    print("Email is not configured: set BREVO_API_KEY and MAIL_FROM")
    return False


# ---------------- EMAIL VERIFICATION (6-digit code) ---------------- #

def hash_code(userid, code):
    return hmac.new(
        app.secret_key.encode(), f"{userid}:{code}".encode(), hashlib.sha256
    ).hexdigest()


def issue_code(userid):
    """
    Create + email a fresh code. Returns (status, extra):
      ("sent", masked_email) | ("wait", seconds) | ("failed", None) | ("noemail", None)
    """
    with users_lock:
        users = load_users()
        user = find_user(users, userid)

        if not user or not user.get("email"):
            return "noemail", None

        now = time.time()
        wait = RESEND_COOLDOWN - (now - user.get("verify_sent_at", 0))
        if wait > 0:
            return "wait", int(wait) + 1

        code = "{:06d}".format(secrets.randbelow(10 ** 6))
        user["verify_hash"] = hash_code(userid, code)
        user["verify_expires"] = now + CODE_TTL
        user["verify_attempts"] = 0
        user["verify_sent_at"] = now
        save_users(users)
        email = user["email"]

    minutes = CODE_TTL // 60
    ok = send_email(
        email,
        "Your DirectLine verification code",
        f"Your DirectLine verification code is {code}\n\n"
        f"It expires in {minutes} minutes. If you didn't sign up, ignore this email.",
        f"""<div style="font-family:Arial,sans-serif;max-width:420px">
        <h2>DirectLine</h2>
        <p>Your verification code is:</p>
        <p style="font-size:32px;font-weight:bold;letter-spacing:6px">{code}</p>
        <p>It expires in {minutes} minutes. If you didn't sign up, you can ignore this email.</p>
        </div>""",
    )

    if not ok:
        with users_lock:
            users = load_users()
            user = find_user(users, userid)
            if user:
                user["verify_sent_at"] = 0     # let them retry straight away
                save_users(users)
        return "failed", None

    return "sent", mask_email(email)


def start_verification(userid):
    """Send a code and leave a message for the verify page to show."""
    status, extra = issue_code(userid)

    if status == "sent":
        session["verify_msg"] = ["info", f"We sent a 6-digit code to {extra}. It expires in {CODE_TTL // 60} minutes."]
    elif status == "wait":
        session["verify_msg"] = ["info", "A code was sent recently. Check your inbox (and spam folder)."]
    else:
        session["verify_msg"] = ["error", "We couldn't send the email right now. Tap \"Resend code\" to try again."]


def finish_login(userid):
    for key in ("pending_user", "verify_user", "verify_msg"):
        session.pop(key, None)
    session["user"] = userid
    return redirect("/chat")


# ---------------- HOME / STEP 1: USER ID + CAPTCHA ---------------- #

@app.route("/")
def home():
    # already fully logged in -> skip straight to chat
    if "user" in session:
        return redirect("/chat")

    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():

    userid = request.form.get("userid", "").strip().lower()
    captcha_input = request.form.get("captcha", "")

    # captcha is checked first and is always consumed (single use)
    captcha_id = session.pop("captcha_id", None)

    if not captcha_id:
        return redirect("/")

    if not userid:
        drop_captcha(captcha_id)
        return render_home_error("User ID is required")

    if not check_captcha(captcha_id, captcha_input):
        return render_home_error("Wrong captcha, try the new one")

    users = load_users()
    existing = find_user(users, userid)

    # remember who is going through the auth flow right now
    session["pending_user"] = userid

    if existing is None:
        # brand new user id -> must create a password first
        return redirect("/set-password")
    else:
        # known user id -> must enter their existing password
        return redirect("/enter-password")


def render_home_error(message):
    # the captcha image is requested again by the page, so a fresh one appears
    return render_template("index.html", error=message)


# ---------------- STEP 2a: NEW USER SETS PASSWORD + EMAIL ---------------- #

@app.route("/set-password", methods=["GET", "POST"])
def set_password():

    userid = session.get("pending_user")

    if not userid:
        return redirect("/")

    with users_lock:
        users = load_users()

        # safety net: if this id got created in the meantime, don't overwrite it
        if find_user(users, userid) is not None:
            return redirect("/enter-password")

        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm", "")

            def fail(msg):
                return render_template(
                    "set_password.html", userid=userid, email=email, error=msg
                )

            if not EMAIL_RE.match(email) or len(email) > 254:
                return fail("Enter a valid email address")

            if email_in_use(users, email):
                return fail("This email is already registered")

            if not password or len(password) < 4:
                return fail("Password must be at least 4 characters")

            if password != confirm:
                return fail("Passwords do not match")

            users.append({
                "userid": userid,
                "password": generate_password_hash(password),
                "email": email,
                "email_verified": False,
                "created_at": time.time(),
            })
            save_users(users)

            # not logged in yet: they still have to verify the email
            session.pop("pending_user", None)
            session["verify_user"] = userid

    if request.method == "POST":
        start_verification(userid)
        return redirect("/verify-email")

    return render_template("set_password.html", userid=userid, email="", error=None)


# ---------------- STEP 2b: RETURNING USER ENTERS PASSWORD ---------------- #

@app.route("/enter-password", methods=["GET", "POST"])
def enter_password():

    userid = session.get("pending_user")

    if not userid:
        return redirect("/")

    users = load_users()
    existing = find_user(users, userid)

    if existing is None:
        return redirect("/set-password")

    if request.method == "POST":
        password = request.form.get("password", "")

        if not check_password_hash(existing["password"], password):
            return render_template(
                "password.html",
                userid=userid,
                error="Wrong password"
            )

        if existing.get("email_verified"):
            return finish_login(userid)

        # password is right but the email was never verified
        session.pop("pending_user", None)
        session["verify_user"] = userid

        if not existing.get("email"):
            return redirect("/add-email")     # older account without an email

        start_verification(userid)
        return redirect("/verify-email")

    return render_template("password.html", userid=userid, error=None)


# ---------------- ADD / CHANGE EMAIL (only before it is verified) ---------------- #

@app.route("/add-email", methods=["GET", "POST"])
def add_email():

    userid = session.get("verify_user")

    if not userid:
        return redirect("/")

    with users_lock:
        users = load_users()
        user = find_user(users, userid)

        if user is None:
            session.pop("verify_user", None)
            return redirect("/")

        if user.get("email_verified"):
            return finish_login(userid)

        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()

            error = None
            if not EMAIL_RE.match(email) or len(email) > 254:
                error = "Enter a valid email address"
            elif email_in_use(users, email, exclude_userid=userid):
                error = "This email is already registered"

            if error:
                return render_template("add_email.html", userid=userid, email=email, error=error)

            user["email"] = email
            user["created_at"] = time.time()
            for k in ("verify_hash", "verify_expires", "verify_attempts", "verify_sent_at"):
                user.pop(k, None)
            save_users(users)

    if request.method == "POST":
        start_verification(userid)
        return redirect("/verify-email")

    return render_template("add_email.html", userid=userid, email=user.get("email", ""), error=None)


# ---------------- VERIFY EMAIL CODE ---------------- #

@app.route("/verify-email", methods=["GET", "POST"])
def verify_email():

    userid = session.get("verify_user")

    if not userid:
        return redirect("/")

    with users_lock:
        users = load_users()
        user = find_user(users, userid)

        if user is None:
            session.pop("verify_user", None)
            return redirect("/")

        if user.get("email_verified"):
            return finish_login(userid)

        if not user.get("email"):
            return redirect("/add-email")

        email_masked = mask_email(user["email"])
        error = None
        info = None

        if request.method == "POST":
            code = re.sub(r"\D", "", request.form.get("code", ""))

            if not user.get("verify_hash") or time.time() > user.get("verify_expires", 0):
                error = "This code has expired. Tap \"Resend code\" to get a new one."

            elif user.get("verify_attempts", 0) >= MAX_CODE_ATTEMPTS:
                error = "Too many wrong attempts. Tap \"Resend code\" to get a new one."

            elif hmac.compare_digest(user["verify_hash"], hash_code(userid, code)):
                user["email_verified"] = True
                for k in ("verify_hash", "verify_expires", "verify_attempts", "verify_sent_at"):
                    user.pop(k, None)
                save_users(users)
                return finish_login(userid)

            else:
                user["verify_attempts"] = user.get("verify_attempts", 0) + 1
                save_users(users)
                left = MAX_CODE_ATTEMPTS - user["verify_attempts"]
                error = f"Wrong code. {left} attempt(s) left." if left > 0 else \
                        "Too many wrong attempts. Tap \"Resend code\" to get a new one."

        else:
            msg = session.pop("verify_msg", None)
            if msg:
                if msg[0] == "error":
                    error = msg[1]
                else:
                    info = msg[1]

    return render_template("verify.html", email=email_masked, error=error, info=info)


@app.route("/resend-code", methods=["POST"])
def resend_code():

    userid = session.get("verify_user")

    if not userid:
        return redirect("/")

    status, extra = issue_code(userid)

    if status == "sent":
        session["verify_msg"] = ["info", f"A new code was sent to {extra}."]
    elif status == "wait":
        session["verify_msg"] = ["error", f"Please wait {extra} seconds before requesting another code."]
    elif status == "noemail":
        return redirect("/add-email")
    else:
        session["verify_msg"] = ["error", "We couldn't send the email right now. Please try again in a moment."]

    return redirect("/verify-email")


# ---------------- CHAT PAGE ---------------- #

def chat_usernames(me):
    # only people with a verified email show up in the chat list
    users = load_users()
    return [u["userid"] for u in users if u.get("email_verified") and u["userid"] != me]


@app.route("/chat")
def chat():

    if "user" not in session:
        return redirect("/")

    me = session["user"]

    return render_template(
        "chat.html",
        users=chat_usernames(me),
        me=me
    )


# ---------------- LIVE USER LIST ---------------- #
# Sidebar polls this every few seconds so newly registered
# users show up for others without a page refresh.

@app.route("/api/users")
def api_users():

    if "user" not in session:
        return jsonify([])

    return jsonify(chat_usernames(session["user"]))


# ---------------- SEND MESSAGE ---------------- #

@app.route("/send", methods=["POST"])
def send():

    if "user" not in session:
        return jsonify({"status": "error", "message": "Not logged in"}), 401

    sender = session["user"]

    receiver = request.form.get("receiver", "").strip().lower()

    message = request.form.get("message", "").strip()

    if not receiver or not message:
        return jsonify({"status": "error", "message": "Receiver and message required"}), 400

    messages = load_messages()

    messages.append({
        "from": sender,
        "to": receiver,
        "message": message
    })

    save_messages(messages)

    return jsonify({"status": "ok"})


# ---------------- LOAD CHAT ---------------- #

@app.route("/messages/<receiver>")
def messages(receiver):

    if "user" not in session:
        return jsonify([])

    me = session["user"]

    all_messages = load_messages()

    chat = []

    for m in all_messages:

        if (
            (m["from"] == me and m["to"] == receiver)
            or
            (m["from"] == receiver and m["to"] == me)
        ):

            chat.append(m)

    return jsonify(chat)


# ---------------- LOGOUT ---------------- #

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


# ---------------- RUN (local only; Render uses gunicorn) ---------------- #

if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=os.environ.get("FLASK_DEBUG") == "1"
    )
