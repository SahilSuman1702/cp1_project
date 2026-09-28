from flask import Flask, render_template, request, redirect, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os
import random

app = Flask(__name__)
app.secret_key = "directline_demo_secret_change_me"

USERS_FILE = "users.json"
MESSAGES_FILE = "messages.json"


# ---------------- USERS ---------------- #

def load_users():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as f:
            json.dump([], f)

    with open(USERS_FILE, "r") as f:
        return json.load(f)


def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)


def find_user(users, userid):
    for u in users:
        if u.get("userid") == userid:
            return u
    return None


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


# ---------------- HOME / STEP 1: USER ID + CAPTCHA ---------------- #

@app.route("/")
def home():
    # already fully logged in -> skip straight to chat
    if "user" in session:
        return redirect("/chat")

    a = random.randint(1, 9)
    b = random.randint(1, 9)

    session["captcha"] = a + b

    return render_template("index.html", a=a, b=b)


@app.route("/login", methods=["POST"])
def login():

    userid = request.form.get("userid", "").strip().lower()
    captcha_input = request.form.get("captcha", "")

    if not userid:
        return render_home_error("User ID is required")

    if "captcha" not in session:
        return redirect("/")

    try:
        captcha_input = int(captcha_input)
    except ValueError:
        return render_home_error("Wrong Captcha")

    if captcha_input != session["captcha"]:
        return render_home_error("Wrong Captcha")

    # captcha solved once, remove it so it can't be replayed
    session.pop("captcha", None)

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
    a = random.randint(1, 9)
    b = random.randint(1, 9)
    session["captcha"] = a + b
    return render_template("index.html", a=a, b=b, error=message)


# ---------------- STEP 2a: NEW USER SETS PASSWORD ---------------- #

@app.route("/set-password", methods=["GET", "POST"])
def set_password():

    userid = session.get("pending_user")

    if not userid:
        return redirect("/")

    users = load_users()

    # safety net: if this id got created in the meantime, don't overwrite it
    if find_user(users, userid) is not None:
        return redirect("/enter-password")

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not password or len(password) < 4:
            return render_template(
                "set_password.html",
                userid=userid,
                error="Password must be at least 4 characters"
            )

        if password != confirm:
            return render_template(
                "set_password.html",
                userid=userid,
                error="Passwords do not match"
            )

        users.append({
            "userid": userid,
            "password": generate_password_hash(password)
        })
        save_users(users)

        session.pop("pending_user", None)
        session["user"] = userid

        return redirect("/chat")

    return render_template("set_password.html", userid=userid, error=None)


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

        session.pop("pending_user", None)
        session["user"] = userid

        return redirect("/chat")

    return render_template("password.html", userid=userid, error=None)


# ---------------- CHAT PAGE ---------------- #

@app.route("/chat")
def chat():

    if "user" not in session:
        return redirect("/")

    users = load_users()

    me = session["user"]

    usernames = [u["userid"] for u in users if u["userid"] != me]

    return render_template(
        "chat.html",
        users=usernames,
        me=me
    )


# ---------------- LIVE USER LIST ---------------- #
# Sidebar polls this every few seconds so newly registered
# users show up for others without a page refresh.

@app.route("/api/users")
def api_users():

    if "user" not in session:
        return jsonify([])

    me = session["user"]

    users = load_users()

    usernames = [u["userid"] for u in users if u["userid"] != me]

    return jsonify(usernames)


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


# ---------------- RUN ---------------- #

if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=True
    )
