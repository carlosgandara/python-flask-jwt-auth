import secrets
import datetime
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect
import bcrypt
import jwt

from flask_limiter import Limiter                     # <-- NEW
from flask_limiter.util import get_remote_address     # <-- NEW

from config import (
    JWT_SECRET, JWT_EXPIRATION, RESET_TOKEN_EXPIRATION, VERIFICATION_EXPIRATION
)
from utils.db import find_user_by_email, create_user, update_user, _read_db
from utils.mail_service import send_email

app = Flask(__name__)
app.config["SECRET_KEY"] = JWT_SECRET

# ---------- Rate Limiter Setup ----------           # <-- NEW
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# ---------- Error handler for 429 ----------        # <-- NEW
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Too many requests. Please slow down."}), 429

def generate_jwt(email):
    payload = {"sub": email, "exp": datetime.datetime.utcnow() + JWT_EXPIRATION}
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")

# ---------- HTML Pages ----------
@app.route("/")
def home():
    return redirect("/login")

@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")

@app.route("/register", methods=["GET"])
def register_page():
    return render_template("register.html")

@app.route("/forgot-password", methods=["GET"])
def forgot_page():
    return render_template("forgot_password.html")

@app.route("/reset-password", methods=["GET"])
def reset_page():
    return render_template("reset_password.html", token=request.args.get("token"))

# ---------- API Endpoints with Rate Limits ----------
@app.route("/register", methods=["POST"])
@limiter.limit("5 per minute")                        # <-- NEW
def register():
    data = request.get_json()
    email, password = data.get("email"), data.get("password")
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    if find_user_by_email(email):
        return jsonify({"error": "User already exists"}), 409

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    user = create_user(email, hashed.decode("utf-8"))

    token = secrets.token_urlsafe(32)
    expiry = datetime.datetime.utcnow() + VERIFICATION_EXPIRATION
    update_user(email, {
        "verification_token": token,
        "verification_expiry": expiry.isoformat()
    })

    verify_link = f"http://localhost:5000/verify-email?token={token}"
    subject = "Verify your email"
    text = f"Welcome! Click the link to verify: {verify_link}"
    html = f'''
    <p>Welcome!</p>
    <p>Click the button below to verify:</p>
    <p><a href="{verify_link}" style="display:inline-block;padding:12px 24px;background:#007bff;color:#fff;text-decoration:none;border-radius:6px;">Verify Email</a></p>
    <p>Expires in 24h.</p>
    '''
    try:
        send_email(email, subject, text, html)
    except Exception as e:
        print("Verification email failed:", e)

    return jsonify({"message": "User created. Verification email sent."}), 201

@app.route("/verify-email", methods=["GET"])
def verify_email():
    token = request.args.get("token")
    if not token:
        return render_template("verify_error.html", error="Missing token."), 400

    db_data = _read_db()
    user_found = None
    for user in db_data["users"]:
        stored_token = user.get("verification_token")
        expiry_str = user.get("verification_expiry")
        if not stored_token or not expiry_str:
            continue
        expiry = datetime.datetime.fromisoformat(expiry_str)
        if expiry < datetime.datetime.utcnow():
            continue
        if token == stored_token:
            user_found = user
            break

    if not user_found:
        return render_template("verify_error.html", error="Invalid or expired token."), 400

    update_user(user_found["email"], {
        "verified": True,
        "verification_token": None,
        "verification_expiry": None
    })
    return render_template("verify_success.html")

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")                        # <-- NEW
def login():
    data = request.get_json()
    email, password = data.get("email"), data.get("password")
    user = find_user_by_email(email)
    if not user or not bcrypt.checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
        return jsonify({"error": "Invalid credentials"}), 401
    if not user.get("verified", False):
        return jsonify({"error": "Please verify your email first."}), 403
    token = generate_jwt(email)
    return jsonify({"access_token": token}), 200

@app.route("/forgot-password", methods=["POST"])
@limiter.limit("5 per minute")                        # <-- NEW
def forgot_password():
    data = request.get_json()
    email = data.get("email")
    user = find_user_by_email(email)
    if not user:
        return jsonify({"message": "If that email exists, a reset link was sent"}), 200

    token = secrets.token_urlsafe(32)
    hashed_token = bcrypt.hashpw(token.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    expiry = datetime.datetime.utcnow() + RESET_TOKEN_EXPIRATION
    update_user(email, {"reset_token": hashed_token, "reset_expiry": expiry.isoformat()})

    reset_link = f"http://localhost:5000/reset-password?token={token}"
    subject = "Password Reset"
    text = f"Click: {reset_link}"
    html = f'''
    <p>Click the button to reset:</p>
    <p><a href="{reset_link}" style="display:inline-block;padding:12px 24px;background:#28a745;color:#fff;text-decoration:none;border-radius:6px;">Reset Password</a></p>
    <p>Expires in 15 min.</p>
    '''
    try:
        send_email(email, subject, text, html)
    except Exception as e:
        print("Email error:", e)
    return jsonify({"message": "If that email exists, a reset link was sent"}), 200

@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json()
    token, new_password = data.get("token"), data.get("new_password")
    if not token or not new_password:
        return jsonify({"error": "Token and password required"}), 400

    db_data = _read_db()
    user_found = None
    for user in db_data["users"]:
        stored_hash = user.get("reset_token")
        expiry_str = user.get("reset_expiry")
        if not stored_hash or not expiry_str:
            continue
        expiry = datetime.datetime.fromisoformat(expiry_str)
        if expiry < datetime.datetime.utcnow():
            continue
        if bcrypt.checkpw(token.encode("utf-8"), stored_hash.encode("utf-8")):
            user_found = user
            break

    if not user_found:
        return jsonify({"error": "Invalid or expired token"}), 400

    new_hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    update_user(user_found["email"], {
        "password": new_hashed,
        "reset_token": None,
        "reset_expiry": None
    })
    return jsonify({"message": "Password updated"}), 200

# ---------- Protected Route ----------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401
        token = auth.split(" ")[1]
        try:
            payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            request.user_email = payload["sub"]
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return jsonify({"error": "Invalid or expired token"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/protected", methods=["GET"])
@token_required
def protected():
    return jsonify({"message": f"Hello {request.user_email}!"}), 200

if __name__ == "__main__":
    app.run(debug=True)