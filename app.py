"""
PaySecure - app.py
Flask backend for phishing detection & payment verification system.
"""

import sqlite3
import json
import re
import os
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, g
)
from werkzeug.security import generate_password_hash, check_password_hash


# APP CONFIG

app = Flask(__name__)
app.secret_key = os.urandom(24)  

DATABASE = "database.db"


# DATABASE HELPERS

def get_db():
    """Open a DB connection tied to the current request context."""
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row   # rows behave like dicts
    return db

@app.teardown_appcontext
def close_db(exception):
    """Auto-close DB connection after every request."""
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def init_db():
    """Create tables and seed initial data (Admin + Aggressive Phishing Rules)."""
    with app.app_context():
        db = get_db()
        # 1. Build the tables from schema.sql
        with open("schema.sql", "r") as f:
            db.executescript(f.read())

        # 2. Seed admin account if missing
        existing_admin = db.execute(
            "SELECT id FROM users WHERE role = 'admin'"
        ).fetchone()
        
        if not existing_admin:
            db.execute(
                """INSERT INTO users (username, email, password_hash, role)
                   VALUES (?, ?, ?, ?)""",
                (
                    "admin",
                    "admin@paysecure.com",
                    generate_password_hash("admin123"),
                    "admin",
                ),
            )
            db.commit()
            print("[DB] Admin account seeded.")

        # 3. Seed Aggressive Phishing Rules (Matches Zetech ERD)
        if not db.execute("SELECT id FROM phishing_rules LIMIT 1").fetchone():
            rules = [
                # Keywords (Shorter patterns are more reliable for detection)
                ('verify', 'keyword', 2),
                ('suspend', 'keyword', 3),
                ('blocked', 'keyword', 3),
                ('immediately', 'keyword', 2),
                ('urgent', 'keyword', 2),
                ('winner', 'keyword', 3),
                ('reversal', 'keyword', 3),
                ('update', 'keyword', 1),
                ('login', 'keyword', 2),
                
                # Suspicious Domains (High impact for instant 'Dangerous' verdict)
                ('bit.ly', 'suspicious_domain', 4),
                ('tinyurl', 'suspicious_domain', 4),
                ('mpesaa', 'suspicious_domain', 5),
                ('safar1com', 'suspicious_domain', 5),
                ('equit0', 'suspicious_domain', 5),
                
                # Safe Whitelist (Weight 0)
                ('safaricom.com', 'safe_domain', 0),
                ('equitybank.co.ke', 'safe_domain', 0),
                ('kcbgroup.com', 'safe_domain', 0)
            ]
            db.executemany(
                "INSERT INTO phishing_rules (pattern, type, weight) VALUES (?, ?, ?)", 
                rules
            )
            db.commit()
            print("[DB] Aggressive Phishing Rules seeded.")
        else:
            print("[DB] System database and rules are ready.")


def log_activity(user_id, action, detail=None):
    """Write a row to activity_logs."""
    db = get_db()
    ip = request.remote_addr
    db.execute(
        """INSERT INTO activity_logs (user_id, action, detail, ip_address)
           VALUES (?, ?, ?, ?)""",
        (user_id, action, detail, ip),
    )
    db.commit()


# AUTH DECORATORS

def login_required(f):
    """Redirect to login if user is not in session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access that page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """Redirect to dashboard if user is not an admin."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in.", "warning")
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            flash("Access denied. Admins only.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated


# PHISHING DETECTION ENGINE

PHISHING_KEYWORDS = [
    "verify your account", "confirm your payment", "click here immediately",
    "your account will be suspended", "urgent action required",
    "enter your pin", "enter your password", "login to avoid",
    "limited time offer", "you have won", "congratulations you",
    "free money", "send money now", "update your details",
    "bank account blocked", "mpesa reversal", "your sim will be deactivated",
]

SUSPICIOUS_DOMAINS = [
    "bit.ly", "tinyurl", "shorturl", "goo.gl", "ow.ly",
    "mpesaa", "safar1com", "equit0bank", "kcbb.co", "paypa1",
    "secure-update", "account-verify", "login-confirm",
]

SAFE_DOMAINS = [
    "safaricom.com", "equitybank.co.ke", "kcbgroup.com",
    "paypal.com", "mpesa.safaricom.com", "equity.co.ke",
]

def analyze_message(text: str) -> dict:
    text_lower = text.lower()
    flags = []
    score = 0
    
    db = get_db()
    rules = db.execute("SELECT pattern, type, weight FROM phishing_rules").fetchall()
    
    # 1. Database Pattern Matching
    for rule in rules:
        if rule['pattern'] in text_lower:
            if rule['type'] == 'keyword':
                flags.append(f"Suspicious keyword: '{rule['pattern']}'")
                score += rule['weight']
            elif rule['type'] == 'suspicious_domain':
                flags.append(f"Blacklisted domain/link detected: '{rule['pattern']}'")
                score += rule['weight']

    # 2. Hardcoded Critical Security Checks (RegEx)
    # PIN/Password requests are an automatic 'Dangerous' verdict (Score +4)
    if re.search(r"pin|password|otp|secret|passcode|p.i.n", text_lower):
        flags.append("CRITICAL: Message requests sensitive credentials (PIN/OTP).")
        score += 4

    # Money/Transaction requests (Automatic Suspicious/Dangerous)
    if re.search(r"send|transfer|deposit|reverse|reversal|ksh|amount", text_lower):
        flags.append("Financial transaction request detected.")
        score += 3

    # Link Detection (Any link not in whitelist gets a small penalty)
    links = re.findall(r"https?://[^\s]+|www\.[^\s]+", text_lower)
    if links:
        for link in links:
            is_whitelisted = any(safe['pattern'] in link for safe in rules if safe['type'] == 'safe_domain')
            if not is_whitelisted:
                flags.append(f"Unverified external link: {link}")
                score += 2

    # Debugging: Print score to terminal so you can see it live!
    print(f"--- Analysis Log: Score={score} | Verdict Calculation Proceeding ---")

    # 3. Final Verdict Calculation
    if score == 0:
        verdict = "safe"
    elif score <= 3:
        verdict = "suspicious"
    else:
        verdict = "dangerous"

    return {"verdict": verdict, "flags": list(set(flags)), "score": score} # set() removes duplicates


# ROUTES — AUTH

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        # Validation
        if not all([username, email, password, confirm]):
            flash("All fields are required.", "danger")
            return render_template("register.html")
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return render_template("register.html")

        db = get_db()
        # Check duplicates
        if db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
            flash("Username already taken.", "danger")
            return render_template("register.html")
        if db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
            flash("Email already registered.", "danger")
            return render_template("register.html")

        db.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, generate_password_hash(password)),
        )
        db.commit()
        flash("Account created! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Both fields are required.", "danger")
            return render_template("login.html")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            session["role"]     = user["role"]
            log_activity(user["id"], "login")
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    log_activity(session["user_id"], "logout")
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ─────────────────────────────────────────
# ROUTES — CORE PAGES
# ─────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    # Recent verifications for this user
    recent = db.execute(
        """SELECT verdict, checked_at FROM verifications
           WHERE user_id = ? ORDER BY checked_at DESC LIMIT 5""",
        (session["user_id"],),
    ).fetchall()
    log_activity(session["user_id"], "dashboard_view")
    return render_template("dashboard.html", recent=recent)


@app.route("/learn")
@login_required
def learn():
    log_activity(session["user_id"], "learn_view")
    return render_template("learn.html")


@app.route("/verify", methods=["GET", "POST"])
@login_required
def verify():
    result = None

    if request.method == "POST":
        input_text = request.form.get("message_input", "").strip()

        if not input_text:
            flash("Please paste a message or link to verify.", "warning")
            return render_template("verify.html", result=None)

        analysis = analyze_message(input_text)
        flags_json = json.dumps(analysis["flags"])

        db = get_db()
        db.execute(
            """INSERT INTO verifications (user_id, input_text, verdict, flags)
               VALUES (?, ?, ?, ?)""",
            (session["user_id"], input_text, analysis["verdict"], flags_json),
        )
        db.commit()

        log_activity(
            session["user_id"],
            "verify",
            f"verdict={analysis['verdict']} score={analysis['score']}",
        )

        result = {
            "verdict": analysis["verdict"],
            "flags":   analysis["flags"],
            "score":   analysis["score"],
            "input":   input_text,
        }

    return render_template("verify.html", result=result)


# ─────────────────────────────────────────
# ROUTES — ADMIN
# ─────────────────────────────────────────
@app.route("/admin")
@admin_required
def admin():
    db = get_db()

    total_users = db.execute(
        "SELECT COUNT(*) as c FROM users WHERE role = 'student'"
    ).fetchone()["c"]

    total_verifications = db.execute(
        "SELECT COUNT(*) as c FROM verifications"
    ).fetchone()["c"]

    dangerous_count = db.execute(
        "SELECT COUNT(*) as c FROM verifications WHERE verdict = 'dangerous'"
    ).fetchone()["c"]

    recent_logs = db.execute(
        """SELECT u.username, a.action, a.detail, a.ip_address, a.logged_at
           FROM activity_logs a
           JOIN users u ON u.id = a.user_id
           ORDER BY a.logged_at DESC LIMIT 20"""
    ).fetchall()

    return render_template(
        "admin.html",
        total_users=total_users,
        total_verifications=total_verifications,
        dangerous_count=dangerous_count,
        recent_logs=recent_logs,
    )


if __name__ == "__main__":
    init_db()
    app.run(debug=True)