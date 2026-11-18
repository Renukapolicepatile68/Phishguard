import csv
import hashlib
import io
import json
import os
import secrets
import smtplib
from datetime import date, datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps
from pathlib import Path
from urllib.parse import quote, urlsplit

from flask import Flask, jsonify, request, send_file, send_from_directory, session
from flask_cors import CORS
from flask.json.provider import DefaultJSONProvider
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from werkzeug.security import check_password_hash, generate_password_hash

from database import DB_INTEGRITY_ERRORS, get_db, init_db
from url_analyzer import analyze_url


app = Flask(__name__)
FRONTEND_ROOT = Path(__file__).resolve().parent.parent


class ISOJSONProvider(DefaultJSONProvider):
    def default(self, value):
        if isinstance(value, datetime):
            return value.isoformat(sep=" ")
        if isinstance(value, date):
            return value.isoformat()
        return super().default(value)


app.json = ISOJSONProvider(app)
production = os.environ.get("PHISHGUARD_ENV") == "production"
if production and not os.environ.get("PHISHGUARD_SECRET_KEY"):
    raise RuntimeError("PHISHGUARD_SECRET_KEY must be configured in production.")
cookie_samesite = os.environ.get("PHISHGUARD_COOKIE_SAMESITE", "Lax").capitalize()
if cookie_samesite not in ("Lax", "Strict", "None"):
    raise RuntimeError("PHISHGUARD_COOKIE_SAMESITE must be Lax, Strict, or None.")
if cookie_samesite == "None" and not production:
    raise RuntimeError("SameSite=None cookies require PHISHGUARD_ENV=production and HTTPS.")
app.config.update(
    SECRET_KEY=os.environ.get("PHISHGUARD_SECRET_KEY") or secrets.token_urlsafe(48),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=cookie_samesite,
    SESSION_COOKIE_SECURE=production,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)

default_origins = "" if production else "http://127.0.0.1:5500"
allowed_origins = [
    origin.strip().rstrip("/")
    for origin in os.environ.get(
        "PHISHGUARD_ALLOWED_ORIGINS",
        default_origins,
    ).split(",")
    if origin.strip()
]
for origin in allowed_origins:
    parsed_origin = urlsplit(origin)
    if (
        origin == "*"
        or parsed_origin.scheme not in ("http", "https")
        or not parsed_origin.netloc
        or parsed_origin.path
        or parsed_origin.query
        or parsed_origin.fragment
    ):
        raise RuntimeError("PHISHGUARD_ALLOWED_ORIGINS must contain exact origins, without paths or wildcards.")
    if production and parsed_origin.scheme != "https":
        raise RuntimeError("Production CORS origins must use HTTPS.")
CORS(app, origins=allowed_origins, supports_credentials=True)
init_db()

DEFAULT_SETTINGS = {
    "store_history": True,
    "critical_alerts": True,
}
RESET_MESSAGE = "If an account exists for that email, password reset instructions have been sent."


def api_error(message, status):
    return jsonify({"error": message}), status


def request_data():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def valid_email(email):
    return (
        len(email) <= 254
        and email.count("@") == 1
        and bool(email.split("@")[0])
        and "." in email.split("@")[1]
        and not any(character.isspace() for character in email)
    )


def csrf_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        token = session.get("csrf_token", "")
        supplied = request.headers.get("X-CSRF-Token", "")
        if not token or not secrets.compare_digest(token, supplied):
            return api_error("Your session expired. Refresh the page and try again.", 403)
        return function(*args, **kwargs)

    return wrapper


def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            return api_error("Please log in to continue.", 401)
        with get_db() as db:
            user = db.execute(
                "SELECT session_version FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        if not user or user["session_version"] != session.get("session_version"):
            session.clear()
            return api_error("Your session expired. Please log in again.", 401)
        return function(*args, **kwargs)

    return wrapper


def account_required(function):
    return csrf_required(login_required(function))


def result_label(result):
    return {
        "safe": "Safe",
        "phishing": "Phishing",
        "malicious": "Malicious",
    }.get(result, result.title())


def scan_record(row):
    record = dict(row)
    record["signals"] = json.loads(record.pop("signals_json", "[]"))
    record["classification"] = result_label(record["result"])
    return record


def start_session(user):
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["session_version"] = user["session_version"]
    session["name"] = user["name"]
    session["csrf_token"] = secrets.token_urlsafe(32)


def user_settings(user_id):
    with get_db() as db:
        row = db.execute(
            "SELECT preferences_json FROM user_settings WHERE user_id = ?", (user_id,)
        ).fetchone()
    preferences = DEFAULT_SETTINGS.copy()
    if row:
        preferences.update(json.loads(row["preferences_json"]))
    return preferences


def send_reset_email(email, token):
    host = os.environ.get("PHISHGUARD_SMTP_HOST")
    sender = os.environ.get("PHISHGUARD_SMTP_FROM")
    if not host or not sender:
        raise RuntimeError("Password reset email is not configured.")

    port = int(os.environ.get("PHISHGUARD_SMTP_PORT", "587"))
    username = os.environ.get("PHISHGUARD_SMTP_USER", "")
    password = os.environ.get("PHISHGUARD_SMTP_PASSWORD", "")
    app_url = os.environ.get(
        "PHISHGUARD_APP_URL",
        os.environ.get("RENDER_EXTERNAL_URL", "http://127.0.0.1:5500"),
    ).rstrip("/")

    message = EmailMessage()
    message["Subject"] = "Reset your PhishGuard password"
    message["From"] = sender
    message["To"] = email
    message.set_content(
        "A password reset was requested for your PhishGuard account.\n\n"
        f"Reset your password within one hour: {app_url}/reset-password.html?token={quote(token)}\n\n"
        "If you did not request this, you can ignore this message."
    )

    if os.environ.get("PHISHGUARD_SMTP_SSL", "").lower() == "true":
        with smtplib.SMTP_SSL(host, port, timeout=15) as smtp:
            if username:
                smtp.login(username, password)
            smtp.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            smtp.starttls()
            if username:
                smtp.login(username, password)
            smtp.send_message(message)


@app.errorhandler(413)
def request_too_large(_error):
    return api_error("The uploaded file exceeds the 2 MB limit.", 413)


@app.errorhandler(500)
def internal_error(_error):
    return api_error("The server could not complete this request.", 500)


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "PhishGuard API"})


@app.get("/")
def frontend_home():
    return send_from_directory(FRONTEND_ROOT, "index.html")


@app.get("/<path:filename>")
def frontend_file(filename):
    if filename in {
        "index.html",
        "signup.html",
        "forgot-password.html",
        "reset-password.html",
        "dashboard.html",
        "manifest.webmanifest",
        "sw.js",
    } or filename.startswith(("assets/", "css/", "js/")):
        return send_from_directory(FRONTEND_ROOT, filename)
    return api_error("Not found.", 404)


@app.post("/api/signup")
def signup():
    data = request_data()
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    if not 2 <= len(name) <= 80 or not valid_email(email) or not 8 <= len(password) <= 128:
        return api_error("Enter a name, valid email, and password with at least 8 characters.", 400)

    try:
        with get_db() as db:
            cursor = db.execute(
                "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?) RETURNING id",
                (name, email, generate_password_hash(password)),
            )
            user = db.execute(
                "SELECT id, name, email, session_version FROM users WHERE id = ?",
                (cursor.fetchone()["id"],),
            ).fetchone()
    except DB_INTEGRITY_ERRORS:
        return api_error("An account with that email already exists.", 409)

    start_session(user)
    return jsonify({"message": "Account created successfully.", "user": {
        "name": user["name"], "email": user["email"], "csrf_token": session["csrf_token"]
    }}), 201


@app.post("/api/login")
def login():
    data = request_data()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    with get_db() as db:
        user = db.execute(
            "SELECT id, name, email, password_hash, session_version FROM users WHERE email = ?",
            (email,),
        ).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        return api_error("Invalid email or password.", 401)
    start_session(user)
    return jsonify({"message": "Login successful.", "user": {
        "name": user["name"], "email": user["email"], "csrf_token": session["csrf_token"]
    }})


@app.post("/api/logout")
@account_required
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully."})


@app.get("/api/me")
@login_required
def me():
    with get_db() as db:
        user = db.execute(
            "SELECT name, email, created_at FROM users WHERE id = ?",
            (session["user_id"],),
        ).fetchone()
    if not user:
        session.clear()
        return api_error("Account not found.", 401)
    return jsonify({"user": dict(user), "csrf_token": session["csrf_token"]})


@app.put("/api/profile")
@account_required
def update_profile():
    data = request_data()
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    current_password = str(data.get("current_password", ""))
    if not 2 <= len(name) <= 80 or not valid_email(email):
        return api_error("Enter a valid name and email address.", 400)

    with get_db() as db:
        user = db.execute(
            "SELECT password_hash FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        if not user or not check_password_hash(user["password_hash"], current_password):
            return api_error("Your current password is incorrect.", 403)
        try:
            db.execute(
                "UPDATE users SET name = ?, email = ? WHERE id = ?",
                (name, email, session["user_id"]),
            )
        except DB_INTEGRITY_ERRORS:
            return api_error("That email address is already in use.", 409)

    session["name"] = name
    return jsonify({"message": "Profile updated.", "user": {"name": name, "email": email}})


@app.delete("/api/me")
@account_required
def delete_account():
    password = str(request_data().get("password", ""))
    with get_db() as db:
        user = db.execute(
            "SELECT password_hash FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            return api_error("Your password is incorrect.", 403)
        user_id = session["user_id"]
        db.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM user_settings WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    session.clear()
    return jsonify({"message": "Account deleted."})


@app.post("/api/forgot-password")
def forgot_password():
    email = str(request_data().get("email", "")).strip().lower()
    if not valid_email(email):
        return api_error("Enter a valid email address.", 400)
    if not os.environ.get("PHISHGUARD_SMTP_HOST") or not os.environ.get("PHISHGUARD_SMTP_FROM"):
        return api_error("Password reset email is not configured. Set the SMTP environment variables and try again.", 503)
    with get_db() as db:
        user = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if not user:
            return jsonify({"message": RESET_MESSAGE})
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        db.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (user["id"],))
        db.execute(
            "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
            (user["id"], token_hash, expires_at),
        )
    try:
        send_reset_email(email, token)
    except (OSError, smtplib.SMTPException, RuntimeError, ValueError):
        with get_db() as db:
            db.execute(
                "DELETE FROM password_reset_tokens WHERE user_id = ? AND token_hash = ?",
                (user["id"], token_hash),
            )
        app.logger.exception("Password reset email delivery failed.")
        return api_error("Password reset email is unavailable. Check the SMTP configuration and try again.", 503)
    return jsonify({"message": RESET_MESSAGE})


@app.post("/api/reset-password")
def reset_password():
    data = request_data()
    token = str(data.get("token", ""))
    password = str(data.get("password", ""))
    if not token or len(token) > 256 or not 8 <= len(password) <= 128:
        return api_error("Enter a valid reset link and a password with at least 8 characters.", 400)

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with get_db() as db:
        reset = db.execute(
            "SELECT user_id, expires_at FROM password_reset_tokens WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
        if not reset or datetime.fromisoformat(reset["expires_at"]) <= datetime.now(timezone.utc):
            if reset:
                db.execute("DELETE FROM password_reset_tokens WHERE token_hash = ?", (token_hash,))
            return api_error("This reset link is invalid or expired. Request a new one.", 400)
        db.execute(
            "UPDATE users SET password_hash = ?, session_version = session_version + 1 WHERE id = ?",
            (generate_password_hash(password), reset["user_id"]),
        )
        db.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (reset["user_id"],))
    session.clear()
    return jsonify({"message": "Password reset successfully. Please log in with your new password."})


@app.post("/api/scan")
@account_required
def scan():
    try:
        result = analyze_url(str(request_data().get("url", "")))
    except ValueError as error:
        return api_error(str(error), 400)

    if not user_settings(session["user_id"])["store_history"]:
        return jsonify({
            **result,
            "classification": result_label(result["result"]),
            "created_at": datetime.now().astimezone().isoformat(),
            "id": None,
            "saved": False,
        }), 201
    with get_db() as db:
        cursor = db.execute(
            "INSERT INTO scans (user_id, url, result, risk_score, signals_json) VALUES (?, ?, ?, ?, ?) RETURNING id",
            (
                session["user_id"],
                result["url"],
                result["result"],
                result["risk_score"],
                json.dumps(result["signals"]),
            ),
        )
        row = db.execute(
            "SELECT id, url, result, risk_score, signals_json, created_at FROM scans WHERE id = ?",
            (cursor.fetchone()["id"],),
        ).fetchone()
    record = scan_record(row)
    record.update({"features": result["features"], "protocol": result["protocol"], "saved": True})
    return jsonify(record), 201


@app.get("/api/history")
@login_required
def history():
    search = request.args.get("q", "").strip()[:256]
    classification = request.args.get("result", "").strip().lower()
    days = request.args.get("days", "").strip()
    try:
        limit = min(100, max(1, int(request.args.get("limit", "100"))))
        offset = max(0, int(request.args.get("offset", "0")))
        day_count = int(days) if days else 0
    except ValueError:
        return api_error("Invalid history filter.", 400)
    if classification and classification not in ("safe", "phishing", "malicious"):
        return api_error("Invalid classification filter.", 400)
    if day_count not in (0, 1, 7, 30, 90):
        return api_error("Invalid date range.", 400)

    conditions = ["user_id = ?"]
    values = [session["user_id"]]
    if search:
        conditions.append("url LIKE ? ESCAPE '\\'")
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        values.append(f"%{escaped}%")
    if classification:
        conditions.append("result = ?")
        values.append(classification)
    if day_count:
        if day_count == 1:
            conditions.append("created_at >= date('now')")
        else:
            conditions.append("created_at >= datetime('now', ?)")
            values.append(f"-{day_count} days")
    where = " AND ".join(conditions)
    with get_db() as db:
        rows = db.execute(
            f"SELECT id, url, result, risk_score, signals_json, created_at FROM scans WHERE {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            (*values, limit, offset),
        ).fetchall()
        total = db.execute(f"SELECT COUNT(*) AS total FROM scans WHERE {where}", values).fetchone()["total"]
    return jsonify({"scans": [scan_record(row) for row in rows], "total": total})


@app.get("/api/history/<int:scan_id>")
@login_required
def scan_detail(scan_id):
    with get_db() as db:
        row = db.execute(
            "SELECT id, url, result, risk_score, signals_json, created_at FROM scans WHERE id = ? AND user_id = ?",
            (scan_id, session["user_id"]),
        ).fetchone()
    if not row:
        return api_error("Scan not found.", 404)
    return jsonify({"scan": scan_record(row)})


@app.delete("/api/history/<int:scan_id>")
@account_required
def delete_scan(scan_id):
    with get_db() as db:
        cursor = db.execute(
            "DELETE FROM scans WHERE id = ? AND user_id = ?",
            (scan_id, session["user_id"]),
        )
    if not cursor.rowcount:
        return api_error("Scan not found.", 404)
    return jsonify({"message": "Scan deleted."})


@app.delete("/api/history")
@account_required
def clear_history():
    with get_db() as db:
        db.execute("DELETE FROM scans WHERE user_id = ?", (session["user_id"],))
    return jsonify({"message": "Scan history cleared."})


@app.post("/api/bulk-scan")
@account_required
def bulk_scan():
    upload = request.files.get("file")
    if not upload or not upload.filename or not upload.filename.lower().endswith(".csv"):
        return api_error("Choose a CSV file containing one URL per row.", 400)
    try:
        text = io.TextIOWrapper(upload.stream, encoding="utf-8-sig", newline="")
        rows = csv.reader(text)
        urls = []
        for row in rows:
            if not row or not row[0].strip():
                continue
            value = row[0].strip()
            if not urls and value.lower() in ("url", "website", "domain"):
                continue
            urls.append(value)
            if len(urls) > 500:
                return api_error("A bulk scan can contain at most 500 URLs.", 400)
    except (UnicodeDecodeError, csv.Error):
        return api_error("The CSV file could not be read as UTF-8.", 400)
    if not urls:
        return api_error("The CSV file does not contain any URLs.", 400)

    results = []
    for url in urls:
        try:
            results.append(analyze_url(url))
        except ValueError as error:
            return api_error(f"Invalid URL in CSV: {error}", 400)

    if user_settings(session["user_id"])["store_history"]:
        with get_db() as db:
            for result in results:
                cursor = db.execute(
                    "INSERT INTO scans (user_id, url, result, risk_score, signals_json) VALUES (?, ?, ?, ?, ?) RETURNING id",
                    (
                        session["user_id"],
                        result["url"],
                        result["result"],
                        result["risk_score"],
                        json.dumps(result["signals"]),
                    ),
                )
                result["id"] = cursor.fetchone()["id"]
                result["classification"] = result_label(result["result"])
    else:
        for result in results:
            result["classification"] = result_label(result["result"])
    counts = {key: sum(item["result"] == key for item in results)
              for key in ("safe", "phishing", "malicious")}
    return jsonify({
        "scans": results,
        "total": len(results),
        "counts": counts,
        "saved": user_settings(session["user_id"])["store_history"],
    }), 201


@app.get("/api/analytics")
@login_required
def analytics():
    try:
        days = int(request.args.get("days", "7"))
    except ValueError:
        return api_error("Invalid date range.", 400)
    if days not in (7, 30):
        return api_error("Invalid date range.", 400)
    with get_db() as db:
        counts = db.execute(
            """SELECT COUNT(*) AS total,
                      SUM(CASE WHEN result = 'safe' THEN 1 ELSE 0 END) AS safe,
                      SUM(CASE WHEN result = 'phishing' THEN 1 ELSE 0 END) AS phishing,
                      SUM(CASE WHEN result = 'malicious' THEN 1 ELSE 0 END) AS malicious,
                      CAST(COALESCE(ROUND(AVG(risk_score), 1), 0) AS REAL) AS average_risk
               FROM scans WHERE user_id = ?""",
            (session["user_id"],),
        ).fetchone()
        daily = db.execute(
            """SELECT CAST(date(created_at) AS TEXT) AS day, COUNT(*) AS total,
                      SUM(CASE WHEN result != 'safe' THEN 1 ELSE 0 END) AS threats
               FROM scans WHERE user_id = ? AND created_at >= datetime('now', ?)
               GROUP BY date(created_at)""",
            (session["user_id"], f"-{days - 1} days"),
        ).fetchall()
        recent = db.execute(
            """SELECT id, url, result, risk_score, created_at FROM scans
               WHERE user_id = ? AND result = 'malicious'
               ORDER BY id DESC LIMIT 10""",
            (session["user_id"],),
        ).fetchall()
    daily_by_date = {row["day"]: dict(row) for row in daily}
    activity = []
    today = datetime.now().date()
    for offset in range(days - 1, -1, -1):
        day = (today - timedelta(days=offset)).isoformat()
        item = daily_by_date.get(day, {"day": day, "total": 0, "threats": 0})
        activity.append(item)
    return jsonify({
        "summary": dict(counts),
        "activity": activity,
        "recent_threats": [dict(row) for row in recent]
            if user_settings(session["user_id"])["critical_alerts"] else [],
    })


@app.get("/api/settings")
@login_required
def get_settings():
    with get_db() as db:
        row = db.execute(
            "SELECT preferences_json FROM user_settings WHERE user_id = ?",
            (session["user_id"],),
        ).fetchone()
    preferences = DEFAULT_SETTINGS.copy()
    if row:
        preferences.update(json.loads(row["preferences_json"]))
    return jsonify({"settings": preferences})


@app.put("/api/settings")
@account_required
def update_settings():
    data = request_data()
    if set(data) != set(DEFAULT_SETTINGS) or any(type(value) is not bool for value in data.values()):
        return api_error("Submit a boolean value for every setting.", 400)
    with get_db() as db:
        db.execute(
            """INSERT INTO user_settings (user_id, preferences_json) VALUES (?, ?)
               ON CONFLICT(user_id) DO UPDATE SET preferences_json = excluded.preferences_json""",
            (session["user_id"], json.dumps(data)),
        )
    return jsonify({"settings": data})


@app.get("/api/history/export.csv")
@login_required
def export_history():
    with get_db() as db:
        rows = db.execute(
            "SELECT url, result, risk_score, created_at FROM scans WHERE user_id = ? ORDER BY id DESC",
            (session["user_id"],),
        ).fetchall()
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["URL", "Threat type", "Risk score", "Scanned at"])
    for row in rows:
        writer.writerow([row["url"], result_label(row["result"]), row["risk_score"], row["created_at"]])
    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8-sig")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="phishguard-scan-history.csv",
    )


@app.get("/api/reports/<report_type>.pdf")
@login_required
def generate_report(report_type):
    titles = {
        "url": "URL Security Report",
        "threat": "Threat Summary",
        "model": "URL Analysis Method",
    }
    if report_type not in titles:
        return api_error("Unknown report type.", 404)
    with get_db() as db:
        scans = db.execute(
            """SELECT COUNT(*) AS total,
                      SUM(CASE WHEN result = 'safe' THEN 1 ELSE 0 END) AS safe,
                      SUM(CASE WHEN result = 'phishing' THEN 1 ELSE 0 END) AS phishing,
                      SUM(CASE WHEN result = 'malicious' THEN 1 ELSE 0 END) AS malicious,
                      CAST(COALESCE(ROUND(AVG(risk_score), 1), 0) AS REAL) AS average_risk
               FROM scans WHERE user_id = ?""",
            (session["user_id"],),
        ).fetchone()
        recent = db.execute(
            """SELECT url, result, risk_score, created_at FROM scans
               WHERE user_id = ? ORDER BY id DESC LIMIT 20""",
            (session["user_id"],),
        ).fetchall()

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    pdf.setTitle(f"PhishGuard {titles[report_type]}")
    pdf.setFont("Helvetica-Bold", 22)
    pdf.drawString(48, height - 56, "PhishGuard")
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(48, height - 88, titles[report_type])
    pdf.setFont("Helvetica", 10)
    pdf.drawString(48, height - 108, f"Generated {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M %Z')}")

    y = height - 148
    pdf.setFont("Helvetica-Bold", 11)
    pdf.drawString(48, y, "Your saved scan data")
    y -= 24
    pdf.setFont("Helvetica", 10)
    metrics = [
        ("Total scans", scans["total"] or 0),
        ("Safe", scans["safe"] or 0),
        ("Phishing", scans["phishing"] or 0),
        ("Malicious", scans["malicious"] or 0),
        ("Average risk score", f"{scans['average_risk']}/100"),
    ]
    for label, value in metrics:
        pdf.drawString(56, y, f"{label}: {value}")
        y -= 18

    if report_type == "model":
        y -= 6
        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(48, y, "Analysis approach")
        y -= 18
        pdf.setFont("Helvetica", 9)
        pdf.drawString(56, y, "Transparent URL heuristics; this is not a trained machine-learning model.")
        y -= 15
        pdf.drawString(56, y, "Risk indicators include protocol, IP host, URL length, subdomains, and URL patterns.")

    if report_type != "model":
        y -= 8
        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(48, y, "Recent scans")
        y -= 20
        for row in recent:
            if y < 62:
                pdf.showPage()
                y = height - 56
                pdf.setFont("Helvetica", 8)
            pdf.setFont("Helvetica", 8)
            pdf.drawString(48, y, quote(row["url"], safe=":/?#[]@!$&'()*+,;=%")[:88])
            pdf.drawRightString(width - 48, y, f"{result_label(row['result'])} · {row['risk_score']}/100")
            y -= 14
    pdf.save()
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"PhishGuard_{report_type}_Report.pdf",
    )


if __name__ == "__main__":
    app.run(
        host=os.environ.get("PHISHGUARD_HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )
