import json
import os
import re
import secrets
import urllib.parse
import urllib.request
from pathlib import Path

from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    stream_with_context,
    url_for,
)

# =========================================================
# APP CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

templates_path = BASE_DIR / "templates"
static_path = BASE_DIR / "static"

app = Flask(
    __name__,
    template_folder=str(templates_path) if templates_path.exists() else "templates",
    static_folder=str(static_path) if static_path.exists() else "static",
    static_url_path="/static",
)

handler = app
application = app

# =========================================================
# ENVIRONMENT VARIABLES & SESSIONS
# =========================================================

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip() or secrets.token_hex(32)
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "").strip()
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "").strip() or os.environ.get("ADMIN_PASSWORD", "admin123").strip()
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "").strip()

app.secret_key = SESSION_SECRET

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
)

MAX_RECIPIENTS = 25

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)

def valid_email(value):
    if not isinstance(value, str):
        return False
    value = value.strip()
    return bool(EMAIL_RE.fullmatch(value)) and len(value) <= 254

def normalize_email(value):
    return str(value or "").strip().lower()

def authenticated():
    return session.get("authenticated") is True

def clean_header(value, max_length=998):
    value = str(value or "").replace("\r", " ").replace("\n", " ")
    return value.strip()[:max_length]

def personalize_template(template, recipient):
    result = str(template or "")
    values = {
        "{{name}}": str(recipient.get("name", "") or ""),
        "{{email}}": str(recipient.get("email", "") or ""),
    }
    for placeholder, value in values.items():
        result = result.replace(placeholder, value)
    return result

# =========================================================
# TURNSTILE VERIFICATION
# =========================================================
def verify_turnstile(token, remote_ip=None):
    if not TURNSTILE_SECRET_KEY:
        return True, None
    if not token:
        return False, "Cloudflare verification is required."

    payload = {"secret": TURNSTILE_SECRET_KEY, "response": token}
    if remote_ip:
        payload["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))
        if result.get("success") is True:
            return True, None
        return False, "Cloudflare verification failed."
    except Exception:
        return False, "Unable to verify Cloudflare."

# =========================================================
# AUTH ROUTES
# =========================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if authenticated():
        return redirect(url_for("home"))
    if request.method == "GET":
        return render_template("login.html", error=None, turnstile_site_key=TURNSTILE_SITE_KEY)

    password = str(request.form.get("password", ""))
    if not secrets.compare_digest(password, LOGIN_PASSWORD):
        return render_template("login.html", error="Incorrect password.", turnstile_site_key=TURNSTILE_SITE_KEY), 401

    session.clear()
    session.permanent = True
    session["authenticated"] = True
    return redirect(url_for("home"))

@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
def home():
    if not authenticated():
        return redirect(url_for("login"))
    return render_template("index.html", turnstile_site_key=TURNSTILE_SITE_KEY)

# =========================================================
# SEND EMAIL VIA RESEND API
# =========================================================
def send_via_resend(sender_name, sender_email, recipient_email, subject, html_body):
    if not RESEND_API_KEY:
        return False, "RESEND_API_KEY is missing in Vercel settings."

    payload = {
        "from": f"{sender_name} <onboarding@resend.dev>",
        "to": [recipient_email],
        "subject": subject,
        "html": html_body,
        "reply_to": sender_email
    }

    req_data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=req_data,
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            if "id" in res_data:
                return True, None
            return False, "Resend failed to queue email."
    except Exception as e:
        return False, str(e)

# =========================================================
# SEND BATCH ROUTE (NDJSON Stream matching frontend)
# =========================================================
@app.route("/send-batch", methods=["POST"])
def send_batch():
    if not authenticated():
        return jsonify({"success": False, "message": "Authentication required.", "login_required": True}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "message": "Invalid JSON request."}), 400

    sender_name = clean_header(data.get("sender_name", ""), 200)
    gmail = clean_header(data.get("gmail", ""), 254)
    subject = clean_header(data.get("subject", ""), 998)
    body = str(data.get("body", ""))
    is_html = data.get("is_html", False) is True
    recipients = data.get("recipients", [])
    turnstile_token = str(data.get("turnstile_token", "")).strip()

    if not sender_name or not valid_email(gmail) or not subject or not body.strip():
        return jsonify({"success": False, "message": "All required fields must be filled correctly."}), 400

    if not isinstance(recipients, list):
        return jsonify({"success": False, "message": "Invalid recipient list."}), 400

    forwarded_for = request.headers.get("X-Forwarded-For")
    remote_ip = forwarded_for.split(",", 1)[0].strip() if forwarded_for else request.remote_addr

    verified, verify_error = verify_turnstile(turnstile_token, remote_ip)
    if not verified:
        return jsonify({"success": False, "message": verify_error}), 403

    clean_recipients = []
    seen = set()
    for item in recipients:
        if isinstance(item, str):
            email = normalize_email(item)
            item_data = {"email": email}
        elif isinstance(item, dict):
            email = normalize_email(item.get("email", ""))
            item_data = item
        else:
            continue

        if not valid_email(email) or email in seen:
            continue
        seen.add(email)
        clean_recipients.append(item_data)

    clean_recipients = clean_recipients[:MAX_RECIPIENTS]
    if not clean_recipients:
        return jsonify({"success": False, "message": "No valid recipients found."}), 400

    @stream_with_context
    def generate():
        total = len(clean_recipients)
        sent_count = 0
        failed_count = 0

        yield json.dumps({"type": "start", "total": total, "sent": 0, "failed": 0, "remaining": total}, ensure_ascii=False) + "\n"

        for recipient_data in clean_recipients:
            recipient_email = recipient_data["email"]
            personalized_subject = personalize_template(subject, recipient_data)
            personalized_body = personalize_template(body, recipient_data)

            html_content = personalized_body if is_html else f"<div style='font-family:sans-serif;'>{personalized_body.replace(chr(10), '<br>')}</div>"

            success, err_msg = send_via_resend(
                sender_name=sender_name,
                sender_email=gmail,
                recipient_email=recipient_email,
                subject=personalized_subject,
                html_body=html_content
            )

            if success:
                sent_count += 1
                event = {"type": "progress", "email": recipient_email, "result": "sent", "total": total, "sent": sent_count, "failed": failed_count, "remaining": total - sent_count - failed_count}
            else:
                failed_count += 1
                event = {"type": "progress", "email": recipient_email, "result": "failed", "error": err_msg or "Failed", "total": total, "sent": sent_count, "failed": failed_count, "remaining": total - sent_count - failed_count}

            yield json.dumps(event, ensure_ascii=False) + "\n"

        yield json.dumps({"type": "complete", "success": True, "message": "Sending completed.", "total": total, "sent": sent_count, "failed": failed_count, "remaining": 0}, ensure_ascii=False) + "\n"

    response = Response(generate(), content_type="application/x-ndjson; charset=utf-8")
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["X-Accel-Buffering"] = "no"
    return response

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "Secure Mail Console API", "authenticated": authenticated()})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
