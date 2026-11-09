import os
import re
import hmac
import random
import secrets
import smtplib
import ssl
import time
from pathlib import Path
from email.message import EmailMessage
from email.utils import formataddr, parseaddr

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

# Expected project structure:
# api/index.py, templates/index.html, templates/login.html, static/style.css
PROJECT_ROOT = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(PROJECT_ROOT / "templates"),
    static_folder=str(PROJECT_ROOT / "static"),
    static_url_path="/static",
)

# Configure SESSION_SECRET in Vercel. Fallback is for local development only.
app.secret_key = os.environ.get("SESSION_SECRET") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("VERCEL") == "1",
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=1024 * 1024,
)

MAX_RECIPIENTS = 25
SEND_INTERVAL_SECONDS = 1.0  # modest pacing; does not bypass Gmail limits
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465


def error_response(message, status=400):
    return jsonify({"error": message}), status


def valid_email(value):
    if not isinstance(value, str):
        return False
    value = value.strip()
    if not value or len(value) > 254 or any(ch.isspace() for ch in value):
        return False
    display_name, address = parseaddr(value)
    if display_name or address != value or address.count("@") != 1:
        return False
    local, domain = address.rsplit("@", 1)
    return bool(
        local and domain and "." in domain
        and not domain.startswith(".") and not domain.endswith(".")
        and ".." not in domain
    )


def recipient_address(item):
    if isinstance(item, str):
        return item.strip()
    if isinstance(item, dict):
        return str(item.get("email", "")).strip()
    return ""


def expand_spintax(value):
    pattern = re.compile(r"\{([^{}]+)\}")
    for _ in range(10):
        updated = pattern.sub(
            lambda match: random.choice(
                [x.strip() for x in match.group(1).split("|") if x.strip()]
                or [match.group(0)]
            ),
            value,
        )
        if updated == value:
            break
        value = updated
    return value


def build_message(sender_email, sender_name, recipient, subject, body, html_mode):
    recipient_name = recipient.split("@", 1)[0]
    personalized_subject = expand_spintax(subject)
    personalized_body = body.replace("{{name}}", recipient_name)
    personalized_body = personalized_body.replace("{{email}}", recipient)
    personalized_body = expand_spintax(personalized_body)

    message = EmailMessage()
    message["Subject"] = personalized_subject
    message["From"] = formataddr((sender_name, sender_email)) if sender_name else sender_email
    message["To"] = recipient

    if html_mode:
        message.set_content("This message contains an HTML version.")
        message.add_alternative(personalized_body, subtype="html")
    else:
        message.set_content(personalized_body)
    return message


@app.get("/")
def home():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if session.get("logged_in"):
            return redirect(url_for("home"))
        return render_template("login.html")

    configured_password = os.environ.get("LOGIN_PASSWORD", "")
    supplied_password = request.form.get("password", "")
    if not configured_password:
        return render_template(
            "login.html", error="LOGIN_PASSWORD is not configured in Vercel."
        ), 500
    if not hmac.compare_digest(supplied_password, configured_password):
        return render_template("login.html", error="Incorrect workspace password."), 401

    session.clear()
    session["logged_in"] = True
    return redirect(url_for("home"))


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.post("/send-batch")
def send_batch():
    if not session.get("logged_in"):
        return error_response("Your session has expired. Please sign in again.", 401)

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error_response("A valid JSON request body is required.")

    # Accepts both field-name formats used by the supplied frontend versions.
    sender_email = str(data.get("senderEmail") or data.get("gmail") or "").strip().lower()
    app_password = str(data.get("appPassword") or data.get("app_password") or "").strip().replace(" ", "")
    sender_name = str(data.get("senderName") or data.get("sender_name") or "").strip()[:100]
    subject = str(data.get("subject") or "").strip()
    body = str(data.get("body") or "")
    html_mode = bool(data.get("htmlMode", data.get("is_html", False)))
    consent = data.get("consentConfirmed", data.get("consent_confirmed", False)) is True
    raw_recipients = data.get("recipients", [])

    if not valid_email(sender_email) or not sender_email.endswith("@gmail.com"):
        return error_response("Please enter a valid @gmail.com sender address.")
    if not app_password:
        return error_response("Google App Password is required.")
    if not subject:
        return error_response("Email subject is required.")
    if len(subject) > 250:
        return error_response("Email subject must be 250 characters or fewer.")
    if not body.strip():
        return error_response("Message body is required.")
    if len(body) > 100000:
        return error_response("Message body is too large.")
    if not consent:
        return error_response("Confirm that all recipients agreed to receive this email.")
    if not isinstance(raw_recipients, list):
        return error_response("Recipients must be provided as a list.")

    recipients, seen = [], set()
    for item in raw_recipients:
        address = recipient_address(item)
        if address and address.lower() not in seen:
            seen.add(address.lower())
            recipients.append(address)

    if not recipients:
        return error_response("Please provide at least one recipient email address.")
    if len(recipients) > MAX_RECIPIENTS:
        return error_response("A maximum of 25 recipients is allowed per request.")
    invalid = [address for address in recipients if not valid_email(address)]
    if invalid:
        return error_response("Invalid recipient email address: " + ", ".join(invalid[:5]))

    results = []
    try:
        with smtplib.SMTP_SSL(
            SMTP_HOST, SMTP_PORT, context=ssl.create_default_context(), timeout=30
        ) as smtp:
            smtp.login(sender_email, app_password)
            for index, recipient in enumerate(recipients):
                if index:
                    time.sleep(SEND_INTERVAL_SECONDS)
                try:
                    message = build_message(
                        sender_email, sender_name, recipient, subject, body, html_mode
                    )
                    refused = smtp.send_message(message)
                    if recipient in refused:
                        results.append({
                            "status": "failed", "email": recipient,
                            "detail": "Gmail refused this recipient.",
                        })
                    else:
                        results.append({
                            "status": "sent", "email": recipient,
                            "detail": "Gmail accepted the message for sending; Inbox delivery is not guaranteed.",
                        })
                except Exception as exc:
                    results.append({
                        "status": "failed", "email": recipient,
                        "detail": f"Sending failed: {str(exc)[:200]}",
                    })
    except smtplib.SMTPAuthenticationError:
        return error_response(
            "Gmail authentication failed. Check the Gmail address and Google App Password.",
            401,
        )
    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        return error_response(f"Could not connect to Gmail SMTP: {str(exc)[:250]}", 502)

    sent_count = sum(item["status"] == "sent" for item in results)
    return jsonify({
        "results": results,
        "total": len(results),
        "sent": sent_count,
        "failed": len(results) - sent_count,
    }), 200


@app.errorhandler(413)
def request_too_large(_error):
    return error_response("Request is too large.", 413)


@app.errorhandler(500)
def internal_server_error(_error):
    return error_response("An internal server error occurred.", 500)


# Vercel Python runtime entry points.
application = app
