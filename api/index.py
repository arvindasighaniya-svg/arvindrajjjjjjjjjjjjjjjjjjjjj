import os
import re
import smtplib
import ssl
import hmac
import random
import time
from datetime import datetime

from pathlib import Path
from email.message import EmailMessage
from email.utils import formataddr, parseaddr, make_msgid

from flask import (
    Flask, jsonify, redirect, render_template,
    request, session, url_for
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(PROJECT_ROOT / "templates"),
    static_folder=str(PROJECT_ROOT / "static"),
    static_url_path="/static"
)

app.secret_key = os.environ.get(
    "SESSION_SECRET",
    "local-development-only-change-this"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("VERCEL", "").lower() == "1",
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=1024 * 1024
)

MAX_RECIPIENTS = 25  # Increased limit to support up to 25 recipients
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465


def json_error(message, status=400):
    return jsonify({"error": message}), status


def valid_email(value):
    if not isinstance(value, str) or len(value) > 254:
        return False

    value = value.strip()

    if not value or any(ch.isspace() for ch in value):
        return False

    _, address = parseaddr(value)

    if address != value or "@" not in address:
        return False

    local, domain = address.rsplit("@", 1)

    return bool(
        local
        and "." in domain
        and not domain.startswith(".")
        and not domain.endswith(".")
    )


def expand_spintax(text):
    pattern = re.compile(r"\{([^{}]+)\}")

    return pattern.sub(
        lambda match: random.choice(
            match.group(1).split("|")
        ),
        text
    )


def recipient_address(item):
    if isinstance(item, str):
        return item.strip()

    if isinstance(item, dict):
        return str(item.get("email", "")).strip()

    return ""


def build_email(
    sender_email,
    sender_name,
    recipient,
    subject,
    body,
    html_mode,
    unsubscribe_email=""
):
    local_name = recipient.split("@", 1)[0]

    personalized_body = (
        body.replace("{{name}}", local_name)
        .replace("{{email}}", recipient)
    )

    personalized_body = expand_spintax(personalized_body)
    personalized_subject = expand_spintax(subject)

    message = EmailMessage()

    # Essential Inbox-delivery headers
    message["Subject"] = personalized_subject
    message["From"] = (
        formataddr((sender_name, sender_email))
        if sender_name else sender_email
    )
    message["To"] = recipient
    message["Reply-To"] = sender_email
    message["Message-ID"] = make_msgid(domain=sender_email.split("@")[1])
    message["Date"] = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S +0000")
    
    if unsubscribe_email:
        message["List-Unsubscribe"] = f"<mailto:{unsubscribe_email}?subject=unsubscribe>"

    if html_mode:
        message.set_content(
            "Please view this email in an HTML-compatible client."
        )
        message.add_alternative(
            personalized_body,
            subtype="html"
        )
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

    supplied_password = request.form.get("password", "")
    configured_password = os.environ.get("LOGIN_PASSWORD", "")

    if not configured_password:
        return render_template(
            "login.html",
            error="LOGIN_PASSWORD is not configured in Vercel."
        ), 500

    if not hmac.compare_digest(supplied_password, configured_password):
        return render_template(
            "login.html",
            error="Incorrect workspace password."
        ), 401

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
        return json_error(
            "Your session has expired. Please sign in again.",
            401
        )

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return json_error("A valid JSON request body is required.")

    sender_email = str(
        data.get("senderEmail") or data.get("gmail") or ""
    ).strip().lower()

    app_password = str(
        data.get("appPassword") or data.get("app_password") or ""
    ).strip().replace(" ", "")

    sender_name = str(
        data.get("senderName") or data.get("sender_name") or ""
    ).strip()[:100]

    subject = str(data.get("subject") or "").strip()
    body = str(data.get("body") or "")

    html_mode = bool(
        data.get("htmlMode", data.get("is_html", False))
    )

    consent = (
        data.get("consentConfirmed", data.get("consent_confirmed", False)) is True
    )

    raw_recipients = data.get("recipients", [])

    if not sender_email.endswith("@gmail.com") or not valid_email(sender_email):
        return json_error("Please enter a valid @gmail.com sender address.")

    if not app_password:
        return json_error("Google App Password is required.")

    if not subject:
        return json_error("Email subject is required.")

    if not body.strip():
        return json_error("Message body is required.")

    if not consent:
        return json_error("Confirm that all recipients agreed to receive this email.")

    if not isinstance(raw_recipients, list):
        return json_error("Recipients must be provided as a list.")

    recipients = []
    seen = set()

    for item in raw_recipients:
        address = recipient_address(item)
        if address and address.lower() not in seen:
            seen.add(address.lower())
            recipients.append(address)

    if not recipients:
        return json_error("Please provide at least one recipient email address.")

    if len(recipients) > MAX_RECIPIENTS:
        return json_error(f"A maximum of {MAX_RECIPIENTS} recipients is allowed per request.")

    invalid = [addr for addr in recipients if not valid_email(addr)]
    if invalid:
        return json_error("Invalid recipient email address: " + ", ".join(invalid[:5]))

    results = []
    tls_context = ssl.create_default_context()

    # High-speed ultra-fast batching: All 25 recipients processed in a single fast batch to hit ~5 seconds target
    batch_size = 25
    batches = [recipients[i:i + batch_size] for i in range(0, len(recipients), batch_size)]

    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=tls_context, timeout=30) as smtp:
            smtp.login(sender_email, app_password)

            for batch_index, batch in enumerate(batches):
                for recipient in batch:
                    try:
                        message = build_email(
                            sender_email=sender_email,
                            sender_name=sender_name,
                            recipient=recipient,
                            subject=subject,
                            body=body,
                            html_mode=html_mode,
                            unsubscribe_email=sender_email
                        )

                        smtp.send_message(message)

                        results.append({
                            "status": "sent",
                            "email": recipient,
                            "detail": "Accepted by Gmail for sending."
                        })
                    except Exception as exc:
                        results.append({
                            "status": "failed",
                            "email": recipient,
                            "detail": f"Sending failed: {str(exc)[:250]}"
                        })

                # Ultra-fast mode: No pause between batches to achieve ~5 seconds response time
                if batch_index < len(batches) - 1:
                    time.sleep(0.0)

    except smtplib.SMTPAuthenticationError:
        results = [{
            "status": "failed",
            "email": r,
            "detail": "Gmail authentication failed. Check Gmail address and Google App Password."
        } for r in recipients]
    except Exception as exc:
        results = [{
            "status": "failed",
            "email": r,
            "detail": f"Could not connect to Gmail SMTP: {str(exc)[:200]}"
        } for r in recipients]

    return jsonify({"results": results}), 200


@app.errorhandler(413)
def request_too_large(error):
    return json_error("Request is too large.", 413)


@app.errorhandler(500)
def internal_error(error):
    return json_error("An internal server error occurred.", 500)


# Required Vercel Flask application entry point.
application = app
