import os
import re
import hmac
import ssl
import smtplib
import time
import unicodedata
from pathlib import Path
from html import unescape
from email.message import EmailMessage
from email.utils import formataddr, parseaddr, make_msgid, formatdate

from flask import Flask, jsonify, redirect, render_template, request, session, url_for


# --------------------------------------------------
# APP CONFIGURATION
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(PROJECT_ROOT / "templates"),
    static_folder=str(PROJECT_ROOT / "static"),
    static_url_path="/static",
)

SECRET_KEY = os.environ.get("SESSION_SECRET")
if not SECRET_KEY and os.environ.get("VERCEL", "").lower() == "1":
    raise RuntimeError("SESSION_SECRET must be configured in Vercel.")

app.secret_key = SECRET_KEY or "local-development-only-change-this"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("VERCEL", "").lower() == "1",
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
    MAX_CONTENT_LENGTH=1024 * 1024,
)


# --------------------------------------------------
# EMAIL SETTINGS
# --------------------------------------------------

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25
MAX_RECIPIENTS = 25
# A modest pause helps avoid bursts. It is not a deliverability guarantee.
SEND_INTERVAL_SECONDS = 3


# --------------------------------------------------
# RESPONSE HELPERS
# --------------------------------------------------

def json_error(message, status=400):
    return jsonify({"error": message}), status


def safe_error(exc, limit=200):
    # Avoid returning credentials or full server internals to the browser.
    return str(exc).replace("\r", " ").replace("\n", " ")[:limit]


# --------------------------------------------------
# EMAIL VALIDATION
# --------------------------------------------------

def clean_email(value):
    if not isinstance(value, str):
        return ""
    value = unicodedata.normalize("NFKC", value)
    value = "".join(
        ch for ch in value
        if ch.isprintable() and not unicodedata.category(ch).startswith("C")
    )
    return value.replace("\xa0", "").strip().replace(" ", "")


def valid_email(value):
    value = clean_email(value)
    if not value or len(value) > 254:
        return False
    _, address = parseaddr(value)
    if address != value or "@" not in address or ".." in address:
        return False
    local, domain = address.rsplit("@", 1)
    if not local or not domain or len(local) > 64:
        return False
    if domain.startswith(".") or domain.endswith(".") or "." not in domain:
        return False
    if any(ch.isspace() for ch in address):
        return False
    return True


def recipient_address(item):
    if isinstance(item, str):
        return clean_email(item.strip().strip("\"'"))
    if isinstance(item, dict):
        value = item.get("email", "")
        return clean_email(value.strip().strip("\"'") if isinstance(value, str) else "")
    return ""


# --------------------------------------------------
# HTML TO TEXT
# --------------------------------------------------

def html_to_plain_text(html_content):
    text = re.sub(r"(?i)<br\s*/?>", "\n", html_content)
    text = re.sub(r"(?i)</(p|div|tr|li|h[1-6])>", "\n", text)
    text = re.sub(r"<[^>]+?>", "", text)
    text = unescape(text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


# --------------------------------------------------
# EMAIL BUILDER
# --------------------------------------------------

def build_email(sender_email, sender_name, recipient, subject, body, html_mode=False):
    local_part = recipient.split("@", 1)[0]
    display_name = re.sub(r"[._-]+", " ", local_part).strip().title() or local_part

    personalized_body = (
        body.replace("{{name}}", display_name)
        .replace("{{username}}", local_part)
        .replace("{{email}}", recipient)
    )

    clean_sender_name = re.sub(r"[\r\n]+", " ", sender_name).strip()[:100]
    clean_subject = re.sub(r"[\r\n]+", " ", subject).strip()

    message = EmailMessage()
    message["Subject"] = clean_subject
    message["From"] = formataddr((clean_sender_name, sender_email)) if clean_sender_name else sender_email
    message["To"] = recipient
    message["Reply-To"] = sender_email
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid(domain=sender_email.split("@", 1)[1])

    if html_mode:
        plain_text = html_to_plain_text(personalized_body)
        message.set_content(
            plain_text or "Please view this email in an HTML-compatible email client.",
            charset="utf-8",
        )
        message.add_alternative(personalized_body, subtype="html", charset="utf-8")
    else:
        message.set_content(personalized_body, charset="utf-8")

    return message


# --------------------------------------------------
# SMTP CONNECTION
# --------------------------------------------------

def create_smtp_connection(sender_email, app_password):
    context = ssl.create_default_context()
    smtp = smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        context=context,
        timeout=SMTP_TIMEOUT,
    )
    try:
        smtp.login(sender_email, app_password)
        return smtp
    except Exception:
        try:
            smtp.close()
        except Exception:
            pass
        raise


# --------------------------------------------------
# LOGIN PAGE
# --------------------------------------------------

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
        return render_template("login.html", error="LOGIN_PASSWORD is not configured."), 500

    if not hmac.compare_digest(supplied_password, configured_password):
        return render_template("login.html", error="Incorrect workspace password."), 401

    session.clear()
    session["logged_in"] = True
    session.permanent = True
    return redirect(url_for("home"))


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------
# BATCH EMAIL SENDER
# --------------------------------------------------

@app.post("/send-batch")
def send_batch():
    if not session.get("logged_in"):
        return json_error("Your session has expired. Please sign in again.", 401)

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return json_error("A valid JSON request body is required.")

    sender_email = clean_email(str(data.get("senderEmail") or data.get("gmail") or "").lower())
    app_password = str(data.get("appPassword") or data.get("app_password") or "").strip().replace(" ", "")
    sender_name = str(data.get("senderName") or data.get("sender_name") or "").strip()[:100]
    subject = str(data.get("subject") or "").strip()
    body = str(data.get("body") or "")
    html_mode = data.get("htmlMode", data.get("is_html", False)) is True
    consent = data.get("consentConfirmed", data.get("consent_confirmed", False)) is True
    raw_recipients = data.get("recipients", [])

    if not sender_email.endswith("@gmail.com") or not valid_email(sender_email):
        return json_error("Please enter a valid Gmail sender address.")
    if not app_password:
        return json_error("Google App Password is required.")
    if not subject or len(subject) > 998:
        return json_error("Please enter a valid email subject.")
    if not body.strip():
        return json_error("Email message body is required.")
    if not consent:
        return json_error("Please confirm that every recipient explicitly agreed to receive these emails.")
    if not isinstance(raw_recipients, list):
        return json_error("Recipients must be provided as a list.")

    recipients = []
    seen = set()
    for item in raw_recipients:
        address = recipient_address(item)
        if not address:
            continue
        key = address.casefold()
        if key not in seen:
            seen.add(key)
            recipients.append(address)

    if not recipients:
        return json_error("Please provide at least one valid recipient.")
    if len(recipients) > MAX_RECIPIENTS:
        return json_error(f"Maximum {MAX_RECIPIENTS} recipients allowed per batch.")

    invalid = [address for address in recipients if not valid_email(address)]
    if invalid:
        return json_error("Invalid email addresses: " + ", ".join(invalid[:5]))

    results = []
    smtp = None

    try:
        smtp = create_smtp_connection(sender_email, app_password)
    except smtplib.SMTPAuthenticationError:
        return jsonify({
            "success": False,
            "total": len(recipients),
            "accepted": 0,
            "failed": len(recipients),
            "results": [{
                "status": "failed",
                "email": address,
                "detail": "Gmail authentication failed. Check the Google App Password and account security settings.",
            } for address in recipients],
        }), 200
    except Exception as exc:
        return jsonify({
            "success": False,
            "total": len(recipients),
            "accepted": 0,
            "failed": len(recipients),
            "results": [{
                "status": "failed",
                "email": address,
                "detail": "SMTP connection failed: " + safe_error(exc),
            } for address in recipients],
        }), 200

    try:
        for index, recipient in enumerate(recipients):
            message = build_email(
                sender_email=sender_email,
                sender_name=sender_name,
                recipient=recipient,
                subject=subject,
                body=body,
                html_mode=html_mode,
            )
            try:
                refused = smtp.send_message(message)
                if refused:
                    results.append({
                        "status": "failed",
                        "email": recipient,
                        "detail": "Gmail refused this recipient.",
                    })
                else:
                    results.append({
                        "status": "sent",
                        "email": recipient,
                        "detail": "Accepted by Gmail SMTP; Inbox placement is not confirmed.",
                    })
            except smtplib.SMTPRecipientsRefused:
                results.append({
                    "status": "failed",
                    "email": recipient,
                    "detail": "Gmail refused this recipient address.",
                })
            except (smtplib.SMTPServerDisconnected, TimeoutError, ConnectionError, OSError) as exc:
                # The server may have accepted the message before the connection failed.
                # Do not automatically retry: that could send a duplicate.
                results.append({
                    "status": "unknown",
                    "email": recipient,
                    "detail": "SMTP connection ended before confirmation. Check the sender's Sent folder before retrying. " + safe_error(exc),
                })
                # Remaining recipients cannot safely use a broken connection.
                for remaining in recipients[index + 1:]:
                    results.append({
                        "status": "not_sent",
                        "email": remaining,
                        "detail": "Not attempted because the SMTP connection was lost.",
                    })
                break
            except smtplib.SMTPException as exc:
                code = getattr(exc, "smtp_code", None)
                results.append({
                    "status": "failed",
                    "email": recipient,
                    "detail": f"SMTP rejected the message{f' (code {code})' if code else ''}: {safe_error(exc)}",
                })
            except Exception as exc:
                results.append({
                    "status": "failed",
                    "email": recipient,
                    "detail": "Message processing failed: " + safe_error(exc),
                })

            if index < len(recipients) - 1:
                time.sleep(SEND_INTERVAL_SECONDS)
    finally:
        if smtp:
            try:
                smtp.quit()
            except Exception:
                try:
                    smtp.close()
                except Exception:
                    pass

    accepted_count = sum(1 for item in results if item["status"] == "sent")
    failed_count = sum(1 for item in results if item["status"] in ("failed", "not_sent"))
    unknown_count = sum(1 for item in results if item["status"] == "unknown")

    return jsonify({
        "success": failed_count == 0 and unknown_count == 0,
        "total": len(recipients),
        "accepted": accepted_count,
        "failed": failed_count,
        "unknown": unknown_count,
        "results": results,
    }), 200


# --------------------------------------------------
# ERROR HANDLERS
# --------------------------------------------------

@app.errorhandler(413)
def request_too_large(error):
    return json_error("Request is too large.", 413)


@app.errorhandler(500)
def internal_error(error):
    return json_error("An internal server error occurred.", 500)


# --------------------------------------------------
# VERCEL ENTRY POINT
# --------------------------------------------------

application = app
