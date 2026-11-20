import os
import re
import hmac
import ssl
import smtplib
import time
import unicodedata

from pathlib import Path
from email.message import EmailMessage
from email.utils import formataddr, parseaddr, formatdate
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

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
if not SECRET_KEY and os.environ.get("VERCEL") == "1":
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
# GMAIL SMTP SETTINGS
# --------------------------------------------------

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465

# Keep batches modest. Gmail quotas and policies still apply.
MAX_RECIPIENTS = 25
SEND_INTERVAL_SECONDS = 2.0
SMTP_TIMEOUT_SECONDS = 30


# --------------------------------------------------
# RESPONSE HELPERS
# --------------------------------------------------

def json_error(message, status=400):
    return jsonify({"error": message}), status


# --------------------------------------------------
# INPUT VALIDATION
# --------------------------------------------------

def clean_email(value):
    if not isinstance(value, str):
        return ""

    value = unicodedata.normalize("NFKC", value).strip()
    if any(ch.isspace() for ch in value):
        return ""

    return value


def valid_email(value):
    value = clean_email(value)

    if not value or len(value) > 254:
        return False

    _, address = parseaddr(value)
    if address != value or address.count("@") != 1:
        return False

    local, domain = address.rsplit("@", 1)

    if not local or len(local) > 64 or not domain:
        return False

    if "." not in domain or domain.startswith(".") or domain.endswith("."):
        return False

    if ".." in address:
        return False

    return True


def recipient_address(item):
    if isinstance(item, str):
        return clean_email(item.strip().strip("\"'"))

    if isinstance(item, dict):
        return clean_email(str(item.get("email", "")).strip().strip("\"'"))

    return ""


def safe_header(value, max_length=998):
    """Remove CR/LF to prevent email-header injection."""
    value = str(value or "")
    value = re.sub(r"[\r\n]+", " ", value)
    return value.strip()[:max_length]


# --------------------------------------------------
# EMAIL BUILDER
# --------------------------------------------------

def build_email(sender_email, sender_name, recipient, subject, body, html_mode=False):
    message = EmailMessage()

    clean_sender_name = safe_header(sender_name, 100)
    clean_subject = safe_header(subject, 250)

    message["Subject"] = clean_subject
    message["From"] = (
        formataddr((clean_sender_name, sender_email))
        if clean_sender_name
        else sender_email
    )
    message["To"] = recipient
    message["Reply-To"] = sender_email
    message["Date"] = formatdate(localtime=True)

    # Keep the message personal and transparent. Do not rotate/spin wording
    # to try to influence spam filters.
    if html_mode:
        message.set_content(
            "This email contains an HTML version. "
            "If you cannot view it, please reply to the sender."
        )
        message.add_alternative(str(body), subtype="html", charset="utf-8")
    else:
        message.set_content(str(body), charset="utf-8")

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
        timeout=SMTP_TIMEOUT_SECONDS,
    )
    try:
        smtp.login(sender_email, app_password)
    except Exception:
        smtp.close()
        raise
    return smtp


# --------------------------------------------------
# LOGIN
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
        return render_template(
            "login.html",
            error="LOGIN_PASSWORD is not configured in Vercel.",
        ), 500

    if not hmac.compare_digest(supplied_password, configured_password):
        return render_template(
            "login.html",
            error="Incorrect workspace password.",
        ), 401

    session.clear()
    session["logged_in"] = True
    session.permanent = True
    return redirect(url_for("home"))


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
        return json_error(
            "Your session has expired. Please sign in again.",
            401,
        )

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return json_error("A valid JSON request body is required.")

    sender_email = clean_email(
        str(data.get("senderEmail") or data.get("gmail") or "").lower()
    )
    app_password = str(
        data.get("appPassword") or data.get("app_password") or ""
    ).strip().replace(" ", "")
    sender_name = safe_header(
        data.get("senderName") or data.get("sender_name") or "",
        100,
    )
    subject = str(data.get("subject") or "").strip()
    body = str(data.get("body") or "")
    html_mode = (
        data.get("htmlMode", data.get("is_html", False)) is True
    )
    consent = (
        data.get("consentConfirmed", data.get("consent_confirmed", False))
        is True
    )
    raw_recipients = data.get("recipients", [])

    if not valid_email(sender_email) or not sender_email.endswith("@gmail.com"):
        return json_error("Please enter a valid @gmail.com sender address.")

    if not app_password:
        return json_error("Google App Password is required.")

    if not subject or len(subject) > 250:
        return json_error("Please enter a subject between 1 and 250 characters.")

    if not body.strip():
        return json_error("Email message body is required.")

    if len(body) > 100000:
        return json_error("Email message body is too long.")

    if not consent:
        return json_error(
            "Confirm that every recipient has agreed to receive this email."
        )

    if not isinstance(raw_recipients, list):
        return json_error("Recipients must be provided as a list.")

    recipients = []
    seen = set()

    for item in raw_recipients:
        address = recipient_address(item)
        if not address:
            continue
        key = address.lower()
        if key not in seen:
            seen.add(key)
            recipients.append(address)

    if not recipients:
        return json_error("Please provide at least one recipient email address.")

    if len(recipients) > MAX_RECIPIENTS:
        return json_error(
            f"A maximum of {MAX_RECIPIENTS} recipients is allowed per batch."
        )

    invalid = [address for address in recipients if not valid_email(address)]
    if invalid:
        return json_error(
            "Invalid recipient email address: " + ", ".join(invalid[:5])
        )

    results = []
    smtp = None

    try:
        # One authenticated connection, one recipient at a time.
        # No parallel workers and no automatic retries (which can duplicate mail).
        smtp = create_smtp_connection(sender_email, app_password)

        for index, recipient in enumerate(recipients):
            try:
                message = build_email(
                    sender_email=sender_email,
                    sender_name=sender_name,
                    recipient=recipient,
                    subject=subject,
                    body=body,
                    html_mode=html_mode,
                )
                smtp.send_message(message)
                results.append({
                    "status": "accepted",
                    "email": recipient,
                    "detail": (
                        "Accepted by Gmail for sending. "
                        "Inbox placement is not confirmed."
                    ),
                })

            except smtplib.SMTPAuthenticationError:
                results.append({
                    "status": "failed",
                    "email": recipient,
                    "detail": "Gmail authentication failed. Check the Gmail address and App Password.",
                })
                # Authentication errors affect the connection; stop the batch.
                for remaining in recipients[index + 1:]:
                    results.append({
                        "status": "not_attempted",
                        "email": remaining,
                        "detail": "Not attempted because Gmail authentication failed.",
                    })
                break

            except smtplib.SMTPRecipientsRefused:
                results.append({
                    "status": "failed",
                    "email": recipient,
                    "detail": "Gmail refused this recipient address.",
                })

            except smtplib.SMTPDataError as exc:
                code = getattr(exc, "smtp_code", None)
                results.append({
                    "status": "failed",
                    "email": recipient,
                    "detail": f"Gmail rejected the message (SMTP {code}). {str(exc)[:180]}",
                })

            except (smtplib.SMTPServerDisconnected, TimeoutError, OSError) as exc:
                results.append({
                    "status": "failed",
                    "email": recipient,
                    "detail": f"SMTP connection error: {str(exc)[:180]}",
                })
                for remaining in recipients[index + 1:]:
                    results.append({
                        "status": "not_attempted",
                        "email": remaining,
                        "detail": "Not attempted because the SMTP connection failed.",
                    })
                break

            except Exception as exc:
                results.append({
                    "status": "failed",
                    "email": recipient,
                    "detail": f"Sending failed: {str(exc)[:180]}",
                })

            if index < len(recipients) - 1:
                time.sleep(SEND_INTERVAL_SECONDS)

    except smtplib.SMTPAuthenticationError:
        results = [{
            "status": "failed",
            "email": recipient,
            "detail": "Gmail authentication failed. Check the Gmail address and Google App Password.",
        } for recipient in recipients]

    except Exception as exc:
        results = [{
            "status": "failed",
            "email": recipient,
            "detail": f"Could not connect to Gmail SMTP: {str(exc)[:180]}",
        } for recipient in recipients]

    finally:
        if smtp is not None:
            try:
                smtp.quit()
            except Exception:
                try:
                    smtp.close()
                except Exception:
                    pass

    accepted_count = sum(1 for item in results if item["status"] == "accepted")
    failed_count = sum(1 for item in results if item["status"] == "failed")
    not_attempted_count = sum(
        1 for item in results if item["status"] == "not_attempted"
    )

    return jsonify({
        "success": failed_count == 0 and not_attempted_count == 0,
        "total": len(recipients),
        "accepted_by_gmail": accepted_count,
        "failed": failed_count,
        "not_attempted": not_attempted_count,
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


# Vercel Python runtime entry point
application = app
