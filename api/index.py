import os
import re
import hmac
import ssl
import smtplib
import time
import logging
import unicodedata
from pathlib import Path
from html import unescape
from email.message import EmailMessage
from email.utils import formataddr, parseaddr, formatdate, make_msgid

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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# --------------------------------------------------
# CONSERVATIVE EMAIL SETTINGS
# --------------------------------------------------
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25
MAX_RECIPIENTS = 10
SEND_INTERVAL_SECONDS = 0.20


# --------------------------------------------------
# HELPERS
# --------------------------------------------------
def json_error(message, status=400):
    return jsonify({"error": message}), status


def clean_email(value):
    if not isinstance(value, str):
        return ""
    value = unicodedata.normalize("NFKC", value)
    value = "".join(
        ch for ch in value
        if ch.isprintable() and not unicodedata.category(ch).startswith("C")
    )
    return value.replace("\xa0", "").strip()


def valid_email(value):
    value = clean_email(value)
    if not value or len(value) > 254 or any(ch.isspace() for ch in value):
        return False
    _, address = parseaddr(value)
    if address != value or "@" not in address:
        return False
    local, domain = address.rsplit("@", 1)
    return bool(
        local and len(local) <= 64 and domain and "." in domain
        and not domain.startswith(".") and not domain.endswith(".")
        and ".." not in address
    )


def recipient_address(item):
    if isinstance(item, str):
        return clean_email(item.strip())
    if isinstance(item, dict):
        return clean_email(str(item.get("email", "")).strip())
    return ""


def html_to_plain_text(value):
    value = re.sub(r"(?i)<br\s*/?>", "\n", value)
    value = re.sub(r"(?i)</(p|div|tr|li|h[1-6])>", "\n", value)
    value = re.sub(r"<[^>]+>", "", value)
    value = unescape(value)
    value = re.sub(r"\n{3,}", "\n\n", value)
    return value.strip()


def build_email(sender_email, sender_name, recipient, subject, body, html_mode=False):
    # Deliberately do not randomize/spin message text. Send the content the
    # sender actually entered, with only basic recipient personalization.
    local_part = recipient.split("@", 1)[0]
    display_name = re.sub(r"[._-]+", " ", local_part).strip().title() or local_part
    personalized_body = (
        body.replace("{{name}}", display_name)
        .replace("{{username}}", local_part)
        .replace("{{email}}", recipient)
    )

    message = EmailMessage()
    safe_sender_name = re.sub(r"[\r\n]+", " ", sender_name).strip()[:100]
    safe_subject = re.sub(r"[\r\n]+", " ", subject).strip()
    message["Subject"] = safe_subject
    message["From"] = formataddr((safe_sender_name, sender_email)) if safe_sender_name else sender_email
    message["To"] = recipient
    message["Reply-To"] = sender_email
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid(domain=sender_email.rsplit("@", 1)[1])

    if html_mode:
        plain = html_to_plain_text(personalized_body)
        message.set_content(plain or "Please view this message in an HTML-compatible email client.", charset="utf-8")
        message.add_alternative(personalized_body, subtype="html", charset="utf-8")
    else:
        message.set_content(personalized_body, charset="utf-8")
    return message


def create_smtp_connection(sender_email, app_password):
    context = ssl.create_default_context()
    smtp = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=SMTP_TIMEOUT)
    try:
        smtp.login(sender_email, app_password)
        return smtp
    except Exception:
        try:
            smtp.quit()
        except Exception:
            pass
        raise


def close_smtp(smtp):
    if smtp is not None:
        try:
            smtp.quit()
        except Exception:
            try:
                smtp.close()
            except Exception:
                pass


# --------------------------------------------------
# LOGIN / LOGOUT
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

    supplied = request.form.get("password", "")
    configured = os.environ.get("LOGIN_PASSWORD", "")
    if not configured:
        return render_template("login.html", error="LOGIN_PASSWORD is not configured."), 500
    if not hmac.compare_digest(supplied, configured):
        return render_template("login.html", error="Incorrect workspace password."), 401

    session.clear()
    session["logged_in"] = True
    session.permanent = True
    return redirect(url_for("home"))


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------
# SEND EMAILS
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
        return json_error("Confirm that every recipient has explicitly agreed to receive these emails.")
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
        return json_error("Please provide at least one valid recipient.")
    if len(recipients) > MAX_RECIPIENTS:
        return json_error(f"Maximum {MAX_RECIPIENTS} recipients allowed per batch.")

    invalid = [address for address in recipients if not valid_email(address)]
    if invalid:
        return json_error("Invalid email addresses: " + ", ".join(invalid[:5]))

    results = []
    smtp = None
    try:
        # One authenticated connection, one recipient per message, and a
        # deliberate delay. No parallel burst and no automatic resend after
        # an uncertain SMTP result (which could create duplicate mail).
        smtp = create_smtp_connection(sender_email, app_password)
        for index, recipient in enumerate(recipients):
            if index:
                time.sleep(SEND_INTERVAL_SECONDS)
            try:
                message = build_email(sender_email, sender_name, recipient, subject, body, html_mode)
                refused = smtp.send_message(message)
                if refused:
                    results.append({
                        "status": "failed",
                        "email": recipient,
                        "detail": "Gmail refused this recipient address.",
                    })
                else:
                    results.append({
                        "status": "sent",
                        "email": recipient,
                        "detail": "Accepted by Gmail; Inbox placement is not confirmed.",
                    })
            except smtplib.SMTPAuthenticationError:
                results.append({"status": "failed", "email": recipient, "detail": "Gmail authentication failed. Check your Google App Password."})
                break
            except smtplib.SMTPRecipientsRefused:
                results.append({"status": "failed", "email": recipient, "detail": "Gmail refused this recipient address."})
            except smtplib.SMTPDataError as exc:
                code = getattr(exc, "smtp_code", 0)
                results.append({"status": "failed", "email": recipient, "detail": f"Gmail rejected the message (SMTP {code}): {str(exc)[:150]}"})
                if code >= 500:
                    break
            except (smtplib.SMTPServerDisconnected, ConnectionError, TimeoutError, OSError) as exc:
                # Delivery may have occurred if the connection failed after DATA.
                results.append({"status": "delivery_unknown", "email": recipient, "detail": "Connection ended during sending. Check before retrying to avoid a duplicate."})
                logger.warning("SMTP connection issue for %s: %s", recipient, exc)
                break
            except smtplib.SMTPException as exc:
                results.append({"status": "failed", "email": recipient, "detail": f"SMTP error: {str(exc)[:160]}"})
                break

        completed = {item["email"] for item in results}
        for recipient in recipients:
            if recipient not in completed:
                results.append({"status": "not_attempted", "email": recipient, "detail": "Not attempted because an earlier SMTP error stopped the batch."})
    except smtplib.SMTPAuthenticationError:
        return json_error("Gmail authentication failed. Check that 2-Step Verification and a valid Google App Password are enabled.", 502)
    except (smtplib.SMTPException, OSError, TimeoutError) as exc:
        logger.exception("Could not connect to Gmail SMTP")
        return jsonify({"error": "Could not connect to Gmail SMTP.", "detail": str(exc)[:180]}), 502
    finally:
        close_smtp(smtp)

    order = {email: i for i, email in enumerate(recipients)}
    results.sort(key=lambda item: order.get(item.get("email"), len(recipients)))
    accepted = sum(item["status"] == "sent" for item in results)
    failed = sum(item["status"] == "failed" for item in results)
    unknown = sum(item["status"] == "delivery_unknown" for item in results)
    not_attempted = sum(item["status"] == "not_attempted" for item in results)

    return jsonify({
        "success": failed == 0 and unknown == 0 and not_attempted == 0,
        "total": len(recipients),
        "accepted": accepted,
        "failed": failed,
        "delivery_unknown": unknown,
        "not_attempted": not_attempted,
        "results": results,
    }), 200


# --------------------------------------------------
# ERROR HANDLERS / VERCEL ENTRY POINT
# --------------------------------------------------
@app.errorhandler(413)
def request_too_large(error):
    return json_error("Request is too large.", 413)


@app.errorhandler(500)
def internal_error(error):
    logger.exception("Unhandled application error")
    return json_error("An internal server error occurred.", 500)


application = app
