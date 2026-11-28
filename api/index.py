import os
import re
import hmac
import ssl
import smtplib
import time
import random
import logging
import unicodedata
from pathlib import Path
from html import unescape
from email.message import EmailMessage
from email.utils import formataddr, parseaddr, formatdate, make_msgid
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import (
    Flask, jsonify, redirect, render_template,
    request, session, url_for
)

# --------------------------------------------------
# APP CONFIGURATION
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(PROJECT_ROOT / "templates"),
    static_folder=str(PROJECT_ROOT / "static"),
    static_url_path="/static"
)

SECRET_KEY = os.environ.get("SESSION_SECRET")
if not SECRET_KEY and os.environ.get("VERCEL") == "1":
    raise RuntimeError("SESSION_SECRET must be configured.")

app.secret_key = SECRET_KEY or "local-development-only-change-this"

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("VERCEL", "").lower() == "1",
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
    MAX_CONTENT_LENGTH=1024 * 1024
)

# --------------------------------------------------
# EMAIL SETTINGS
# --------------------------------------------------

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

MAX_RECIPIENTS = 25
MAX_WORKERS = 3

# A message rejected with an explicit temporary SMTP response may be
# retried. A dropped connection after DATA is NOT retried because Gmail
# may already have accepted the message (retrying could create duplicates).
MAX_SAFE_RETRIES = 2
RETRY_BASE_DELAY = 1.0

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mail_sender")


# --------------------------------------------------
# RESPONSE HELPERS
# --------------------------------------------------

def json_error(message, status=400, **extra):
    payload = {"success": False, "error": message}
    payload.update(extra)
    return jsonify(payload), status


# --------------------------------------------------
# INPUT AND EMAIL VALIDATION
# --------------------------------------------------

def clean_text(value, limit=None):
    if not isinstance(value, str):
        value = str(value or "")
    value = unicodedata.normalize("NFKC", value)
    value = "".join(
        ch for ch in value
        if ch.isprintable() and not unicodedata.category(ch).startswith("C")
    )
    value = value.strip()
    return value[:limit] if limit else value


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

    display, address = parseaddr(value)
    if display or address != value or "@" not in address:
        return False

    local, domain = address.rsplit("@", 1)
    if not local or not domain or len(local) > 64:
        return False
    if domain.startswith(".") or domain.endswith(".") or ".." in address:
        return False
    if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+", local):
        return False
    if not re.fullmatch(r"[A-Za-z0-9.-]+", domain):
        return False
    if "." not in domain:
        return False
    labels = domain.split(".")
    if any(not label or label.startswith("-") or label.endswith("-") for label in labels):
        return False
    return True


def recipient_address(item):
    if isinstance(item, str):
        return clean_email(item.replace('"', "").replace("'", ""))
    if isinstance(item, dict):
        return clean_email(
            str(item.get("email", "")).replace('"', "").replace("'", "")
        )
    return ""


# --------------------------------------------------
# SPINTAX
# --------------------------------------------------

_SPINTAX_PATTERN = re.compile(r"\{([^{}]+)\}")


def expand_spintax(value):
    value = str(value or "")
    for _ in range(100):
        match = _SPINTAX_PATTERN.search(value)
        if not match:
            break
        choices = match.group(1).split("|")
        value = value[:match.start()] + random.choice(choices) + value[match.end():]
    return value


# --------------------------------------------------
# HTML TO TEXT
# --------------------------------------------------

def html_to_plain_text(html_content):
    text = re.sub(r"(?i)<br\s*/?>", "\n", html_content)
    text = re.sub(r"(?i)</(p|div|tr|li|h[1-6])>", "\n", text)
    text = re.sub(r"<[^>]+?>", "", text)
    text = unescape(text)
    text = re.sub(r"\n[ \t]*\n(?:[ \t]*\n)+", "\n\n", text)
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
    personalized_body = expand_spintax(personalized_body)
    personalized_subject = expand_spintax(subject)

    message = EmailMessage()
    safe_sender_name = re.sub(r"[\r\n]+", " ", sender_name).strip()[:100]
    safe_subject = re.sub(r"[\r\n]+", " ", personalized_subject).strip()

    message["Subject"] = safe_subject
    message["From"] = (
        formataddr((safe_sender_name, sender_email))
        if safe_sender_name else sender_email
    )
    message["To"] = recipient
    message["Reply-To"] = sender_email
    message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = make_msgid(
        domain=sender_email.rsplit("@", 1)[1]
    )

    if html_mode:
        plain_text = html_to_plain_text(personalized_body)
        message.set_content(
            plain_text or "Please view this email in an HTML-compatible email client.",
            charset="utf-8"
        )
        message.add_alternative(
            personalized_body,
            subtype="html",
            charset="utf-8"
        )
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
        timeout=SMTP_TIMEOUT
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
# SINGLE EMAIL SENDER
# --------------------------------------------------

def send_single_email(smtp, sender_email, sender_name, subject, body,
                      html_mode, recipient):
    message = build_email(
        sender_email=sender_email,
        sender_name=sender_name,
        recipient=recipient,
        subject=subject,
        body=body,
        html_mode=html_mode
    )
    refused = smtp.send_message(message)
    if refused:
        return {
            "status": "failed",
            "email": recipient,
            "detail": "Gmail refused this recipient."
        }
    return {
        "status": "sent",
        "email": recipient,
        "detail": "Accepted by Gmail SMTP"
    }


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
        return render_template(
            "login.html",
            error="LOGIN_PASSWORD is not configured."
        ), 500

    if not hmac.compare_digest(supplied_password, configured_password):
        return render_template(
            "login.html",
            error="Incorrect workspace password."
        ), 401

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
        return json_error(
            "Your session has expired. Please sign in again.", 401
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
    sender_name = clean_text(
        data.get("senderName") or data.get("sender_name") or "", 100
    )
    subject = clean_text(data.get("subject") or "", 998)
    body = str(data.get("body") or "")

    html_mode = data.get("htmlMode", data.get("is_html", False)) is True
    consent = (
        data.get("consentConfirmed", data.get("consent_confirmed", False))
        is True
    )
    raw_recipients = data.get("recipients", [])

    if not sender_email.endswith("@gmail.com") or not valid_email(sender_email):
        return json_error("Please enter a valid Gmail sender address.")
    if not app_password:
        return json_error("Google App Password is required.")
    if not subject:
        return json_error("Please enter a valid email subject.")
    if not body.strip():
        return json_error("Email message body is required.")
    if not consent:
        return json_error(
            "Confirm that all recipients have consented to receive these emails."
        )
    if not isinstance(raw_recipients, list):
        return json_error("Recipients must be provided as a list.")
    if len(raw_recipients) > MAX_RECIPIENTS * 3:
        return json_error("Too many recipient entries in one request.")

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
        return json_error(
            f"Maximum {MAX_RECIPIENTS} recipients allowed per batch."
        )

    invalid = [address for address in recipients if not valid_email(address)]
    if invalid:
        return json_error(
            "Invalid email addresses: " + ", ".join(invalid[:5])
        )

    worker_count = min(MAX_WORKERS, len(recipients))
    recipient_groups = [
        recipients[index::worker_count] for index in range(worker_count)
    ]

    def send_recipient_group(group):
        group_results = []
        smtp = None

        try:
            smtp = create_smtp_connection(sender_email, app_password)

            for recipient in group:
                attempts = 0
                result = None

                while attempts <= MAX_SAFE_RETRIES:
                    attempts += 1
                    try:
                        if smtp is None:
                            smtp = create_smtp_connection(
                                sender_email, app_password
                            )

                        result = send_single_email(
                            smtp=smtp,
                            sender_email=sender_email,
                            sender_name=sender_name,
                            subject=subject,
                            body=body,
                            html_mode=html_mode,
                            recipient=recipient
                        )
                        break

                    except smtplib.SMTPAuthenticationError:
                        result = {
                            "status": "failed",
                            "email": recipient,
                            "detail": "Gmail authentication failed. Check the Gmail App Password and account security settings."
                        }
                        close_smtp(smtp)
                        smtp = None
                        break

                    except smtplib.SMTPRecipientsRefused:
                        result = {
                            "status": "failed",
                            "email": recipient,
                            "detail": "Gmail refused this recipient address."
                        }
                        break

                    except smtplib.SMTPDataError as exc:
                        code = getattr(exc, "smtp_code", 0)
                        detail = clean_text(str(exc), 220)
                        if 400 <= code < 500 and attempts <= MAX_SAFE_RETRIES:
                            close_smtp(smtp)
                            smtp = None
                            time.sleep(RETRY_BASE_DELAY * attempts)
                            continue
                        result = {
                            "status": "failed",
                            "email": recipient,
                            "detail": f"SMTP rejected the message ({code}): {detail}"
                        }
                        break

                    except (smtplib.SMTPServerDisconnected, ConnectionError,
                            TimeoutError, OSError):
                        close_smtp(smtp)
                        smtp = None
                        result = {
                            "status": "uncertain",
                            "email": recipient,
                            "detail": "Connection dropped during sending; delivery status is unknown. Check Gmail Sent before retrying."
                        }
                        break

                    except smtplib.SMTPException as exc:
                        result = {
                            "status": "failed",
                            "email": recipient,
                            "detail": clean_text(str(exc), 220) or "SMTP error."
                        }
                        close_smtp(smtp)
                        smtp = None
                        break

                    except Exception:
                        logger.exception("Unexpected error while sending to %s", recipient)
                        result = {
                            "status": "failed",
                            "email": recipient,
                            "detail": "Unexpected sending error. Check server logs."
                        }
                        close_smtp(smtp)
                        smtp = None
                        break

                if result is None:
                    result = {
                        "status": "failed",
                        "email": recipient,
                        "detail": "Sending attempts were exhausted."
                    }
                group_results.append(result)

        except smtplib.SMTPAuthenticationError:
            group_results.extend({
                "status": "failed",
                "email": recipient,
                "detail": "Gmail authentication failed. Check the Gmail App Password."
            } for recipient in group)

        except (smtplib.SMTPException, OSError, TimeoutError) as exc:
            detail = clean_text(str(exc), 180) or "SMTP connection failed."
            group_results.extend({
                "status": "failed",
                "email": recipient,
                "detail": f"SMTP connection failed: {detail}"
            } for recipient in group)

        except Exception:
            logger.exception("Unexpected worker failure")
            group_results.extend({
                "status": "failed",
                "email": recipient,
                "detail": "Worker failed unexpectedly. Check server logs."
            } for recipient in group)

        finally:
            close_smtp(smtp)

        return group_results

    results = []
    try:
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [
                executor.submit(send_recipient_group, group)
                for group in recipient_groups
            ]
            for future in as_completed(futures):
                try:
                    results.extend(future.result())
                except Exception:
                    logger.exception("Batch worker crashed")
    except Exception:
        logger.exception("Batch processing failed")
        return jsonify({
            "success": False,
            "error": "Batch processing failed. Check server logs.",
            "results": results
        }), 502

    order = {email.casefold(): index for index, email in enumerate(recipients)}
    results.sort(
        key=lambda item: order.get(item.get("email", "").casefold(), len(recipients))
    )

    sent_count = sum(1 for item in results if item["status"] == "sent")
    failed_count = sum(1 for item in results if item["status"] == "failed")
    uncertain_count = sum(1 for item in results if item["status"] == "uncertain")

    return jsonify({
        "success": failed_count == 0 and uncertain_count == 0,
        "total": len(recipients),
        "accepted": sent_count,
        "failed": failed_count,
        "uncertain": uncertain_count,
        "results": results
    }), 200


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200


# --------------------------------------------------
# ERROR HANDLERS
# --------------------------------------------------

@app.errorhandler(413)
def request_too_large(error):
    return json_error("Request is too large.", 413)


@app.errorhandler(404)
def not_found(error):
    if request.path.startswith("/send"):
        return json_error("API endpoint not found.", 404)
    return "Page not found", 404


@app.errorhandler(500)
def internal_error(error):
    logger.exception("Unhandled server error")
    return json_error("An internal server error occurred.", 500)


# --------------------------------------------------
# VERCEL ENTRY POINT
# --------------------------------------------------

application = app
