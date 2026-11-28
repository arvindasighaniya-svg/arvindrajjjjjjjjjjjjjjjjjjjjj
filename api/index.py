
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
from email.utils import formataddr, formatdate, make_msgid, parseaddr

from flask import (
    Flask, jsonify, redirect, render_template,
    request, session, url_for
)


# ==================================================
# APP CONFIGURATION
# ==================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(PROJECT_ROOT / "templates"),
    static_folder=str(PROJECT_ROOT / "static"),
    static_url_path="/static"
)

SECRET_KEY = os.environ.get("SESSION_SECRET")

if not SECRET_KEY and os.environ.get("VERCEL") == "1":
    raise RuntimeError("Please configure SESSION_SECRET in Vercel.")

app.secret_key = SECRET_KEY or "local-development-only-change-this"

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("VERCEL", "").lower() == "1",
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
    MAX_CONTENT_LENGTH=1024 * 1024
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ==================================================
# SMTP SETTINGS
# ==================================================

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

MAX_RECIPIENTS = 10
SEND_INTERVAL = 0.5


# ==================================================
# GENERAL HELPERS
# ==================================================

def json_error(message, status=400):
    return jsonify({
        "success": False,
        "error": message
    }), status


def clean_text(value, limit=5000):
    if not isinstance(value, str):
        value = str(value or "")

    value = unicodedata.normalize("NFKC", value)

    value = "".join(
        char for char in value
        if char.isprintable()
        and not unicodedata.category(char).startswith("C")
    )

    return value.strip()[:limit]


def clean_email(value):
    if not isinstance(value, str):
        return ""

    value = unicodedata.normalize("NFKC", value)

    return "".join(
        char for char in value
        if char.isprintable()
        and not unicodedata.category(char).startswith("C")
    ).replace("\xa0", "").strip()


def valid_email(value):
    value = clean_email(value)

    if not value or len(value) > 254:
        return False

    if any(char.isspace() for char in value):
        return False

    display_name, address = parseaddr(value)

    if display_name or address != value or "@" not in address:
        return False

    local, domain = address.rsplit("@", 1)

    if not local or not domain:
        return False

    if "." not in domain:
        return False

    if domain.startswith(".") or domain.endswith("."):
        return False

    if ".." in address:
        return False

    return True


def get_recipient(item):
    if isinstance(item, str):
        return clean_email(item)

    if isinstance(item, dict):
        return clean_email(item.get("email", ""))

    return ""


def get_allowed_recipients(sender_email):
    """
    ALLOWED_RECIPIENTS must contain addresses that explicitly
    opted in to receive your emails.

    If the variable is empty, only the sender's own Gmail
    address is allowed for testing.
    """

    raw = os.environ.get("ALLOWED_RECIPIENTS", "")

    addresses = re.split(r"[,;\r\n]+", raw)

    allowed = {
        clean_email(address).casefold()
        for address in addresses
        if clean_email(address)
    }

    if allowed:
        return allowed

    return {sender_email.casefold()}


def html_to_text(value):
    value = re.sub(r"(?i)<br\s*/?>", "\n", value)
    value = re.sub(
        r"(?i)</(p|div|li|h[1-6])>",
        "\n",
        value
    )

    value = re.sub(r"<[^>]+>", "", value)
    value = unescape(value)

    return value.strip()


# ==================================================
# EMAIL BUILDER
# ==================================================

def build_email(
    sender_email,
    sender_name,
    recipient,
    subject,
    body,
    html_mode=False
):
    local_part = recipient.split("@", 1)[0]

    recipient_name = re.sub(
        r"[._-]+",
        " ",
        local_part
    ).strip().title()

    personalized_body = (
        body.replace("{{name}}", recipient_name)
        .replace("{{username}}", local_part)
        .replace("{{email}}", recipient)
    )

    message = EmailMessage()

    safe_name = re.sub(r"[\r\n]+", " ", sender_name).strip()
    safe_subject = re.sub(r"[\r\n]+", " ", subject).strip()

    message["Subject"] = safe_subject

    if safe_name:
        message["From"] = formataddr(
            (safe_name, sender_email)
        )
    else:
        message["From"] = sender_email

    message["To"] = recipient
    message["Reply-To"] = sender_email
    message["Date"] = formatdate(localtime=True)

    domain = sender_email.rsplit("@", 1)[1]
    message["Message-ID"] = make_msgid(domain=domain)

    if html_mode:
        plain_text = html_to_text(personalized_body)

        message.set_content(
            plain_text or "Please view this message in an HTML-compatible email client.",
            charset="utf-8"
        )

        message.add_alternative(
            personalized_body,
            subtype="html",
            charset="utf-8"
        )
    else:
        message.set_content(
            personalized_body,
            charset="utf-8"
        )

    return message


# ==================================================
# SMTP CONNECTION
# ==================================================

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
    if smtp is None:
        return

    try:
        smtp.quit()
    except Exception:
        try:
            smtp.close()
        except Exception:
            pass


# ==================================================
# LOGIN
# ==================================================

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

    if not hmac.compare_digest(
        supplied_password,
        configured_password
    ):
        return render_template(
            "login.html",
            error="Incorrect password."
        ), 401

    session.clear()
    session["logged_in"] = True
    session.permanent = True

    return redirect(url_for("home"))


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ==================================================
# SEND BATCH
# ==================================================

@app.post("/send-batch")
def send_batch():

    if not session.get("logged_in"):
        return json_error(
            "Session expired. Please login again.",
            401
        )

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return json_error("Invalid JSON request.")

    sender_email = clean_email(
        str(
            data.get("senderEmail")
            or data.get("gmail")
            or ""
        ).lower()
    )

    app_password = str(
        data.get("appPassword")
        or data.get("app_password")
        or ""
    ).replace(" ", "").strip()

    sender_name = clean_text(
        data.get("senderName")
        or data.get("sender_name")
        or "",
        100
    )

    subject = clean_text(
        data.get("subject") or "",
        998
    )

    body = data.get("body") or ""

    html_mode = (
        data.get("htmlMode", data.get("is_html", False))
        is True
    )

    consent = (
        data.get(
            "consentConfirmed",
            data.get("consent_confirmed", False)
        ) is True
    )

    raw_recipients = data.get("recipients", [])

    # ----------------------------------------------
    # VALIDATION
    # ----------------------------------------------

    if (
        not valid_email(sender_email)
        or not sender_email.endswith("@gmail.com")
    ):
        return json_error("Enter a valid Gmail sender address.")

    if not app_password:
        return json_error("Google App Password is required.")

    if not subject:
        return json_error("Email subject is required.")

    if not isinstance(body, str) or not body.strip():
        return json_error("Email message is required.")

    if not consent:
        return json_error(
            "Confirm that recipients have explicitly opted in."
        )

    if not isinstance(raw_recipients, list):
        return json_error("Recipients must be a list.")

    recipients = []
    seen = set()

    for item in raw_recipients:
        address = get_recipient(item)

        if not address:
            continue

        key = address.casefold()

        if key not in seen:
            seen.add(key)
            recipients.append(address)

    if not recipients:
        return json_error("No valid recipients provided.")

    if len(recipients) > MAX_RECIPIENTS:
        return json_error(
            f"Maximum {MAX_RECIPIENTS} recipients per batch."
        )

    invalid = [
        address for address in recipients
        if not valid_email(address)
    ]

    if invalid:
        return json_error(
            "Invalid email address: " + ", ".join(invalid[:5])
        )

    # ----------------------------------------------
    # SERVER-SIDE OPT-IN CHECK
    # ----------------------------------------------

    allowed = get_allowed_recipients(sender_email)

    blocked = [
        address for address in recipients
        if address.casefold() not in allowed
    ]

    if blocked:
        return json_error(
            "Recipients are not approved. Add only confirmed "
            "opt-in addresses to ALLOWED_RECIPIENTS in Vercel. "
            "If it is empty, only the sender's own Gmail can "
            "be used for testing.",
            403
        )

    # ----------------------------------------------
    # SEND EMAILS
    # ----------------------------------------------

    smtp = None
    results = []

    try:
        smtp = create_smtp_connection(
            sender_email,
            app_password
        )

        for index, recipient in enumerate(recipients):

            if index > 0:
                time.sleep(SEND_INTERVAL)

            try:
                message = build_email(
                    sender_email,
                    sender_name,
                    recipient,
                    subject,
                    body,
                    html_mode
                )

                refused = smtp.send_message(message)

                if refused:
                    results.append({
                        "email": recipient,
                        "status": "failed",
                        "detail": "Gmail refused this recipient."
                    })
                else:
                    results.append({
                        "email": recipient,
                        "status": "sent",
                        "detail": (
                            "Accepted by Gmail SMTP. "
                            "Inbox placement is not confirmed."
                        )
                    })

            except smtplib.SMTPRecipientsRefused:
                results.append({
                    "email": recipient,
                    "status": "failed",
                    "detail": "Gmail refused this recipient."
                })

            except smtplib.SMTPAuthenticationError:
                results.append({
                    "email": recipient,
                    "status": "failed",
                    "detail": "Gmail authentication failed."
                })
                break

            except smtplib.SMTPDataError as exc:
                results.append({
                    "email": recipient,
                    "status": "failed",
                    "detail": (
                        "Gmail rejected the message. SMTP code: "
                        + str(getattr(exc, "smtp_code", "unknown"))
                    )
                })
                break

            except (
                smtplib.SMTPServerDisconnected,
                ConnectionError,
                TimeoutError,
                OSError
            ) as exc:
                results.append({
                    "email": recipient,
                    "status": "delivery_unknown",
                    "detail": (
                        "Connection ended during sending. "
                        "Check Gmail Sent before retrying."
                    )
                })

                logger.warning(
                    "SMTP connection issue: %s",
                    exc
                )

                break

            except smtplib.SMTPException as exc:
                results.append({
                    "email": recipient,
                    "status": "failed",
                    "detail": "SMTP error: " + clean_text(str(exc), 150)
                })
                break

            except Exception:
                logger.exception(
                    "Unexpected sending error for %s",
                    recipient
                )

                results.append({
                    "email": recipient,
                    "status": "failed",
                    "detail": "Unexpected sending error."
                })
                break

        attempted = {
            item["email"].casefold()
            for item in results
        }

        for recipient in recipients:
            if recipient.casefold() not in attempted:
                results.append({
                    "email": recipient,
                    "status": "not_attempted",
                    "detail": "Stopped because an earlier send failed."
                })

    except smtplib.SMTPAuthenticationError:
        return json_error(
            "Gmail login failed. Check your Gmail address "
            "and Google App Password.",
            502
        )

    except (smtplib.SMTPException, OSError, TimeoutError) as exc:
        logger.exception("Gmail SMTP connection failed")

        return jsonify({
            "success": False,
            "error": "Could not connect to Gmail SMTP.",
            "detail": clean_text(str(exc), 180)
        }), 502

    finally:
        close_smtp(smtp)

    accepted = sum(
        item["status"] == "sent"
        for item in results
    )

    failed = sum(
        item["status"] == "failed"
        for item in results
    )

    unknown = sum(
        item["status"] == "delivery_unknown"
        for item in results
    )

    not_attempted = sum(
        item["status"] == "not_attempted"
        for item in results
    )

    return jsonify({
        "success": (
            failed == 0
            and unknown == 0
            and not_attempted == 0
        ),
        "total": len(recipients),
        "accepted": accepted,
        "failed": failed,
        "delivery_unknown": unknown,
        "not_attempted": not_attempted,
        "results": results
    }), 200


# ==================================================
# HEALTH CHECK
# ==================================================

@app.get("/health")
def health():
    return jsonify({
        "status": "ok"
    }), 200


# ==================================================
# ERROR HANDLERS
# ==================================================

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
    logger.exception("Internal server error")

    return json_error(
        "An internal server error occurred.",
        500
    )


# ==================================================
# VERCEL ENTRY POINT
# ==================================================

application = app
