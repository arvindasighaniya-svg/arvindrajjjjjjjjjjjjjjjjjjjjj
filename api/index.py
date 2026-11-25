
import os
import re
import hmac
import ssl
import smtplib
import time
import random
import unicodedata
import logging

from pathlib import Path
from html import unescape
from email.message import EmailMessage
from email.utils import formataddr, parseaddr, make_msgid, formatdate

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for
)


# ==================================================
# LOGGING
# ==================================================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


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
    raise RuntimeError("SESSION_SECRET must be configured.")

app.secret_key = SECRET_KEY or "local-development-only-change-this"

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("VERCEL", "").lower() == "1",
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
    MAX_CONTENT_LENGTH=1024 * 1024
)


# ==================================================
# SMTP SETTINGS
# ==================================================

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465

SMTP_TIMEOUT = 25

MAX_RECIPIENTS = 25
MAX_RETRIES = 2

# Sequential sending: no uncontrolled parallel SMTP workers.
RETRY_DELAY = 2

# Optional minimum delay between messages.
try:
    SEND_INTERVAL = max(
        0.0,
        float(os.environ.get("SEND_INTERVAL_SECONDS", "0.2"))
    )
except (TypeError, ValueError):
    SEND_INTERVAL = 0.2


# ==================================================
# RESPONSE HELPERS
# ==================================================

def json_error(message, status=400):
    return jsonify({
        "success": False,
        "error": message
    }), status


def safe_error(exc):
    return str(exc).replace("\r", " ").replace("\n", " ")[:200]


# ==================================================
# INPUT CLEANING
# ==================================================

def clean_email(value):

    if not isinstance(value, str):
        return ""

    value = unicodedata.normalize("NFKC", value)

    value = "".join(
        char for char in value
        if char.isprintable()
        and not unicodedata.category(char).startswith("C")
    )

    return value.strip().replace(" ", "")


def clean_header(value, maximum=998):

    value = str(value or "")

    value = re.sub(
        r"[\r\n\x00]",
        " ",
        value
    )

    return value.strip()[:maximum]


def valid_email(value):

    value = clean_email(value)

    if not value or len(value) > 254:
        return False

    _, address = parseaddr(value)

    if address != value or "@" not in address:
        return False

    local, domain = address.rsplit("@", 1)

    if not local or not domain:
        return False

    if len(local) > 64:
        return False

    if "." not in domain:
        return False

    if domain.startswith(".") or domain.endswith("."):
        return False

    if ".." in address:
        return False

    if any(char in local for char in '<>(),;:\\[]"'):
        return False

    if any(char in domain for char in " <>@"):
        return False

    return True


def recipient_address(item):

    if isinstance(item, str):
        return clean_email(
            item.replace('"', "").replace("'", "")
        )

    if isinstance(item, dict):

        return clean_email(
            str(item.get("email", ""))
            .replace('"', "")
            .replace("'", "")
        )

    return ""


# ==================================================
# SPINTAX
# ==================================================

def expand_spintax(text):

    pattern = re.compile(r"\{([^{}]+)\}")

    for _ in range(20):

        if not pattern.search(text):
            break

        text = pattern.sub(
            lambda match: random.choice(
                match.group(1).split("|")
            ),
            text
        )

    return text


# ==================================================
# HTML TO TEXT
# ==================================================

def html_to_plain_text(html_content):

    text = re.sub(
        r"(?i)<br\s*/?>",
        "\n",
        html_content
    )

    text = re.sub(
        r"(?i)</(p|div|tr|li|h[1-6])>",
        "\n",
        text
    )

    text = re.sub(
        r"<[^>]+?>",
        "",
        text
    )

    text = unescape(text)

    text = re.sub(
        r"\n{3,}",
        "\n\n",
        text
    )

    return text.strip()


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

    display_name = re.sub(
        r"[._-]+",
        " ",
        local_part
    ).strip().title() or local_part

    personalized_body = (
        body.replace("{{name}}", display_name)
        .replace("{{username}}", local_part)
        .replace("{{email}}", recipient)
    )

    personalized_body = expand_spintax(
        personalized_body
    )

    personalized_subject = expand_spintax(
        subject
    )

    message = EmailMessage()

    message["Subject"] = clean_header(
        personalized_subject
    )

    clean_sender_name = clean_header(
        sender_name,
        100
    )

    message["From"] = (
        formataddr((clean_sender_name, sender_email))
        if clean_sender_name
        else sender_email
    )

    message["To"] = recipient
    message["Reply-To"] = sender_email

    message["Date"] = formatdate(
        localtime=True
    )

    # Let Python generate a valid unique Message-ID.
    message["Message-ID"] = make_msgid()

    if html_mode:

        plain_text = html_to_plain_text(
            personalized_body
        )

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

def create_smtp_connection(
    sender_email,
    app_password
):

    context = ssl.create_default_context()

    smtp = smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        context=context,
        timeout=SMTP_TIMEOUT
    )

    try:

        smtp.login(
            sender_email,
            app_password
        )

        return smtp

    except Exception:

        try:
            smtp.close()
        except Exception:
            pass

        raise


# ==================================================
# SMTP CLEANUP
# ==================================================

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
# SINGLE EMAIL SENDER
# ==================================================

def send_single_email(
    smtp,
    sender_email,
    sender_name,
    subject,
    body,
    html_mode,
    recipient
):

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
            "detail": "Gmail refused the recipient."
        }

    return {
        "status": "sent",
        "email": recipient,
        "detail": "Accepted by Gmail; inbox delivery not confirmed."
    }


# ==================================================
# SEQUENTIAL BATCH PROCESSING
# ==================================================

def process_batch(
    sender_email,
    app_password,
    sender_name,
    subject,
    body,
    html_mode,
    recipients
):

    results = []

    smtp = None
    last_send_time = 0

    try:

        # One authenticated connection per batch.
        smtp = create_smtp_connection(
            sender_email,
            app_password
        )

        for recipient in recipients:

            if SEND_INTERVAL > 0:

                elapsed = time.monotonic() - last_send_time

                remaining = SEND_INTERVAL - elapsed

                if remaining > 0:
                    time.sleep(remaining)

            attempts = 0
            result = None

            while attempts < MAX_RETRIES:

                attempts += 1

                try:

                    if smtp is None:

                        smtp = create_smtp_connection(
                            sender_email,
                            app_password
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

                    last_send_time = time.monotonic()

                    break

                except smtplib.SMTPAuthenticationError:

                    result = {
                        "status": "failed",
                        "email": recipient,
                        "detail": "Gmail authentication failed. Check your App Password."
                    }

                    close_smtp(smtp)
                    smtp = None

                    break

                except smtplib.SMTPRecipientsRefused:

                    result = {
                        "status": "failed",
                        "email": recipient,
                        "detail": "Gmail refused this recipient."
                    }

                    break

                except smtplib.SMTPDataError as exc:

                    code = getattr(exc, "smtp_code", 0)

                    result = {
                        "status": "failed",
                        "email": recipient,
                        "detail": safe_error(exc)
                    }

                    if 400 <= code < 500 and attempts < MAX_RETRIES:

                        close_smtp(smtp)
                        smtp = None

                        time.sleep(RETRY_DELAY)

                        continue

                    break

                except (
                    smtplib.SMTPServerDisconnected,
                    ConnectionError,
                    TimeoutError,
                    OSError
                ) as exc:

                    # The server may have accepted the message before
                    # the connection failed. Do not blindly resend it.
                    result = {
                        "status": "delivery_unknown",
                        "email": recipient,
                        "detail": (
                            "Connection failed during sending. "
                            "Check the recipient mailbox before retrying. "
                            + safe_error(exc)
                        )
                    }

                    close_smtp(smtp)
                    smtp = None

                    break

                except Exception as exc:

                    result = {
                        "status": "failed",
                        "email": recipient,
                        "detail": safe_error(exc)
                    }

                    break

            if result is None:

                result = {
                    "status": "failed",
                    "email": recipient,
                    "detail": "Maximum retry attempts reached."
                }

            results.append(result)

    except smtplib.SMTPAuthenticationError:

        results.extend([
            {
                "status": "failed",
                "email": recipient,
                "detail": "Gmail authentication failed."
            }
            for recipient in recipients[len(results):]
        ])

    except Exception as exc:

        results.extend([
            {
                "status": "failed",
                "email": recipient,
                "detail": "SMTP connection failed: " + safe_error(exc)
            }
            for recipient in recipients[len(results):]
        ])

    finally:

        close_smtp(smtp)

    return results


# ==================================================
# LOGIN PAGE
# ==================================================

@app.get("/")
def home():

    if not session.get("logged_in"):

        return redirect(
            url_for("login")
        )

    return render_template("index.html")


# ==================================================
# LOGIN
# ==================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "GET":

        if session.get("logged_in"):

            return redirect(
                url_for("home")
            )

        return render_template("login.html")

    supplied_password = request.form.get(
        "password",
        ""
    )

    configured_password = os.environ.get(
        "LOGIN_PASSWORD",
        ""
    )

    if not configured_password:

        return render_template(
            "login.html",
            error="LOGIN_PASSWORD is not configured."
        ), 500

    if not hmac.compare_digest(
        supplied_password,
        configured_password
    ):

        return render_template(
            "login.html",
            error="Incorrect workspace password."
        ), 401

    session.clear()

    session["logged_in"] = True
    session.permanent = True

    return redirect(
        url_for("home")
    )


# ==================================================
# LOGOUT
# ==================================================

@app.route(
    "/logout",
    methods=["GET", "POST"]
)
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ==================================================
# BATCH EMAIL API
# ==================================================

@app.post("/send-batch")
def send_batch():

    if not session.get("logged_in"):

        return json_error(
            "Your session has expired. Please sign in again.",
            401
        )

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):

        return json_error(
            "A valid JSON request body is required."
        )

    # Sender details

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
    ).strip().replace(" ", "")

    sender_name = clean_header(
        data.get("senderName")
        or data.get("sender_name")
        or "",
        100
    )

    subject = str(
        data.get("subject") or ""
    ).strip()

    body = str(
        data.get("body") or ""
    )

    html_mode = (
        data.get(
            "htmlMode",
            data.get("is_html", False)
        ) is True
    )

    consent = (
        data.get(
            "consentConfirmed",
            data.get("consent_confirmed", False)
        ) is True
    )

    raw_recipients = data.get(
        "recipients",
        []
    )

    # Validate sender

    if (
        not sender_email.endswith("@gmail.com")
        or not valid_email(sender_email)
    ):

        return json_error(
            "Please enter a valid Gmail sender address."
        )

    if not app_password:

        return json_error(
            "Google App Password is required."
        )

    if not subject or len(subject) > 998:

        return json_error(
            "Please enter a valid email subject."
        )

    if not body.strip():

        return json_error(
            "Email message body is required."
        )

    if not consent:

        return json_error(
            "Recipient consent confirmation is required."
        )

    if not isinstance(raw_recipients, list):

        return json_error(
            "Recipients must be provided as a list."
        )

    # Validate recipients

    recipients = []
    seen = set()

    for item in raw_recipients:

        address = recipient_address(item)

        if not address:
            continue

        if not valid_email(address):
            continue

        key = address.lower()

        if key not in seen:

            seen.add(key)
            recipients.append(address)

    if not recipients:

        return json_error(
            "Please provide at least one valid recipient."
        )

    if len(recipients) > MAX_RECIPIENTS:

        return json_error(
            f"Maximum {MAX_RECIPIENTS} recipients allowed per batch."
        )

    # Server-side recipient authorization.
    #
    # ALLOWED_RECIPIENTS must contain only addresses whose owners
    # have explicitly opted in to receive these messages.
    # Example Vercel value:
    # ALLOWED_RECIPIENTS=person1@example.com,person2@example.com
    #
    # A browser checkbox is not treated as proof of consent.

    configured_recipients = os.environ.get(
        "ALLOWED_RECIPIENTS",
        ""
    )

    allowed_recipients = {
        clean_email(address).lower()
        for address in configured_recipients.split(",")
        if clean_email(address) and valid_email(clean_email(address))
    }

    if not allowed_recipients:
        return json_error(
            "No opted-in recipients are configured. Add consented addresses to the ALLOWED_RECIPIENTS Vercel environment variable.",
            403
        )

    unauthorized_recipients = [
        address
        for address in recipients
        if address.lower() not in allowed_recipients
    ]

    if unauthorized_recipients:
        return jsonify({
            "success": False,
            "error": "Some recipients are not on the server-side opted-in list.",
            "unauthorized": unauthorized_recipients[:10],
            "total_unauthorized": len(unauthorized_recipients)
        }), 403

    # Sequential processing

    try:

        results = process_batch(
            sender_email=sender_email,
            app_password=app_password,
            sender_name=sender_name,
            subject=subject,
            body=body,
            html_mode=html_mode,
            recipients=recipients
        )

    except Exception as exc:

        logger.exception("Batch processing failed")

        return jsonify({
            "success": False,
            "error": "Batch processing failed.",
            "detail": safe_error(exc)
        }), 502

    # Preserve original recipient order.

    result_order = {
        email: index
        for index, email in enumerate(recipients)
    }

    results.sort(
        key=lambda item: result_order.get(
            item.get("email"),
            len(recipients)
        )
    )

    sent_count = sum(
        item["status"] == "sent"
        for item in results
    )

    failed_count = sum(
        item["status"] == "failed"
        for item in results
    )

    unknown_count = sum(
        item["status"] == "delivery_unknown"
        for item in results
    )

    return jsonify({

        "success": (
            failed_count == 0
            and unknown_count == 0
        ),

        "total": len(recipients),

        "accepted": sent_count,

        "failed": failed_count,

        "delivery_unknown": unknown_count,

        "results": results

    }), 200


# ==================================================
# HEALTH CHECK
# ==================================================

@app.get("/health")
def health():

    return jsonify({
        "status": "ok",
        "application": "running"
    }), 200


# ==================================================
# ERROR HANDLERS
# ==================================================

@app.errorhandler(413)
def request_too_large(error):

    return json_error(
        "Request is too large.",
        413
    )


@app.errorhandler(404)
def page_not_found(error):

    return json_error(
        "Requested page was not found.",
        404
    )


@app.errorhandler(405)
def method_not_allowed(error):

    return json_error(
        "Method not allowed.",
        405
    )


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
