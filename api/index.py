
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
from email.utils import (
    formataddr,
    parseaddr,
    make_msgid,
    formatdate
)
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for
)


# --------------------------------------------------
# LOGGING
# --------------------------------------------------

logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)


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
    raise RuntimeError(
        "SESSION_SECRET must be configured."
    )

app.secret_key = (
    SECRET_KEY
    or "local-development-only-change-this"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=(
        os.environ.get("VERCEL", "").lower() == "1"
    ),
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
    MAX_CONTENT_LENGTH=1024 * 1024
)


# --------------------------------------------------
# EMAIL SETTINGS
# --------------------------------------------------

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 30

MAX_RECIPIENTS = 25

# Keep concurrency conservative for Gmail.
MAX_WORKERS = 2

MAX_RETRIES = 2
RETRY_DELAY = 3


# --------------------------------------------------
# RESPONSE HELPERS
# --------------------------------------------------

def json_error(message, status=400):

    return jsonify({
        "success": False,
        "error": message
    }), status


# --------------------------------------------------
# EMAIL CLEANING
# --------------------------------------------------

def clean_email(value):

    if not isinstance(value, str):
        return ""

    value = unicodedata.normalize(
        "NFKC",
        value
    )

    value = "".join(
        character
        for character in value
        if character.isprintable()
        and not unicodedata.category(
            character
        ).startswith("C")
    )

    return value.replace(
        "\xa0",
        ""
    ).strip().replace(" ", "")


# --------------------------------------------------
# EMAIL VALIDATION
# --------------------------------------------------

def valid_email(value):

    value = clean_email(value)

    if not value or len(value) > 254:
        return False

    _, address = parseaddr(value)

    if address != value:
        return False

    if "@" not in address:
        return False

    local, domain = address.rsplit("@", 1)

    if not local or not domain:
        return False

    if len(local) > 64:
        return False

    if "." not in domain:
        return False

    if ".." in address:
        return False

    if domain.startswith("."):
        return False

    if domain.endswith("."):
        return False

    return True


# --------------------------------------------------
# RECIPIENT EXTRACTION
# --------------------------------------------------

def recipient_address(item):

    if isinstance(item, str):
        return clean_email(item)

    if isinstance(item, dict):

        return clean_email(
            str(
                item.get("email", "")
            )
        )

    return ""


# --------------------------------------------------
# SPINTAX
# --------------------------------------------------

def expand_spintax(text):

    pattern = re.compile(
        r"\{([^{}]+)\}"
    )

    while pattern.search(text):

        text = pattern.sub(
            lambda match: random.choice(
                match.group(1).split("|")
            ),
            text
        )

    return text


# --------------------------------------------------
# HTML TO TEXT
# --------------------------------------------------

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


# --------------------------------------------------
# EMAIL BUILDER
# --------------------------------------------------

def build_email(
    sender_email,
    sender_name,
    recipient,
    subject,
    body,
    html_mode=False
):

    local_part = recipient.split(
        "@",
        1
    )[0]

    display_name = re.sub(
        r"[._-]+",
        " ",
        local_part
    ).strip().title() or local_part

    personalized_body = (
        body.replace(
            "{{name}}",
            display_name
        )
        .replace(
            "{{username}}",
            local_part
        )
        .replace(
            "{{email}}",
            recipient
        )
    )

    personalized_body = expand_spintax(
        personalized_body
    )

    personalized_subject = expand_spintax(
        subject
    )

    message = EmailMessage()

    clean_sender_name = re.sub(
        r"[\r\n]+",
        " ",
        sender_name
    ).strip()[:100]

    clean_subject = re.sub(
        r"[\r\n]+",
        " ",
        personalized_subject
    ).strip()

    message["Subject"] = clean_subject

    message["From"] = (
        formataddr(
            (
                clean_sender_name,
                sender_email
            )
        )
        if clean_sender_name
        else sender_email
    )

    message["To"] = recipient

    message["Reply-To"] = sender_email

    message["Date"] = formatdate(
        localtime=True
    )

    message["Message-ID"] = make_msgid(
        domain=sender_email.split(
            "@",
            1
        )[1]
    )

    if html_mode:

        plain_text = html_to_plain_text(
            personalized_body
        )

        message.set_content(
            plain_text
            or "Please view this email in an HTML-compatible email client.",
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


# --------------------------------------------------
# SMTP CONNECTION
# --------------------------------------------------

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
            smtp.quit()
        except Exception:
            pass

        raise


# --------------------------------------------------
# SMTP CLEANUP
# --------------------------------------------------

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


# --------------------------------------------------
# SINGLE EMAIL SENDER
# --------------------------------------------------

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

    refused = smtp.send_message(
        message,
        from_addr=sender_email,
        to_addrs=[recipient]
    )

    if refused:

        raise smtplib.SMTPRecipientsRefused(
            refused
        )

    return {
        "status": "sent",
        "email": recipient,
        "detail": "Accepted by Gmail; inbox delivery not confirmed"
    }


# --------------------------------------------------
# LOGIN PAGE
# --------------------------------------------------

@app.get("/")
def home():

    if not session.get("logged_in"):

        return redirect(
            url_for("login")
        )

    return render_template(
        "index.html"
    )


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

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

        return render_template(
            "login.html"
        )

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


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route(
    "/logout",
    methods=["GET", "POST"]
)
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# --------------------------------------------------
# AUTHENTICATION HELPER
# --------------------------------------------------

def is_logged_in():

    return bool(
        session.get("logged_in")
    )


# --------------------------------------------------
# SEND WORKER
# --------------------------------------------------

def send_recipient_group(
    group,
    sender_email,
    app_password,
    sender_name,
    subject,
    body,
    html_mode
):

    results = []

    smtp = None

    try:

        smtp = create_smtp_connection(
            sender_email,
            app_password
        )

        for recipient in group:

            attempts = 0

            sent = False

            last_error = "Unknown SMTP error"

            while (
                attempts < MAX_RETRIES
                and not sent
            ):

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

                    results.append(result)

                    sent = True

                except smtplib.SMTPAuthenticationError:

                    last_error = (
                        "Gmail authentication failed. "
                        "Check your Google App Password."
                    )

                    close_smtp(smtp)

                    smtp = None

                    break

                except smtplib.SMTPRecipientsRefused:

                    last_error = (
                        "Gmail refused this recipient address."
                    )

                    break

                except smtplib.SMTPDataError as exc:

                    code = getattr(
                        exc,
                        "smtp_code",
                        0
                    )

                    last_error = str(exc)[:200]

                    if not (
                        400 <= code < 500
                    ):

                        break

                    close_smtp(smtp)

                    smtp = None

                    if attempts < MAX_RETRIES:

                        time.sleep(
                            RETRY_DELAY * attempts
                        )

                except (
                    smtplib.SMTPServerDisconnected,
                    ConnectionError,
                    TimeoutError,
                    OSError
                ) as exc:

                    last_error = str(exc)[:200]

                    close_smtp(smtp)

                    smtp = None

                    if attempts < MAX_RETRIES:

                        time.sleep(
                            RETRY_DELAY * attempts
                        )

                except Exception as exc:

                    last_error = str(exc)[:200]

                    break

            if not sent:

                results.append({
                    "status": "failed",
                    "email": recipient,
                    "detail": last_error
                })

    except smtplib.SMTPAuthenticationError:

        results.extend(
            {
                "status": "failed",
                "email": recipient,
                "detail": "Gmail authentication failed."
            }
            for recipient in group
        )

    except Exception as exc:

        logger.exception(
            "SMTP worker failed"
        )

        results.extend(
            {
                "status": "failed",
                "email": recipient,
                "detail": (
                    "SMTP connection failed: "
                    + str(exc)[:180]
                )
            }
            for recipient in group
        )

    finally:

        close_smtp(smtp)

    return results


# --------------------------------------------------
# BATCH EMAIL SENDER
# --------------------------------------------------

@app.post("/send-batch")
def send_batch():

    if not is_logged_in():

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

    # SENDER EMAIL

    sender_email = clean_email(
        str(
            data.get("senderEmail")
            or data.get("gmail")
            or ""
        ).lower()
    )

    # SERVER-SIDE PASSWORD FIRST

    app_password = os.environ.get(
        "GMAIL_APP_PASSWORD",
        ""
    ).strip().replace(" ", "")

    # Backward compatibility with existing frontend.
    if not app_password:

        app_password = str(
            data.get("appPassword")
            or data.get("app_password")
            or ""
        ).strip().replace(" ", "")

    # SENDER NAME

    sender_name = str(
        data.get("senderName")
        or data.get("sender_name")
        or ""
    ).strip()[:100]

    # SUBJECT

    subject = str(
        data.get("subject")
        or ""
    ).strip()

    # BODY

    body = str(
        data.get("body")
        or ""
    )

    # HTML MODE

    html_mode = (
        data.get(
            "htmlMode",
            data.get("is_html", False)
        ) is True
    )

    # CONSENT

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

    # VALIDATE SENDER

    if (
        not sender_email.endswith("@gmail.com")
        or not valid_email(sender_email)
    ):

        return json_error(
            "Please enter a valid Gmail sender address."
        )

    # VALIDATE APP PASSWORD

    if not app_password:

        return json_error(
            "GMAIL_APP_PASSWORD or Google App Password is required."
        )

    # VALIDATE SUBJECT

    if (
        not subject
        or len(subject) > 998
        or "\r" in subject
        or "\n" in subject
    ):

        return json_error(
            "Please enter a valid email subject."
        )

    # VALIDATE BODY

    if not body.strip():

        return json_error(
            "Email message body is required."
        )

    # CONSENT CHECK

    if not consent:

        return json_error(
            "Please confirm that all recipients have consented to receive your email."
        )

    # RECIPIENT LIST

    if not isinstance(
        raw_recipients,
        list
    ):

        return json_error(
            "Recipients must be provided as a list."
        )

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

    # EMPTY LIST

    if not recipients:

        return json_error(
            "Please provide at least one valid recipient."
        )

    # MAXIMUM RECIPIENTS

    if len(recipients) > MAX_RECIPIENTS:

        return json_error(
            f"Maximum {MAX_RECIPIENTS} recipients allowed per batch."
        )

    # INVALID EMAILS

    invalid = [
        address
        for address in recipients
        if not valid_email(address)
    ]

    if invalid:

        return json_error(
            "Invalid email addresses: "
            + ", ".join(invalid[:5])
        )

    # --------------------------------------------------
    # GROUP RECIPIENTS
    # --------------------------------------------------

    worker_count = min(
        MAX_WORKERS,
        len(recipients)
    )

    recipient_groups = [
        recipients[index::worker_count]
        for index in range(worker_count)
    ]

    results = []

    # --------------------------------------------------
    # EXECUTE WORKERS
    # --------------------------------------------------

    try:

        with ThreadPoolExecutor(
            max_workers=worker_count
        ) as executor:

            futures = [

                executor.submit(
                    send_recipient_group,
                    group,
                    sender_email,
                    app_password,
                    sender_name,
                    subject,
                    body,
                    html_mode
                )

                for group in recipient_groups
            ]

            for future in as_completed(futures):

                try:

                    results.extend(
                        future.result()
                    )

                except Exception as exc:

                    logger.exception(
                        "Worker execution failed"
                    )

                    results.append({
                        "status": "failed",
                        "email": "",
                        "detail": (
                            "Worker execution failed: "
                            + str(exc)[:200]
                        )
                    })

    except Exception as exc:

        logger.exception(
            "Batch processing failed"
        )

        return jsonify({
            "success": False,
            "error": "Batch processing failed.",
            "detail": str(exc)[:200],
            "results": results
        }), 502

    # --------------------------------------------------
    # SORT RESULTS
    # --------------------------------------------------

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

    # --------------------------------------------------
    # COUNTS
    # --------------------------------------------------

    sent_count = sum(
        1
        for item in results
        if item.get("status") == "sent"
    )

    failed_count = sum(
        1
        for item in results
        if item.get("status") == "failed"
    )

    # --------------------------------------------------
    # FINAL RESPONSE
    # --------------------------------------------------

    return jsonify({

        "success": failed_count == 0,

        "total": len(recipients),

        "accepted": sent_count,

        "failed": failed_count,

        "results": results

    }), 200


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.get("/health")
def health():

    return jsonify({
        "status": "ok",
        "application": "Flask Email Application"
    })


# --------------------------------------------------
# ERROR HANDLERS
# --------------------------------------------------

@app.errorhandler(413)
def request_too_large(error):

    return json_error(
        "Request is too large.",
        413
    )


@app.errorhandler(500)
def internal_error(error):

    logger.exception(
        "Internal server error"
    )

    return json_error(
        "An internal server error occurred.",
        500
    )


# --------------------------------------------------
# VERCEL ENTRY POINT
# --------------------------------------------------

application = app
