
import os
import re
import hmac
import ssl
import smtplib
import time
import random
import unicodedata

from pathlib import Path
from html import unescape
from email.message import EmailMessage
from email.utils import (
    formataddr,
    parseaddr,
    make_msgid,
    formatdate
)

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
# EMAIL CONFIGURATION
# --------------------------------------------------

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465

MAX_RECIPIENTS = 25
MAX_WORKERS = 1
MAX_RETRIES = 2

SMTP_TIMEOUT = 20

MIN_SEND_DELAY = 2.0
MAX_SEND_DELAY = 3.0

MAX_SUBJECT_LENGTH = 998
MAX_BODY_LENGTH = 100000


# --------------------------------------------------
# RESPONSE HELPERS
# --------------------------------------------------

def json_error(message, status=400):
    return jsonify({
        "error": message
    }), status


# --------------------------------------------------
# EMAIL CLEANING
# --------------------------------------------------

def clean_email(value):

    if not isinstance(value, str):
        return ""

    value = unicodedata.normalize("NFKC", value)

    value = value.replace("\xa0", "").strip()

    value = "".join(
        char for char in value
        if char.isprintable()
        and not unicodedata.category(char).startswith("C")
    )

    return value.replace(" ", "")


def valid_email(value):

    value = clean_email(value)

    if not value or len(value) > 254:
        return False

    _, address = parseaddr(value)

    if address != value:
        return False

    if address.count("@") != 1:
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

    if any(char.isspace() for char in address):
        return False

    return True


def recipient_address(item):

    if isinstance(item, str):
        return clean_email(item)

    if isinstance(item, dict):
        return clean_email(
            str(item.get("email", ""))
        )

    return ""


# --------------------------------------------------
# SPINTAX
# --------------------------------------------------

def expand_spintax(text):

    pattern = re.compile(r"\{([^{}]+)\}")

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
# PERSONALIZATION
# --------------------------------------------------

def personalize_text(text, recipient):

    local_part = recipient.split("@", 1)[0]

    display_name = re.sub(
        r"[._-]+",
        " ",
        local_part
    ).strip().title() or local_part

    return (
        text.replace("{{name}}", display_name)
        .replace("{{username}}", local_part)
        .replace("{{email}}", recipient)
    )


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

    personalized_body = personalize_text(
        body,
        recipient
    )

    personalized_subject = personalize_text(
        subject,
        recipient
    )

    personalized_body = expand_spintax(
        personalized_body
    )

    personalized_subject = expand_spintax(
        personalized_subject
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
            (clean_sender_name, sender_email)
        )
        if clean_sender_name
        else sender_email
    )

    message["To"] = recipient

    message["Reply-To"] = sender_email

    message["Date"] = formatdate(
        localtime=False
    )

    sender_domain = sender_email.rsplit("@", 1)[1]

    message["Message-ID"] = make_msgid(
        domain=sender_domain
    )

    if html_mode:

        plain_text = html_to_plain_text(
            personalized_body
        )

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
# SMTP CLOSE
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
        "detail": "Accepted by Gmail"
    }


# --------------------------------------------------
# SAFE SINGLE RECIPIENT DELIVERY
# --------------------------------------------------

def send_recipient(
    sender_email,
    app_password,
    sender_name,
    subject,
    body,
    html_mode,
    recipient
):

    smtp = None

    try:

        for attempt in range(MAX_RETRIES):

            try:

                if smtp is None:

                    smtp = create_smtp_connection(
                        sender_email,
                        app_password
                    )

                time.sleep(
                    random.uniform(
                        MIN_SEND_DELAY,
                        MAX_SEND_DELAY
                    )
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

                return result

            except smtplib.SMTPAuthenticationError:

                return {
                    "status": "failed",
                    "email": recipient,
                    "detail": "Gmail authentication failed. Check your Google App Password."
                }

            except smtplib.SMTPRecipientsRefused:

                return {
                    "status": "failed",
                    "email": recipient,
                    "detail": "Gmail refused this recipient address."
                }

            except smtplib.SMTPDataError as exc:

                code = getattr(exc, "smtp_code", 0)

                detail = str(exc)[:200]

                close_smtp(smtp)
                smtp = None

                if 400 <= code < 500 and attempt + 1 < MAX_RETRIES:

                    time.sleep(3)
                    continue

                return {
                    "status": "failed",
                    "email": recipient,
                    "detail": detail
                }

            except (
                smtplib.SMTPServerDisconnected,
                ConnectionError,
                TimeoutError,
                OSError
            ) as exc:

                # A connection failure after SMTP DATA may have
                # an ambiguous delivery result. Do not resend it
                # automatically because this can create duplicates.

                close_smtp(smtp)
                smtp = None

                return {
                    "status": "unknown",
                    "email": recipient,
                    "detail": (
                        "Delivery could not be confirmed. "
                        + str(exc)[:150]
                    )
                }

            except Exception as exc:

                return {
                    "status": "failed",
                    "email": recipient,
                    "detail": str(exc)[:200]
                }

    finally:

        close_smtp(smtp)

    return {
        "status": "failed",
        "email": recipient,
        "detail": "Sending attempts exhausted."
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

    return render_template("index.html")


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
# BATCH EMAIL SENDER
# --------------------------------------------------

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

    sender_name = str(
        data.get("senderName")
        or data.get("sender_name")
        or ""
    ).strip()[:100]

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

    # ----------------------------------------------
    # VALIDATION
    # ----------------------------------------------

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

    if len(app_password) < 16:

        return json_error(
            "Please check your Google App Password."
        )

    if not subject or len(subject) > MAX_SUBJECT_LENGTH:

        return json_error(
            "Please enter a valid email subject."
        )

    if not body.strip():

        return json_error(
            "Email message body is required."
        )

    if len(body) > MAX_BODY_LENGTH:

        return json_error(
            "Email message body is too long."
        )

    if not consent:

        return json_error(
            "Please confirm that all recipients have consented to receive your email."
        )

    if not isinstance(raw_recipients, list):

        return json_error(
            "Recipients must be provided as a list."
        )

    # ----------------------------------------------
    # RECIPIENT CLEANING
    # ----------------------------------------------

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

        return json_error(
            "Please provide at least one valid recipient."
        )

    if len(recipients) > MAX_RECIPIENTS:

        return json_error(
            f"Maximum {MAX_RECIPIENTS} recipients allowed per batch."
        )

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

    # ----------------------------------------------
    # SEND EMAILS
    # ----------------------------------------------

    results = []

    try:

        # One recipient per message.
        # Recipients cannot see each other's addresses.

        for recipient in recipients:

            result = send_recipient(
                sender_email=sender_email,
                app_password=app_password,
                sender_name=sender_name,
                subject=subject,
                body=body,
                html_mode=html_mode,
                recipient=recipient
            )

            results.append(result)

    except Exception as exc:

        return jsonify({
            "error": "Batch processing failed.",
            "detail": str(exc)[:200],
            "results": results
        }), 502

    # ----------------------------------------------
    # FINAL COUNTS
    # ----------------------------------------------

    sent_count = sum(
        1
        for item in results
        if item["status"] == "sent"
    )

    failed_count = sum(
        1
        for item in results
        if item["status"] == "failed"
    )

    unknown_count = sum(
        1
        for item in results
        if item["status"] == "unknown"
    )

    return jsonify({

        "success": (
            failed_count == 0
            and unknown_count == 0
        ),

        "total": len(recipients),

        "accepted": sent_count,

        "failed": failed_count,

        "unknown": unknown_count,

        "results": results

    }), 200


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

    return json_error(
        "An internal server error occurred.",
        500
    )


# --------------------------------------------------
# VERCEL ENTRY POINT
# --------------------------------------------------

application = app
