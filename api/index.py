
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
from email.utils import formataddr, parseaddr, make_msgid, formatdate
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
# APPLICATION CONFIGURATION
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
# SMTP CONFIGURATION
# --------------------------------------------------

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465

MAX_RECIPIENTS = 25
MAX_WORKERS = 2
MAX_RETRIES = 2
SMTP_TIMEOUT = 25

RETRY_DELAY = 2


# --------------------------------------------------
# RESPONSE HELPERS
# --------------------------------------------------

def json_error(message, status=400):
    return jsonify({
        "success": False,
        "error": message
    }), status


# --------------------------------------------------
# EMAIL VALIDATION
# --------------------------------------------------

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

def expand_spintax(content):

    pattern = re.compile(r"\{([^{}]+)\}")

    while pattern.search(content):

        content = pattern.sub(
            lambda match: random.choice(
                match.group(1).split("|")
            ),
            content
        )

    return content


# --------------------------------------------------
# HTML TO TEXT
# --------------------------------------------------

def html_to_plain_text(content):

    content = re.sub(
        r"(?i)<br\s*/?>",
        "\n",
        content
    )

    content = re.sub(
        r"(?i)</(p|div|tr|li|h[1-6])>",
        "\n",
        content
    )

    content = re.sub(
        r"<[^>]+>",
        "",
        content
    )

    content = unescape(content)

    content = re.sub(
        r"\n{3,}",
        "\n\n",
        content
    )

    return content.strip()


# --------------------------------------------------
# PERSONALIZATION
# --------------------------------------------------

def get_display_name(recipient):

    local = recipient.split("@", 1)[0]

    name = re.sub(
        r"[._-]+",
        " ",
        local
    ).strip()

    return name.title() or local


def personalize_content(content, recipient):

    local = recipient.split("@", 1)[0]

    name = get_display_name(recipient)

    return (
        content
        .replace("{{name}}", name)
        .replace("{{username}}", local)
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

    personalized_body = personalize_content(
        expand_spintax(body),
        recipient
    )

    personalized_subject = expand_spintax(subject)

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

    message = EmailMessage()

    message["Subject"] = clean_subject

    message["From"] = (
        formataddr(
            (clean_sender_name, sender_email)
        )
        if clean_sender_name
        else sender_email
    )

    # One individual recipient per message.
    message["To"] = recipient

    message["Reply-To"] = sender_email
    message["Date"] = formatdate(localtime=True)

    message["Message-ID"] = make_msgid(
        domain=sender_email.split("@", 1)[1]
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

    smtp.login(
        sender_email,
        app_password
    )

    return smtp


# --------------------------------------------------
# INDIVIDUAL EMAIL SENDER
# --------------------------------------------------

def send_single_email(
    smtp,
    sender_email,
    sender_name,
    recipient,
    subject,
    body,
    html_mode
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

        return {
            "status": "failed",
            "email": recipient,
            "detail": "Recipient refused by Gmail."
        }

    return {
        "status": "sent",
        "email": recipient,
        "detail": "Accepted by Gmail"
    }


# --------------------------------------------------
# SINGLE CONNECTION WORKER
# --------------------------------------------------

def send_recipient_group(
    recipients,
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

        for recipient in recipients:

            sent = False
            last_error = "Unknown SMTP error"

            for attempt in range(MAX_RETRIES):

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
                        recipient=recipient,
                        subject=subject,
                        body=body,
                        html_mode=html_mode
                    )

                    results.append(result)

                    sent = result["status"] == "sent"

                    break

                except smtplib.SMTPAuthenticationError:

                    last_error = (
                        "Gmail authentication failed. "
                        "Check your Google App Password."
                    )

                    if smtp:

                        try:
                            smtp.quit()
                        except Exception:
                            pass

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

                    if not 400 <= code < 500:
                        break

                    if smtp:

                        try:
                            smtp.quit()
                        except Exception:
                            pass

                    smtp = None

                except (
                    smtplib.SMTPServerDisconnected,
                    ConnectionError,
                    TimeoutError,
                    OSError
                ) as exc:

                    last_error = str(exc)[:200]

                    if smtp:

                        try:
                            smtp.close()
                        except Exception:
                            pass

                    smtp = None

                except Exception as exc:

                    last_error = str(exc)[:200]
                    break

                if attempt < MAX_RETRIES - 1:

                    time.sleep(
                        RETRY_DELAY + random.uniform(0, 1)
                    )

            if not sent:

                if not results or results[-1].get("email") != recipient:

                    results.append({
                        "status": "failed",
                        "email": recipient,
                        "detail": last_error
                    })

    except smtplib.SMTPAuthenticationError:

        results.extend([
            {
                "status": "failed",
                "email": recipient,
                "detail": "Gmail authentication failed."
            }
            for recipient in recipients
        ])

    except Exception as exc:

        results.extend([
            {
                "status": "failed",
                "email": recipient,
                "detail": f"SMTP connection failed: {str(exc)[:150]}"
            }
            for recipient in recipients
        ])

    finally:

        if smtp:

            try:
                smtp.quit()
            except Exception:
                pass

    return results


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

    return redirect(url_for("home"))


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout", methods=["GET", "POST"])
def logout():

    session.clear()

    return redirect(url_for("login"))


# --------------------------------------------------
# BATCH API
# Each recipient receives an individual message.
# --------------------------------------------------

@app.post("/send-batch")
def send_batch():

    if not session.get("logged_in"):

        return json_error(
            "Your session has expired. Please sign in again.",
            401
        )

    data = request.get_json(silent=True)

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

    # Sender validation.

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

    # Clean and deduplicate recipients.

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
            f"Maximum {MAX_RECIPIENTS} recipients allowed per request."
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

    # Split recipients into small worker groups.
    # Every message is sent individually.

    worker_count = min(
        MAX_WORKERS,
        len(recipients)
    )

    groups = [
        recipients[index::worker_count]
        for index in range(worker_count)
    ]

    results = []

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

                for group in groups
            ]

            for future in as_completed(futures):

                try:

                    results.extend(
                        future.result()
                    )

                except Exception as exc:

                    results.append({
                        "status": "failed",
                        "email": "",
                        "detail": str(exc)[:200]
                    })

    except Exception as exc:

        return jsonify({
            "success": False,
            "error": "Email processing failed.",
            "detail": str(exc)[:200],
            "results": results
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
        "smtp": SMTP_HOST,
        "individual_delivery": True
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

    return json_error(
        "An internal server error occurred.",
        500
    )


# --------------------------------------------------
# VERCEL ENTRY POINT
# --------------------------------------------------

application = app
