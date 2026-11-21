
import os
import re
import hmac
import ssl
import smtplib
import time
import unicodedata

from pathlib import Path
from html import unescape
from concurrent.futures import ThreadPoolExecutor, as_completed
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

MAX_RECIPIENTS = 25
MAX_WORKERS = 3
MAX_RETRIES = 2
SMTP_TIMEOUT = 25


# --------------------------------------------------
# RESPONSE HELPERS
# --------------------------------------------------

def json_error(message, status=400):
    return jsonify({"error": message}), status


# --------------------------------------------------
# INPUT CLEANING
# --------------------------------------------------

def clean_email(value):
    if not isinstance(value, str):
        return ""

    value = unicodedata.normalize("NFKC", value)

    value = "".join(
        ch for ch in value
        if ch.isprintable()
        and not unicodedata.category(ch).startswith("C")
    )

    return value.replace("\xa0", "").replace(" ", "").strip()


def valid_email(value):
    value = clean_email(value)

    if not value or len(value) > 254:
        return False

    _, address = parseaddr(value)

    if address != value or address.count("@") != 1:
        return False

    local, domain = address.rsplit("@", 1)

    if not local or not domain:
        return False

    if len(local) > 64:
        return False

    if ".." in address:
        return False

    if domain.startswith(".") or domain.endswith("."):
        return False

    if "." not in domain:
        return False

    if not re.fullmatch(
        r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+",
        local
    ):
        return False

    if not re.fullmatch(
        r"[A-Za-z0-9.-]+",
        domain
    ):
        return False

    return True


def recipient_address(item):
    if isinstance(item, str):
        return clean_email(item)

    if isinstance(item, dict):
        return clean_email(str(item.get("email", "")))

    return ""


def clean_header(value, maximum=998):
    value = str(value or "")

    value = re.sub(r"[\r\n]+", " ", value)

    return value.strip()[:maximum]


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

def personalize_body(body, recipient):

    local_part = recipient.split("@", 1)[0]

    display_name = re.sub(
        r"[._-]+",
        " ",
        local_part
    ).strip().title() or local_part

    return (
        body.replace("{{name}}", display_name)
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

    personalized_body = personalize_body(
        body,
        recipient
    )

    message = EmailMessage()

    clean_sender_name = clean_header(
        sender_name,
        100
    )

    clean_subject = clean_header(
        subject,
        998
    )

    message["Subject"] = clean_subject

    message["From"] = (
        formataddr((clean_sender_name, sender_email))
        if clean_sender_name
        else sender_email
    )

    message["To"] = recipient
    message["Reply-To"] = sender_email
    message["Date"] = formatdate(localtime=True)

    sender_domain = sender_email.split("@", 1)[1]

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
            smtp.close()
        except Exception:
            pass

        raise


# --------------------------------------------------
# SMTP CONNECTION RETRY
# --------------------------------------------------

def connect_with_retry(
    sender_email,
    app_password
):

    last_error = "SMTP connection failed."

    for attempt in range(MAX_RETRIES):

        try:

            return create_smtp_connection(
                sender_email,
                app_password
            )

        except smtplib.SMTPAuthenticationError:

            raise

        except Exception as exc:

            last_error = str(exc)[:200]

            if attempt < MAX_RETRIES - 1:
                time.sleep(2)

    raise ConnectionError(last_error)


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

    smtp.send_message(message)

    return {
        "status": "sent",
        "email": recipient,
        "detail": "Accepted by Gmail"
    }


# --------------------------------------------------
# LOGIN PAGE
# --------------------------------------------------

@app.get("/")
def home():

    if not session.get("logged_in"):
        return redirect(url_for("login"))

    return render_template("index.html")


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

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
# SEND RECIPIENT GROUP
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

    group_results = []
    smtp = None

    for recipient in group:

        # Connect or reconnect before sending.

        if smtp is None:

            try:

                smtp = connect_with_retry(
                    sender_email,
                    app_password
                )

            except smtplib.SMTPAuthenticationError:

                group_results.append({
                    "status": "failed",
                    "email": recipient,
                    "detail": "Gmail authentication failed. Check your App Password."
                })

                for remaining in group[
                    group.index(recipient) + 1:
                ]:

                    group_results.append({
                        "status": "failed",
                        "email": remaining,
                        "detail": "Gmail authentication failed."
                    })

                break

            except Exception as exc:

                group_results.append({
                    "status": "failed",
                    "email": recipient,
                    "detail": f"SMTP connection failed: {str(exc)[:180]}"
                })

                continue

        try:

            result = send_single_email(
                smtp=smtp,
                sender_email=sender_email,
                sender_name=sender_name,
                subject=subject,
                body=body,
                html_mode=html_mode,
                recipient=recipient
            )

            group_results.append(result)

        except smtplib.SMTPRecipientsRefused:

            group_results.append({
                "status": "failed",
                "email": recipient,
                "detail": "Gmail refused this recipient address."
            })

        except smtplib.SMTPDataError as exc:

            code = getattr(exc, "smtp_code", 0)

            group_results.append({
                "status": "failed",
                "email": recipient,
                "detail": f"Gmail SMTP rejected the message ({code}): {str(exc)[:150]}"
            })

            # A rejected message can be retried safely only
            # after an explicit temporary SMTP rejection.
            # This implementation reports it instead of
            # risking duplicate delivery.

        except (
            smtplib.SMTPServerDisconnected,
            ConnectionError,
            TimeoutError,
            OSError
        ) as exc:

            group_results.append({
                "status": "failed",
                "email": recipient,
                "detail": (
                    "Connection interrupted; delivery status may be uncertain. "
                    "Check Gmail Sent before retrying. "
                    + str(exc)[:120]
                )
            })

            if smtp:

                try:
                    smtp.close()
                except Exception:
                    pass

            smtp = None

        except smtplib.SMTPException as exc:

            group_results.append({
                "status": "failed",
                "email": recipient,
                "detail": f"SMTP error: {str(exc)[:180]}"
            })

            if smtp:

                try:
                    smtp.close()
                except Exception:
                    pass

            smtp = None

        except Exception as exc:

            group_results.append({
                "status": "failed",
                "email": recipient,
                "detail": f"Sending error: {str(exc)[:180]}"
            })

    if smtp:

        try:
            smtp.quit()
        except Exception:
            pass

    return group_results


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

    data = request.get_json(silent=True)

    if not isinstance(data, dict):

        return json_error(
            "A valid JSON request body is required."
        )

    # Sender email

    sender_email = clean_email(
        str(
            data.get("senderEmail")
            or data.get("gmail")
            or ""
        ).lower()
    )

    # Gmail App Password

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

    # Sender validation

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
            "Please enter a valid Google App Password."
        )

    # Subject validation

    if not subject or len(subject) > 998:

        return json_error(
            "Please enter a valid email subject."
        )

    if "\r" in subject or "\n" in subject:

        return json_error(
            "Invalid email subject."
        )

    # Body validation

    if not body.strip():

        return json_error(
            "Email message body is required."
        )

    # Consent validation

    if not consent:

        return json_error(
            "Please confirm that all recipients have consented to receive your email."
        )

    # Recipient validation

    if not isinstance(raw_recipients, list):

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

    # --------------------------------------------------
    # GROUP PROCESSING
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

                    results.append({
                        "status": "failed",
                        "email": "",
                        "detail": f"Worker execution failed: {str(exc)[:180]}"
                    })

    except Exception as exc:

        return jsonify({
            "error": "Batch processing failed.",
            "detail": str(exc)[:200],
            "results": results
        }), 502

    # --------------------------------------------------
    # RESULT ORDER
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
