import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def create_email_body(vulnerability):
    """Create the email body using the HTML template."""

    with open("email_template.html", "r", encoding="utf-8") as file:
        template = file.read()

    for key, value in vulnerability.items():
        template = template.replace(
            "{{ " + key + " }}",
            str(value) if value else "- NA -"
        )

    return template


def send_email_alert(vulnerability):
    """Send Critical and High vulnerability alerts by email."""

    severity = vulnerability.get("severity", "- NA -")

    # Send alerts only for Critical and High vulnerabilities
    if severity not in ["Critical", "High"]:
        print(f"[EMAIL SKIPPED] Severity '{severity}' is not Critical or High.")
        return

    # Read email settings from environment variables.
    # If SMTP settings are not configured, use safe demo mode.
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    sender_email = os.getenv("SENDER_EMAIL")
    sender_password = os.getenv("SENDER_PASSWORD")
    receiver_email = os.getenv("RECEIVER_EMAIL")

    # Safe demonstration mode
    if not all([
        smtp_server,
        sender_email,
        sender_password,
        receiver_email
    ]):
        print("[EMAIL DEMO] SMTP credentials are not configured.")
        print("[EMAIL DEMO] Security alert report generated successfully.")
        print(f"[EMAIL DEMO] Recipient: Project Security Team")
        print(f"[EMAIL DEMO] Subject: {severity} OEM Vulnerability Alert")
        print("[EMAIL DEMO] Report contains the complete vulnerability details.")
        return
    

    subject = f"[{severity}] OEM Vulnerability Alert - {vulnerability.get('unique_id', '- NA -')}"

    html_body = create_email_body(vulnerability)

    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = sender_email
    message["To"] = receiver_email

    message.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(
                sender_email,
                receiver_email,
                message.as_string()
            )

        print("[EMAIL SENT] Vulnerability alert sent successfully.")

    except Exception as error:
        print(f"[EMAIL ERROR] Could not send email: {error}")


if __name__ == "__main__":
    test_vulnerability = {
        "name": "Chrome",
        "version": "120.0",
        "oem": "- NA -",
        "severity": "Critical",
        "description": "A security vulnerability was found in Chrome.",
        "mitigation": "Update Chrome to the latest version.",
        "patch_url": "https://example.com/patch",
        "published_date": "2023-11-15",
        "unique_id": "CVE-2023-47131",
        "source_url": "https://example.com/advisory"
    }

    send_email_alert(test_vulnerability)