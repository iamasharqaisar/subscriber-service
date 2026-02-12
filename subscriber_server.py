import argparse
import json
import os
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path

from flask import Flask, jsonify, request


def load_subscribers(path: Path) -> list:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    if isinstance(data, list):
        return data
    return []


def save_subscribers(path: Path, emails: list) -> None:
    path.write_text(json.dumps(sorted(set(emails)), indent=2), encoding="utf-8")


def send_welcome_email(
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_pass: str,
    sender: str,
    recipient: str,
    subject: str,
    body: str,
) -> None:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.starttls(context=context)
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)


app = Flask("ZeroVirusSubscribe")
STORE_PATH: Path = Path("subscribers.json")
TOKEN_REQUIRED = ""
SMTP_CONFIG = None


@app.post("/subscribe")
def subscribe() -> tuple:
    token_required = TOKEN_REQUIRED
    if token_required:
        token = request.headers.get("X-Auth-Token", "")
        if not token:
            token = request.args.get("token", "")
        if token != token_required:
            return jsonify({"status": "error", "error": "forbidden"}), 403

    payload = request.get_json(silent=True) or {}
    email = str(payload.get("email", "")).strip()
    if "@" not in email or "." not in email:
        return jsonify({"status": "error", "error": "invalid email"}), 400

    emails = load_subscribers(STORE_PATH)
    if email not in emails:
        emails.append(email)
        save_subscribers(STORE_PATH, emails)

    welcome_sent = False
    smtp_config = SMTP_CONFIG
    if smtp_config:
        try:
            send_welcome_email(
                smtp_host=smtp_config["host"],
                smtp_port=smtp_config["port"],
                smtp_user=smtp_config["user"],
                smtp_pass=smtp_config["pass"],
                sender=smtp_config["from"],
                recipient=email,
                subject=smtp_config["subject"],
                body=smtp_config["body"],
            )
            welcome_sent = True
        except Exception:
            welcome_sent = False

    return jsonify({"status": "ok", "email": email, "welcome_sent": welcome_sent}), 200


def main() -> None:
    global STORE_PATH, TOKEN_REQUIRED, SMTP_CONFIG
    parser = argparse.ArgumentParser(description="ZeroVirus subscriber server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host")
    parser.add_argument("--port", type=int, default=8787, help="Bind port")
    parser.add_argument(
        "--store",
        default="subscribers.json",
        help="Path to subscribers JSON file",
    )
    parser.add_argument(
        "--token",
        default="",
        help="Optional auth token (client sends X-Auth-Token header)",
    )
    parser.add_argument(
        "--smtp-host",
        default=os.getenv("ZV_SMTP_HOST", "smtp.gmail.com"),
        help="SMTP host",
    )
    parser.add_argument(
        "--smtp-port",
        type=int,
        default=int(os.getenv("ZV_SMTP_PORT", "587")),
        help="SMTP port",
    )
    parser.add_argument(
        "--smtp-user",
        default=os.getenv("ZV_SMTP_USER") or os.getenv("ZV_GMAIL_USER", ""),
        help="SMTP username",
    )
    parser.add_argument(
        "--smtp-pass",
        default=os.getenv("ZV_SMTP_PASS") or os.getenv("GMAIL_APP_PASSWORD", ""),
        help="SMTP password/app password",
    )
    parser.add_argument(
        "--from-email",
        default=os.getenv("ZV_SMTP_FROM") or os.getenv("ZV_GMAIL_USER", ""),
        help="From email address (e.g. viruseszero@gmail.com)",
    )
    parser.add_argument(
        "--welcome-subject",
        default="Welcome to ZeroVirus Updates",
        help="Subject for the welcome email",
    )
    parser.add_argument(
        "--welcome-body",
        default=(
            "Hi,\n\nThanks for subscribing to ZeroVirus updates.\n"
            "ZeroVirus provides on-demand and scheduled scanning to help keep your PC safe.\n"
            "You will receive release notifications when new versions are published.\n\n"
            "— ZeroVirus Team"
        ),
        help="Body text for the welcome email",
    )
    args = parser.parse_args()

    store = Path(args.store).resolve()
    store.parent.mkdir(parents=True, exist_ok=True)

    STORE_PATH = store
    TOKEN_REQUIRED = args.token
    if args.smtp_host and args.smtp_user and args.smtp_pass and args.from_email:
        SMTP_CONFIG = {
            "host": args.smtp_host,
            "port": args.smtp_port,
            "user": args.smtp_user,
            "pass": args.smtp_pass,
            "from": args.from_email,
            "subject": args.welcome_subject,
            "body": args.welcome_body,
        }
        print("SMTP welcome email enabled.")
    else:
        SMTP_CONFIG = None
    print(f"Subscriber server listening on http://{args.host}:{args.port}/subscribe")
    if args.token:
        print("Token auth enabled.")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8787)))


if __name__ == "__main__":
    main()
