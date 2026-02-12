import argparse
import json
import os
import smtplib
import ssl
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


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


class SubscribeHandler(BaseHTTPRequestHandler):
    server_version = "ZeroVirusSubscribe/1.0"

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/subscribe":
            self.send_error(404, "Not Found")
            return

        token_required = getattr(self.server, "token", "")
        if token_required:
            token = self.headers.get("X-Auth-Token", "")
            if not token:
                qs = parse_qs(parsed.query or "")
                token = (qs.get("token") or [""])[0]
            if token != token_required:
                self.send_error(403, "Forbidden")
                return

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
            return

        email = str(payload.get("email", "")).strip()
        if "@" not in email or "." not in email:
            self.send_error(400, "Invalid email")
            return

        store: Path = getattr(self.server, "store")
        emails = load_subscribers(store)
        if email not in emails:
            emails.append(email)
            save_subscribers(store, emails)

        welcome_sent = False
        smtp_config = getattr(self.server, "smtp_config", None)
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

        response = json.dumps(
            {"status": "ok", "email": email, "welcome_sent": welcome_sent}
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format: str, *args) -> None:
        return


def main() -> None:
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

    server = HTTPServer((args.host, args.port), SubscribeHandler)
    server.store = store
    server.token = args.token
    if args.smtp_host and args.smtp_user and args.smtp_pass and args.from_email:
        server.smtp_config = {
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
        server.smtp_config = None
    print(f"Subscriber server listening on http://{args.host}:{args.port}/subscribe")
    if args.token:
        print("Token auth enabled.")
    server.serve_forever()


if __name__ == "__main__":
    main()
