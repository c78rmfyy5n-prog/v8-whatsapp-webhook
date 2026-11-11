#!/usr/bin/env python3
"""
WhatsApp Business Cloud API webhook receiver — starter kit for Chua's
GXS driver-payment tally.

What it does (and only this):
  * Answers Meta's webhook verification challenge (GET /webhook).
  * Receives new WhatsApp messages pushed by Meta (POST /webhook).
  * Optionally verifies the X-Hub-Signature-256 signature with the app secret.
  * Appends each message, untouched, to whatsapp_messages.jsonl next to
    this script: sender number, time, type, text/caption, media id, and
    any S$ amount found in the text.

What it does NOT do:
  * It never sends WhatsApp messages, never reads past chats (Meta does
    not offer that — only new messages arrive after the webhook is live),
    and it never marks a payment as confirmed. A WhatsApp message is
    only a "claimed paid" signal; a GXS email receipt is the proof that
    confirms it. Matching by driver + amount + rent week happens in
    the tally step, not here, so one payment is never double-counted.

Setup (see whatsapp_setup_guide.md for the full steps):
  1. Set environment variables, never paste them in chat:
       WHATSAPP_VERIFY_TOKEN   - a secret string you invent; must match
                                 the Verify Token you enter in Meta's
                                 app dashboard.
       WHATSAPP_APP_SECRET     - your Meta app secret (recommended;
                                 enables signature verification).
       PORT                    - optional, defaults to 3000.
  2. Run:  python3 whatsapp_webhook_server.py
  3. Expose it over public HTTPS, e.g. with Cloudflare Tunnel:
       cloudflared tunnel --url http://localhost:3000
     Then set the webhook callback URL in Meta's dashboard to:
       https://<your-tunnel-url>/webhook
     and subscribe to the "messages" field.

Python standard library only — no packages to install. Works on
Windows, macOS and Linux, so the desktop OS does not block starting.
"""

import hashlib
import hmac
import json
import os
import re
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

VERIFY_TOKEN = os.environ.get("WHATSAPP_VERIFY_TOKEN", "")
APP_SECRET = os.environ.get("WHATSAPP_APP_SECRET", "")
PORT = int(os.environ.get("PORT", "3000"))
STORE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "whatsapp_messages.jsonl")

# e.g. "S$420", "$420", "420" in a payment message — stored as a hint only.
AMOUNT_RE = re.compile(r"S?\$?\s*(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)")


def extract_amount(text):
    """Return the first plausible amount in text, or None. Hint only."""
    if not text:
        return None
    match = AMOUNT_RE.search(text)
    if not match:
        return None
    try:
        return float(match.group(1).replace(",", ""))
    except ValueError:
        return None


def append_record(record):
    with open(STORE_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def flatten_messages(payload):
    """Yield one flat record per incoming WhatsApp message."""
    for entry in payload.get("entry", []):
        for change in entry.get("changes", []):
            value = change.get("value", {})
            for msg in value.get("messages", []):
                msg_type = msg.get("type", "")
                text = ""
                media_id = None
                if msg_type == "text":
                    text = msg.get("text", {}).get("body", "")
                elif msg_type in ("image", "document"):
                    text = msg.get(msg_type, {}).get("caption", "")
                    media_id = msg.get(msg_type, {}).get("id")
                yield {
                    "received_at_utc": datetime.now(timezone.utc).isoformat(),
                    "from_number": msg.get("from"),
                    "message_id": msg.get("id"),
                    "whatsapp_timestamp": msg.get("timestamp"),
                    "type": msg_type,
                    "text": text,
                    "media_id": media_id,
                    "extracted_amount_hint_sgd": extract_amount(text),
                    # Classification is deliberately NOT done here:
                    # WhatsApp = claimed only; GXS email = confirmed.
                    "tally_status": "whatsapp_claimed_unmatched",
                }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # keep stdout clean
        pass

    def _send(self, code, body, content_type="text/plain"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send(200, "WhatsApp webhook receiver is running.\n")
            return
        if parsed.path == "/webhook":
            qs = parse_qs(parsed.query)
            mode = qs.get("hub.mode", [""])[0]
            token = qs.get("hub.verify_token", [""])[0]
            challenge = qs.get("hub.challenge", [""])[0]
            if mode == "subscribe" and VERIFY_TOKEN and token == VERIFY_TOKEN:
                self._send(200, challenge)
            else:
                self._send(403, "Verification failed: check WHATSAPP_VERIFY_TOKEN.\n")
            return
        self._send(404, "Not found.\n")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/webhook":
            self._send(404, "Not found.\n")
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length)
        if APP_SECRET:
            signature = self.headers.get("X-Hub-Signature-256", "")
            expected = "sha256=" + hmac.new(
                APP_SECRET.encode(), raw, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                self._send(403, "Bad signature.\n")
                return
        try:
            payload = json.loads(raw.decode("utf-8"))
        except ValueError:
            self._send(400, "Invalid JSON.\n")
            return
        count = 0
        for record in flatten_messages(payload):
            append_record(record)
            count += 1
        self._send(200, f"Stored {count} message(s).\n")


if __name__ == "__main__":
    if not VERIFY_TOKEN:
        print("WARNING: WHATSAPP_VERIFY_TOKEN is not set — "
              "Meta verification will fail until it is set.")
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Listening on port {PORT}. Webhook path: /webhook")
    print(f"Storing messages in: {STORE_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
