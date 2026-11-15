#!/usr/bin/env python3
"""
WhatsApp Business Cloud API webhook receiver + inbox — v2 for V8 Car Rentals.

v2 = v1 (webhook receive + store) PLUS:
  * GET  /inbox        — mobile-friendly HTML inbox, messages grouped by
                          sender/recipient number, newest first, with a
                          reply box per conversation.
  * GET  /api/messages — JSON list of stored messages, newest first.
  * POST /send         — JSON {"to": "<e164 without +>", "text": "..."}
                          sends a WhatsApp text via the Graph API and
                          stores the outgoing message (direction="out").

v1 behaviour preserved exactly: GET /webhook verification challenge,
X-Hub-Signature-256 check (when WHATSAPP_APP_SECRET is set), the same
flattening of entry[].changes[].value.messages[], and the same record
fields (plus one added field, direction="in"/"out"). Stdlib only.

====================================================================
PERMANENT STORAGE — READ THIS BEFORE DEPLOYING
====================================================================
Problem: v1 appends to whatsapp_messages.jsonl next to the script.
On Render that file lives on the service's ephemeral filesystem and is
LOST on every redeploy / restart. The inbox would then show nothing.

Chosen solution (a) — Google Sheets via a Google Apps Script bridge.
Evaluated:
  (a) Apps Script bridge -> Google Sheet: FREE, permanent (the sheet
      lives in the user's Google Drive, independent of Render), the
      user can open/search it any time, and it ties into the existing
      GXS tally work which already lives in Google Sheets. The Render
      server only needs stdlib urllib to POST to it. CHOSEN.
  (b) Render persistent disk: survives restarts, but costs
      US$0.25/GB/month, needs dashboard configuration, and is still
      lost if the Render service is ever deleted. Not truly permanent.
  (c) Free hosted Postgres (Render free tier expires after 90 days;
      Supabase/Neon need a non-stdlib driver and a separate signup):
      more moving parts than (a), and the user gains nothing the
      Sheet does not already give.

How it works in this file:
  * Every incoming AND outgoing message is ALWAYS appended to the
    local whatsapp_messages.jsonl first (graceful fallback — the
    webhook never fails because the permanent store is down).
  * It is then also POSTed (5s timeout, fire-and-forget) to the
    Apps Script web-app URL in env SHEETS_BRIDGE_URL. If the bridge
    is unreachable, the message stays in the local file only and an
    error is written to stderr; nothing is lost locally and the
    webhook still returns 200 to Meta.
  * GET /api/messages and GET /inbox read the permanent store first
    when SHEETS_BRIDGE_URL is set (the script's doGet returns the
    sheet rows as JSON), falling back to the local jsonl file when
    the bridge is unreachable. So the inbox still shows history
    after a Render restart, as long as the bridge is up.

Setup the user must do (nothing is invented here — no sheet ID, URL
or secret is hard-coded):
  1. In Google Drive, create a spreadsheet, e.g. named
     "V8 WhatsApp Messages". Note its ID from the URL (the long
     string between /d/ and /edit). Keep the ID out of chat/code;
     it goes into the Apps Script below, not into this server.
  2. In that spreadsheet, open Extensions > Apps Script and paste
     a script with:
       - doPost(e): parse e.postData.contents as JSON, append one
         row to the first sheet with columns:
           received_at_utc | direction | from_number | to_number |
           message_id | type | text | media_id |
           extracted_amount_hint_sgd | tally_status
         Return ContentService JSON {"ok": true}.
       - doGet(e): read all rows of the first sheet (skip the header)
         and return them as JSON {"messages": [ {same fields}, ... ]}.
       - Optional: if e.parameter.secret (or a header) does not match
         a secret you choose, return {"error": "forbidden"}.
     Deploy it as a Web app: Execute as "Me", access "Anyone"
     (the secret below is what keeps it private, not the URL).
  3. Copy the deployed web-app URL (ends in /exec) into Render as
     env var SHEETS_BRIDGE_URL.
  4. If you set a secret in the script, copy the same value into
     Render as env var SHEETS_BRIDGE_SECRET.
  5. If the bridge is never configured, v2 behaves exactly like v1
     (local jsonl only) — the inbox works, but history is still
     lost on a Render restart. That is the documented fallback, not
     a silent failure.

Other env vars (all set in Render, never in code/chat):
  WHATSAPP_VERIFY_TOKEN    - as in v1; must match Meta's Verify Token.
  WHATSAPP_APP_SECRET      - as in v1 (recommended; signature check).
  WHATSAPP_ACCESS_TOKEN    - permanent System User token for sending.
                             Required only for POST /send.
  WHATSAPP_PHONE_NUMBER_ID - 1368475013023383 for +65 97250880.
                             Required only for POST /send.
  WHATSAPP_BUSINESS_NUMBER - e.g. 6597250880; used as the sender on
                             outgoing records. Defaults to 6597250880.
  INBOX_TOKEN              - optional. If set, /inbox, /api/messages
                             and /send require it as ?token=... or as
                             an "Authorization: Bearer <token>" header.
                             Strongly recommended in production: without
                             it, anyone who guesses the Render URL can
                             read messages and send as the business.
  SHEETS_BRIDGE_URL        - Apps Script web-app URL (see above).
  SHEETS_BRIDGE_SECRET     - optional shared secret for the bridge.
  PORT                     - optional, defaults to 3000 (Render sets
                             its own PORT; the server reads it).

Python standard library only.
"""

import hashlib
import hmac
import html
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

VERIFY_TOKEN = os.environ.get("WHATSAPP_VERIFY_TOKEN", "")
APP_SECRET = os.environ.get("WHATSAPP_APP_SECRET", "")
ACCESS_TOKEN = os.environ.get("WHATSAPP_ACCESS_TOKEN", "")
PHONE_NUMBER_ID = os.environ.get("WHATSAPP_PHONE_NUMBER_ID", "")
BUSINESS_NUMBER = os.environ.get("WHATSAPP_BUSINESS_NUMBER", "6597250880")
INBOX_TOKEN = os.environ.get("INBOX_TOKEN", "")
BRIDGE_URL = os.environ.get("SHEETS_BRIDGE_URL", "")
BRIDGE_SECRET = os.environ.get("SHEETS_BRIDGE_SECRET", "")
PORT = int(os.environ.get("PORT", "3000"))
GRAPH_VERSION = "v27.0"
STORE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "whatsapp_messages.jsonl")

# e.g. "S$420", "$420", "420" in a payment message — stored as a hint only.
AMOUNT_RE = re.compile(r"S?\$?\s*(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)")


def _log_error(msg):
    """Errors only — the server stays quiet per request, as in v1."""
    sys.stderr.write("whatsapp_webhook_server_v2: %s\n" % msg)
    sys.stderr.flush()


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
    """Local store first — this must never fail the webhook."""
    with open(STORE_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def bridge_store(record):
    """Best-effort permanent store via the Apps Script bridge.

    Returns True on success, False otherwise. Never raises.
    """
    if not BRIDGE_URL:
        return False
    try:
        data = json.dumps(record, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(BRIDGE_URL, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        if BRIDGE_SECRET:
            req.add_header("X-Bridge-Secret", BRIDGE_SECRET)
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
        return True
    except Exception as exc:  # bridge down / bad URL / timeout: local only
        _log_error("bridge store failed (%s); kept local copy only" % exc)
        return False


def store_record(record):
    """Local jsonl always; permanent bridge best-effort on top."""
    append_record(record)
    bridge_store(record)


def read_local_records():
    records = []
    try:
        with open(STORE_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except ValueError:
                    continue
    except FileNotFoundError:
        pass
    except OSError as exc:
        _log_error("reading local store failed: %s" % exc)
    return records


def read_bridge_records():
    """Fetch the permanent record from the Apps Script bridge (doGet).

    Returns a list, or None if the bridge is not configured/unreachable.
    """
    if not BRIDGE_URL:
        return None
    try:
        url = BRIDGE_URL
        if BRIDGE_SECRET:
            sep = "&" if "?" in url else "?"
            url = url + sep + "secret=" + BRIDGE_SECRET
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        messages = payload.get("messages")
        if not isinstance(messages, list):
            return None
        # Sheets returns phone numbers as JSON numbers, not strings.
        # html.escape() and the inbox grouping need strings, so coerce
        # the fields the inbox uses. (Found live 12 Nov: /inbox 502'd
        # because from_number arrived as int 6588198484.)
        for msg in messages:
            if isinstance(msg, dict):
                for key in ("from_number", "to_number", "message_id",
                            "type", "text", "media_id", "tally_status",
                            "received_at_utc", "whatsapp_timestamp"):
                    if key in msg and msg[key] is not None:
                        msg[key] = str(msg[key])
                if "extracted_amount_hint_sgd" in msg \
                        and msg["extracted_amount_hint_sgd"] == "":
                    msg["extracted_amount_hint_sgd"] = None
        return messages
    except Exception as exc:
        _log_error("bridge read failed (%s); falling back to local file" % exc)
        return None


def read_records():
    """Permanent store first (survives Render restarts), local fallback."""
    bridged = read_bridge_records()
    if bridged is not None:
        return bridged
    return read_local_records()


def flatten_messages(payload):
    """Yield one flat record per incoming WhatsApp message (v1 behaviour,
    plus direction="in")."""
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
                    "direction": "in",
                    "from_number": msg.get("from"),
                    "to_number": BUSINESS_NUMBER,
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


def send_whatsapp_text(to_number, text):
    """Send one text via the Graph API. Returns (status_code, payload)."""
    url = "https://graph.facebook.com/%s/%s/messages" % (
        GRAPH_VERSION, PHONE_NUMBER_ID)
    body = json.dumps({
        "messaging_product": "whatsapp",
        "recipient_type": "individual",
        "to": to_number,
        "type": "text",
        "text": {"preview_url": False, "body": text},
    }).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", "Bearer " + ACCESS_TOKEN)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8"))
        except Exception:
            payload = {"error": {"message": "Graph API HTTP %s" % exc.code}}
        return exc.code, payload
    except Exception as exc:
        return 502, {"error": {"message": "send failed: %s" % exc}}


def _counterpart(record):
    """The other party in a conversation: sender for inbound, recipient
    for outbound."""
    if record.get("direction") == "out":
        return str(record.get("to_number") or "")
    return str(record.get("from_number") or "")


def render_inbox(records):
    """Simple mobile-friendly inbox HTML, grouped by counterpart."""
    groups = {}
    for rec in records:
        groups.setdefault(_counterpart(rec), []).append(rec)
    # Newest conversation first (by its latest message).
    ordered = sorted(
        groups.items(),
        key=lambda kv: max((r.get("received_at_utc") or "" for r in kv[1]),
                           default=""),
        reverse=True)
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>V8 Car Rentals — WhatsApp Inbox</title>"
        "<style>body{font-family:system-ui,sans-serif;margin:16px;max-width:720px}"
        ".conv{border:1px solid #ccc;border-radius:8px;padding:12px;margin:12px 0}"
        ".msg{margin:6px 0}.in{color:#111}.out{color:#0a5;text-align:right}"
        "form{display:flex;gap:6px;margin-top:8px}"
        "input[type=text]{flex:1;padding:8px}button{padding:8px 12px}"
        "small{color:#666}</style></head><body>"
        "<h1>V8 Car Rentals — WhatsApp Inbox</h1>"
        "<p><small>Messages are stored permanently in Google Sheets "
        "(via the bridge) and locally as a fallback. Replying sends "
        "from +65 9725 0880.</small></p>",
    ]
    if not ordered:
        parts.append("<p>No messages yet.</p>")
    for number, msgs in ordered:
        msgs_sorted = sorted(msgs, key=lambda r: r.get("received_at_utc") or "")
        parts.append("<div class='conv'><h2>%s</h2>" % html.escape(number or "?"))
        for rec in msgs_sorted:
            cls = "out" if rec.get("direction") == "out" else "in"
            who = "You" if cls == "out" else html.escape(number or "?")
            parts.append(
                "<div class='msg %s'><b>%s</b> "
                "<small>%s</small><br>%s</div>" % (
                    cls, who,
                    html.escape(str(rec.get("received_at_utc") or "")),
                    html.escape(str(rec.get("text") or ""))))
        parts.append(
            "<form method='post' action='/send' data-to='%s'>"
            "<input type='text' name='text' placeholder='Reply…' required>"
            "<button type='submit'>Send</button></form>"
            "<script>document.querySelectorAll('form[data-to]').forEach(f=>{"
            "f.addEventListener('submit',async e=>{e.preventDefault();"
            "const t=f.querySelector('input').value;"
            "const tk=new URLSearchParams(location.search).get('token')||'';"
            "const r=await fetch('/send'+(tk?'?token='+encodeURIComponent(tk):''),{method:'POST',"
            "headers:{'Content-Type':'application/json'},"
            "body:JSON.stringify({to:f.dataset.to,text:t})});"
            "if(r.ok){location.reload()}else{alert('Send failed: '+await r.text())}})"
            "})</script>" % html.escape(number or ""))
        parts.append("</div>")
    parts.append("</body></html>")
    return "".join(parts)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # keep stdout clean
        pass

    def _send(self, code, body, content_type="text/plain"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, code, payload):
        self._send(code, json.dumps(payload, ensure_ascii=False),
                   "application/json")

    def _inbox_authorised(self, parsed):
        if not INBOX_TOKEN:
            return True
        qs = parse_qs(parsed.query)
        if qs.get("token", [""])[0] == INBOX_TOKEN:
            return True
        auth = self.headers.get("Authorization", "")
        return auth == "Bearer " + INBOX_TOKEN

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
        if parsed.path in ("/inbox", "/api/messages"):
            if not self._inbox_authorised(parsed):
                self._send(403, "Forbidden: inbox token required.\n")
                return
            records = read_records()
            records = sorted(records,
                             key=lambda r: r.get("received_at_utc") or "",
                             reverse=True)
            if parsed.path == "/api/messages":
                self._send_json(200, {"messages": records})
            else:
                self._send(200, render_inbox(records), "text/html")
            return
        self._send(404, "Not found.\n")

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length)
        content_type = self.headers.get("Content-Type", "")
        if "application/json" in content_type:
            return json.loads(raw.decode("utf-8"))
        # HTML form posts from the inbox page fall back to urlencoded.
        return {k: v[0] for k, v in parse_qs(raw.decode("utf-8")).items()}

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/send":
            if not self._inbox_authorised(parsed):
                self._send_json(403, {"error": "forbidden: inbox token required"})
                return
            if not ACCESS_TOKEN or not PHONE_NUMBER_ID:
                self._send_json(
                    500, {"error": "WHATSAPP_ACCESS_TOKEN and "
                                   "WHATSAPP_PHONE_NUMBER_ID are not set"})
                return
            try:
                data = self._read_json_body()
            except ValueError:
                self._send_json(400, {"error": "invalid JSON body"})
                return
            to_number = str(data.get("to", "")).strip().lstrip("+")
            text = str(data.get("text", "")).strip()
            if not to_number or not text:
                self._send_json(400, {"error": "both 'to' and 'text' are required"})
                return
            status, payload = send_whatsapp_text(to_number, text)
            if status != 200:
                _log_error("Graph API send failed: %s" % payload)
                self._send_json(status, payload)
                return
            meta_id = ""
            try:
                meta_id = payload.get("messages", [{}])[0].get("id", "")
            except Exception:
                meta_id = ""
            record = {
                "received_at_utc": datetime.now(timezone.utc).isoformat(),
                "direction": "out",
                "from_number": BUSINESS_NUMBER,
                "to_number": to_number,
                "message_id": meta_id,
                "whatsapp_timestamp": str(int(datetime.now(timezone.utc).timestamp())),
                "type": "text",
                "text": text,
                "media_id": None,
                "extracted_amount_hint_sgd": extract_amount(text),
                "tally_status": "whatsapp_claimed_unmatched",
            }
            store_record(record)
            self._send_json(200, {"message_id": meta_id, "to": to_number})
            return
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
            store_record(record)
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
