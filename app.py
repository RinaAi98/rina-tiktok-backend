import base64
import hashlib
import hmac
import json
import os
import time
from urllib.parse import urlencode

import requests
from flask import Flask, jsonify, redirect, request

app = Flask(__name__)

CLIENT_KEY = os.getenv("TIKTOK_CLIENT_KEY", "")
CLIENT_SECRET = os.getenv("TIKTOK_CLIENT_SECRET", "")
REDIRECT_URI = os.getenv("TIKTOK_REDIRECT_URI", "")
STATE_SECRET = os.getenv("TIKTOK_STATE_SECRET", "")


def make_state():
    payload = f"{int(time.time())}.{os.urandom(16).hex()}"
    sig = hmac.new(STATE_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    raw = f"{payload}.{sig}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def verify_state(state):
    try:
        raw = base64.urlsafe_b64decode(state + "=" * (-len(state) % 4)).decode()
        ts, nonce, sig = raw.rsplit(".", 2)
        payload = f"{ts}.{nonce}"
        expected = hmac.new(STATE_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected) and abs(time.time() - int(ts)) <= 600
    except Exception:
        return False


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "rina-tiktok-backend"})


@app.get("/tiktok/login")
def tiktok_login():
    if not CLIENT_KEY or not REDIRECT_URI or not STATE_SECRET:
        return jsonify({"error": "backend_not_configured"}), 500
    state = make_state()
    params = {
        "client_key": CLIENT_KEY,
        "response_type": "code",
        "scope": "user.info.basic,video.publish,video.upload,video.list",
        "redirect_uri": REDIRECT_URI,
        "state": state,
    }
    return redirect("https://www.tiktok.com/v2/auth/authorize/?" + urlencode(params))


@app.get("/tiktok/callback")
def tiktok_callback():
    code = request.args.get("code", "")
    state = request.args.get("state", "")
    if not code or not verify_state(state):
        return jsonify({"error": "invalid_oauth_state_or_code"}), 400
    resp = requests.post(
        "https://open.tiktokapis.com/v2/oauth/token/",
        data={
            "client_key": CLIENT_KEY,
            "client_secret": CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": REDIRECT_URI,
        },
        timeout=20,
    )
    if not resp.ok:
        return jsonify({"error": "token_exchange_failed", "status": resp.status_code}), 502
    token = resp.json()
    # Never persist or expose client secrets. Return only a safe success page.
    return jsonify({
        "status": "authorized",
        "scope": token.get("scope", ""),
        "expires_in": token.get("expires_in"),
        "message": "TikTok authorization completed successfully.",
    })


@app.post("/tiktok/webhook")
def tiktok_webhook():
    raw = request.get_data()
    signature = request.headers.get("TikTok-Signature", "")
    try:
        parts = dict(item.split("=", 1) for item in signature.split(",") if "=" in item)
        ts = parts.get("t", "")
        sig = parts.get("s", "")
        if abs(time.time() - int(ts)) > 300:
            return jsonify({"error": "stale_signature"}), 401
        expected = hmac.new(CLIENT_SECRET.encode(), f"{ts}.".encode() + raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return jsonify({"error": "invalid_signature"}), 401
    except Exception:
        return jsonify({"error": "invalid_signature"}), 401
    try:
        event = json.loads(raw.decode("utf-8"))
    except Exception:
        event = {"raw": raw.decode("utf-8", errors="replace")}
    print(json.dumps({"event_received": True, "event": event}, separators=(",", ":")))
    return jsonify({"status": "received"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8765")))
