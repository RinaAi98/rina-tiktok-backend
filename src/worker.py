import base64
import hashlib
import hmac
import json
import os
import time
from urllib.parse import urlencode

import urllib.error
import urllib.parse
import urllib.request
from flask import Flask, jsonify, redirect, request
from workers import env, wsgi

app = Flask(__name__)


def _env_value(name):
    """Read Cloudflare Worker bindings from the Python Workers env object."""
    try:
        value = getattr(env, name, None)
        if value is not None:
            return str(value)
    except Exception:
        pass
    return os.getenv(name, "")


def _config():
    return (
        _env_value("TIKTOK_CLIENT_KEY"),
        _env_value("TIKTOK_CLIENT_SECRET"),
        _env_value("TIKTOK_REDIRECT_URI"),
        _env_value("TIKTOK_STATE_SECRET"),
    )


def make_state(state_secret):
    payload = f"{int(time.time())}.{os.urandom(16).hex()}"
    sig = hmac.new(state_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    raw = f"{payload}.{sig}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def verify_state(state, state_secret):
    try:
        raw = base64.urlsafe_b64decode(state + "=" * (-len(state) % 4)).decode()
        ts, nonce, sig = raw.rsplit(".", 2)
        payload = f"{ts}.{nonce}"
        expected = hmac.new(state_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected) and abs(time.time() - int(ts)) <= 600
    except Exception:
        return False


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "rina-tiktok-backend"})


@app.get("/tiktok/login")
def tiktok_login():
    client_key, _, redirect_uri, state_secret = _config()
    if not client_key or not redirect_uri or not state_secret:
        return jsonify({"error": "backend_not_configured"}), 500
    state = make_state(state_secret)
    params = {
        "client_key": client_key,
        "response_type": "code",
        "scope": "user.info.basic,video.publish,video.upload,video.list",
        "redirect_uri": redirect_uri,
        "state": state,
    }
    return redirect("https://www.tiktok.com/v2/auth/authorize/?" + urlencode(params))


@app.get("/tiktok/callback")
def tiktok_callback():
    client_key, client_secret, redirect_uri, state_secret = _config()
    code = request.args.get("code", "")
    state = request.args.get("state", "")
    if not code or not verify_state(state, state_secret):
        return jsonify({"error": "invalid_oauth_state_or_code"}), 400
    body = urllib.parse.urlencode({
        "client_key": client_key,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }).encode()
    try:
        req = urllib.request.Request(
            "https://open.tiktokapis.com/v2/oauth/token/",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=20) as response:
            token = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        raw_error = exc.read().decode("utf-8", errors="replace")
        try:
            error_data = json.loads(raw_error)
        except Exception:
            error_data = {}
        return jsonify({
            "error": "token_exchange_failed",
            "tiktok_error": error_data.get("error"),
            "error_description": error_data.get("error_description"),
            "log_id": error_data.get("log_id"),
        }), 502
    except Exception as exc:
        return jsonify({
            "error": "token_exchange_failed",
            "reason": type(exc).__name__,
        }), 502
    return jsonify({
        "status": "authorized",
        "scope": token.get("scope", ""),
        "expires_in": token.get("expires_in"),
        "message": "TikTok authorization completed successfully.",
    })


@app.post("/tiktok/webhook")
def tiktok_webhook():
    _, client_secret, _, _ = _config()
    raw = request.get_data()
    signature = request.headers.get("TikTok-Signature", "")
    try:
        parts = dict(item.split("=", 1) for item in signature.split(",") if "=" in item)
        ts = parts.get("t", "")
        sig = parts.get("s", "")
        if abs(time.time() - int(ts)) > 300:
            return jsonify({"error": "stale_signature"}), 401
        expected = hmac.new(client_secret.encode(), f"{ts}.".encode() + raw, hashlib.sha256).hexdigest()
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


Default = wsgi.entrypoint(app)
