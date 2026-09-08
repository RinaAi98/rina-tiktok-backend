import base64
import hashlib
import hmac
import json
import os
import time
from urllib.parse import urlencode

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
    try:
        value = env.get(name)
        if value is not None:
            return str(value)
    except Exception:
        pass
    try:
        value = env[name]
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

    body = urlencode({
        "client_key": client_key,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    })

    try:
        import httpx
        import asyncio

        async def exchange_token():
            async with httpx.AsyncClient(timeout=20.0) as client:
                return await client.post(
                    "https://open.tiktokapis.com/v2/oauth/token/",
                    content=body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

        response = asyncio.run(exchange_token())
        try:
            token = response.json()
        except Exception:
            token = {}
        if response.status_code >= 400:
            return jsonify({
                "error": "token_exchange_failed",
                "tiktok_error": token.get("error"),
                "error_description": token.get("error_description"),
                "log_id": token.get("log_id"),
                "http_status": response.status_code,
            }), 502
    except Exception as exc:
        return jsonify({
            "error": "token_exchange_failed",
            "reason": type(exc).__name__,
            "detail": str(exc),
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
