import base64
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from urllib.parse import urlencode

from js import fetch
from flask import Flask, jsonify, redirect, request
from pyodide.ffi import run_sync
from workers import WorkerEntrypoint, wsgi

app = Flask(__name__)
KV_NAME = "RINA_TIKTOK_KV"
TOKEN_KEY = "tiktok/token/v1"
QUEUE_KEY = "tiktok/daily/v1"
DEFAULT_DAILY_VIDEO_URL = "https://rinaai98.github.io/rina-tiktok-media/daily.mp4"


def _request_env():
    try:
        return request.environ["workers.env"]
    except Exception:
        return None


def _env_value(name, runtime_env=None):
    source = runtime_env
    if source is None:
        source = _request_env()
    if source is not None:
        try:
            value = getattr(source, name, None)
            if value is not None:
                return str(value)
        except Exception:
            pass
        try:
            value = source.get(name)
            if value is not None:
                return str(value)
        except Exception:
            pass
        try:
            value = source[name]
            if value is not None:
                return str(value)
        except Exception:
            pass
    return os.getenv(name, "")


def _config(runtime_env=None):
    return (
        _env_value("TIKTOK_CLIENT_KEY", runtime_env),
        _env_value("TIKTOK_CLIENT_SECRET", runtime_env),
        _env_value("TIKTOK_REDIRECT_URI", runtime_env),
        _env_value("TIKTOK_STATE_SECRET", runtime_env),
    )


def _kv(runtime_env=None):
    source = runtime_env or _request_env()
    if source is None:
        return None
    try:
        return getattr(source, KV_NAME)
    except Exception:
        return None


def _kv_get(key, runtime_env=None):
    kv = _kv(runtime_env)
    if kv is None:
        return None
    return run_sync(kv.get(key))


def _kv_put(key, value, runtime_env=None):
    kv = _kv(runtime_env)
    if kv is None:
        return False
    run_sync(kv.put(key, value))
    return True


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


async def _http_post(url, *, content=None, json_body=None, headers=None):
    options = {"method": "POST", "headers": headers or {}}
    if json_body is not None:
        options["body"] = json.dumps(json_body)
    elif content is not None:
        options["body"] = content
    response = await fetch(url, options)
    return response.status, await response.json()


async def _refresh_token(runtime_env):
    client_key, client_secret, _, _ = _config(runtime_env)
    raw = await runtime_env.RINA_TIKTOK_KV.get(TOKEN_KEY)
    if not raw:
        return None, "token_storage_empty"
    token = json.loads(raw)
    if token.get("expires_at", 0) > int(time.time()) + 1800:
        return token.get("access_token"), None
    refresh_token = token.get("refresh_token")
    if not refresh_token:
        return None, "refresh_token_missing"
    body = urlencode({
        "client_key": client_key,
        "client_secret": client_secret,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    })
    status_code, data = await _http_post(
        "https://open.tiktokapis.com/v2/oauth/token/",
        content=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if status_code >= 400 or data.get("error"):
        return None, data.get("error_description") or data.get("error") or "refresh_failed"
    new_token = {
        "access_token": data.get("access_token"),
        "refresh_token": data.get("refresh_token") or refresh_token,
        "open_id": data.get("open_id", token.get("open_id")),
        "scope": data.get("scope", token.get("scope", "")),
        "expires_at": int(time.time()) + int(data.get("expires_in", 86400)),
        "refresh_expires_at": int(time.time()) + int(data.get("refresh_expires_in", 31536000)),
    }
    await runtime_env.RINA_TIKTOK_KV.put(TOKEN_KEY, json.dumps(new_token))
    return new_token["access_token"], None


async def _daily_upload(runtime_env):
    raw_queue = await runtime_env.RINA_TIKTOK_KV.get(QUEUE_KEY)
    if not raw_queue:
        queue = {
            "video_url": DEFAULT_DAILY_VIDEO_URL,
            "title": "RINA daily video",
            "privacy_level": "PUBLIC_TO_EVERYONE",
            "disable_duet": False,
            "disable_comment": False,
            "disable_stitch": False,
            "is_aigc": True,
            "last_uploaded_date": None,
        }
    else:
        queue = json.loads(raw_queue)
    today = datetime.now(timezone.utc).date().isoformat()
    if queue.get("last_uploaded_date") == today:
        return {"status": "already_done", "date": today}
    access_token, error = await _refresh_token(runtime_env)
    if not access_token:
        return {"status": "blocked", "reason": error}
    video_url = queue.get("video_url") or _env_value("TIKTOK_DAILY_VIDEO_URL", runtime_env) or DEFAULT_DAILY_VIDEO_URL
    title = str(queue.get("title") or "RINA daily video").strip()[:2200]
    creator_status, creator_data = await _http_post(
        "https://open.tiktokapis.com/v2/post/publish/creator_info/query/",
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
    )
    if creator_status >= 400 or creator_data.get("error", {}).get("code") != "ok":
        return {
            "status": "blocked",
            "reason": creator_data.get("error", {}).get("code") or "creator_info_failed",
            "message": creator_data.get("error", {}).get("message"),
        }
    privacy_options = creator_data.get("data", {}).get("privacy_level_options", [])
    privacy_level = queue.get("privacy_level") or _env_value("TIKTOK_PRIVACY_LEVEL", runtime_env) or "SELF_ONLY"
    if privacy_level not in privacy_options:
        return {"status": "blocked", "reason": "privacy_level_not_allowed", "requested": privacy_level, "allowed": privacy_options}
    payload = {
        "post_info": {
            "title": title,
            "privacy_level": privacy_level,
            "disable_duet": bool(queue.get("disable_duet", False)),
            "disable_comment": bool(queue.get("disable_comment", False)),
            "disable_stitch": bool(queue.get("disable_stitch", False)),
            "is_aigc": bool(queue.get("is_aigc", False)),
        },
        "source_info": {"source": "PULL_FROM_URL", "video_url": video_url},
    }
    status_code, data = await _http_post(
        "https://open.tiktokapis.com/v2/post/publish/video/init/",
        json_body=payload,
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
    )
    if status_code >= 400 or data.get("error", {}).get("code") != "ok":
        return {
            "status": "failed",
            "http_status": status_code,
            "error": data.get("error", {}).get("code"),
            "message": data.get("error", {}).get("message"),
        }
    queue["last_uploaded_date"] = today
    queue["last_publish_id"] = data.get("data", {}).get("publish_id")
    await runtime_env.RINA_TIKTOK_KV.put(QUEUE_KEY, json.dumps(queue))
    return {"status": "direct_post_submitted", "date": today, "publish_id": queue["last_publish_id"]}


@app.get("/health")
def health():
    client_key, client_secret, redirect_uri, state_secret = _config()
    return jsonify({
        "status": "ok",
        "service": "rina-tiktok-backend",
        "oauth_configured": all([client_key, client_secret, redirect_uri, state_secret]),
        "daily_automation": bool(_kv()),
        "bindings": {
            "client_key": bool(client_key),
            "client_secret": bool(client_secret),
            "redirect_uri": bool(redirect_uri),
            "state_secret": bool(state_secret),
            "kv": bool(_kv()),
        },
    })


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
        status_code, token = run_sync(_http_post(
            "https://open.tiktokapis.com/v2/oauth/token/",
            content=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ))
        if status_code >= 400 or token.get("error"):
            return jsonify({
                "error": "token_exchange_failed",
                "tiktok_error": token.get("error"),
                "error_description": token.get("error_description"),
                "log_id": token.get("log_id"),
            }), 502
        stored = _kv_put(TOKEN_KEY, json.dumps({
            "access_token": token.get("access_token"),
            "refresh_token": token.get("refresh_token"),
            "open_id": token.get("open_id"),
            "scope": token.get("scope", ""),
            "expires_at": int(time.time()) + int(token.get("expires_in", 86400)),
            "refresh_expires_at": int(time.time()) + int(token.get("refresh_expires_in", 31536000)),
        }))
    except Exception as exc:
        return jsonify({"error": "token_exchange_failed", "reason": type(exc).__name__}), 502
    return jsonify({
        "status": "authorized",
        "persistent_session": stored,
        "scope": token.get("scope", ""),
        "expires_in": token.get("expires_in"),
        "message": "TikTok authorization completed successfully.",
    })


@app.post("/tiktok/daily-queue")
def daily_queue():
    _, _, _, state_secret = _config()
    if request.headers.get("X-RINA-Automation-Key", "") != state_secret:
        return jsonify({"error": "unauthorized"}), 401
    if not _kv():
        return jsonify({"error": "kv_not_configured"}), 503
    body = request.get_json(silent=True) or {}
    video_url = str(body.get("video_url", "")).strip()
    title = str(body.get("title", "RINA daily video")).strip()[:2200]
    privacy_level = str(body.get("privacy_level", "")).strip()
    if not video_url.startswith("https://"):
        return jsonify({"error": "video_url_must_be_https"}), 400
    if privacy_level and privacy_level not in {
        "PUBLIC_TO_EVERYONE",
        "MUTUAL_FOLLOW_FRIENDS",
        "FOLLOWER_OF_CREATOR",
        "SELF_ONLY",
    }:
        return jsonify({"error": "invalid_privacy_level"}), 400
    queue = {
        "video_url": video_url,
        "title": title,
        "privacy_level": privacy_level or "SELF_ONLY",
        "disable_duet": bool(body.get("disable_duet", False)),
        "disable_comment": bool(body.get("disable_comment", False)),
        "disable_stitch": bool(body.get("disable_stitch", False)),
        "is_aigc": bool(body.get("is_aigc", False)),
        "last_uploaded_date": None,
    }
    _kv_put(QUEUE_KEY, json.dumps(queue))
    return jsonify({"status": "queued", "daily": True})


@app.get("/tiktok/automation/status")
def automation_status():
    if not _kv():
        return jsonify({"status": "not_configured", "reason": "kv_not_configured"}), 503
    token = _kv_get(TOKEN_KEY) or ""
    queue = _kv_get(QUEUE_KEY) or ""
    return jsonify({
        "status": "ready" if token else "waiting",
        "token_saved": bool(token),
        "daily_queue_saved": bool(queue),
        "default_daily_media": DEFAULT_DAILY_VIDEO_URL,
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
    return jsonify({"status": "received"})


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        return await wsgi.fetch(app, request, self.env)

    async def scheduled(self, controller, env, ctx):
        try:
            result = await _daily_upload(env)
        except Exception as exc:
            result = {"status": "blocked", "reason": type(exc).__name__}
        print(json.dumps({"daily_tiktok_upload": result}, separators=(",", ":")))
