import base64
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from urllib.parse import urlencode, urlparse, parse_qs

from flask import Flask, jsonify, redirect, request
from pyodide.ffi import run_sync, to_js
from js import Object, fetch as js_fetch
from workers import WorkerEntrypoint, Response, wsgi

app = Flask(__name__)
KV_NAME = "RINA_TIKTOK_KV"
TOKEN_KEY = "tiktok/token/v1"
QUEUE_KEY = "tiktok/daily/v1"
DEFAULT_DAILY_VIDEO_URL = "https://rinaai98.github.io/rina-tiktok-media/daily.mp4"
MAX_VIDEO_SIZE_BYTES = 4 * 1024 * 1024 * 1024
MAX_PENDING_SHARES = 5
UPLOAD_CHUNK_MAX = 64 * 1024 * 1024
BUILD_VERSION = "2026-09-10-upload-v2-direct"
# Temporary one-time Sandbox test gate. Remove after verification.


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


def _to_js(value):
    return to_js(value, dict_converter=Object.fromEntries)


async def _http_head(url):
    response = await js_fetch(url, _to_js({"method": "HEAD"}))
    return response.status, {}


async def _http_post(url, *, content=None, json_body=None, headers=None):
    request_headers = headers or {}
    body = None
    if json_body is not None:
        body = json.dumps(json_body)
    elif content is not None:
        body = content
    options = {"method": "POST", "headers": request_headers}
    if body is not None:
        options["body"] = body
    response = await js_fetch(url, _to_js(options))
    text = await response.text()
    try:
        payload = json.loads(text) if text else {}
    except Exception:
        payload = {"raw": text}
    return response.status, payload


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


async def _publish_status(runtime_env, access_token, publish_id):
    status_code, data = await _http_post(
        "https://open.tiktokapis.com/v2/post/publish/status/fetch/",
        json_body={"publish_id": publish_id},
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
    )
    if status_code >= 400 or data.get("error", {}).get("code") != "ok":
        return None, data.get("error", {}).get("message") or data.get("error", {}).get("code") or "status_fetch_failed"
    return data.get("data", {}).get("status"), None


async def _daily_upload(runtime_env):
    raw_queue = await runtime_env.RINA_TIKTOK_KV.get(QUEUE_KEY)
    if not raw_queue:
        queue = {
            "video_url": DEFAULT_DAILY_VIDEO_URL,
            "title": "RINA daily video",
            "privacy_level": "SELF_ONLY",
            "disable_duet": False,
            "disable_comment": False,
            "disable_stitch": False,
            "is_aigc": True,
            "last_uploaded_date": None,
        }
        # Persist the safe default so scheduled runs are stateful.
        await runtime_env.RINA_TIKTOK_KV.put(QUEUE_KEY, json.dumps(queue))
    else:
        queue = json.loads(raw_queue)
    today = datetime.now(timezone.utc).date().isoformat()
    if queue.get("last_uploaded_date") == today:
        return {"status": "already_done", "date": today}
    access_token, error = await _refresh_token(runtime_env)
    if not access_token:
        return {"status": "blocked", "reason": error}

    # Resume a previously submitted post before creating another one.
    pending_publish_id = queue.get("last_publish_id")
    pending_status = queue.get("last_publish_status")
    if pending_publish_id and pending_status not in ("PUBLISH_COMPLETE", "FAILED", "ERROR"):
        current_status, status_error = await _publish_status(runtime_env, access_token, pending_publish_id)
        if status_error:
            return {"status": "pending", "publish_id": pending_publish_id, "reason": status_error}
        queue["last_publish_status"] = current_status
        if current_status == "PUBLISH_COMPLETE":
            queue["last_uploaded_date"] = queue.get("last_publish_date") or today
            await runtime_env.RINA_TIKTOK_KV.put(QUEUE_KEY, json.dumps(queue))
            return {"status": "publish_complete", "date": queue["last_uploaded_date"], "publish_id": pending_publish_id}
        if current_status in ("FAILED", "ERROR"):
            await runtime_env.RINA_TIKTOK_KV.put(QUEUE_KEY, json.dumps(queue))
            return {"status": "failed", "publish_id": pending_publish_id, "publish_status": current_status}
        await runtime_env.RINA_TIKTOK_KV.put(QUEUE_KEY, json.dumps(queue))
        return {"status": "processing", "publish_id": pending_publish_id, "publish_status": current_status}

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
    creator = creator_data.get("data", {})
    privacy_options = creator.get("privacy_level_options", [])
    max_duration = int(creator.get("max_video_post_duration_sec") or 0)
    privacy_level = queue.get("privacy_level") or _env_value("TIKTOK_PRIVACY_LEVEL", runtime_env) or "SELF_ONLY"
    # TikTok requires the latest creator settings to drive the posting decision.
    if not privacy_options:
        return {"status": "blocked", "reason": "creator_privacy_options_missing"}
    if privacy_level not in privacy_options:
        return {"status": "blocked", "reason": "privacy_level_not_allowed", "requested": privacy_level, "allowed": privacy_options}
    # An unaudited client is restricted to SELF_ONLY/private posting. Never attempt
    # a public post that TikTok will reject; this keeps the scheduler fail-closed.
    if "PUBLIC_TO_EVERYONE" not in privacy_options and privacy_level != "SELF_ONLY":
        return {"status": "blocked", "reason": "unaudited_or_private_creator", "allowed": privacy_options}
    if max_duration and queue.get("duration_sec") and float(queue["duration_sec"]) > max_duration:
        return {"status": "blocked", "reason": "video_duration_exceeds_creator_limit", "duration_sec": queue["duration_sec"], "max_duration_sec": max_duration}
    if queue.get("size_bytes") and int(queue["size_bytes"]) > MAX_VIDEO_SIZE_BYTES:
        return {"status": "blocked", "reason": "video_too_large", "size_bytes": queue["size_bytes"]}
    payload = {
        "post_info": {
            "title": title,
            "privacy_level": privacy_level,
            "disable_duet": bool(queue.get("disable_duet", False)),
            "disable_comment": bool(queue.get("disable_comment", False)),
            "disable_stitch": bool(queue.get("disable_stitch", False)),
            "is_aigc": bool(queue.get("is_aigc", False)),
            "brand_content_toggle": bool(queue.get("brand_content_toggle", False)),
            "brand_organic_toggle": bool(queue.get("brand_organic_toggle", False)),
            "video_cover_timestamp_ms": int(queue["video_cover_timestamp_ms"]) if queue.get("video_cover_timestamp_ms") is not None else None,
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
    publish_id = data.get("data", {}).get("publish_id")
    if not publish_id:
        return {"status": "failed", "reason": "publish_id_missing"}

    # Do not mark the day complete until TikTok confirms PUBLISH_COMPLETE.
    queue["last_publish_id"] = publish_id
    queue["last_publish_status"] = "PROCESSING_UPLOAD"
    queue["last_publish_date"] = today
    await runtime_env.RINA_TIKTOK_KV.put(QUEUE_KEY, json.dumps(queue))

    current_status, status_error = await _publish_status(runtime_env, access_token, publish_id)
    if status_error:
        return {"status": "processing", "date": today, "publish_id": publish_id, "reason": status_error}
    queue["last_publish_status"] = current_status
    if current_status == "PUBLISH_COMPLETE":
        queue["last_uploaded_date"] = today
        await runtime_env.RINA_TIKTOK_KV.put(QUEUE_KEY, json.dumps(queue))
        return {"status": "publish_complete", "date": today, "publish_id": publish_id}
    if current_status in ("FAILED", "ERROR"):
        await runtime_env.RINA_TIKTOK_KV.put(QUEUE_KEY, json.dumps(queue))
        return {"status": "failed", "date": today, "publish_id": publish_id, "publish_status": current_status}
    await runtime_env.RINA_TIKTOK_KV.put(QUEUE_KEY, json.dumps(queue))
    return {"status": "processing", "date": today, "publish_id": publish_id, "publish_status": current_status}


@app.get("/health")
def health():
    client_key, client_secret, redirect_uri, state_secret = _config()
    return jsonify({
        "status": "ok",
        "service": "rina-tiktok-backend",
        "build_version": BUILD_VERSION,
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
        "brand_content_toggle": bool(body.get("brand_content_toggle", False)),
        "brand_organic_toggle": bool(body.get("brand_organic_toggle", False)),
        "video_cover_timestamp_ms": body.get("video_cover_timestamp_ms"),
        "duration_sec": body.get("duration_sec"),
        "size_bytes": body.get("size_bytes"),
        "last_uploaded_date": None,
    }
    _kv_put(QUEUE_KEY, json.dumps(queue))
    return jsonify({"status": "queued", "daily": True})


@app.get("/tiktok/preflight")
def tiktok_preflight():
    """Read-only readiness check; never initializes a TikTok post."""
    if not _kv():
        return jsonify({"status": "blocked", "reason": "kv_not_configured"}), 503
    # Preflight is read-only with respect to TikTok publishing: it never
    # initializes a post. It may refresh the OAuth access token in KV, just
    # like the scheduled publisher, so an expired access token is not reported
    # as a false blocker while the refresh token is still valid.
    runtime_env = _request_env()
    if runtime_env is None or _kv(runtime_env) is None:
        return jsonify({"status": "blocked", "reason": "kv_not_configured"}), 503
    try:
        token, refresh_error = run_sync(_refresh_token(runtime_env))
    except Exception as exc:
        return jsonify({"status": "blocked", "reason": type(exc).__name__}), 502
    if not token:
        return jsonify({"status": "blocked", "reason": refresh_error or "access_token_unavailable"}), 401
    try:
        status_code, creator_data = run_sync(_http_post(
            "https://open.tiktokapis.com/v2/post/publish/creator_info/query/",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        ))
    except Exception as exc:
        return jsonify({"status": "blocked", "reason": type(exc).__name__}), 502
    if status_code >= 400 or creator_data.get("error", {}).get("code") != "ok":
        return jsonify({
            "status": "blocked",
            "reason": creator_data.get("error", {}).get("code") or "creator_info_failed",
            "message": creator_data.get("error", {}).get("message"),
        }), 502
    creator = creator_data.get("data", {})
    raw_queue = _kv_get(QUEUE_KEY) or ""
    queue = json.loads(raw_queue) if raw_queue else {"video_url": DEFAULT_DAILY_VIDEO_URL, "privacy_level": "SELF_ONLY"}
    allowed = creator.get("privacy_level_options", [])
    requested = queue.get("privacy_level") or "SELF_ONLY"
    video_url = queue.get("video_url") or DEFAULT_DAILY_VIDEO_URL
    reasons = []
    if requested not in allowed:
        reasons.append("privacy_level_not_allowed")
    if requested == "PUBLIC_TO_EVERYONE" and "PUBLIC_TO_EVERYONE" not in allowed:
        reasons.append("public_post_not_allowed")
    duration = queue.get("duration_sec")
    maximum = creator.get("max_video_post_duration_sec")
    if duration and maximum and float(duration) > float(maximum):
        reasons.append("duration_exceeds_creator_limit")
    media_status, content_type, content_length = None, "", None
    # Do not perform an outbound media probe from the Flask/WSGI preflight.
    # The actual TikTok PULL_FROM_URL request performs the authoritative URL
    # validation; preflight remains read-only and avoids WSGI/async FFI issues.
    return jsonify({
        "status": "ready" if not reasons else "blocked",
        "creator": {
            "username": creator.get("creator_username"),
            "nickname": creator.get("creator_nickname"),
            "privacy_level_options": allowed,
            "max_video_post_duration_sec": maximum,
            "comment_disabled": creator.get("comment_disabled"),
            "duet_disabled": creator.get("duet_disabled"),
            "stitch_disabled": creator.get("stitch_disabled"),
        },
        "build_version": BUILD_VERSION,
        "queue": {
            "video_url": video_url,
            "privacy_level": requested,
            "duration_sec": duration,
            "size_bytes": queue.get("size_bytes") or (int(content_length) if content_length else None),
        },
        "media": {
            "http_status": media_status,
            "content_type": content_type,
            "content_length": int(content_length) if content_length else None,
            "url_ownership_verification_required": True,
        },
        "reasons": reasons,
        "note": "Read-only preflight; no publish request was sent.",
    })


@app.get("/tiktok/oauth/status")
def oauth_status():
    """Read-only OAuth/token metadata; never returns token secrets."""
    if not _kv():
        return jsonify({"status": "blocked", "reason": "kv_not_configured"}), 503
    raw = _kv_get(TOKEN_KEY) or ""
    if not raw:
        return jsonify({"status": "waiting", "token_saved": False}), 200
    try:
        token = json.loads(raw)
    except Exception:
        return jsonify({"status": "blocked", "reason": "token_record_invalid"}), 502
    expires_at = int(token.get("expires_at", 0) or 0)
    refresh_expires_at = int(token.get("refresh_expires_at", 0) or 0)
    now = int(time.time())
    return jsonify({
        "status": "ready",
        "token_saved": bool(token.get("access_token")),
        "open_id": token.get("open_id"),
        "scope": token.get("scope", ""),
        "expires_at": expires_at,
        "expires_in_sec": max(0, expires_at - now),
        "refresh_expires_at": refresh_expires_at,
        "refresh_expires_in_sec": max(0, refresh_expires_at - now),
    })


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


async def _tiktok_file_upload(runtime_env, video_bytes, title, privacy_level, content_type):
    access_token, error = await _refresh_token(runtime_env)
    if not access_token:
        return {"status": "blocked", "reason": error}, 401
    size = len(video_bytes)
    if size <= 0:
        return {"status": "blocked", "reason": "empty_video"}, 400
    if size > UPLOAD_CHUNK_MAX:
        return {"status": "blocked", "reason": "video_too_large_for_current_worker_upload", "max_bytes": UPLOAD_CHUNK_MAX}, 413
    creator_status, creator = await _http_post(
        "https://open.tiktokapis.com/v2/post/publish/creator_info/query/",
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
    )
    if creator_status >= 400 or creator.get("error", {}).get("code") != "ok":
        return {"status": "blocked", "reason": "creator_info_failed", "message": creator.get("error", {}).get("message")}, 502
    allowed = creator.get("data", {}).get("privacy_level_options", [])
    if privacy_level not in allowed:
        return {"status": "blocked", "reason": "privacy_level_not_allowed", "allowed": allowed}, 400
    init_status, init_data = await _http_post(
        "https://open.tiktokapis.com/v2/post/publish/video/init/",
        json_body={
            "post_info": {"title": title[:150], "privacy_level": privacy_level},
            "source_info": {"source": "FILE_UPLOAD", "video_size": size, "chunk_size": size, "total_chunk_count": 1},
        },
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
    )
    if init_status >= 400 or init_data.get("error", {}).get("code") != "ok":
        return {"status": "blocked", "reason": "publish_init_failed", "tiktok": init_data}, 502
    publish_id = init_data.get("data", {}).get("publish_id")
    upload_url = init_data.get("data", {}).get("upload_url")
    if not publish_id or not upload_url:
        return {"status": "blocked", "reason": "upload_url_missing"}, 502
    response = await js_fetch(upload_url, _to_js({
        "method": "PUT",
        "headers": {"Content-Type": content_type, "Content-Length": str(size), "Content-Range": f"bytes 0-{size - 1}/{size}"},
        "body": to_js(video_bytes),
    }))
    if response.status >= 300:
        text = await response.text()
        return {"status": "blocked", "reason": "video_upload_failed", "http_status": response.status, "response": text[:500]}, 502
    return {"status": "uploaded_to_tiktok", "publish_id": publish_id, "bytes": size, "note": "TikTok processing/publish continues asynchronously."}, 200


async def _tiktok_upload_init(runtime_env, video_size, title, privacy_level):
    access_token, error = await _refresh_token(runtime_env)
    if not access_token:
        return {"status": "blocked", "reason": error}, 401
    if video_size <= 0:
        return {"status": "blocked", "reason": "empty_video"}, 400
    if video_size > MAX_VIDEO_SIZE_BYTES:
        return {"status": "blocked", "reason": "video_too_large", "max_bytes": MAX_VIDEO_SIZE_BYTES}, 413
    creator_status, creator = await _http_post(
        "https://open.tiktokapis.com/v2/post/publish/creator_info/query/",
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
    )
    if creator_status >= 400 or creator.get("error", {}).get("code") != "ok":
        return {"status": "blocked", "reason": "creator_info_failed", "message": creator.get("error", {}).get("message")}, 502
    allowed = creator.get("data", {}).get("privacy_level_options", [])
    if privacy_level not in allowed:
        return {"status": "blocked", "reason": "privacy_level_not_allowed", "allowed": allowed}, 400
    chunk_size = min(video_size, UPLOAD_CHUNK_MAX)
    if video_size > UPLOAD_CHUNK_MAX:
        chunk_count = (video_size + chunk_size - 1) // chunk_size
    else:
        chunk_count = 1
    init_status, init_data = await _http_post(
        "https://open.tiktokapis.com/v2/post/publish/video/init/",
        json_body={
            "post_info": {"title": title[:2200], "privacy_level": privacy_level},
            "source_info": {"source": "FILE_UPLOAD", "video_size": video_size, "chunk_size": chunk_size, "total_chunk_count": chunk_count},
        },
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
    )
    if init_status >= 400 or init_data.get("error", {}).get("code") != "ok":
        return {"status": "blocked", "reason": "publish_init_failed", "tiktok": init_data}, 502
    data = init_data.get("data", {})
    publish_id = data.get("publish_id")
    upload_url = data.get("upload_url")
    if not publish_id or not upload_url:
        return {"status": "blocked", "reason": "upload_url_missing"}, 502
    return {"status": "ready_for_direct_upload", "publish_id": publish_id, "upload_url": upload_url, "video_size": video_size, "chunk_size": chunk_size, "total_chunk_count": chunk_count, "expires_in_sec": 3600}, 200


@app.post("/tiktok/upload/init")
def tiktok_upload_init():
    runtime_env = _request_env()
    upload_key = _env_value("TIKTOK_UPLOAD_KEY", runtime_env)
    supplied_key = request.headers.get("X-RINA-Upload-Key", "")
    if not upload_key or not hmac.compare_digest(supplied_key, upload_key):
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json(silent=True) or {}
    try:
        video_size = int(body.get("video_size", 0))
    except Exception:
        return jsonify({"error": "invalid_video_size"}), 400
    content_type = str(body.get("content_type", "video/mp4"))
    if content_type not in ("video/mp4", "video/quicktime", "video/webm"):
        return jsonify({"error": "unsupported_video_type", "content_type": content_type}), 400
    title = str(body.get("title", "RINA daily video")).strip()
    privacy_level = str(body.get("privacy_level", "SELF_ONLY")).strip()
    try:
        result, status = run_sync(_tiktok_upload_init(runtime_env, video_size, title, privacy_level))
        result["content_type"] = content_type
        return jsonify(result), status
    except Exception as exc:
        return jsonify({"error": "upload_init_exception", "reason": type(exc).__name__}), 502


@app.post("/tiktok/upload")
def tiktok_upload_legacy_blocked():
    return jsonify({"error": "direct_upload_required", "message": "Initialize at /tiktok/upload/init, then PUT the video directly to TikTok upload_url."}), 410


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


async def _tiktok_callback_native(request, env):
    """Native async OAuth callback; avoids Flask/WSGI sync bridging for I/O."""
    _, client_secret, redirect_uri, state_secret = _config(env)
    params = parse_qs(urlparse(request.url).query)
    code = params.get("code", [""])[0]
    state = params.get("state", [""])[0]
    if not code or not verify_state(state, state_secret):
        return Response.json({"error": "invalid_oauth_state_or_code"}, status=400)
    body = urlencode({
        "client_key": _config(env)[0],
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    })
    try:
        response_status, token = await _http_post(
            "https://open.tiktokapis.com/v2/oauth/token/",
            content=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if response_status >= 400 or token.get("error"):
            return Response.json({
                "error": "token_exchange_failed",
                "tiktok_error": token.get("error"),
                "error_description": token.get("error_description"),
                "log_id": token.get("log_id"),
            }, status=502)
        await env.RINA_TIKTOK_KV.put(TOKEN_KEY, json.dumps({
            "access_token": token.get("access_token"),
            "refresh_token": token.get("refresh_token"),
            "open_id": token.get("open_id"),
            "scope": token.get("scope", ""),
            "expires_at": int(time.time()) + int(token.get("expires_in", 86400)),
            "refresh_expires_at": int(time.time()) + int(token.get("refresh_expires_in", 31536000)),
        }))
        return Response.json({
            "status": "authorized",
            "persistent_session": True,
            "scope": token.get("scope", ""),
            "expires_in": token.get("expires_in"),
            "message": "TikTok authorization completed successfully.",
        })
    except Exception as exc:
        return Response.json({"error": "token_exchange_failed", "reason": type(exc).__name__}, status=502)


async def _tiktok_preflight_native(env):
    """Async preflight path; avoids WSGI run_sync for network/KV I/O."""
    # Match the scheduled publisher: refresh an expired access token using
    # the stored refresh token, without initializing or publishing a post.
    try:
        token, refresh_error = await _refresh_token(env)
    except Exception as exc:
        return Response.json({"status": "blocked", "reason": "token_refresh_" + type(exc).__name__}, status=502)
    if not token:
        return Response.json({"status": "blocked", "reason": refresh_error or "access_token_unavailable"}, status=401)
    try:
        status_code, creator_data = await _http_post(
            "https://open.tiktokapis.com/v2/post/publish/creator_info/query/",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
    except Exception as exc:
        return Response.json({"status": "blocked", "reason": "creator_request_" + type(exc).__name__}, status=502)
    if status_code >= 400 or creator_data.get("error", {}).get("code") != "ok":
        return Response.json({
            "status": "blocked",
            "reason": creator_data.get("error", {}).get("code") or "creator_info_failed",
            "message": creator_data.get("error", {}).get("message"),
        }, status=502)
    creator = creator_data.get("data", {})
    raw_queue = await env.RINA_TIKTOK_KV.get(QUEUE_KEY)
    queue = json.loads(raw_queue) if raw_queue else {
        "video_url": DEFAULT_DAILY_VIDEO_URL,
        "privacy_level": "SELF_ONLY",
    }
    allowed = creator.get("privacy_level_options", [])
    requested = queue.get("privacy_level") or "SELF_ONLY"
    reasons = []
    if requested not in allowed:
        reasons.append("privacy_level_not_allowed")
    if requested == "PUBLIC_TO_EVERYONE" and "PUBLIC_TO_EVERYONE" not in allowed:
        reasons.append("public_post_not_allowed")
    duration = queue.get("duration_sec")
    maximum = creator.get("max_video_post_duration_sec")
    if duration and maximum and float(duration) > float(maximum):
        reasons.append("duration_exceeds_creator_limit")
    return Response.json({
        "status": "ready" if not reasons else "blocked",
        "build_version": BUILD_VERSION,
        "creator": {
            "username": creator.get("creator_username"),
            "nickname": creator.get("creator_nickname"),
            "privacy_level_options": allowed,
            "max_video_post_duration_sec": maximum,
            "comment_disabled": creator.get("comment_disabled"),
            "duet_disabled": creator.get("duet_disabled"),
            "stitch_disabled": creator.get("stitch_disabled"),
        },
        "queue": queue,
        "media": {"url": queue.get("video_url") or DEFAULT_DAILY_VIDEO_URL},
        "reasons": reasons,
        "note": "Read-only preflight; no publish request was sent.",
    })


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        path = urlparse(request.url).path
        if path == "/tiktok/callback":
            return await _tiktok_callback_native(request, self.env)
        if path == "/tiktok/preflight":
            return await _tiktok_preflight_native(self.env)
        return await wsgi.fetch(app, request, self.env)

    async def scheduled(self, controller, env, ctx):
        try:
            result = await _daily_upload(env)
        except Exception as exc:
            result = {"status": "blocked", "reason": type(exc).__name__}
        print(json.dumps({"daily_tiktok_upload": result}, separators=(",", ":")))
