# RINA TikTok Backend

Free public backend for RINA AI's TikTok Login Kit, Content Posting API,
and webhook handling. The production target is Cloudflare Workers Python.

## Endpoints

- `GET /health` — health check
- `GET /tiktok/login` — OAuth authorization redirect
- `GET /tiktok/callback` — OAuth callback
- `POST /tiktok/webhook` — signed webhook receiver
- `POST /tiktok/daily-queue` — authenticated daily video queue
- `GET /tiktok/automation/status` — automation readiness

## Cloudflare Workers

This repo is configured for Python Workers + Flask WSGI.
Cloudflare can import this public GitHub repository directly from the
Workers & Pages dashboard and deploy it to a `workers.dev` URL.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/RinaAi98/rina-tiktok-backend)

Required files:
- `src/worker.py`
- `wrangler.jsonc`
- `pyproject.toml`

## Secrets / variables

Configure these as Cloudflare Worker secrets/environment variables.
Never commit real values.

- `TIKTOK_CLIENT_KEY`
- `TIKTOK_CLIENT_SECRET`
- `TIKTOK_REDIRECT_URI`
- `TIKTOK_STATE_SECRET`

`TIKTOK_REDIRECT_URI` must exactly match the URL configured in TikTok
Developer Portal.

## TikTok audit status

RINA's TikTok OAuth and creator-info flow is working. Public Direct Post is
currently blocked by TikTok's official unaudited-client restriction. This is
not bypassed in code; public posting requires TikTok App Review approval.

For review, demonstrate the complete flow: login/authorization, creator info,
video preview, explicit publish consent, Direct Post initialization, and
publish-status polling. The app must only publish after explicit user consent.
