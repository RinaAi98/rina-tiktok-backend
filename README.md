# RINA TikTok Backend

Minimal public backend for TikTok Login Kit and Content Posting API.

## Endpoints

- `GET /health` — health check
- `GET /tiktok/login` — OAuth authorization redirect
- `GET /tiktok/callback` — OAuth callback
- `POST /tiktok/webhook` — signed webhook receiver

## Render

Runtime: Python
Build: `pip install -r requirements.txt`
Start: `python app.py`
Region: Singapore
Plan: Free

## Environment variables

Set these in Render, never commit them:

- `TIKTOK_CLIENT_KEY`
- `TIKTOK_CLIENT_SECRET`
- `TIKTOK_REDIRECT_URI`
- `TIKTOK_STATE_SECRET`

`TIKTOK_REDIRECT_URI` must exactly match the URL configured in TikTok Developer.
