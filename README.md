# TeleRelay Base44 Telegram Bridge

Standalone Telegram bridge for the TeleRelay Base44 app.

## Architecture

Base44 TeleRelay -> HTTPS -> this bridge -> Telegram

Each TeleRelay user gets an independent Telegram StringSession. Starting a bridge login does not log the user out of Telegram on their phone or desktop.

## Environment variables

Set these in the hosting provider's secret/environment settings. Never commit them to GitHub.

- TELEGRAM_API_ID
- TELEGRAM_API_HASH
- BRIDGE_API_KEY
- SESSION_ENCRYPTION_KEY
- GITHUB_TOKEN
- GITHUB_REPO=vexlypremspo-star/teleRelay-base44-bridge
- GITHUB_SESSION_PATH=teleRelay_base44_sessions.enc

## Endpoints

- GET /
- POST /telegram/login/start
- POST /telegram/login/verify
- POST /telegram/login/2fa
- GET /telegram/status
- GET /telegram/folders
- GET /telegram/chats
- GET /telegram/chats/{chat_id}/messages
- POST /telegram/forward
- POST /telegram/logout

## Safety

Telegram deletion APIs are explicitly blocked. This bridge is intended for authentication, reading chats/messages, and forwarding messages.

## Secrets

Do not commit Telegram API hashes, bridge keys, encryption keys, GitHub tokens, passwords, or .env files.
