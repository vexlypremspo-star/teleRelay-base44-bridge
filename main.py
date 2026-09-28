import os
import base64
import json
import hmac
import re
import time
import urllib.error
import urllib.request
from collections import defaultdict, deque
from typing import Dict

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from cryptography.fernet import Fernet
from telethon import TelegramClient, functions, types, utils
from telethon.sessions import StringSession

# TeleRelay is a read/forward bridge. Telegram deletion APIs are blocked.
_BLOCKED_TELEGRAM_REQUESTS = {
    "DeleteHistoryRequest",
    "DeleteMessagesRequest",
    "DeleteChatUserRequest",
    "DeleteTopicHistoryRequest",
    "DeleteSavedHistoryRequest",
    "DeleteUserHistoryRequest",
    "DeleteParticipantHistoryRequest",
    "DiscardEncryptionRequest",
}


class SafeTelegramClient(TelegramClient):
    async def __call__(self, request, *args, **kwargs):
        if request.__class__.__name__ in _BLOCKED_TELEGRAM_REQUESTS:
            raise RuntimeError(
                f"Blocked Telegram deletion operation: {request.__class__.__name__}"
            )
        return await super().__call__(request, *args, **kwargs)

    async def delete_messages(self, *args, **kwargs):
        raise RuntimeError("Blocked Telegram deletion operation: delete_messages")

    async def delete_dialog(self, *args, **kwargs):
        raise RuntimeError("Blocked Telegram deletion operation: delete_dialog")


load_dotenv()

API_ID = int(os.environ["TELEGRAM_API_ID"])
API_HASH = os.environ["TELEGRAM_API_HASH"]
BRIDGE_API_KEY = os.environ["BRIDGE_API_KEY"]
cipher = Fernet(os.environ["SESSION_ENCRYPTION_KEY"].encode())

app = FastAPI(title="TeleRelay Base44 Telegram Bridge")

# Security defaults: the browser should not call this bridge directly.
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
]
if ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["X-API-Key", "Content-Type"],
    )

MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", "65536"))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "60"))
RATE_LIMIT_REQUESTS = int(os.environ.get("RATE_LIMIT_REQUESTS", "60"))
LOGIN_RATE_LIMIT_REQUESTS = int(os.environ.get("LOGIN_RATE_LIMIT_REQUESTS", "5"))
PENDING_LOGIN_TTL = int(os.environ.get("PENDING_LOGIN_TTL", "600"))

_rate_events = defaultdict(deque)

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_REPO = os.environ.get(
    "GITHUB_REPO",
    "vexlypremspo-star/teleRelay-base44-bridge",
)
GITHUB_SESSION_PATH = os.environ.get(
    "GITHUB_SESSION_PATH",
    "teleRelay_base44_sessions.enc",
)
GITHUB_API_URL = (
    f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_SESSION_PATH}"
)

sessions: Dict[str, str] = {}
clients: Dict[str, SafeTelegramClient] = {}
pending_logins: Dict[str, dict] = {}
github_file_sha: str | None = None


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    if request.method in {"POST", "PUT", "PATCH"}:
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail="Request too large")

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


def _rate_limit(key: str, limit: int) -> None:
    now = time.monotonic()
    events = _rate_events[key]
    while events and now - events[0] > RATE_LIMIT_WINDOW:
        events.popleft()
    if len(events) >= limit:
        raise HTTPException(status_code=429, detail="Too many requests")
    events.append(now)


def _validate_user_id(user_id: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", user_id):
        raise HTTPException(status_code=400, detail="Invalid user_id")
    return user_id


def _cleanup_pending_login(user_id: str) -> dict | None:
    pending = pending_logins.get(user_id)
    if not pending:
        return None
    created_at = float(pending.get("created_at", 0))
    if created_at <= 0 or time.time() - created_at > PENDING_LOGIN_TTL:
        pending_logins.pop(user_id, None)
        clients.pop(user_id, None)
        _save_sessions_safely()
        return None
    return pending


def _github_request(method: str, url: str, body: bytes | None = None):
    if not GITHUB_TOKEN:
        return None

    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "telerelay-base44-bridge",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def _load_sessions() -> None:
    global sessions, pending_logins, github_file_sha

    if not GITHUB_TOKEN:
        return

    try:
        result = _github_request("GET", GITHUB_API_URL)
        if not result:
            return

        github_file_sha = result.get("sha")
        encoded = result.get("content", "").replace("\n", "")
        if not encoded:
            return

        encrypted_bundle = base64.b64decode(encoded).decode("utf-8")
        decrypted_bundle = cipher.decrypt(
            encrypted_bundle.encode("utf-8")
        ).decode("utf-8")
        data = json.loads(decrypted_bundle)

        if isinstance(data, dict) and "sessions" in data:
            raw_sessions = data.get("sessions", {})
            raw_pending = data.get("pending_logins", {})
            if isinstance(raw_sessions, dict):
                sessions = {
                    str(user_id): str(value)
                    for user_id, value in raw_sessions.items()
                    if isinstance(value, str) and value
                }
            if isinstance(raw_pending, dict):
                pending_logins = raw_pending
        elif isinstance(data, dict):
            sessions = {
                str(user_id): str(value)
                for user_id, value in data.items()
                if isinstance(value, str) and value
            }
    except Exception as error:
        print(f"WARNING: Could not load encrypted sessions: {error}", flush=True)


def _save_sessions() -> None:
    global github_file_sha

    if not GITHUB_TOKEN:
        raise RuntimeError("GITHUB_TOKEN is not configured")

    bundle = json.dumps(
        {"sessions": sessions, "pending_logins": pending_logins},
        separators=(",", ":"),
    ).encode("utf-8")
    encrypted_bundle = cipher.encrypt(bundle).decode("utf-8")
    encoded = base64.b64encode(
        encrypted_bundle.encode("utf-8")
    ).decode("ascii")

    payload = {
        "message": "Update encrypted TeleRelay Telegram sessions",
        "content": encoded,
    }
    if github_file_sha:
        payload["sha"] = github_file_sha

    result = _github_request(
        "PUT",
        GITHUB_API_URL,
        json.dumps(payload).encode("utf-8"),
    )
    if result:
        github_file_sha = result.get("content", {}).get("sha", github_file_sha)


def _save_sessions_safely() -> None:
    try:
        _save_sessions()
    except Exception as error:
        print(
            f"WARNING: Could not persist Telegram session data: {error}",
            flush=True,
        )


_load_sessions()


class LoginStart(BaseModel):
    user_id: str = Field(min_length=1, max_length=128)
    phone: str = Field(min_length=5, max_length=32)


class LoginVerify(BaseModel):
    user_id: str = Field(min_length=1, max_length=128)
    code: str = Field(min_length=1, max_length=32)


class TwoFactorVerify(BaseModel):
    user_id: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class ForwardRequest(BaseModel):
    user_id: str = Field(min_length=1, max_length=128)
    source_chat_id: int
    message_id: int
    destination_chat_ids: list[int] = Field(min_length=1, max_length=20)


def check_api_key(api_key: str | None):
    if not api_key or not hmac.compare_digest(api_key, BRIDGE_API_KEY):
        raise HTTPException(status_code=401, detail="Unauthorized")


def authorize_request(api_key: str | None, user_id: str, *, login_endpoint: bool = False):
    check_api_key(api_key)
    user_id = _validate_user_id(user_id)
    _rate_limit(f"user:{user_id}", LOGIN_RATE_LIMIT_REQUESTS if login_endpoint else RATE_LIMIT_REQUESTS)
    return user_id


def _new_client(session_string: str | None = None) -> SafeTelegramClient:
    return SafeTelegramClient(
        StringSession(session_string or ""),
        API_ID,
        API_HASH,
    )


async def get_client(user_id: str) -> SafeTelegramClient:
    encrypted_session = sessions.get(user_id)
    if not encrypted_session:
        raise HTTPException(
            status_code=404,
            detail="Telegram account is not connected",
        )

    try:
        session_string = cipher.decrypt(
            encrypted_session.encode("utf-8")
        ).decode("utf-8")
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Stored Telegram session could not be decrypted",
        )

    client = clients.get(user_id)
    if client is None:
        client = _new_client(session_string)
        await client.connect()
        clients[user_id] = client

    return client


@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "TeleRelay Base44 Telegram Bridge",
        "mode": "read_forward_only",
        "persistent_sessions": bool(GITHUB_TOKEN),
        "chat_creation": False,
        "chat_deletion": False,
        "message_deletion": False,
    }


@app.post("/telegram/login/start")
async def login_start(
    request: LoginStart,
    x_api_key: str | None = Header(default=None),
):
    authorize_request(x_api_key, request.user_id, login_endpoint=True)

    if request.user_id in sessions:
        client = clients.get(request.user_id)

        if client is None:
            try:
                client = await get_client(request.user_id)
            except Exception:
                client = None

        if client is not None:
            try:
                if await client.is_user_authorized():
                    return {"status": "already_connected", "phone_code_hash": ""}
            except Exception:
                pass

        clients.pop(request.user_id, None)
        sessions.pop(request.user_id, None)
        pending_logins.pop(request.user_id, None)
        _save_sessions_safely()

    client = _new_client()
    await client.connect()

    try:
        sent = await client.send_code_request(request.phone)
    except Exception as error:
        await client.disconnect()
        raise HTTPException(status_code=400, detail=error.__class__.__name__)

    clients[request.user_id] = client
    pending_logins[request.user_id] = {
        "session_string": client.session.save(),
        "phone": request.phone,
        "phone_code_hash": sent.phone_code_hash,
        "created_at": time.time(),
    }
    _save_sessions_safely()

    return {"status": "code_sent", "phone_code_hash": sent.phone_code_hash}


@app.post("/telegram/login/verify")
async def login_verify(
    request: LoginVerify,
    x_api_key: str | None = Header(default=None),
):
    authorize_request(x_api_key, request.user_id, login_endpoint=True)

    client = clients.get(request.user_id)
    pending = _cleanup_pending_login(request.user_id)

    if client is None and pending:
        session_string = pending.get("session_string")
        if session_string:
            client = _new_client(session_string)
            await client.connect()
            clients[request.user_id] = client

    if client is None:
        raise HTTPException(
            status_code=404,
            detail="Login session not found. Request a new Telegram login code.",
        )

    try:
        phone_code_hash = pending.get("phone_code_hash") if pending else None
        if phone_code_hash:
            await client.sign_in(
                code=request.code,
                phone_code_hash=phone_code_hash,
                phone=pending.get("phone"),
            )
        else:
            await client.sign_in(code=request.code)
    except Exception as error:
        if error.__class__.__name__ == "SessionPasswordNeededError":
            if pending:
                pending["session_string"] = client.session.save()
                pending_logins[request.user_id] = pending
                _save_sessions_safely()
            return {"status": "2fa_required"}

        raise HTTPException(status_code=400, detail=error.__class__.__name__)

    try:
        if not await client.is_user_authorized():
            raise HTTPException(
                status_code=401,
                detail="Telegram authorization was not completed",
            )

        me = await client.get_me()
        if me is None:
            raise HTTPException(
                status_code=401,
                detail="Telegram did not return the logged-in user",
            )
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(status_code=502, detail=error.__class__.__name__)

    session_string = client.session.save()
    sessions[request.user_id] = cipher.encrypt(
        session_string.encode("utf-8")
    ).decode("utf-8")
    pending_logins.pop(request.user_id, None)
    _save_sessions_safely()

    return {"status": "connected"}


@app.post("/telegram/login/2fa")
async def login_2fa(
    request: TwoFactorVerify,
    x_api_key: str | None = Header(default=None),
):
    authorize_request(x_api_key, request.user_id, login_endpoint=True)

    client = clients.get(request.user_id)
    pending = _cleanup_pending_login(request.user_id)

    if client is None and pending:
        session_string = pending.get("session_string")
        if session_string:
            client = _new_client(session_string)
            await client.connect()
            clients[request.user_id] = client

    if client is None:
        raise HTTPException(
            status_code=404,
            detail="Login session not found. Request a new Telegram login code.",
        )

    try:
        await client.sign_in(password=request.password)
    except Exception as error:
        raise HTTPException(status_code=400, detail=error.__class__.__name__)

    if not await client.is_user_authorized():
        raise HTTPException(
            status_code=401,
            detail="Telegram 2FA authorization was not completed",
        )

    session_string = client.session.save()
    sessions[request.user_id] = cipher.encrypt(
        session_string.encode("utf-8")
    ).decode("utf-8")
    pending_logins.pop(request.user_id, None)
    _save_sessions_safely()

    return {"status": "connected"}


def _peer_id(peer) -> str | None:
    try:
        return str(utils.get_peer_id(peer))
    except Exception:
        return None


def _dialog_matches_folder(dialog, dialog_filter) -> bool:
    peer_id = str(dialog.id)
    include_peers = {
        value
        for value in (_peer_id(peer) for peer in getattr(dialog_filter, "include_peers", []))
        if value is not None
    }
    exclude_peers = {
        value
        for value in (_peer_id(peer) for peer in getattr(dialog_filter, "exclude_peers", []))
        if value is not None
    }

    if peer_id in exclude_peers:
        return False

    entity = dialog.entity
    is_group = bool(dialog.is_group)
    is_broadcast = bool(
        dialog.is_channel and getattr(entity, "broadcast", False)
    )
    is_bot = bool(getattr(entity, "bot", False))
    is_contact = bool(getattr(entity, "contact", False))
    is_non_contact = bool(
        getattr(entity, "contact", False) is False and dialog.is_user
    )

    included = peer_id in include_peers

    if getattr(dialog_filter, "contacts", False) and is_contact:
        included = True
    if getattr(dialog_filter, "non_contacts", False) and is_non_contact:
        included = True
    if getattr(dialog_filter, "groups", False) and is_group:
        included = True
    if getattr(dialog_filter, "broadcasts", False) and is_broadcast:
        included = True
    if getattr(dialog_filter, "bots", False) and is_bot:
        included = True

    has_include_rules = bool(
        include_peers
        or getattr(dialog_filter, "contacts", False)
        or getattr(dialog_filter, "non_contacts", False)
        or getattr(dialog_filter, "groups", False)
        or getattr(dialog_filter, "broadcasts", False)
        or getattr(dialog_filter, "bots", False)
    )

    if not has_include_rules:
        included = True

    if not included:
        return False

    if getattr(dialog_filter, "exclude_archived", False) and getattr(
        dialog, "folder_id", None
    ) == 1:
        return False

    if getattr(dialog_filter, "exclude_read", False) and getattr(
        dialog, "unread_count", 0
    ) == 0:
        return False

    return True


def _chat_payload(dialog) -> dict:
    entity = dialog.entity
    is_channel = bool(dialog.is_channel)
    is_broadcast = bool(is_channel and getattr(entity, "broadcast", False))

    if is_broadcast:
        chat_type = "channel"
    elif bool(dialog.is_group) or is_channel:
        chat_type = "group"
    else:
        chat_type = "private"

    return {
        "id": dialog.id,
        "name": dialog.name,
        "title": getattr(entity, "title", None) or dialog.name,
        "username": getattr(entity, "username", None),
        "first_name": getattr(entity, "first_name", None),
        "last_name": getattr(entity, "last_name", None),
        "is_group": bool(dialog.is_group),
        "is_channel": is_channel,
        "type": chat_type,
        "memberCount": int(getattr(entity, "participants_count", 0) or 0),
    }


@app.get("/telegram/status")
async def telegram_status(
    user_id: str,
    x_api_key: str | None = Header(default=None),
):
    authorize_request(x_api_key, user_id) 

    if user_id not in sessions:
        return {"connected": False}

    try:
        client = await get_client(user_id)
        if not await client.is_user_authorized():
            return {"connected": False}

        me = await client.get_me()
        return {
            "connected": True,
            "telegram_user_id": str(me.id),
            "telegram_username": getattr(me, "username", None),
        }
    except Exception:
        return {"connected": False}


@app.get("/telegram/folders")
async def get_folders(
    user_id: str,
    x_api_key: str | None = Header(default=None),
):
    authorize_request(x_api_key, user_id)
    client = await get_client(user_id)

    result = await client(functions.messages.GetDialogFiltersRequest())
    folders = []

    for dialog_filter in getattr(result, "filters", []):
        if isinstance(dialog_filter, types.DialogFilterDefault):
            continue

        title = getattr(dialog_filter, "title", None)
        if hasattr(title, "text"):
            title = title.text

        folders.append({
            "id": int(dialog_filter.id),
            "title": str(title or f"Folder {dialog_filter.id}"),
        })

    return {"folders": folders}


@app.get("/telegram/chats")
async def get_chats(
    user_id: str,
    folder_id: int | None = None,
    limit: int | None = None,
    x_api_key: str | None = Header(default=None),
):
    authorize_request(x_api_key, user_id)
    client = await get_client(user_id)

    requested_limit = None if limit is None else max(1, min(limit, 5000))

    if folder_id in (0, 1):
        dialogs = [
            dialog
            async for dialog in client.iter_dialogs(
                folder=folder_id,
                limit=requested_limit,
            )
        ]
    elif folder_id is not None:
        result = await client(functions.messages.GetDialogFiltersRequest())
        dialog_filter = next(
            (
                item
                for item in getattr(result, "filters", [])
                if getattr(item, "id", None) == folder_id
            ),
            None,
        )

        if dialog_filter is None:
            raise HTTPException(status_code=404, detail="Telegram folder not found")

        dialogs = []
        async for dialog in client.iter_dialogs(limit=None):
            if _dialog_matches_folder(dialog, dialog_filter):
                dialogs.append(dialog)
                if requested_limit is not None and len(dialogs) >= requested_limit:
                    break
    else:
        dialogs = [
            dialog
            async for dialog in client.iter_dialogs(limit=requested_limit)
        ]

    return {"chats": [_chat_payload(dialog) for dialog in dialogs]}


@app.get("/telegram/chats/{chat_id}/messages")
async def get_messages(
    chat_id: int,
    user_id: str,
    limit: int = 20,
    x_api_key: str | None = Header(default=None),
):
    check_api_key(x_api_key)
    client = await get_client(user_id)

    safe_limit = max(1, min(limit, 100))
    messages = []
    async for message in client.iter_messages(chat_id, limit=safe_limit):
        messages.append({
            "id": message.id,
            "text": message.text or "",
            "date": message.date.isoformat() if message.date else None,
            "has_media": message.media is not None,
        })

    return {"messages": messages}


@app.post("/telegram/forward")
async def forward_message(
    request: ForwardRequest,
    x_api_key: str | None = Header(default=None),
):
    authorize_request(x_api_key, request.user_id)
    client = await get_client(request.user_id)

    results = []
    for destination in request.destination_chat_ids[:20]:
        try:
            await client.forward_messages(
                destination,
                request.message_id,
                from_peer=request.source_chat_id,
            )
            results.append({
                "destination_chat_id": destination,
                "status": "success",
            })
        except Exception as error:
            results.append({
                "destination_chat_id": destination,
                "status": "failed",
                "error": error.__class__.__name__,
            })

    return {"results": results}


@app.post("/telegram/logout")
async def logout(
    user_id: str,
    x_api_key: str | None = Header(default=None),
):
    authorize_request(x_api_key, user_id)
    client = clients.pop(user_id, None)
    if client:
        await client.log_out()

    sessions.pop(user_id, None)
    pending_logins.pop(user_id, None)
    _save_sessions_safely()

    return {"status": "logged_out"}
