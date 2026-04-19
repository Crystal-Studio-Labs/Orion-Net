"""Orion-Net: room server that registers with Orion-Core hub.

Configuration via .env file (or environment variables directly):

  HUB_URL             = wss://orion-core.onrender.com
  MY_ROOM_NAME        = Project Orion
  PORT                = 8765
  ROOM_MOTD           = Welcome To Orion Network.
  ROOM_PASSWORD       = # empty = public room
  RENDER_EXTERNAL_URL = # set on Render/cloud deployments
  MSG_HISTORY_SIZE    = 50

Create a .env file in the same directory — all fields are optional.

MESSAGE SCHEMA — every packet is JSON with a "type" field:
  Server → Client:
    {"type":"session_key","key":"<b64>"}
    {"type":"room_meta","locked":bool,"motd":"<str>","room_name":"<str>","history":[...]}
    {"type":"auth_ok"}
    {"type":"auth_fail","message":"<str>"}
    {"type":"event","event":"join|leave|rename|system","text":"<str>"}
    {"type":"chat","from":"<name>","ciphertext":"<b64>"}
    {"type":"error","message":"<str>"}
  Client → Server:
    {"type":"handshake","pubkey":"<pem>"}
    {"type":"auth","ciphertext":"<b64>"}      -- encrypted password
    {"type":"name","ciphertext":"<b64>"}      -- encrypted display name
    {"type":"chat","ciphertext":"<b64>"}      -- encrypted message body
"""

import asyncio
import os
import re
import json
import logging
import hashlib
import time
import base64
import random
import string
import datetime
from collections import deque
from pathlib import Path
from dotenv import load_dotenv
from websockets import serve, connect
from websockets.exceptions import ConnectionClosed
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# ─────────────────────────────────────────────
#  Load .env  (env vars already set take priority)
# ─────────────────────────────────────────────

_env_path = Path(__file__).parent / ".env"
load_dotenv(_env_path, override=False)   # override=False: real env vars win

def _get(key: str, default):
    return os.environ.get(key, default)

HUB_URL             = _get("HUB_URL",             "https://orion-core.onrender.com")
MY_ROOM_NAME        = _get("MY_ROOM_NAME",         "Orion Room")
RENDER_EXTERNAL_URL = _get("RENDER_EXTERNAL_URL",  "") or ""
PORT                = int(_get("PORT",             8765))
ROOM_MOTD           = _get("ROOM_MOTD",            "Welcome to this Orion-Net room!")
ROOM_PASSWORD       = _get("ROOM_PASSWORD",        "") or ""
MSG_HISTORY_SIZE    = int(_get("MSG_HISTORY_SIZE", 50))

# ─────────────────────────────────────────────
#  ANSI palette
# ─────────────────────────────────────────────

R      = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
CYAN   = "\033[38;5;51m"
BLUE   = "\033[38;5;39m"
LBLUE  = "\033[38;5;75m"
YELLOW = "\033[38;5;226m"
GREEN  = "\033[38;5;82m"
RED    = "\033[38;5;196m"
GREY   = "\033[38;5;240m"
LGREY  = "\033[38;5;245m"
WHITE  = "\033[38;5;255m"
PURPLE = "\033[38;5;141m"

# ─────────────────────────────────────────────
#  Logging
# ─────────────────────────────────────────────

class OrionFormatter(logging.Formatter):
    _ICONS  = {"INFO": f"{GREEN}●{R}", "WARNING": f"{YELLOW}▲{R}",
                "ERROR": f"{RED}✖{R}", "CRITICAL": f"{RED}✖{R}", "DEBUG": f"{GREY}·{R}"}
    _COLORS = {"INFO": WHITE, "WARNING": YELLOW, "ERROR": RED, "CRITICAL": RED, "DEBUG": GREY}

    def format(self, record):
        icon  = self._ICONS.get(record.levelname, f"{GREY}·{R}")
        color = self._COLORS.get(record.levelname, GREY)
        ts    = self.formatTime(record, "%H:%M:%S")
        msg   = re.sub(r"(\[[a-z0-9]{4,}\])", f"{CYAN}\\1{R}{color}", record.getMessage())
        return f"{GREY}{ts}{R}  {icon}  {color}{msg}{R}"

_log_handler = logging.StreamHandler()
_log_handler.setFormatter(OrionFormatter())
logging.getLogger().handlers           = [_log_handler]
logging.getLogger().setLevel(logging.INFO)
logging.getLogger("websockets").setLevel(logging.WARNING)
logging.getLogger("websockets.server").setLevel(logging.WARNING)
log = logging.getLogger("orion-net")

# ─────────────────────────────────────────────
#  TUI helpers
# ─────────────────────────────────────────────

def _strip_ansi(s: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", s)

def _gradient_line(text: str, colors: list) -> str:
    out, n = "", len(colors)
    for i, ch in enumerate(text):
        out += ch if ch == " " else colors[min(int(i / max(len(text), 1) * n), n-1)] + ch
    return out + R

def get_banner() -> str:
    raw = ("▛▀▖       ▖      ▐   ▞▀▖   ▗       \n"
           "▙▄▘▙▀▖▞▀▖▗▖▞▀▖▞▀▖▜▀  ▌ ▌▙▀▖▄ ▞▀▖▛▀▖\n"
           "▌  ▌  ▌ ▌ ▌▛▀ ▌ ▖▐ ▖ ▌ ▌▌  ▐ ▌ ▌▌ ▌\n"
           "▘  ▘  ▝▀ ▄▘▝▀▘▝▀  ▀  ▝▀ ▘  ▀▘▝▀ ▘ ▘")
    grad = ["\033[38;5;17m","\033[38;5;18m","\033[38;5;19m","\033[38;5;20m","\033[38;5;21m",
            "\033[38;5;27m","\033[38;5;33m","\033[38;5;39m","\033[38;5;45m","\033[38;5;51m",
            "\033[38;5;45m","\033[38;5;39m","\033[38;5;33m","\033[38;5;27m","\033[38;5;21m"]
    return "\n".join(_gradient_line(l, grad) for l in raw.split("\n"))

def _box_row(label: str, value: str, W: int = 60) -> str:
    inner = f"  {DIM}{LGREY}{label:<13}{R}  {value}"
    pad   = (W - 2) - len(_strip_ansi(inner)) - 1
    return f"{GREY}│{R}{inner}{' ' * max(pad, 0)}{GREY}│{R}"

def _box_center(text: str, W: int = 60) -> str:
    plain = _strip_ansi(text)
    tp    = (W - 2) - len(plain)
    return f"{GREY}│{R}{' ' * (tp//2)}{text}{' ' * (tp - tp//2)}{GREY}│{R}"

def _box_sep(W: int = 60) -> str: return f"{GREY}├{'─'*(W-2)}┤{R}"
def _box_top(W: int = 60) -> str: return f"{GREY}╭{'─'*(W-2)}╮{R}"
def _box_bot(W: int = 60) -> str: return f"{GREY}╰{'─'*(W-2)}╯{R}"

def print_startup_panel(port: int, room_name: str, hub: str, motd: str,
                        public_addr: str, protected: bool):
    W   = 60
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    access_str = f"{YELLOW}🔒 Password protected{R}" if protected else f"{GREEN}🔓 Public (open){R}"
    env_src    = f"{GREEN}.env file{R}" if _env_path.exists() else f"{LGREY}environment variables{R}"
    print()
    print(get_banner())
    print()
    print(_box_top(W))
    print(_box_center(f"{CYAN}{BOLD}✦  ORION-NET  ✦{R}  {DIM}room server{R}", W))
    print(_box_center(f"{GREY}{now}{R}", W))
    print(_box_sep(W))
    print(_box_row("Room",    f"{YELLOW}{BOLD}{room_name}{R}", W))
    print(_box_row("Port",    f"{CYAN}{port}{R}", W))
    print(_box_row("Address", f"{LBLUE}{public_addr}{R}", W))
    print(_box_row("Hub",     f"{GREY}{hub}{R}", W))
    print(_box_row("MOTD",    f"{DIM}{motd[:38]}{'…' if len(motd) > 38 else ''}{R}", W))
    print(_box_row("History", f"{LGREY}last {MSG_HISTORY_SIZE} msgs (in-memory){R}", W))
    print(_box_row("Access",  access_str, W))
    print(_box_sep(W))
    print(_box_row("Config",  env_src, W))
    print(_box_bot(W))
    print()

def print_hub_status(room_id: str = ""):
    W = 60
    print(_box_top(W))
    if room_id:
        print(_box_row("Status",  f"{GREEN}● Registered with hub{R}", W))
        print(_box_row("Room ID", f"{CYAN}{BOLD}{room_id}{R}", W))
    else:
        print(_box_center(f"{YELLOW}▲  Reconnecting to hub…{R}", W))
    print(_box_bot(W))
    print()

def log_event(kind: str, msg: str):
    icons = {
        "join": f"{GREEN}→{R}", "leave": f"{YELLOW}←{R}",
        "auth_ok": f"{GREEN}✔{R}", "auth_fail": f"{RED}✘{R}",
        "chat": f"{BLUE}◆{R}", "cmd": f"{PURPLE}⌘{R}",
        "hub": f"{CYAN}⇅{R}", "sys": f"{YELLOW}⚙{R}",
        "error": f"{RED}✖{R}", "heartbeat": f"{GREY}♡{R}",
    }
    icon    = icons.get(kind, f"{GREY}·{R}")
    ts      = datetime.datetime.now().strftime("%H:%M:%S")
    msg_col = RED if kind in ("auth_fail","error") else (YELLOW if kind in ("leave","sys") else WHITE)
    msg     = re.sub(r"(\[[a-z0-9]{4,}\])", f"{CYAN}\\1{R}{msg_col}", msg)
    print(f"{GREY}{ts}{R}  {icon}  {msg_col}{msg}{R}")

# ─────────────────────────────────────────────
#  Runtime state  (all ephemeral)
# ─────────────────────────────────────────────

start_time        = time.time()
MAINTENANCE_MODE  = False

# ws → display name  (registered only after successful name handshake)
connected_clients: dict = {}

# Ephemeral in-memory history — no persistence, cleared on restart
message_history: deque = deque(maxlen=MSG_HISTORY_SIZE)

SESSION_KEY  = Fernet.generate_key()
cipher_suite = Fernet(SESSION_KEY)
log.info(f"Session key ready  {GREY}({SESSION_KEY.decode()[:8]}…){R}")

# ─────────────────────────────────────────────
#  Protocol helpers
# ─────────────────────────────────────────────

def _make_event(event: str, text: str) -> str:
    return json.dumps({"type": "event", "event": event, "text": text})

def _make_chat(sender: str, ct_b64: str) -> str:
    return json.dumps({"type": "chat", "from": sender, "ciphertext": ct_b64})

def _encrypt(text: str) -> str:
    return base64.b64encode(cipher_suite.encrypt(text.encode())).decode()

def _ts() -> str:
    return datetime.datetime.now().strftime("%H:%M")

# ─────────────────────────────────────────────
#  Broadcast helpers
# ─────────────────────────────────────────────

async def _broadcast_raw(payload: str, exclude=None):
    for ws in list(connected_clients.keys()):
        if ws is exclude:
            continue
        try:
            await ws.send(payload)
        except Exception:
            connected_clients.pop(ws, None)

async def _broadcast_event(event: str, text: str, exclude=None):
    message_history.append({"type": "event", "event": event, "text": text, "ts": _ts()})
    await _broadcast_raw(_make_event(event, text), exclude=exclude)

async def _send_chat(sender: str, plaintext: str, target=None):
    ct  = _encrypt(plaintext)
    pkt = _make_chat(sender, ct)
    message_history.append({"type": "chat", "from": sender, "ciphertext": ct, "ts": _ts()})
    if target:
        await target.send(pkt)
    else:
        await _broadcast_raw(pkt)

# ─────────────────────────────────────────────
#  Client handler
# ─────────────────────────────────────────────

async def handle_chat_client(websocket):
    if MAINTENANCE_MODE:
        try:
            await websocket.send(json.dumps({
                "type": "error",
                "message": "⚠️ Maintenance Mode is ON. Please try again later."
            }))
        except Exception:
            pass
        await websocket.close()
        return

    client_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    log_event("join", f"New connection  [{client_id}]")

    try:
        # ── 1. RSA handshake ────────────────────────────────────────
        raw_hs = await asyncio.wait_for(websocket.recv(), timeout=30)
        hs     = json.loads(raw_hs)
        if hs.get("type") != "handshake":
            await websocket.close()
            return

        public_key = serialization.load_pem_public_key(hs["pubkey"].encode())
        enc_key    = public_key.encrypt(
            SESSION_KEY,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None),
        )
        await websocket.send(json.dumps({
            "type": "session_key",
            "key":  base64.b64encode(enc_key).decode(),
        }))

        # ── 2. room_meta  ────────────────────────────────────────────
        # MOTD is sent ONLY here — not again as an event (prevents double display)
        await websocket.send(json.dumps({
            "type":      "room_meta",
            "locked":    bool(ROOM_PASSWORD),
            "motd":      ROOM_MOTD,
            "room_name": MY_ROOM_NAME,
            "history":   list(message_history),
        }))

        # ── 3. Password check ────────────────────────────────────────
        if ROOM_PASSWORD:
            raw_auth  = await asyncio.wait_for(websocket.recv(), timeout=60)
            auth_data = json.loads(raw_auth)

            if auth_data.get("type") != "auth":
                await websocket.send(json.dumps({"type":"auth_fail","message":"❌ Auth packet expected."}))
                await websocket.close()
                log_event("auth_fail", f"[{client_id}]  protocol violation")
                return

            try:
                submitted = cipher_suite.decrypt(
                    base64.b64decode(auth_data["ciphertext"])
                ).decode()
            except Exception:
                await websocket.send(json.dumps({"type":"auth_fail","message":"❌ Could not decrypt password."}))
                await websocket.close()
                log_event("auth_fail", f"[{client_id}]  bad crypto")
                return

            if submitted != ROOM_PASSWORD:
                await websocket.send(json.dumps({"type":"auth_fail","message":"❌ Wrong password."}))
                await websocket.close()
                log_event("auth_fail", f"[{client_id}]  wrong password")
                return

            await websocket.send(json.dumps({"type": "auth_ok"}))
            log_event("auth_ok", f"[{client_id}]  authenticated")

        # ── 4. Receive display name ──────────────────────────────────
        name_pkt = json.loads(await asyncio.wait_for(websocket.recv(), timeout=30))
        # Accept both {"type":"name",...} and legacy {"type":"chat",...}
        if name_pkt.get("type") not in ("name", "chat"):
            await websocket.close()
            return
        name = cipher_suite.decrypt(base64.b64decode(name_pkt["ciphertext"])).decode().strip()
        if not name or len(name) > 24:
            name = f"anon-{client_id}"

        # Register client only after full handshake completes
        connected_clients[websocket] = name
        log_event("join", f"[{client_id}]  '{name}'  ({len(connected_clients)} in room)")

        # ── 5. Welcome events (system only — MOTD already sent via room_meta) ──
        n = len(connected_clients)
        await websocket.send(_make_event("system",
            f"Welcome to {MY_ROOM_NAME}, {name}!  "
            f"({n} user{'s' if n != 1 else ''} here)"))
        await websocket.send(_make_event("system",
            "Messages are ephemeral — lost when the room goes offline."))
        await websocket.send(_make_event("system",
            "/help  /who  /time  /uptime  /motd  /nick <n>  /leave"))

        # Broadcast join to everyone else
        await _broadcast_event("join", f"{name} joined the room.", exclude=websocket)

        # ── 6. Message loop ──────────────────────────────────────────
        async for raw_msg in websocket:
            try:
                data = json.loads(raw_msg)
                if data.get("type") != "chat":
                    continue

                message = cipher_suite.decrypt(
                    base64.b64decode(data["ciphertext"])
                ).decode()
                sender  = connected_clients.get(websocket, "anonymous")

                if message.startswith("/"):
                    cmd_low = message.strip().lower()

                    if cmd_low == "/help":
                        await websocket.send(_make_event("system",
                            "Commands:\n"
                            "  /help       — this message\n"
                            "  /who        — list users in room\n"
                            "  /time       — server time\n"
                            "  /uptime     — room uptime\n"
                            "  /motd       — message of the day\n"
                            "  /nick <n>   — change your nickname\n"
                            "  /leave      — leave the room"))

                    elif cmd_low == "/who":
                        users = list(connected_clients.values())
                        await websocket.send(_make_event("system",
                            f"In room ({len(users)}): {', '.join(users)}"))

                    elif cmd_low == "/time":
                        await websocket.send(_make_event("system",
                            f"Server time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))

                    elif cmd_low == "/uptime":
                        up   = int(time.time() - start_time)
                        h, r = divmod(up, 3600); m, s = divmod(r, 60)
                        await websocket.send(_make_event("system",
                            f"Room uptime: {h}h {m}m {s}s"))

                    elif cmd_low == "/motd":
                        # /motd command sends it as event type "motd" for styled display
                        await websocket.send(_make_event("motd", ROOM_MOTD))

                    elif cmd_low.startswith("/nick "):
                        new_name = message.strip()[6:].strip()
                        if new_name and 1 <= len(new_name) <= 24:
                            old_name = connected_clients[websocket]
                            connected_clients[websocket] = new_name
                            await _broadcast_event("rename",
                                f"{old_name} is now known as {new_name}.")
                            log_event("cmd", f"[{client_id}]  /nick  {old_name} → {new_name}")
                        else:
                            await websocket.send(_make_event("system",
                                "Nickname must be 1–24 characters."))

                    else:
                        await websocket.send(_make_event("system",
                            f"Unknown: {cmd_low.split()[0]}  (try /help)"))

                    log_event("cmd", f"[{client_id}]  {cmd_low.split()[0]}")

                else:
                    log_event("chat", f"[{client_id}]  {LGREY}{sender}{R}  (encrypted)")
                    await _send_chat(sender, message)

            except Exception as e:
                log_event("error", f"[{client_id}]  decode: {e}")

    except asyncio.TimeoutError:
        log_event("error", f"[{client_id}]  handshake timeout")
    except ConnectionClosed:
        pass
    except Exception as e:
        log_event("error", f"[{client_id}]  {e}")
    finally:
        name = connected_clients.pop(websocket, None)
        if name:
            log_event("leave", f"[{client_id}]  '{name}'  ({len(connected_clients)} remaining)")
            try:
                await _broadcast_event("leave", f"{name} left the room.")
            except Exception:
                pass

# ─────────────────────────────────────────────
#  Simple HTTP health check (for Render)
#  Render's health check hits / over HTTP — websockets.serve is WS-only
#  and returns 426, causing Render to think the service is unhealthy.
#  This runs a tiny aiohttp-like responder on the same port is NOT possible,
#  so we run it on PORT+1 and tell Render to check that.
#  Actually: websockets 10+ handles HTTP upgrades fine; the "opening handshake
#  failed" logs come from Render's TCP health probe or bots. They are harmless
#  but spammy. We suppress them via log level above. No extra port needed.
# ─────────────────────────────────────────────

# ─────────────────────────────────────────────
#  PoW solver
# ─────────────────────────────────────────────

def solve_challenge(challenge: str, difficulty: int) -> str:
    target, nonce = "0" * difficulty, 0
    while True:
        if hashlib.sha256(f"{challenge}{nonce}".encode()).hexdigest().startswith(target):
            return str(nonce)
        nonce += 1

# ─────────────────────────────────────────────
#  Hub registration loop
# ─────────────────────────────────────────────

async def register_with_hub():
    hub_url    = HUB_URL.replace("http://","ws://").replace("https://","wss://")
    hub_ws_url = hub_url.rstrip("/") + "/ws"

    while True:
        try:
            log_event("hub", f"Connecting  {GREY}{hub_ws_url}{R}")
            async with connect(hub_ws_url) as ws:
                my_address = (
                    RENDER_EXTERNAL_URL
                    .replace("https://","wss://").replace("http://","ws://")
                ) or f"ws://localhost:{PORT}"

                await ws.send(json.dumps({
                    "type":    "register",
                    "name":    MY_ROOM_NAME,
                    "address": my_address,
                    "online":  len(connected_clients),
                    "locked":  bool(ROOM_PASSWORD),
                }))

                async def send_updates():
                    last_count, last_ping = len(connected_clients), time.time()
                    while True:
                        await asyncio.sleep(5)
                        current, now = len(connected_clients), time.time()
                        if current != last_count:
                            try:
                                await ws.send(json.dumps({"type":"status_update","online":current}))
                                last_count = current
                            except Exception:
                                break
                        if now - last_ping >= 300:
                            try:
                                await ws.send(json.dumps({"type":"status_update","online":current}))
                                last_ping = now
                                log_event("heartbeat", f"Heartbeat  {GREY}({current} online){R}")
                            except Exception:
                                break

                update_task = asyncio.create_task(send_updates())
                try:
                    async for raw in ws:
                        try:
                            data = json.loads(raw)
                        except Exception:
                            continue

                        if data.get("type") == "challenge":
                            ch   = data["challenge_string"]
                            diff = int(data.get("difficulty", 4))
                            log_event("hub", f"Solving PoW  {GREY}(diff={diff}){R}")
                            nonce = solve_challenge(ch, diff)
                            await ws.send(json.dumps({
                                "type": "response",
                                "challenge_string": ch,
                                "nonce": nonce,
                            }))

                        elif data.get("type") == "success":
                            room_id = data.get("id", "?")
                            global MAINTENANCE_MODE
                            MAINTENANCE_MODE = data.get("maintenance", False)
                            log_event("hub", f"Registered  Room ID: {CYAN}{BOLD}{room_id}{R}")
                            print_hub_status(room_id)

                        elif data.get("type") == "maintenance_update":
                            MAINTENANCE_MODE = data.get("enabled", False)
                            flag = "ON" if MAINTENANCE_MODE else "OFF"
                            log_event("sys", f"Maintenance → {YELLOW if MAINTENANCE_MODE else GREEN}{flag}{R}")
                            txt = ("⚠️ Maintenance Mode enabled." if MAINTENANCE_MODE
                                   else "✅ Maintenance Mode disabled.")
                            await _broadcast_raw(_make_event("system", txt))

                        elif data.get("type") == "broadcast":
                            msg = data.get("message", "")
                            if msg:
                                log_event("sys", f"Broadcast: {LGREY}{msg}{R}")
                                await _broadcast_raw(_make_event("system", f"📢 {msg}"))
                finally:
                    update_task.cancel()

        except Exception as e:
            log_event("error", f"Hub lost: {e}  {GREY}retrying in 10s{R}")
            await asyncio.sleep(10)

# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────

# ─────────────────────────────────────────────
#  HTTP companion server  (PORT+1)
#  Serves only room.html and /node/status.
#  All lore/puzzle pages live on orion-core.
# ─────────────────────────────────────────────

HTTP_PORT = PORT + 1
_SRC = Path(__file__).parent / "src"

def _http_response(status: str, ctype: str, body: bytes,
                   extra_headers: dict = None) -> bytes:
    hdrs = (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: {ctype}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
    )
    if extra_headers:
        for k, v in extra_headers.items():
            hdrs += f"{k}: {v}\r\n"
    return hdrs.encode() + b"\r\n" + body

async def _http_handler(reader: asyncio.StreamReader,
                        writer: asyncio.StreamWriter):
    """Minimal HTTP handler — room status page and JSON API only."""
    try:
        raw   = await asyncio.wait_for(reader.read(4096), timeout=5)
        req   = raw.decode(errors="replace")
        line  = req.split("\r\n")[0] if "\r\n" in req else req.split("\n")[0]
        parts = line.split()
        path  = parts[1].split("?")[0] if len(parts) >= 2 else "/"

        up = round(time.time() - start_time)

        # ── /node/status — public JSON API ──────────────────────────
        if path == "/node/status":
            body = json.dumps({
                "room_name": MY_ROOM_NAME,
                "motd":      ROOM_MOTD,
                "online":    len(connected_clients),
                "locked":    bool(ROOM_PASSWORD),
                "uptime":    up,
                "node_id":   SESSION_KEY.decode()[:6],
            }).encode()
            writer.write(_http_response("200 OK", "application/json", body, {
                "Access-Control-Allow-Origin": "*",
                "X-Node-Ephemeral": "true",
            }))

        # ── / and /room — room status page ──────────────────────────
        elif path in ("/", "/room"):
            p = _SRC / "room.html"
            if p.exists():
                body = p.read_bytes()
            else:
                body = b"<h1>room.html not found in src/</h1>"
            writer.write(_http_response("200 OK",
                                        "text/html; charset=utf-8", body))

        # ── everything else → redirect to / ─────────────────────────
        else:
            writer.write(
                b"HTTP/1.1 302 Found\r\nLocation: /\r\n"
                b"Connection: close\r\n\r\n")

        await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def main():
    public_addr = (
        RENDER_EXTERNAL_URL
        .replace("https://","wss://").replace("http://","ws://")
    ) or f"ws://localhost:{PORT}"

    print_startup_panel(
        port=PORT, room_name=MY_ROOM_NAME, hub=HUB_URL,
        motd=ROOM_MOTD, public_addr=public_addr, protected=bool(ROOM_PASSWORD),
    )

    # Suppress noisy "opening handshake failed" from health probes / bots
    logging.getLogger("websockets.server").setLevel(logging.ERROR)

    chat_server  = serve(handle_chat_client, "0.0.0.0", PORT)
    http_server  = await asyncio.start_server(_http_handler, "0.0.0.0", HTTP_PORT)

    log_event("hub", f"Chat server  on port {CYAN}{PORT}{R}")
    log_event("hub", f"HTTP status  on port {CYAN}{HTTP_PORT}{R}  (room.html + /node/status)")

    async with chat_server, http_server:
        asyncio.create_task(register_with_hub())
        await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{DIM}Orion-Net shutting down.{R}")
