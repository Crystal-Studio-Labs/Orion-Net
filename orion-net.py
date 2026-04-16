"""Orion-Net: room server that registers with Orion-Core hub.

Configuration priority (highest → lowest):
  1. Environment variables
  2. config.json in same directory
  3. Built-in defaults

config.json example:
  {
    "HUB_URL":             "wss://orion-core.onrender.com",
    "MY_ROOM_NAME":        "My Cool Room",
    "PORT":                8765,
    "ROOM_MOTD":           "Welcome, traveller.",
    "ROOM_PASSWORD":       "secret123",
    "RENDER_EXTERNAL_URL": ""
  }

Leave ROOM_PASSWORD empty or omit it entirely for a public (open) room.

MESSAGE SCHEMA — every packet is JSON with a "type" field:
  Outbound to clients:
    {"type":"session_key","key":"<b64>"}
    {"type":"room_meta","locked":bool,"motd":"<str>","room_name":"<str>","history":[...]}
    {"type":"auth_ok"}
    {"type":"auth_fail","message":"<str>"}
    {"type":"event","event":"join|leave|rename|system|motd","text":"<str>"}
    {"type":"chat","from":"<name>","ciphertext":"<b64>"}
    {"type":"error","message":"<str>"}
  Inbound from clients:
    {"type":"handshake","pubkey":"<pem>"}
    {"type":"auth","ciphertext":"<b64>"}          -- encrypted password
    {"type":"name","ciphertext":"<b64>"}          -- encrypted display name
    {"type":"chat","ciphertext":"<b64>"}          -- encrypted message body
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
from websockets import serve, connect
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# ─────────────────────────────────────────────
#  Config loader  (env → config.json → default)
# ─────────────────────────────────────────────

def _load_config() -> dict:
    cfg_path = Path(__file__).parent / "config.json"
    if cfg_path.exists():
        try:
            with open(cfg_path) as f:
                data = json.load(f)
            # Only filter explicit None; keep 0 for PORT etc.
            return {k: v for k, v in data.items() if v is not None and v != ""}
        except Exception as e:
            print(f"\033[38;5;196m[config] Failed to parse config.json: {e}\033[0m")
    return {}

_cfg = _load_config()

def _get(key: str, default):
    env_val = os.environ.get(key)
    if env_val is not None:
        return env_val
    return _cfg.get(key, default)

HUB_URL             = _get("HUB_URL",             "https://orion-core.onrender.com")
MY_ROOM_NAME        = _get("MY_ROOM_NAME",         "Orion Room")
RENDER_EXTERNAL_URL = _get("RENDER_EXTERNAL_URL",  None) or None
PORT                = int(_get("PORT",             8765))
ROOM_MOTD           = _get("ROOM_MOTD",            "Welcome to this Orion-Net room!")
ROOM_PASSWORD       = _get("ROOM_PASSWORD",        "") or ""
# Max in-memory messages kept per session (ephemeral — lost on restart)
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
logging.getLogger().handlers = [_log_handler]
logging.getLogger().setLevel(logging.INFO)
logging.getLogger("websockets").setLevel(logging.WARNING)
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
    raw = """\
▛▀▖       ▖      ▐   ▞▀▖   ▗       
▙▄▘▙▀▖▞▀▖▗▖▞▀▖▞▀▖▜▀  ▌ ▌▙▀▖▄ ▞▀▖▛▀▖
▌  ▌  ▌ ▌ ▌▛▀ ▌ ▖▐ ▖ ▌ ▌▌  ▐ ▌ ▌▌ ▌
▘  ▘  ▝▀ ▄▘▝▀▘▝▀  ▀  ▝▀ ▘  ▀▘▝▀ ▘ ▘"""
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
    cfg_src    = f"{GREEN}config.json{R}" if _cfg else f"{LGREY}env / defaults{R}"
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
    print(_box_row("History", f"{LGREY}last {MSG_HISTORY_SIZE} msgs (in-memory only){R}", W))
    print(_box_row("Access",  access_str, W))
    print(_box_sep(W))
    print(_box_row("Config",  cfg_src, W))
    print(_box_bot(W))
    print()

def print_hub_status(room_id: str = ""):
    W = 60
    print(_box_top(W))
    if room_id:
        print(_box_row("Status",  f"{GREEN}● Connected to hub{R}", W))
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
#  Runtime state  (all ephemeral — lost on restart)
# ─────────────────────────────────────────────

start_time        = time.time()
MAINTENANCE_MODE  = False

# ws → display name
connected_clients: dict = {}

# Ephemeral in-memory message history (no persistence)
# Each entry: {"type":"chat"|"event", "from":"<name>"|None, "text":"<str>", "ts":"HH:MM"}
message_history: deque = deque(maxlen=MSG_HISTORY_SIZE)

SESSION_KEY  = Fernet.generate_key()
cipher_suite = Fernet(SESSION_KEY)
log.info(f"Session key initialised  {GREY}({SESSION_KEY.decode()[:8]}…){R}")

# ─────────────────────────────────────────────
#  Protocol helpers
# ─────────────────────────────────────────────

def _make_event(event: str, text: str) -> str:
    """Build a structured event packet (NOT encrypted — server-level events)."""
    return json.dumps({"type": "event", "event": event, "text": text})

def _make_chat(sender: str, ciphertext_b64: str) -> str:
    """Build a structured chat packet."""
    return json.dumps({"type": "chat", "from": sender, "ciphertext": ciphertext_b64})

def _encrypt(text: str) -> str:
    """Encrypt text with the room session key and return base64."""
    return base64.b64encode(cipher_suite.encrypt(text.encode())).decode()

def _ts() -> str:
    return datetime.datetime.now().strftime("%H:%M")

# ─────────────────────────────────────────────
#  Broadcast helpers
# ─────────────────────────────────────────────

async def _broadcast_raw(payload: str, exclude=None):
    """Send a raw JSON string to all connected clients."""
    for ws in list(connected_clients.keys()):
        if ws is exclude:
            continue
        try:
            await ws.send(payload)
        except Exception:
            connected_clients.pop(ws, None)

async def _broadcast_event(event: str, text: str, exclude=None):
    """Broadcast a structured event to all clients and add to history."""
    message_history.append({"type": "event", "event": event, "text": text, "ts": _ts()})
    await _broadcast_raw(_make_event(event, text), exclude=exclude)

async def _send_encrypted_chat(sender: str, plaintext: str, target=None):
    """Encrypt a chat message and broadcast or send to single target."""
    ct  = _encrypt(plaintext)
    pkt = _make_chat(sender, ct)
    message_history.append({"type": "chat", "from": sender,
                             "ciphertext": ct, "ts": _ts()})
    if target:
        await target.send(pkt)
    else:
        await _broadcast_raw(pkt)

# ─────────────────────────────────────────────
#  Client handler
# ─────────────────────────────────────────────

async def handle_chat_client(websocket):
    if MAINTENANCE_MODE:
        await websocket.send(json.dumps({
            "type": "error",
            "message": "⚠️ Maintenance Mode is ON. Please try again later."
        }))
        await websocket.close()
        return

    client_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    log_event("join", f"New connection  [{client_id}]")

    try:
        # ── 1. RSA handshake ────────────────────────────────────────
        raw_hs = await websocket.recv()
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

        # ── 2. Send room_meta: locked, MOTD, room name, history ─────
        # History is sent so reconnecting users see recent context.
        # It is ephemeral — cleared when the room restarts.
        history_snapshot = list(message_history)
        await websocket.send(json.dumps({
            "type":      "room_meta",
            "locked":    bool(ROOM_PASSWORD),
            "motd":      ROOM_MOTD,
            "room_name": MY_ROOM_NAME,
            "history":   history_snapshot,
        }))

        # ── 3. Password check (before name is revealed) ─────────────
        if ROOM_PASSWORD:
            raw_auth  = await websocket.recv()
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
                await websocket.send(json.dumps({"type":"auth_fail","message":"❌ Wrong password. Access denied."}))
                await websocket.close()
                log_event("auth_fail", f"[{client_id}]  wrong password")
                return

            await websocket.send(json.dumps({"type": "auth_ok"}))
            log_event("auth_ok", f"[{client_id}]  authenticated")

        # ── 4. Receive encrypted display name ────────────────────────
        # Client sends {"type":"name","ciphertext":"<b64>"}
        name_pkt = json.loads(await websocket.recv())
        if name_pkt.get("type") != "name":
            # Backwards compat: older clients send {"type":"chat","ciphertext":...} for name
            if name_pkt.get("type") != "chat":
                await websocket.close()
                return
        name = cipher_suite.decrypt(base64.b64decode(name_pkt["ciphertext"])).decode().strip()
        if not name or len(name) > 24:
            name = f"anon-{client_id}"

        # Register only after name is confirmed
        connected_clients[websocket] = name
        log_event("join", f"[{client_id}]  '{name}'  ({len(connected_clients)} in room)")

        # ── 5. Welcome sequence ──────────────────────────────────────
        # a) Send MOTD directly to this client as a structured event
        await websocket.send(_make_event("motd", ROOM_MOTD))

        # b) Welcome message from the hub to this client (first-join greeting)
        welcome_lines = [
            f"Welcome to {MY_ROOM_NAME}, {name}!",
            f"There {'is' if len(connected_clients)==1 else 'are'} "
            f"{len(connected_clients)} user{'s' if len(connected_clients)!=1 else ''} here.",
            "This room is ephemeral — messages exist only while the room is active.",
            "Type /help for available commands.",
        ]
        for line in welcome_lines:
            await websocket.send(_make_event("system", line))

        # c) Commands hint
        await websocket.send(_make_event("system",
            "Commands: /help  /who  /time  /uptime  /motd  /nick <name>"))

        # d) Broadcast join event to everyone else
        await _broadcast_event("join", f"{name} has joined the room.", exclude=websocket)

        # ── 6. Main message loop ─────────────────────────────────────
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
                    cmd      = message.strip()
                    cmd_low  = cmd.lower()
                    response = None

                    if cmd_low == "/help":
                        response = (
                            "Commands:\n"
                            "  /help       — this message\n"
                            "  /who        — list users in room\n"
                            "  /time       — server time\n"
                            "  /uptime     — room uptime\n"
                            "  /motd       — message of the day\n"
                            "  /nick <n>   — change your nickname"
                        )
                        await websocket.send(_make_event("system", response))

                    elif cmd_low == "/who":
                        users = list(connected_clients.values())
                        response = f"In room ({len(users)}): {', '.join(users)}"
                        await websocket.send(_make_event("system", response))

                    elif cmd_low == "/time":
                        response = f"Server time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                        await websocket.send(_make_event("system", response))

                    elif cmd_low == "/uptime":
                        up   = int(time.time() - start_time)
                        h, r = divmod(up, 3600); m, s = divmod(r, 60)
                        response = f"Room uptime: {h}h {m}m {s}s"
                        await websocket.send(_make_event("system", response))

                    elif cmd_low == "/motd":
                        await websocket.send(_make_event("motd", ROOM_MOTD))

                    elif cmd_low.startswith("/nick "):
                        new_name = cmd[6:].strip()
                        if new_name and 1 <= len(new_name) <= 24:
                            old_name = connected_clients[websocket]
                            connected_clients[websocket] = new_name
                            await _broadcast_event(
                                "rename",
                                f"{old_name} is now known as {new_name}."
                            )
                            log_event("cmd", f"[{client_id}]  /nick  {old_name} → {new_name}")
                        else:
                            await websocket.send(_make_event("system",
                                "Nickname must be 1–24 characters."))
                    else:
                        await websocket.send(_make_event("system",
                            f"Unknown command: {cmd_low}  (try /help)"))

                    log_event("cmd", f"[{client_id}]  {cmd_low.split()[0]}")

                else:
                    log_event("chat", f"[{client_id}]  {LGREY}{sender}{R}  (encrypted)")
                    await _send_encrypted_chat(sender, message)

            except Exception as e:
                log_event("error", f"[{client_id}]  decode error: {e}")

    except Exception as e:
        log_event("error", f"[{client_id}]  connection error: {e}")
    finally:
        # ── Guaranteed cleanup ───────────────────────────────────────
        name = connected_clients.pop(websocket, None)
        if name:
            log_event("leave", f"[{client_id}]  '{name}'  ({len(connected_clients)} remaining)")
            # Fire-and-forget leave broadcast — don't let it block cleanup
            try:
                await _broadcast_event("leave", f"{name} has left the room.")
            except Exception:
                pass

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
            log_event("hub", f"Connecting to hub  {GREY}{hub_ws_url}{R}")
            async with connect(hub_ws_url) as ws:
                my_address = (
                    (RENDER_EXTERNAL_URL or "")
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
                            log_event("hub", f"Solving PoW  {GREY}(difficulty {diff}){R}")
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
                            log_event("hub", f"Registered  ·  Room ID: {CYAN}{BOLD}{room_id}{R}")
                            print_hub_status(room_id)
                            if MAINTENANCE_MODE:
                                log_event("sys", f"Hub reports  {YELLOW}Maintenance Mode ON{R}")

                        elif data.get("type") == "maintenance_update":
                            MAINTENANCE_MODE = data.get("enabled", False)
                            flag = "ON" if MAINTENANCE_MODE else "OFF"
                            log_event("sys", f"Maintenance Mode → {YELLOW if MAINTENANCE_MODE else GREEN}{flag}{R}")
                            sys_text = (
                                "⚠️ Maintenance Mode enabled. New connections are paused."
                                if MAINTENANCE_MODE else
                                "✅ Maintenance Mode disabled. Connections resumed."
                            )
                            await _broadcast_raw(_make_event("system", sys_text))

                        elif data.get("type") == "broadcast":
                            msg = data.get("message", "")
                            if msg:
                                log_event("sys", f"Admin broadcast: {LGREY}{msg}{R}")
                                await _broadcast_raw(_make_event("system", f"📢 {msg}"))
                finally:
                    update_task.cancel()

        except Exception as e:
            log_event("error", f"Hub connection lost: {e}  {GREY}— retrying in 10s{R}")
            await asyncio.sleep(10)

# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────

async def main():
    public_addr = (
        (RENDER_EXTERNAL_URL or "")
        .replace("https://","wss://").replace("http://","ws://")
    ) or f"ws://localhost:{PORT}"

    print_startup_panel(
        port=PORT, room_name=MY_ROOM_NAME, hub=HUB_URL,
        motd=ROOM_MOTD, public_addr=public_addr, protected=bool(ROOM_PASSWORD),
    )

    chat_server = serve(handle_chat_client, "0.0.0.0", PORT)
    log_event("hub", f"Chat server listening on port {CYAN}{PORT}{R}")
    async with chat_server:
        asyncio.create_task(register_with_hub())
        await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{DIM}Orion-Net shutting down.{R}")