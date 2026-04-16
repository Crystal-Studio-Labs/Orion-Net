# ✦ Orion-Net

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![WebSockets](https://img.shields.io/badge/WebSockets-Enabled-green)
![Encryption](https://img.shields.io/badge/Encryption-RSA%20%2B%20Fernet-purple)
![Status](https://img.shields.io/badge/Status-Active-success)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Architecture](https://img.shields.io/badge/Architecture-Decentralized-orange)
![Deploy](https://img.shields.io/badge/Deploy-Render-46E3B7?logo=render&logoColor=black)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/Crystal-Studio-Labs/orion-net)

---

**Orion-Net** is the **room server component** of the Orion decentralized chat system.  
It powers encrypted chat rooms with **ephemeral messaging**, **secure client communication**, and **hub-based discovery**.

> ✦ Orion — decentralized · encrypted · ephemeral

---

## 🏢 Organization

Developed under:  
👉 https://github.com/Crystal-Studio-Labs

---

## ✨ Features

- 🔐 **End-to-End Encryption**
  - RSA handshake for secure session key exchange
  - Fernet encryption for all messages

- 🏠 **Ephemeral Rooms**
  - In-memory message history (deque)
  - No database, no persistence

- 🌐 **Hub Integration**
  - Registers with Orion-Core
  - Room discovery via Room ID
  - Proof-of-Work (PoW) protection

- 👥 **Multi-User System**
  - Join/leave events
  - Nickname system
  - Live user count

- 🔒 **Access Control**
  - Public rooms
  - Password-protected rooms

- 📡 **Broadcast System**
  - Encrypted messaging
  - Structured events
  - Admin broadcast relay

- ⚙️ **Runtime Features**
  - Maintenance mode
  - Heartbeat system
  - Auto-reconnect to hub

---

## 🚀 Deploy on Render

### 1. Click Deploy Button
Use the button at the top 👆

### 2. Or Manual Setup

- Create **Web Service**
- Connect repo
- Set:

```bash
Start Command: python orion-net.py
```

### 3. Environment Variables

```bash
HUB_URL=wss://orion-core.onrender.com
MY_ROOM_NAME=My Room
PORT=8765
ROOM_MOTD=Welcome!
ROOM_PASSWORD=
RENDER_EXTERNAL_URL=https://your-service.onrender.com
```

> ⚠️ Required for hub discovery

---

## 📦 Local Setup

```bash
git clone https://github.com/Crystal-Studio-Labs/orion-net
cd orion-net
pip install websockets cryptography
python orion-net.py
```

---

## ⚙️ Configuration

Priority:
1. Environment Variables  
2. config.json  
3. Defaults  

---

### Example `config.json`

```json
{
  "HUB_URL": "wss://orion-core.onrender.com",
  "MY_ROOM_NAME": "My Cool Room",
  "PORT": 8765,
  "ROOM_MOTD": "Welcome, traveller.",
  "ROOM_PASSWORD": "secret123",
  "RENDER_EXTERNAL_URL": ""
}
```

---

## 🧠 Architecture

```
        ┌───────────────┐
        │ Orion-Core    │
        │   (Hub)       │
        └──────┬────────┘
               │
        WebSocket (/ws)
               │
     ┌─────────▼─────────┐
     │   Orion-Net       │
     │  (Room Server)    │
     └─────────┬─────────┘
               │
        WebSocket (Room)
               │
     ┌─────────▼─────────┐
     │   Clients (Deck)  │
     └───────────────────┘
```

---

## 🔐 Security Model

- RSA → key exchange  
- Fernet → encryption  
- Password auth → encrypted  

---

## ⚠️ Important Notes

- Messages are **ephemeral**
- Stored only in memory
- Lost on restart
- This is intentional

---

## 🛠️ Tech Stack

- Python
- websockets
- cryptography
- asyncio

---

## 👨‍💻 Author

**Shuvranshu Sahoo**  
🌐 https://sahooshuvranshu.me

---

## 📄 License

MIT License