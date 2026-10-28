# Discord Messenger - A Full-Featured Discord Clone

![Version](https://img.shields.io/badge/version-2.5.0-blue)
![Python](https://img.shields.io/badge/python-3.9%2B-green)
![Flask](https://img.shields.io/badge/Flask-2.x-red)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

A self-hosted, feature-rich Discord clone built with **Flask** (backend) and **vanilla JavaScript** (frontend). It recreates the core Discord experience — servers, channels, direct messages, roles, permissions, and much more — while adding its own unique systems like **BotShop**, **Stories**, **Coin Boosting**, **Cosmetics Shop**, and a full **Admin Console**.

Everything is stored in a single JSON database (`data/database.json`) — no external database server required. The whole app runs from one `app.py` file and one `index.html` file.

---

## ✨ Features at a Glance

### 💬 Core Messaging
- **Servers** with categories, text channels, descriptions, and custom icons/banners
- **Direct Messages** with unread counts, seen/delivered ticks, and typing indicators
- **Replies, forwards, edits, and message deletion** (soft-delete → "This message was deleted")
- **Reactions** with a full emoji picker
- **Message effects** — Glow, Shake, Rainbow, Fire, Ice
- **Pinned messages** (multiple pins per chat, one-bar navigation)
- **Delete-message timers** (auto-disappearing messages: 10s, 1m, 1h, 1d, 1w)
- **Rich media** — image/video/audio uploads, voice messages, location sharing, and native polls
- **Markdown** support — bold, italic, underline, strikethrough, code, code blocks, quotes, links
- **Verified tick** (blue check) and **custom badges**
- **+18 content tagging** with parental-control blurring

### 👥 Social & Accounts
- **Multi-account switching** (up to 3 accounts per browser, no re-login)
- **Incognito accounts** — temporary anonymous accounts deleted with all their data on logout
- **Friend system** — requests, suggestions, mutual friends, block/unblock
- **Stories** — 24h-expiring photo/video/text stories with views, reactions, replies, and close-friends privacy
- **Privacy controls** (Telegram-style): phone, last seen, avatar, birth date, forwards, invites, story visibility
- **Parental controls** — daily limits, allowed hours, blocked tags, adult-content blocking

### 🏰 Server Management
- **Role system** with granular permissions (kick, ban, mute, manage channels, manage messages, etc.)
- **Channel access** — private channels, password-protected channels, read-only, view-only
- **Slowmode**, channel descriptions, age-restricted channels
- **Invites** with expiry and max-uses limits
- **Bans, mutes, kicks, ownership transfer**
- **Server & channel boosting** with coins (progress bars, level 12 → blue check)
- **Server Hub** — browse and join public servers
- **Import from Discord** — request imports via invite links

### 💰 Economy & Customization
- **Coins system** — earn, transfer, spend
- **Cosmetics Shop** — avatar rings (solid/gradient/spin/rainbow/pulse/glow) and bio effects (rainbow/neon/shimmer/glitch/fire/typewriter/sparkle/pulse)
- **Sticker & GIF packs** — user-created, installable, sellable (price in coins)
- **Chat backgrounds** — per-channel/server/DM/global, solid/gradient/image
- **Nitro** — channel and server Nitro entitlements

### 🤖 BotShop (Built-in Bot Platform)
- Upload `.js` bot files (sandboxed with Node.js `vm` + worker threads)
- Bots run with strict limits — 5s timeout, 64MB memory cap, 30 messages/min
- Per-server installation with channel selection and custom prefixes
- **Permission system** — bots declare `// @permissions: channels, roles, members, ...`; owners approve
- **Server management** — bots can create channels, manage roles, kick/ban/mute (within granted permissions)
- **Tickets** — bots with `tickets` permission can create private support channels
- **Economy** — bots can send coins from command author to members
- **Command suggestions** above the chat input with autocomplete

### 🛡️ Admin Console
- **Overview dashboard** — stats, message/signup charts, recent users & reports
- **User management** — edit identity, badges, coins, suspend/unsuspend, reset passwords, send warnings
- **Custom badges** — create, assign, revoke with full history
- **Server management** — edit/delete servers, channels, kick members
- **Reports system** — user-submitted reports with evidence, priorities, status workflow, reply to reporter, and quick actions (delete message, warn, suspend, delete server/channel, hide/delete packs)
- **Emails** — approve/reject registration emails
- **Store, Imports, Site settings, Audit log**
- **Broadcast** — send notifications to all users
- **Report Locks** — servers/channels with too many active reports are automatically restricted

### 🎨 UI/UX
- Discord-inspired clean dark theme with blurple accents
- Fully responsive layout
- Custom dialogs replacing `confirm()`/`prompt()`
- Toast notifications
- Rich animations and transitions
- Verified ticks, typing indicators in the chat header
- Notification center with unread badges

---

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- Node.js 18+ (only required for the **BotShop** feature)
- pip

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/discord-messenger.git
cd discord-messenger

# 2. Install Python dependencies
pip install flask werkzeug requests

# 3. Run the app
python app.py
```

The app will start on `http://localhost:4212`.

On first start, an admin account is created. **The credentials are printed to the console** — save them:

```
🔑 First start: admin login = admin@discord.com / <generated-password>
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | auto-generated | Flask session secret (persisted in `data/secret_key`) |
| `DEFAULT_ADMIN_PASSWORD` | random | Admin password on first start |
| `SESSION_COOKIE_SECURE` | `0` | Set to `1` behind HTTPS |
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `4212` | Bind port |
| `FLASK_DEBUG` | `0` | Debug mode |
| `MAX_UPLOAD_MB` | `100` | Max upload size |
| `MAX_MESSAGE_LENGTH` | `200` | Max message length |
| `ANTIBOT_TOKEN` | (empty) | Shared secret for `/api/antibot/*` endpoints |
| `ALLOWED_ORIGINS` | (empty) | Comma-separated list of allowed origins (CSRF guard) |

---

## 📁 Project Structure

```
.
├── app.py                  # The entire Flask backend
├── index.html              # The entire frontend (HTML + CSS + JS)
├── data/
│   ├── database.json       # Main database (users, servers, messages, ...)
│   ├── emails.json         # Approved registration emails
│   ├── import_requests.json
│   ├── user_settings.json  # Per-user settings (sound, privacy, etc.)
│   ├── stories.json        # Stories (24h expiring)
│   ├── cosmetics.json      # Shop items (rings, bio effects)
│   ├── chat_backgrounds.json
│   ├── secret_key          # Flask secret key
│   ├── db.lock             # Cross-process write lock
│   ├── uploads/            # All uploaded files
│   └── botshop/
│       ├── bots/           # Uploaded bot .js files
│       ├── storage/        # Per-install bot storage (JSON)
│       └── runner.js       # Node.js sandbox runner
└── static/
    ├── gif/                # Legacy GIFs
    ├── sticker/            # Legacy stickers
    └── Picture3.png        # Auth background
```

---

## 🔒 Security Notes

- **All state-changing API requests** are guarded by a cross-process file lock to prevent JSON corruption.
- **CSRF protection** via Origin header validation.
- **Login brute-force protection** — 10 failed attempts per 10 minutes per IP/email.
- **Suspended users** are blocked at the request gate with a `403`.
- **Uploads** are validated by magic bytes (real file content), not just extension. Only images, video, audio, and PDF are accepted.
- **Stories media** is served with a `Content-Security-Policy: sandbox` header and obeys story privacy.
- **BotShop bots** run in isolated `vm` contexts with `codeGeneration: { strings: false, wasm: false }` and worker threads capped at 64MB. They never touch the host filesystem or network.
- **Password hashes** use Werkzeug's `generate_password_hash` (PBKDF2 by default).
- **Server ownership is sovereign** — site admins cannot edit or delete servers by default (`ADMIN_CAN_EDIT_SERVERS = False`). Only the owner can manage their server.

> ⚠️ **Important:** For production deployment, always set `SECRET_KEY`, `DEFAULT_ADMIN_PASSWORD`, and `SESSION_COOKIE_SECURE=1`, and place the app behind a reverse proxy (nginx, Caddy) with HTTPS.

---

## 🤖 BotShop Bot Format

Bots are plain JavaScript files with a comment-header metadata block:

```javascript
// @name: Hello Bot
// @icon: 👋
// @color: #5865f2
// @author: Me
// @version: 1.0.0
// @description: Says hello. Try !hello and !count.
// @permissions: channels, roles      // optional: what the bot can manage
bot.prefix = '!';

bot.command('hello', { description: 'Say hello', usage: '[name]' }, (ctx, args) => {
  ctx.reply('Hello ' + (args[0] || ctx.user.username) + '!');
});

bot.command('count', { description: 'Count uses' }, (ctx) => {
  const n = (ctx.storage.get('n') || 0) + 1;   // saved per server
  ctx.storage.set('n', n);
  ctx.reply('Used ' + n + ' times');
});

bot.on('memberJoin', (ctx) => ctx.send('Welcome ' + ctx.user.username));
```

**Available `ctx` methods:**
- `ctx.reply(text)` / `ctx.send(text[, channelId])` / `ctx.react(emoji)`
- `ctx.createChannel(name, opts)` — needs `channels` permission
- `ctx.storage.get/set/delete/list` — per-server JSON data (max 100KB)
- `ctx.findUser(text)` — look up a member

**Management commands** (declare with `// @permissions:`): `editChannel`, `deleteChannel`, `createCategory`, `createRole`, `giveRole`, `kick`, `ban`, `mute`, `purge`, `editServer`, plus `createTicket` for the `tickets` group and `giveCoins` for the `economy` group.

---

## 🧪 API Overview

The API is RESTful and JSON-based. Every endpoint returns JSON. Some highlights:

| Endpoint | Description |
|---|---|
| `GET/POST /api/servers` | List / create servers |
| `GET/POST /api/channels/<id>/messages` | Read / send messages |
| `POST /api/messages/<id>/react` | Toggle a reaction |
| `POST /api/messages/<id>/poll/vote` | Vote in a poll |
| `GET/POST /api/dm/<user_id>/messages` | Read / send DMs |
| `GET /api/stories` | List stories visible to you |
| `POST /api/stories` | Post a photo/video story |
| `GET /api/botshop/bots` | List available bots |
| `POST /api/botshop/install` | Install a bot on a server |
| `GET /api/cosmetics/items` | List shop items |
| `GET /api/reports/mine` | Your submitted reports |
| `GET /api/admin2/overview` | Admin dashboard stats |
| `GET /api/activity/poll?since=...` | Poll for new messages (for sounds) |

---

## 🎨 Screenshots

*(Add your own screenshots here — a good README makes a big difference.)*

| Chat View | Admin Panel | Shop |
|---|---|---|
| ![chat](screenshots/chat.png) | ![admin](screenshots/admin.png) | ![shop](screenshots/shop.png) |

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask, Werkzeug |
| Database | Single JSON file with file-locking (`fcntl`), atomic writes |
| Frontend | Vanilla JavaScript (no framework), CSS3, Font Awesome 6 |
| Bot runtime | Node.js, `vm` module, worker threads |
| Auth | Flask sessions (signed cookies) |

---

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/my-feature`).
3. Commit your changes.
4. Open a pull request.

For major changes, please open an issue first to discuss what you'd like to change.

---

## 📄 License

This project is licensed under the **MIT License** — see the `LICENSE` file for details.

---

## 🙏 Acknowledgments

- Inspired by [Discord](https://discord.com) — the UI and UX
- Icons by [Font Awesome](https://fontawesome.com)
- Built with [Flask](https://flask.palletsprojects.com)

---

## ⚠️ Disclaimer

This is an **educational / personal project** and is **not affiliated with, endorsed by, or connected to Discord Inc.** "Discord" is a trademark of Discord Inc. Use at your own risk. The authors are not responsible for any misuse or data loss.

---

<p align="center">
  Made with 💜 by <strong>SilverTeam</strong>
</p>
