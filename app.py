from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
import json
import re
import os
import urllib.parse
import uuid
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import threading
import time
from flask import Flask, render_template, render_template_string, request, jsonify, session, redirect, url_for, send_from_directory
app = Flask(__name__)
DATA_DIR = 'data'
os.makedirs(DATA_DIR, exist_ok=True)
import secrets as _secrets
from flask import g


class _FileRLock:
    """Re-entrant lock that is also held across processes (fcntl) when the OS supports it."""
    def __init__(self, path):
        self._rlock = threading.RLock()
        self._path = path
        self._depth = 0
        self._fh = None

    def acquire(self):
        self._rlock.acquire()
        if self._depth == 0:
            try:
                import fcntl
                self._fh = open(self._path, 'a+')
                fcntl.flock(self._fh, fcntl.LOCK_EX)
            except Exception:
                self._fh = None
        self._depth += 1
        return True

    def release(self):
        self._depth -= 1
        if self._depth == 0 and self._fh is not None:
            try:
                import fcntl
                fcntl.flock(self._fh, fcntl.LOCK_UN)
                self._fh.close()
            except Exception:
                pass
            self._fh = None
        self._rlock.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc):
        self.release()
        return False


def _load_secret_key():
    """SECRET_KEY env var, else a random key stored once in data/secret_key (never hard-coded)."""
    env = os.getenv('SECRET_KEY')
    if env:
        return env
    path = os.path.join(DATA_DIR, 'secret_key')
    try:
        with open(path, 'r', encoding='utf-8') as f:
            key = f.read().strip()
            if key:
                return key
    except OSError:
        pass
    key = _secrets.token_hex(32)
    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(key)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except OSError:
        pass
    return key


app.secret_key = _load_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.getenv('SESSION_COOKIE_SECURE', '0') == '1',
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    MAX_CONTENT_LENGTH=int(os.getenv('MAX_UPLOAD_MB', '100')) * 1024 * 1024,
)

# Every state-changing API request runs under this lock, so the JSON "database"
# can no longer lose updates (read-modify-write is atomic per request).
write_lock = _FileRLock(os.path.join(DATA_DIR, 'db.lock'))


@app.before_request
def _csrf_origin_and_write_lock():
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE') and request.path.startswith('/api/'):
        origin = request.headers.get('Origin')
        if origin and not request.path.startswith('/api/antibot/'):
            allowed = {request.host}
            allowed |= {h.strip() for h in os.getenv('ALLOWED_ORIGINS', '').split(',') if h.strip()}
            if urllib.parse.urlparse(origin).netloc not in allowed and origin not in allowed:
                return jsonify({'error': 'Cross-site request blocked'}), 403
        write_lock.acquire()
        g._write_locked = True
    return None


@app.teardown_request
def _release_write_lock(exc):
    if g.pop('_write_locked', False):
        write_lock.release()
UPLOAD_DIR = os.path.join(DATA_DIR, 'uploads')
DB_FILE = os.path.join(DATA_DIR, 'database.json')
db_lock = threading.Lock()

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)
BOOST_CONFIG = {
    'costPerBoost': 500,
    'maxBoostsPerUser': 3,
    'levels': {
        1: 2, 2: 5, 3: 10, 4: 15, 5: 20,
        6: 25, 7: 30, 8: 35, 9: 40, 10: 45,
        11: 50, 12: 60
    }
}
BADGE_FIELDS = [
    'vip', 'staff', 'developer', 'verified', 'nitro', 'partner',
    'early_supporter', 'bug_hunter', 'translator', 'support',
    'is_active', 'reputation', 'server_boost_level', 'is_moderator',
    'is_bot', 'hypesquad_house'
]
EMAILS_FILE = os.path.join(DATA_DIR, 'emails.json')
DEFAULT_ADMIN_EMAIL = "admin@discord.com"
DEFAULT_ADMIN_PASSWORD = os.getenv('DEFAULT_ADMIN_PASSWORD') or _secrets.token_urlsafe(12)
_ADMIN_PW_FROM_ENV = bool(os.getenv('DEFAULT_ADMIN_PASSWORD'))
typing_users = {}  # { "channel_xxx": { "user_id": timestamp } }
typing_lock = threading.Lock()

# ============================================
# PRESENCE / VERIFIED TICK / MESSAGE STATUS HELPERS
# ============================================
import time as _time
presence_seen = {}          # user_id -> unix time of the last authenticated API request
PRESENCE_TTL = 25           # seconds; the client polls every ~3s while the tab is open
TYPING_ACTIVITIES = ('typing', 'sticker', 'emoji', 'gif')


def user_is_verified(u):
    """Blue verified tick (admin or the JS bot can grant it). Both legacy keys are honoured."""
    try:
        return bool(u.get('verified') or u.get('is_verified'))
    except Exception:
        return False


def is_user_online(db, uid):
    """True when the user has an open session (recent request) and is not invisible."""
    u = (db.get('users') or {}).get(uid) or {}
    if not u or u.get('is_deleted'):
        return False
    if u.get('status') == 'offline':
        return False
    try:
        if not get_privacy(db, uid).get('show_online_status', True):
            return False
    except Exception:
        pass
    return (_time.time() - presence_seen.get(uid, 0)) < PRESENCE_TTL


def _typing_entry():
    """Body of the typing ping: {"activity": "typing" | "sticker" | "emoji" | "gif" | "stop"}."""
    data = request.get_json(silent=True) or {}
    act = str(data.get('activity') or 'typing').lower()
    if act != 'stop' and act not in TYPING_ACTIVITIES:
        act = 'typing'
    return {'t': datetime.now().isoformat(), 'a': act}


def _typing_activity_of(entry):
    if isinstance(entry, dict):
        return entry.get('a') or 'typing'
    return 'typing'


def _typing_store(key, uid):
    """Store (or clear, when activity == stop) the typing entry. Caller holds no lock."""
    entry = _typing_entry()
    with typing_lock:
        if entry['a'] == 'stop':
            if key in typing_users:
                typing_users[key].pop(uid, None)
                if not typing_users[key]:
                    del typing_users[key]
        else:
            typing_users.setdefault(key, {})[uid] = entry


def dm_message_status(db, msg, receiver_id):
    """sent (receiver offline) -> delivered (receiver online, not seen) -> seen."""
    if msg.get('seen_at'):
        return 'seen'
    if msg.get('delivered_at'):
        return 'delivered'
    if is_user_online(db, receiver_id):
        msg['delivered_at'] = datetime.now().isoformat()   # sticky: stays delivered even if they go offline
        return 'delivered'
    return 'sent'
# اضافه کردن این کدها قبل از تعریف روت‌ها:
MAX_MESSAGE_LENGTH = int(os.getenv('MAX_MESSAGE_LENGTH', '200'))
# در بالای فایل app.py، کنار سایر متغیرهای دیتابیس
IMPORT_REQUESTS_FILE = os.path.join(DATA_DIR, 'import_requests.json')

def load_import_requests():
    """Load import requests from JSON file"""
    if not os.path.exists(IMPORT_REQUESTS_FILE):
        return []
    try:
        with open(IMPORT_REQUESTS_FILE, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                return []
            return json.loads(content)
    except (json.JSONDecodeError, FileNotFoundError):
        return []

def save_import_requests(requests_list):
    """Save import requests to JSON file"""
    with open(IMPORT_REQUESTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(requests_list, f, indent=4, ensure_ascii=False)
# ============================================
# PRIVACY & FRIENDS PREFERENCES (enforced server-side)
# ============================================
PRIVACY_DEFAULTS = {
    'profile_visibility': 'everyone',
    'show_online_status': True,
    'allow_friend_requests': True,
    'allow_dms_from_strangers': True,
    'show_activity_status': True,
    'allow_analytics': False,
    # Telegram-style visibility controls: everyone | contacts | nobody
    'phone_visibility': 'nobody',
    'last_seen_visibility': 'nobody',
    'avatar_visibility': 'contacts',
    'birthdate_visibility': 'contacts',
    'forwards_visibility': 'everyone',
    'invites_visibility': 'everyone',
    # Stories: everyone | contacts | close_friends | server | nobody
    'story_visibility': 'everyone',
}
PRIVACY_CHOICES = ('everyone', 'contacts', 'nobody', 'close_friends', 'server')
FRIENDS_PREF_DEFAULTS = {
    'auto_accept_mutual': True,
    'request_notifications': True,
    'show_shared_servers': True,
}

def get_privacy(db, uid):
    s = dict(PRIVACY_DEFAULTS)
    s.update(db.get('privacy_settings', {}).get(uid, {}))
    return s

def get_friends_prefs(db, uid):
    p = dict(FRIENDS_PREF_DEFAULTS)
    p.update(db.get('friends_settings', {}).get(uid, {}))
    return p

def are_friends(db, a, b):
    if not a or not b or a == b:
        return False
    return b in (db['users'].get(a, {}).get('friends', []) or [])

def forward_author_name(db, original_user, forwarder_id):
    """Name shown on a forwarded message, honouring the author's 'forwarded messages' privacy."""
    oid = (original_user or {}).get('id')
    name = (original_user or {}).get('username', 'Unknown')
    if not oid or oid == forwarder_id:
        return name
    mode = get_privacy(db, oid).get('forwards_visibility')
    return name if privacy_allows(db, oid, forwarder_id, mode) else 'Hidden user'

def privacy_allows(db, owner_id, viewer_id, mode):
    """True when `viewer_id` may see something the owner restricted with `mode`."""
    mode = 'contacts' if mode == 'friends' else (mode or 'everyone')
    if mode == 'everyone':
        return True
    if mode == 'nobody':
        return False
    return are_friends(db, owner_id, viewer_id) or are_friends(db, viewer_id, owner_id)

def apply_privacy_to_user(db, viewer_id, user):
    """Returns a copy of a user dict with the owner's privacy settings applied for this viewer."""
    uid = user.get('id')
    if not uid or uid == viewer_id or uid not in db.get('users', {}):
        return user
    s = get_privacy(db, uid)
    out = dict(user)
    viewer = db.get('users', {}).get(viewer_id, {}) if viewer_id else {}
    if viewer.get('is_admin'):
        return out
    for _k in _PRIVATE_USER_FIELDS:
        out.pop(_k, None)
    if not privacy_allows(db, uid, viewer_id, s.get('phone_visibility')):
        out['phone'] = None
    if not privacy_allows(db, uid, viewer_id, s.get('birthdate_visibility')):
        out['birthdate'] = None
    if not privacy_allows(db, uid, viewer_id, s.get('avatar_visibility')):
        out['avatar'] = None
        out['is_animated'] = False
    if not privacy_allows(db, uid, viewer_id, s.get('last_seen_visibility')):
        out['last_seen'] = None
        if out.get('status') in ('online', 'idle', 'dnd'):
            out['status'] = 'offline'
    if not s.get('show_online_status', True) and out.get('status') in ('online', 'idle', 'dnd'):
        out['status'] = 'offline'
    if not s.get('show_activity_status', True):
        out['current_activity'] = None
    vis = s.get('profile_visibility', 'everyone')
    hidden = vis == 'nobody' or (vis == 'friends' and not are_friends(db, viewer_id, uid))
    if hidden:
        out['bio'] = ''
        out['banner'] = None
        out['current_activity'] = None
        out['profile_hidden'] = True
    return out

def _privacy_walk(db, viewer_id, data):
    if isinstance(data, list):
        return [_privacy_walk(db, viewer_id, x) for x in data]
    if isinstance(data, dict):
        if 'id' in data and 'username' in data:
            data = apply_privacy_to_user(db, viewer_id, data)
        return {k: _privacy_walk(db, viewer_id, v) for k, v in data.items()}
    return data

def privacy_filtered(fn):
    """Decorator: filters every user object in a JSON response through the owners' privacy settings."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        resp = fn(*args, **kwargs)
        body, status = (resp if isinstance(resp, tuple) else (resp, None))
        if not hasattr(body, 'get_data'):
            return resp
        try:
            data = json.loads(body.get_data(as_text=True))
        except (ValueError, TypeError):
            return resp
        db = load_database()
        filtered = jsonify(_privacy_walk(db, session.get('user_id'), data))
        return (filtered, status) if status is not None else filtered
    return wrapper

# ============================================
# SPAM PROTECTION - Message Rate Limiting
# ============================================
message_timestamps = {}  # { "user_id": [timestamp1, timestamp2, ...] }
rate_limit_lock = threading.Lock()
MESSAGE_RATE_LIMIT_MS = 800  # میلی‌ثانیه
def limit_message_length(content):
    """
    محدود کردن طول پیام به حداکثر MAX_MESSAGE_LENGTH کاراکتر
    برمی‌گرداند: (limited_content, was_truncated, length)
    """
    if not content:
        return content, False, 0
    
    content_length = len(content)
    
    if content_length > MAX_MESSAGE_LENGTH:
        truncated_content = content[:MAX_MESSAGE_LENGTH]
        return truncated_content, True, content_length
    
    return content, False, content_length

def check_message_rate_limit(user_id):
    """
    بررسی محدودیت نرخ ارسال پیام
    برمی‌گرداند: (allowed: bool, wait_time_ms: int)
    """
    now = datetime.now()
    current_ms = int(now.timestamp() * 1000)
    
    with rate_limit_lock:
        if user_id not in message_timestamps:
            message_timestamps[user_id] = []
        
        # پاک کردن تایم‌استمپ‌های قدیمی (بالای 10 ثانیه)
        cutoff_ms = current_ms - 10000
        message_timestamps[user_id] = [
            ts for ts in message_timestamps[user_id] 
            if ts > cutoff_ms
        ]
        
        # بررسی آخرین پیام
        if message_timestamps[user_id]:
            last_msg_ms = message_timestamps[user_id][-1]
            elapsed_ms = current_ms - last_msg_ms
            
            if elapsed_ms < MESSAGE_RATE_LIMIT_MS:
                wait_time_ms = MESSAGE_RATE_LIMIT_MS - elapsed_ms
                return False, wait_time_ms
        
        # ثبت زمان پیام فعلی
        message_timestamps[user_id].append(current_ms)
        return True, 0


def cleanup_rate_limit_data():
    """پاکسازی داده‌های قدیمی"""
    now = datetime.now()
    current_ms = int(now.timestamp() * 1000)
    cutoff_ms = current_ms - 60000  # 1 دقیقه
    
    with rate_limit_lock:
        for user_id in list(message_timestamps.keys()):
            message_timestamps[user_id] = [
                ts for ts in message_timestamps[user_id] 
                if ts > cutoff_ms
            ]
            if not message_timestamps[user_id]:
                del message_timestamps[user_id]

# ============================================
# SYSTEM DMs  (pinned, read-only conversations)
#   "Admin Warn" -> warnings / private messages sent by administrators
#   "Discord"    -> every other system notice (suspension, announcements, report updates...)
# The user can read them but can never reply (the input box is locked).
# ============================================
SYSTEM_DM_USERS = {
    'adminwarn': {'id': 'adminwarn', 'username': 'Admin Warn', 'avatar': None,
                  'avatar_color': '#ed4245', 'icon': 'fa-triangle-exclamation'},
    'discordsys': {'id': 'discordsys', 'username': 'Discord', 'avatar': None,
                   'avatar_color': '#5865f2', 'icon': 'fa-discord'},
    'deliverysys': {'id': 'deliverysys', 'username': 'Discord Message Delivery', 'avatar': None,
                    'avatar_color': '#f0b232', 'icon': 'fa-paper-plane'},
}
SYSTEM_DM_ORDER = ['adminwarn', 'deliverysys', 'discordsys']          # order of the pinned entries
SYSTEM_DM_LOCK_TEXT = "Can't send message"
SYSTEM_DM_WARN_TYPES = ('warning', 'admin_message')    # notification types that go to "Admin Warn"
SYSTEM_DM_MAX_MESSAGES = 200                           # per user and per system conversation


def is_system_dm_id(uid):
    return uid in SYSTEM_DM_USERS


def system_dm_key(user_id, sys_id):
    return f"dm_{'_'.join(sorted([user_id, sys_id]))}"


def system_dm_author(sys_id):
    s = SYSTEM_DM_USERS[sys_id]
    return {'id': s['id'], 'username': s['username'], 'avatar': s['avatar'],
            'avatar_color': s['avatar_color'], 'is_premium': False, 'is_system': True}


def post_system_dm(db, user_id, sys_id, content):
    """Append a message from a system user to the DM of user_id (in memory; the caller saves the db)."""
    target = db['users'].get(user_id)
    if not target or target.get('is_bot') or sys_id not in SYSTEM_DM_USERS:
        return None
    key = system_dm_key(user_id, sys_id)
    lst = db.setdefault('direct_messages', {}).setdefault(key, [])
    mid = uuid.uuid4().hex[:12]
    lst.append({
        'id': mid, 'dm_key': key, 'user_id': sys_id, 'content': str(content)[:2000],
        'image_url': None, 'created_at': datetime.now().isoformat(),
        'reactions': {}, 'reply_to': None, 'effect': 'none', 'system_dm': True,
    })
    if len(lst) > SYSTEM_DM_MAX_MESSAGES:
        del lst[:len(lst) - SYSTEM_DM_MAX_MESSAGES]
    return mid


def system_dm_read_at(db, user_id, sys_id):
    return (db.get('system_dm_read', {}).get(user_id, {}) or {}).get(sys_id, '')


def system_dm_mark_read(db, user_id, sys_id):
    """Returns True when the read marker moved (so the caller knows the db must be saved)."""
    msgs = db.get('direct_messages', {}).get(system_dm_key(user_id, sys_id), [])
    if not msgs:
        return False
    last = msgs[-1].get('created_at', '')
    marks = db.setdefault('system_dm_read', {}).setdefault(user_id, {})
    if marks.get(sys_id, '') >= last:
        return False
    marks[sys_id] = last
    return True


def system_dm_conversations(db, user_id):
    """Pinned conversation entries for /api/dm/conversations."""
    out = []
    for sys_id in SYSTEM_DM_ORDER:
        msgs = db.get('direct_messages', {}).get(system_dm_key(user_id, sys_id), [])
        if not msgs:
            continue
        s = SYSTEM_DM_USERS[sys_id]
        read_at = system_dm_read_at(db, user_id, sys_id)
        unread = sum(1 for m in msgs if (m.get('created_at') or '') > read_at)
        out.append({
            'user_id': sys_id, 'username': s['username'], 'avatar': s['avatar'],
            'avatar_color': s['avatar_color'], 'icon': s['icon'],
            'last_message_at': msgs[-1].get('created_at', ''),
            'unread_count': min(unread, 99), 'is_online': False,
            'pinned': True, 'is_system': True, 'locked': True,
        })
    return out


def system_dm_enrich(db, user_id, sys_id):
    """Messages of a system conversation, in the same shape /api/dm/<id>/messages normally returns."""
    author = system_dm_author(sys_id)
    msgs = db.get('direct_messages', {}).get(system_dm_key(user_id, sys_id), [])
    return [{**m, 'reply_info': None, 'author': author} for m in msgs]


def notify_blocked_delivery(db, sender_id, receiver_id):
    """The receiver blocked the sender: tell the sender (from "Discord Message Delivery") that the message was not sent.
    Works in memory - the caller saves the db."""
    receiver = db['users'].get(receiver_id) or {}
    name = receiver.get('username') or 'This user'
    text = f"{name} has blocked you. Your message was not sent!"
    key = system_dm_key(sender_id, 'deliverysys')
    lst = db.get('direct_messages', {}).get(key, [])
    if lst and lst[-1].get('content') == text:
        try:   # same notice a moment ago (spam-clicking send) -> don't flood the conversation
            if (datetime.now() - datetime.fromisoformat(lst[-1]['created_at'])).total_seconds() < 3:
                return None
        except Exception:
            pass
    return post_system_dm(db, sender_id, 'deliverysys', text)


# ============================================
# DELETE-MESSAGE TIMER (auto-delete) + "This message was deleted" placeholder
# ============================================
AUTO_DELETE_CHOICES = (0, 10, 60, 3600, 86400, 604800)   # seconds; 0 = off
DELETED_TEXT = 'This message was deleted'
_KEEP_ON_DELETE = {'id', 'channel_id', 'dm_key', 'user_id', 'created_at', 'type', 'system_dm'}


def get_auto_delete_seconds(db, scope_key):
    try:
        return int((db.get('auto_delete') or {}).get(scope_key, 0) or 0)
    except (TypeError, ValueError):
        return 0


def stamp_expiry(db, scope_key, message):
    """Give a new message its expiry time when the chat has a delete timer."""
    secs = get_auto_delete_seconds(db, scope_key)
    if secs > 0:
        message['expires_at'] = (datetime.now() + timedelta(seconds=secs)).isoformat()
        message['auto_delete_seconds'] = secs
    return message


def soft_delete_message(msg, by_user_id):
    """Turn a message into a "This message was deleted" placeholder (nothing of the old content is kept)."""
    for k in list(msg.keys()):
        if k not in _KEEP_ON_DELETE:
            del msg[k]
    msg.update({
        'content': DELETED_TEXT, 'image_url': None, 'reactions': {}, 'reply_to': None,
        'effect': 'none', 'edited_at': None,
        'deleted': True, 'deleted_at': datetime.now().isoformat(), 'deleted_by': by_user_id,
    })
    return msg


def purge_expired_messages(db):
    """Remove every message whose delete timer ran out. Returns how many were removed (caller saves when > 0)."""
    now = datetime.now().isoformat()
    removed = 0
    allm = db.get('all_messages', {})
    for mid in [mid for mid, m in allm.items() if m.get('expires_at') and m['expires_at'] <= now]:
        del allm[mid]
        removed += 1
    for lst in db.get('direct_messages', {}).values():
        if any(m.get('expires_at') and m['expires_at'] <= now for m in lst):
            keep = [m for m in lst if not (m.get('expires_at') and m['expires_at'] <= now)]
            removed += len(lst) - len(keep)
            lst[:] = keep
    return removed


def _auto_delete_loop():
    while True:
        time.sleep(15)
        try:
            with write_lock:
                db = load_database()
                if purge_expired_messages(db):
                    save_database(db)
        except Exception as e:
            print(f"⚠️ auto-delete sweep failed: {e}")


def init_database():
    """Initialize database file if it doesn't exist"""
    if not os.path.exists(DB_FILE):
        print("📂 Database file not found. Creating new one...")
        db = {
            "users": {},
            "servers": {},
            "categories": {},
            "channels": {},
            "threads": {},
            "all_messages": {},
            "store_items": {},
            "premium_users": {},
            "saved_messages": {},
            "settings": {
                "store_enabled": True,
                "registration_enabled": True,
                "upload_enabled": True
            },
            "uploads": {},
            "invites": {},
            "bans": {},
            "mutes": {},
            "direct_messages": {},
            "notifications": [],
            "blocked_users": {},
            "devices": {},
            "parental_control": {},
            "privacy_settings": {},
            "antibot_pending": [],
            "friend_requests": [],
            "friends_settings": {},
            # === فیلدهای جدید Badge ===
            "badge_history": {},  # {user_id: [{action, badge, by, at}]}
            "hypesquad_applications": []  # درخواست‌های HypeSquad
        }
        save_database(db)
        create_admin_user(db)
        return db
    return load_database()

def load_emails():
    """Load approved emails from JSON file"""
    if not os.path.exists(EMAILS_FILE):
        return {}
    try:
        with open(EMAILS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return {}

def save_emails(emails):
    """Save approved emails to JSON file"""
    with open(EMAILS_FILE, 'w', encoding='utf-8') as f:
        json.dump(emails, f, indent=4, ensure_ascii=False)

def send_welcome_message(db, server_id, user_id):
    # 1. پیدا کردن کاربر برای دریافت نام او
    user = db['users'].get(user_id, {})
    username = user.get('username', 'User')
    
    # 2. پیدا کردن کانال general در این سرور
    general_channel_id = None
    for ch_id, channel in db['channels'].items():
        # اصلاح شرط: استفاده از == به جای space
        if channel.get('server_id') == server_id and channel.get('name', '').lower() == 'general':
            general_channel_id = ch_id
            break
            
    # اگر کانال general وجود نداشت، پیامی ارسال نمی‌شود
    if not general_channel_id:
        return

    # 3. ساختن پیام خوش‌آمدگویی
    message_id = str(uuid.uuid4().hex[:12])
    welcome_content = f"Welcome to the server, **{username}**! 🎉"
    
    new_message = {
        'id': message_id,
        'channel_id': general_channel_id,
        'user_id': 'system',
        'content': welcome_content,
        'image_url': None,
        'created_at': datetime.now().isoformat(),
        'edited_at': None,
        'reactions': {},
        'type': 'message'
    }
    
    # 4. ذخیره در دیتابیس (فقط در حافظه)
    db['all_messages'][message_id] = new_message
    
    # ❌ حذف خط زیر: save_database(db)
    # ✅ ذخیره نهایی توسط تابعی که این را صدا زده انجام می‌شود

def create_admin_user(db):
    """Create the initial admin user"""
    for uid, user in db['users'].items():
        if user.get('is_admin'):
            return
    
    user_id = str(uuid.uuid4())[:8]
    if not _ADMIN_PW_FROM_ENV:
        print(f'🔑 First start: admin login = {DEFAULT_ADMIN_EMAIL} / {DEFAULT_ADMIN_PASSWORD}  (change it, it is shown only once)')
    db['users'][user_id] = {
        'id': user_id,
        'username': 'Admin',
        'email': DEFAULT_ADMIN_EMAIL,
        'password': generate_password_hash(DEFAULT_ADMIN_PASSWORD),
        'avatar': None,
        'avatar_color': '#7289da',
        'status': 'online',
        'bio': 'System Administrator',
        'is_admin': True,
        'is_premium': True,
        'premium_since': datetime.now().isoformat(),
        'coins': 999999,
        'inventory': [],
        'friends': [],
        'created_at': datetime.now().isoformat(),
        'last_seen': datetime.now().isoformat(),
        'home_logo': None,
	'home_icon': 'fa-discord',
	'home_color': '#7289da',
	'home_bg_color': '#5865f2',
        # === فیلدهای Badge ===
        'vip': True,
        'staff': True,
        'developer': True,
        'verified': True,
        'nitro': True,
        'partner': True,
        'hypesquad_house': 'brilliance',
        'early_supporter': True,
        'bug_hunter': True,
        'translator': True,
        'support': True,
        'is_active': True,
        'reputation': 9999,
        'server_boost_level': 12,
        'is_moderator': False,
        'is_bot': False,
        'is_developer': True,
        'is_verified': True,
        'is_partner': True,
        'is_early_supporter': True,
        'is_bug_hunter': True,
        'is_translator': True,
        'is_support': True,
        'blocked_users': [],
        'devices': [],
        'banner': None,
        'is_animated': False,
        'current_activity': None,
        'is_nitro': True,
        'hypesquad_houses': None
    }
    
    server_id = 'server_admin_global'
    db['servers'][server_id] = {
        'id': server_id,
        'name': 'Admin Headquarters',
        'owner_id': user_id,
        'members': [user_id],
        'icon': '🛡️',
        'created_at': datetime.now().isoformat(),
        # === ساختار boost ===
        'boosts': [],           # لیست کل بوست‌ها
        'user_boosts': {},      # {user_id: [timestamps]}
        'has_blue_check': False,
        'roles': {
            'admin': {
                'id': 'admin',
                'name': 'Admin',
                'color': '#ED4245',
                'permissions': ['manage_server', 'kick', 'ban', 'unban', 'mute', 'manage_channels', 'manage_messages']
            },
            'moderator': {
                'id': 'moderator',
                'name': 'Moderator',
                'color': '#FEE75C',
                'permissions': ['kick', 'ban', 'mute', 'manage_messages']
            },
            'member': {
                'id': 'member',
                'name': 'Member',
                'color': '#747e8c',
                'permissions': ['send_messages', 'react']
            }
        },
        'user_roles': {user_id: ['admin']}
    }
    
    for channel_name in ['general', 'announcements', 'admin-chat']:
        channel_id = f"channel_{uuid.uuid4().hex[:8]}"
        db['channels'][channel_id] = {
            'id': channel_id,
            'server_id': server_id,
            'name': channel_name,
            'type': 'text',
            'category_id': None,
            'created_at': datetime.now().isoformat()
        }
    
    save_database(db)

def load_database():
    """Load database from JSON file safely"""
    if not os.path.exists(DB_FILE):
        return init_database()
    
    try:
        with open(DB_FILE, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # اگر فایل خالی بود
        if not content.strip():
            print("⚠️ Database file is empty. Reinitializing...")
            return init_database()
            
        # تلاش برای پارس کردن JSON
        try:
            db = json.loads(content)
            # اعتبارسنجی ساده: باید یک دیکشنری باشد
            if not isinstance(db, dict):
                raise ValueError("Database root is not a dictionary")
            return db
        except json.JSONDecodeError as e:
            print(f"❌ Database JSON decode error: {e}")
            print("⚠️ Database corrupted. Reinitializing...")
            # ایجاد بک‌آپ از فایل خراب
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = f"{DB_FILE}.corrupted_{timestamp}.bak"
            try:
                import shutil
                shutil.copy2(DB_FILE, backup_file)
                print(f"📁 Backup created: {backup_file}")
            except Exception as copy_err:
                print(f"⚠️ Could not create backup: {copy_err}")
            return init_database()
            
    except Exception as e:
        print(f"❌ Unexpected error loading database: {e}")
        return init_database()


def save_database(db):
    """Save database to JSON file safely"""
    # استفاده از قفل برای جلوگیری از نوشتن همزمان
    with db_lock:
        try:
            # نوشتن موقت در یک فایل موقت و سپس جابجایی آن (Atomic Write)
            # این روش از خراب شدن فایل اصلی جلوگیری می‌کند
            temp_file = f"{DB_FILE}.tmp"
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(db, f, indent=4, ensure_ascii=False)
            
            # جابجایی فایل موقت به فایل اصلی
            import shutil
            shutil.move(temp_file, DB_FILE)
            
        except Exception as e:
            print(f"❌ Error saving database: {e}")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        db = load_database()
        user = db['users'].get(session['user_id'], {})
        if not user.get('is_admin', False):
            return jsonify({'error': 'Admin required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Every permission the server knows about. The server owner always has all of them,
# and nobody can take them away: the owner role and the owner's roles are locked.
ALL_SERVER_PERMISSIONS = ['manage_server', 'kick', 'ban', 'unban', 'mute', 'manage_channels',
                          'manage_messages', 'send_messages', 'react']
LOCKED_ROLE_IDS = ('owner',)


def get_user_permissions(db, user_id, server_id):
    """Get user permissions for a server"""
    server = db['servers'].get(server_id)
    if not server:
        return []
    
    user_roles = server.get('user_roles', {}).get(user_id, ['member'])
    all_permissions = set()
    
    for role_id in user_roles:
        role = server.get('roles', {}).get(role_id)
        if role:
            all_permissions.update(role.get('permissions', []))
    
    # Owner has all permissions (cannot be changed by roles)
    if server.get('owner_id') == user_id:
        all_permissions.update(ALL_SERVER_PERMISSIONS)
    
    return list(all_permissions)

def has_permission(db, user_id, server_id, permission):
    """Check if user has specific permission"""
    return permission in get_user_permissions(db, user_id, server_id)


# ============================================
# OWNER SOVEREIGNTY
# Only the owner of a server can change its settings, channels, categories, roles,
# invites list, members list and private-channel access. Not site admins, not "manage_*" roles.
# The owner is never limited by private / password / read-only / view-only channels.
# ============================================
ADMIN_CAN_SET_NITRO = True        # Nitro is a platform entitlement, not a server setting
ADMIN_CAN_EDIT_SERVERS = False    # admin panel: edit server / kick / delete channel
ADMIN_CAN_DELETE_SERVERS = False  # admin panel: delete a whole server


def is_server_owner(db, uid, server_or_id):
    server = server_or_id if isinstance(server_or_id, dict) else db.get('servers', {}).get(server_or_id)
    return bool(server and uid and server.get('owner_id') == uid)


def owner_only_response(msg='Only the server owner can do this'):
    return jsonify({'error': msg, 'code': 'OWNER_ONLY'}), 403


def _strip_member_from_private_channels(db, server_id, user_id):
    """A member who leaves / is kicked / banned must lose every private-channel right,
    otherwise they get it back the moment they join again."""
    if not server_id or not user_id:
        return False
    owner_id = (db.get('servers', {}).get(server_id) or {}).get('owner_id')
    changed = False
    for ch in db.get('channels', {}).values():
        if ch.get('server_id') != server_id:
            continue
        for key in ('private_members', 'view_only_members', 'unlocked_users'):
            lst = ch.get(key)
            if isinstance(lst, list) and user_id in lst:
                lst[:] = [u for u in lst if u != user_id]
                changed = True
        if ch.get('creator_id') == user_id and owner_id and owner_id != user_id:
            ch['creator_id'] = owner_id
            changed = True
    return changed

# --- File Upload ---
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return _serve_upload(filename)


def _legacy_uploaded_file(filename):
    """
    این روت فایل‌های آپلود شده را از پوشه uploads می‌خواند و به کاربر می‌دهد.
    """
    try:
        return send_from_directory(UPLOAD_DIR, filename)
    except FileNotFoundError:
        # اگر فایل پیدا نشد، یک تصویر پیش‌فرض یا خطا برگردانید
        return jsonify({'error': 'File not found'}), 404


        # --- Leave Server ---
@app.route('/api/servers/<server_id>/leave', methods=['POST'])
@login_required
def leave_server(server_id):
    db = load_database()
    server = db['servers'].get(server_id)
    
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    # صاحب سرور نمی‌تواند سرور را ترک کند (باید حذف کند)
    if server.get('owner_id') == session['user_id']:
        return jsonify({'error': 'Server owner cannot leave. Please delete the server instead.'}), 403
    
    # اگر کاربر عضو نیست
    if session['user_id'] not in server.get('members', []):
        return jsonify({'error': 'Not a member of this server'}), 400
    
    # حذف کاربر از لیست اعضا و نقش‌ها
    if session['user_id'] in server['members']:
        server['members'].remove(session['user_id'])
        _strip_member_from_private_channels(db, server_id, session['user_id'])
    
    if session['user_id'] in server.get('user_roles', {}):
        del server['user_roles'][session['user_id']]
        
    save_database(db)
    return jsonify({'success': True})

def cleanup_old_typing(channel_key, timeout_seconds=5):
    """پاک کردن کاربرانی که دیگر تایپ نمی‌کنند"""
    with typing_lock:
        if channel_key not in typing_users:
            return
        
        now = datetime.now()
        users_to_remove = []
        
        for user_id, timestamp in list(typing_users[channel_key].items()):
            if isinstance(timestamp, dict):
                timestamp = timestamp.get('t')
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp)
                except:
                    timestamp = now
            
            if (now - timestamp).total_seconds() > timeout_seconds:
                users_to_remove.append(user_id)
        
        for user_id in users_to_remove:
            del typing_users[channel_key][user_id]
        
        if not typing_users[channel_key]:
            del typing_users[channel_key]

# --- Channel Typing Endpoints ---

# ============================================
# PRIVATE CHANNEL GUARD
# Every route that works on one channel (typing, threads, bulk delete, auto-delete, ...),
# one thread or one message is checked here, so a channel the user can not see
# behaves exactly like a missing one (404) for them.
# ============================================
_CH_PATH_RE = re.compile(r'^/api/channels/([^/]+)(?:/|$)')
_THREAD_PATH_RE = re.compile(r'^/api/threads/([^/]+)(?:/|$)')
_MSG_PATH_RE = re.compile(r'^/api/messages/([^/]+)(?:/|$)')


@app.before_request
def _private_channel_guard():
    uid = session.get('user_id')
    if not uid or not request.path.startswith('/api/'):
        return None
    m = _CH_PATH_RE.match(request.path)
    t = _THREAD_PATH_RE.match(request.path)
    g = _MSG_PATH_RE.match(request.path)
    if not (m or t or g):
        return None
    db = load_database()
    channel = None
    if m:
        channel = db['channels'].get(m.group(1))
    elif t:
        th = (db.get('threads') or {}).get(t.group(1))
        channel = db['channels'].get(th.get('channel_id')) if th else None
    else:
        msg = (db.get('all_messages') or {}).get(g.group(1))
        channel = db['channels'].get(msg.get('channel_id')) if msg else None
    if channel is None:
        return None          # unknown id: the route answers as before
    server = db['servers'].get(channel.get('server_id'))
    if server is None:
        return None
    if server.get('owner_id') == uid:
        return None          # the owner always has full access: private, password, read-only ... never apply
    if uid not in server.get('members', []):
        return jsonify({'error': 'Not a member'}), 403
    acc = channel_access(db, channel, uid)
    if not acc['visible']:
        return jsonify({'error': 'Channel not found'}), 404
    if acc['locked'] and not request.path.endswith('/unlock'):
        return jsonify({'error': 'This channel is locked. Enter the password first.', 'code': 'CHANNEL_LOCKED'}), 403
    return None


@app.before_request
def _presence_touch():
    """Remember that the logged-in user is online right now (in memory only, no db write)."""
    uid = session.get('user_id')
    if uid and request.path.startswith('/api/'):
        presence_seen[uid] = _time.time()
    return None


@app.route('/api/channels/<channel_id>/typing', methods=['POST'])
@login_required
def channel_typing_signal(channel_id):
    """ثبت سیگنال تایپ کاربر برای کانال"""
    db = load_database()
    
    channel = db['channels'].get(channel_id)
    if not channel:
        return jsonify({'error': 'Channel not found'}), 404
    
    server = db['servers'].get(channel['server_id'])
    if not server or session['user_id'] not in server.get('members', []):
        return jsonify({'error': 'Not a member'}), 403
    
    channel_key = f"channel_{channel_id}"
    
    with typing_lock:
        if channel_key not in typing_users:
            typing_users[channel_key] = {}
        
        pass
    _typing_store(channel_key, session['user_id'])
    
    return jsonify({'success': True})

@app.route('/api/channels/<channel_id>/typing')
@login_required
def get_channel_typing_users(channel_id):
    """دریافت لیست کاربرانی که در کانال تایپ می‌کنند"""
    db = load_database()
    
    channel = db['channels'].get(channel_id)
    if not channel:
        return jsonify({'error': 'Channel not found'}), 404
    
    server = db['servers'].get(channel['server_id'])
    if not server or session['user_id'] not in server.get('members', []):
        return jsonify({'error': 'Not a member'}), 403
    
    channel_key = f"channel_{channel_id}"
    
    # پاک کردن تایمرهای قدیمی
    cleanup_old_typing(channel_key)
    
    with typing_lock:
        typing_snapshot = dict(typing_users.get(channel_key, {}))
        typing_user_ids = list(typing_snapshot.keys())
    
    typing_users_list = []
    for uid in typing_user_ids:
        if uid == session['user_id']:
            continue
        
        user = db['users'].get(uid)
        if user:
            typing_users_list.append({
                'activity': _typing_activity_of(typing_snapshot.get(uid)),
                'id': user.get('id'),
                'username': user.get('username'),
                'avatar': user.get('avatar'),
                'avatar_color': user.get('avatar_color', '#7289da')
            })
    
    return jsonify({'typing_users': typing_users_list})

# --- DM Typing Endpoints ---

@app.route('/api/dm/<user_id>/typing', methods=['POST'])
@login_required
def dm_typing_signal(user_id):
    """ثبت سیگنال تایپ کاربر برای DM"""
    if is_system_dm_id(user_id):
        return jsonify({'error': SYSTEM_DM_LOCK_TEXT, 'code': 'SYSTEM_DM_LOCKED'}), 403
    db = load_database()
    
    if user_id not in db['users']:
        return jsonify({'error': 'User not found'}), 404
    
    dm_key = tuple(sorted([session['user_id'], user_id]))
    dm_key_str = f"dm_{'_'.join(dm_key)}"
    
    with typing_lock:
        if dm_key_str not in typing_users:
            typing_users[dm_key_str] = {}
        
        pass
    _typing_store(dm_key_str, session['user_id'])
    
    return jsonify({'success': True})

@app.route('/api/dm/<user_id>/typing')
@login_required
def get_dm_typing_users(user_id):
    """دریافت لیست کاربرانی که در DM تایپ می‌کنند"""
    if is_system_dm_id(user_id):
        return jsonify({'typing_users': []})
    db = load_database()
    
    if user_id not in db['users']:
        return jsonify({'error': 'User not found'}), 404
    
    dm_key = tuple(sorted([session['user_id'], user_id]))
    dm_key_str = f"dm_{'_'.join(dm_key)}"
    
    # پاک کردن تایمرهای قدیمی
    cleanup_old_typing(dm_key_str)
    
    with typing_lock:
        typing_snapshot = dict(typing_users.get(dm_key_str, {}))
        typing_user_ids = list(typing_snapshot.keys())
    
    typing_users_list = []
    for uid in typing_user_ids:
        if uid == session['user_id']:
            continue
        
        user = db['users'].get(uid)
        if user:
            typing_users_list.append({
                'activity': _typing_activity_of(typing_snapshot.get(uid)),
                'id': user.get('id'),
                'username': user.get('username'),
                'avatar': user.get('avatar'),
                'avatar_color': user.get('avatar_color', '#7289da')
            })
    
    return jsonify({'typing_users': typing_users_list})

# --- Delete Server ---
@app.route('/api/servers/<server_id>', methods=['DELETE'])
@login_required
def delete_server(server_id):
    db = load_database()
    server = db['servers'].get(server_id)
    
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    # فقط صاحب سرور می‌تواند آن را حذف کند
    if server.get('owner_id') != session['user_id']:
        return jsonify({'error': 'Only the server owner can delete this server'}), 403
    
    # 1. حذف سرور
    del db['servers'][server_id]
    
    # 2. حذف تمام کانال‌های این سرور
    channels_to_delete = [ch_id for ch_id, ch in db['channels'].items() if ch.get('server_id') == server_id]
    for ch_id in channels_to_delete:
        del db['channels'][ch_id]
        
    # 3. حذف تمام پیام‌های این سرور (اختیاری، اما برای تمیزی دیتابیس خوب است)
    # اگر دیتابیس بزرگ است، این بخش را حذف کنید تا سرعت بالا برود.
    messages_to_delete = [msg_id for msg_id, msg in db['all_messages'].items() if msg.get('channel_id') in channels_to_delete]
    for msg_id in messages_to_delete:
        del db['all_messages'][msg_id]

    # 4. حذف بن‌ها و میوت‌های این سرور
    if server_id in db.get('bans', {}):
        del db['bans'][server_id]
    if server_id in db.get('mutes', {}):
        del db['mutes'][server_id]
        
    # 5. حذف اینوایت‌های این سرور
    invites_to_delete = [inv_code for inv_code, inv in db['invites'].items() if inv.get('server_id') == server_id]
    for inv_code in invites_to_delete:
        del db['invites'][inv_code]
        
    # 6. حذف دسته‌بندی‌های این سرور
    cats_to_delete = [cat_id for cat_id, cat in db['categories'].items() if cat.get('server_id') == server_id]
    for cat_id in cats_to_delete:
        del db['categories'][cat_id]
        
    for _tid in [t for t, th in (db.get('threads') or {}).items() if th.get('server_id') == server_id]:
        db['threads'].pop(_tid, None)
    for _cid in channels_to_delete:
        (db.get('auto_delete') or {}).pop(_cid, None)
        (db.get('message_pins') or {}).pop('ch_' + _cid, None)
    save_database(db)
    return jsonify({'success': True})

# --- User visuals: custom avatar ring image + DM panel background ---
USER_VISUAL_EXTS = ('gif', 'png', 'jpg', 'jpeg', 'webp')

def _save_user_visual(file, ext, kind):
    if ext not in USER_VISUAL_EXTS:
        return jsonify({'error': 'Only GIF, PNG, JPG or WEBP files are allowed'}), 400
    new_filename = f"{uuid.uuid4().hex}.{ext}"
    url_path = f'/uploads/{new_filename}'
    try:
        file.save(os.path.join(UPLOAD_DIR, new_filename))
    except Exception as e:
        return jsonify({'error': 'Failed to save file', 'details': str(e)}), 500
    db = load_database()
    user = db['users'].get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    if kind == 'ring_image':
        user['avatar_ring'] = {
            'style': 'image', 'name': 'Custom image ring', 'colors': [],
            'url': url_path, 'animated': ext == 'gif'
        }
    else:
        user['dm_panel_bg'] = url_path
    save_database(db)
    user.pop('password', None)
    return jsonify({'success': True, 'url': url_path, 'user': user})

@app.route('/api/profile/visuals/<kind>', methods=['DELETE'])
@login_required
def clear_user_visual(kind):
    if kind not in ('ring_image', 'panel_bg'):
        return jsonify({'error': 'Unknown visual'}), 400
    db = load_database()
    user = db['users'].get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    if kind == 'ring_image':
        ring = user.get('avatar_ring') or {}
        if ring.get('style') == 'image':
            user['avatar_ring'] = None
    else:
        user['dm_panel_bg'] = None
    save_database(db)
    user.pop('password', None)
    return jsonify({'success': True, 'user': user})

# ============================================
# STORIES (Telegram-style, every story expires after 24h)
#
#   * stored in data/stories.json (NOT in the main DB, so it can be cached
#     and purged independently)
#   * uploaded media live in data/uploads/story_<uuid>.<ext>
#   * 24h expiry handled by a background thread + lazy check on read
#   * visibility enforced on list AND on view/react/reply/viewers
#   * in-memory cache invalidated by file mtime (safe across processes)
# ============================================
import json as _stories_json
import time as _stories_time

STORIES_FILE = os.path.join(DATA_DIR, 'stories.json')
stories_lock = _FileRLock(os.path.join(DATA_DIR, 'stories.lock'))
STORY_LIFETIME = 24 * 3600
STORY_IMAGE_EXTS = ('png', 'jpg', 'jpeg', 'gif', 'webp')
STORY_VIDEO_EXTS = ('mp4', 'webm')
STORY_MAX_BYTES = 30 * 1024 * 1024       # 30 MB per upload
STORY_MAX_CAPTION = 200
STORY_TEXT_MAX = 300
STORY_MAX_TEXT_BYTES = 5000              # cap for /text JSON body
STORY_PURGE_INTERVAL = 300               # seconds between background sweeps
STORY_PURGE_MIN_GAP = 60                 # seconds between lazy purges on GET
STORY_FILE_PREFIX = 'story_'             # uploaded media must start with this

# ---- in-memory cache ----
_stories_cache = {'data': None, 'mtime': None, 'loaded': False}
_stories_cache_lock = threading.RLock()
_stories_last_purge = {'t': 0}


def _stories_load_raw():
    """Read the JSON file (no cache). Returns {'stories': {}} on any failure."""
    if not os.path.exists(STORIES_FILE):
        return {'stories': {}}
    try:
        with open(STORIES_FILE, 'r', encoding='utf-8') as f:
            data = _stories_json.load(f)
        if not isinstance(data, dict):
            return {'stories': {}}
        data.setdefault('stories', {})
        return data
    except (ValueError, OSError):
        return {'stories': {}}


def _stories_load():
    """Cached load: returns the same dict object while the file is unchanged.
    The caller MUST hold stories_lock when it modifies the returned dict, and
    must call _stories_save_cached(data) afterwards."""
    with _stories_cache_lock:
        try:
            mtime = os.path.getmtime(STORIES_FILE) if os.path.exists(STORIES_FILE) else None
        except OSError:
            mtime = None
        if _stories_cache['loaded'] and _stories_cache['mtime'] == mtime:
            return _stories_cache['data']
        data = _stories_load_raw()
        _stories_cache['data'] = data
        _stories_cache['mtime'] = mtime
        _stories_cache['loaded'] = True
        return data


def _stories_save_raw(data):
    tmp = STORIES_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        _stories_json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, STORIES_FILE)


def _stories_save(data):
    """Write file and refresh the cache atomically. Caller holds stories_lock."""
    _stories_save_raw(data)
    with _stories_cache_lock:
        _stories_cache['data'] = data
        try:
            _stories_cache['mtime'] = os.path.getmtime(STORIES_FILE)
        except OSError:
            _stories_cache['mtime'] = None
        _stories_cache['loaded'] = True


def _stories_safe_media_name(media_url):
    """Only allow story_*.ext files to be deleted by the purge/delete routes."""
    if not media_url:
        return None
    name = os.path.basename(media_url)
    if not name.startswith(STORY_FILE_PREFIX):
        return None
    if not re.match(r'^story_[0-9a-f]+\.(png|jpe?g|gif|webp|mp4|webm)$', name, re.I):
        return None
    return name


def _stories_remove_media(media_url):
    name = _stories_safe_media_name(media_url)
    if not name:
        return
    try:
        os.remove(os.path.join(UPLOAD_DIR, name))
    except OSError:
        pass


def _stories_purge(data):
    """Delete expired stories and their files. Caller holds stories_lock.
    Returns True when something changed (so the caller knows to save)."""
    now = _stories_time.time()
    expired = [s for s in data['stories'].values() if s.get('expires_at', 0) <= now]
    for s in expired:
        data['stories'].pop(s['id'], None)
        _stories_remove_media(s.get('media_url'))
    return bool(expired)


def _stories_maybe_purge(data):
    """Lazy purge with a minimum gap, so rapid GETs don't rewrite the file."""
    now = _stories_time.time()
    if now - _stories_last_purge['t'] < STORY_PURGE_MIN_GAP:
        return False
    _stories_last_purge['t'] = now
    return _stories_purge(data)


def _stories_purge_loop():
    while True:
        _stories_time.sleep(STORY_PURGE_INTERVAL)
        try:
            with stories_lock:
                data = _stories_load()
                if _stories_purge(data):
                    _stories_save(data)
        except Exception as e:
            print(f"⚠️ stories purge failed: {e}")


def _story_public(s, viewer_id):
    """Story as seen by a viewer. Never leaks other people's views."""
    out = {k: v for k, v in s.items() if k not in ('views', 'replies', 'reactions')}
    out['seen'] = viewer_id in s.get('views', [])
    out['views_count'] = len(s.get('views', []))   # safe: only the count
    reacts = s.get('reactions') or {}
    if viewer_id == s.get('user_id'):               # only the owner sees WHO reacted
        out['reactions'] = {k: list(v) for k, v in reacts.items()}
    else:
        out['reactions'] = {k: len(v) for k, v in reacts.items()}
    return out


def _story_user(db, uid, viewer_id=None):
    u = db['users'].get(uid) or {}
    avatar = u.get('avatar')
    if viewer_id and uid in db['users']:
        avatar = apply_privacy_to_user(db, viewer_id, {'id': uid, 'avatar': avatar}).get('avatar')
    return {
        'id': uid,
        'username': u.get('username', 'Unknown'),
        'avatar': avatar,
        'avatar_color': u.get('avatar_color'),
        'avatar_ring': u.get('avatar_ring'),
    }


def _story_validate_bytes(data_bytes, ext):
    """Verify the real file header matches the extension (magic bytes)."""
    if not data_bytes:
        return False
    head = data_bytes[:16]
    if ext == 'png':
        return head[:8] == b'\x89PNG\r\n\x1a\n'
    if ext in ('jpg', 'jpeg'):
        return head[:3] == b'\xff\xd8\xff'
    if ext == 'gif':
        return head[:6] in (b'GIF87a', b'GIF89a')
    if ext == 'webp':
        return head[:4] == b'RIFF' and head[8:12] == b'WEBP'
    if ext == 'mp4':
        return head[4:8] == b'ftyp'
    if ext == 'webm':
        return head[:4] == b'\x1aE\xdf\xa3'
    return False


def _story_can_view(db, viewer_id, story_user_id):
    """True when viewer_id may see the stories of story_user_id."""
    if viewer_id == story_user_id:
        return True
    if story_user_id not in db['users']:
        return False
    # blocking cuts both directions
    if viewer_id in (db['users'][story_user_id].get('blocked_users') or []):
        return False
    if story_user_id in (db['users'].get(viewer_id, {}).get('blocked_users') or []):
        return False

    privacy = get_privacy(db, story_user_id).get('story_visibility', 'everyone')
    if privacy == 'everyone':
        return True
    if privacy == 'nobody':
        return False
    are_friends = viewer_id in (db['users'][story_user_id].get('friends') or [])
    if privacy == 'contacts':
        return are_friends
    if privacy == 'close_friends':
        return viewer_id in (db['users'][story_user_id].get('close_friends') or [])
    if privacy == 'server':
        for s in db['servers'].values():
            members = s.get('members', [])
            if story_user_id in members and viewer_id in members:
                return True
        return False
    return True


# ---------- close friends ----------
@app.route('/api/close-friends', methods=['GET'])
@login_required
def get_close_friends():
    db = load_database()
    me = db['users'].get(session['user_id'], {})
    ids = me.get('close_friends', []) or []
    friends = []
    for uid in ids:
        u = db['users'].get(uid)
        if u:
            friends.append(sanitize_user_for_viewer(db, session['user_id'], u))
    return jsonify({'close_friends': friends, 'count': len(friends)})


@app.route('/api/close-friends', methods=['POST'])
@login_required
def add_close_friend():
    data = request.get_json(silent=True) or {}
    target = data.get('user_id')
    db = load_database()
    me = db['users'].get(session['user_id'])
    if not me or not target or target not in db['users']:
        return jsonify({'error': 'Invalid user'}), 400
    if target == me['id']:
        return jsonify({'error': 'You cannot add yourself'}), 400
    cf = me.setdefault('close_friends', [])
    if target not in cf:
        cf.append(target)
        save_database(db)
    return jsonify({'success': True})


@app.route('/api/close-friends/<user_id>', methods=['DELETE'])
@login_required
def remove_close_friend(user_id):
    db = load_database()
    me = db['users'].get(session['user_id'])
    if me and user_id in (me.get('close_friends') or []):
        me['close_friends'].remove(user_id)
        save_database(db)
    return jsonify({'success': True})


# ---------- list / create / view / delete stories ----------
@app.route('/api/stories', methods=['GET'])
@login_required
def stories_list():
    me_id = session['user_id']
    db = load_database()

    with stories_lock:
        data = _stories_load()
        if _stories_maybe_purge(data):
            _stories_save(data)
        _now = _stories_time.time()
        active = sorted((s for s in data['stories'].values() if s.get('expires_at', 0) > _now),
                        key=lambda s: s['created_at'])

    # visibility cache per request (viewer_id is always me_id)
    visibility_cache = {}

    def can_view(owner_id):
        if owner_id == me_id:
            return True
        if owner_id in visibility_cache:
            return visibility_cache[owner_id]
        ok = _story_can_view(db, me_id, owner_id)
        visibility_cache[owner_id] = ok
        return ok

    groups = {}
    for s in active:
        uid = s['user_id']
        if not can_view(uid):
            continue
        g = groups.get(uid)
        if g is None:
            g = groups[uid] = {'user': _story_user(db, uid, me_id), 'stories': [], 'unseen': False}
        pub = _story_public(s, me_id)
        if uid != me_id and not pub['seen']:
            g['unseen'] = True
        g['stories'].append(pub)

    result = sorted(groups.values(), key=lambda g: (g['user']['id'] != me_id, not g['unseen']))
    return jsonify({'groups': result})


@app.route('/api/stories', methods=['POST'])
@login_required
def stories_create():
    file = request.files.get('file')
    if not file or not file.filename:
        return jsonify({'error': 'No file selected'}), 400
    if '.' not in file.filename:
        return jsonify({'error': 'Unsupported file type'}), 400
    ext = file.filename.rsplit('.', 1)[1].lower()
    if ext in STORY_IMAGE_EXTS:
        media_type = 'image'
    elif ext in STORY_VIDEO_EXTS:
        media_type = 'video'
    else:
        return jsonify({'error': 'Only images (PNG, JPG, GIF, WEBP) and videos (MP4, WEBM) are allowed'}), 400

    # reject oversized requests before touching disk
    max_mb = STORY_MAX_BYTES // (1024 * 1024)
    if request.content_length and request.content_length > STORY_MAX_BYTES + 1024 * 1024:
        return jsonify({'error': f'File is too large (max {max_mb} MB)'}), 413

    chunks, total = [], 0
    while True:
        chunk = file.stream.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > STORY_MAX_BYTES:
            return jsonify({'error': f'File is too large (max {max_mb} MB)'}), 413
        chunks.append(chunk)
    content_bytes = b''.join(chunks)

    if not _story_validate_bytes(content_bytes, ext):
        return jsonify({'error': f'The file does not look like a valid {ext.upper()} file'}), 400

    name = f"{STORY_FILE_PREFIX}{uuid.uuid4().hex}.{ext}"
    path = os.path.join(UPLOAD_DIR, name)
    try:
        with open(path, 'wb') as out:
            out.write(content_bytes)
    except OSError as e:
        return jsonify({'error': 'Failed to save file', 'details': str(e)}), 500

    caption = (request.form.get('caption') or '').strip()[:STORY_MAX_CAPTION]
    now = _stories_time.time()
    story = {
        'id': uuid.uuid4().hex,
        'user_id': session['user_id'],
        'media_url': f'/uploads/{name}',
        'media_type': media_type,
        'caption': caption,
        'text': '',
        'created_at': now,
        'expires_at': now + STORY_LIFETIME,
        'views': [],
        'reactions': {},
        'replies': [],
    }
    with stories_lock:
        data = _stories_load()
        _stories_purge(data)
        data['stories'][story['id']] = story
        _stories_save(data)
    return jsonify({'success': True, 'story': _story_public(story, session['user_id'])})


@app.route('/api/stories/text', methods=['POST'])
@login_required
def stories_text():
    if request.content_length and request.content_length > STORY_MAX_TEXT_BYTES:
        return jsonify({'error': 'Request too large'}), 413
    data = request.get_json(silent=True) or {}
    text = str(data.get('text') or '').strip()[:STORY_TEXT_MAX]
    if not text:
        return jsonify({'error': 'Text required'}), 400
    now = _stories_time.time()
    story = {
        'id': uuid.uuid4().hex,
        'user_id': session['user_id'],
        'media_url': None,
        'media_type': 'text',
        'text': text,
        'caption': '',
        'created_at': now,
        'expires_at': now + STORY_LIFETIME,
        'views': [],
        'reactions': {},
        'replies': [],
    }
    with stories_lock:
        data_s = _stories_load()
        _stories_purge(data_s)
        data_s['stories'][story['id']] = story
        _stories_save(data_s)
    return jsonify({'success': True, 'story': _story_public(story, session['user_id'])})


def _story_get_viewable(story_id, me_id, db):
    """Fetch a story, ensuring it exists, is not expired, and me_id may see it.
    Returns (story, data) or (None, error_response).
    Caller must hold stories_lock."""
    data = _stories_load()
    s = data['stories'].get(story_id)
    if not s or s.get('expires_at', 0) <= _stories_time.time():
        return None, (jsonify({'error': 'Story not found'}), 404)
    if me_id != s['user_id'] and not _story_can_view(db, me_id, s['user_id']):
        # 404 (not 403) so the existence of hidden stories is not leaked
        return None, (jsonify({'error': 'Story not found'}), 404)
    return s, data


@app.route('/api/stories/<story_id>/view', methods=['POST'])
@login_required
def stories_mark_view(story_id):
    me_id = session['user_id']
    db = load_database()
    with stories_lock:
        s, data_or_err = _story_get_viewable(story_id, me_id, db)
        if s is None:
            return data_or_err
        if me_id != s['user_id'] and me_id not in s['views']:
            s['views'].append(me_id)
            _stories_save(data_or_err)
    return jsonify({'success': True})


@app.route('/api/stories/<story_id>/viewers', methods=['GET'])
@login_required
def stories_viewers(story_id):
    me_id = session['user_id']
    with stories_lock:
        s = _stories_load()['stories'].get(story_id)
        if not s or s.get('expires_at', 0) <= _stories_time.time():
            return jsonify({'error': 'Story not found'}), 404
        if s['user_id'] != me_id:
            return jsonify({'error': 'Only the owner can see viewers'}), 403
        viewer_ids = list(s.get('views', []))
    db = load_database()
    return jsonify({'viewers': [_story_user(db, uid, me_id) for uid in viewer_ids]})


@app.route('/api/stories/<story_id>/react', methods=['POST'])
@login_required
def stories_react(story_id):
    data = request.get_json(silent=True) or {}
    emoji = str(data.get('emoji') or '❤️')[:8]
    if not _valid_story_emoji(emoji):
        return jsonify({'error': 'Invalid emoji'}), 400
    me_id = session['user_id']
    db = load_database()
    with stories_lock:
        s, data_or_err = _story_get_viewable(story_id, me_id, db)
        if s is None:
            return data_or_err
        if me_id == s['user_id']:
            return jsonify({'error': 'You cannot react to your own story'}), 400
        reactions = s.setdefault('reactions', {})
        users = reactions.setdefault(emoji, [])
        if me_id in users:
            users.remove(me_id)
            if not users:
                del reactions[emoji]
        else:
            users.append(me_id)
        _stories_save(data_or_err)
        result = {k: len(v) for k, v in reactions.items()}
    return jsonify({'success': True, 'reactions': result})


@app.route('/api/stories/<story_id>/reply', methods=['POST'])
@login_required
def stories_reply(story_id):
    if request.content_length and request.content_length > 5000:
        return jsonify({'error': 'Reply is too long'}), 413
    data = request.get_json(silent=True) or {}
    text = str(data.get('text') or '').strip()[:500]
    if not text:
        return jsonify({'error': 'Empty reply'}), 400
    me_id = session['user_id']
    db = load_database()
    owner_id = None
    with stories_lock:
        s, data_or_err = _story_get_viewable(story_id, me_id, db)
        if s is None:
            return data_or_err
        if me_id == s['user_id']:
            return jsonify({'error': 'You cannot reply to your own story'}), 400
        owner_id = s['user_id']
        _err = _story_reply_dm_error(db, me_id, owner_id)
        if _err:
            return _err
        _ok, _wait = check_message_rate_limit(me_id)
        if not _ok:
            return jsonify({'error': 'Too many messages! Please slow down.', 'wait_ms': _wait}), 429
        s.setdefault('replies', []).append({
            'user_id': me_id, 'text': text, 'at': _stories_time.time(),
        })
        _stories_save(data_or_err)

    # also deliver the reply as a DM to the story owner
    db = load_database()                      # fresh copy: the one loaded earlier may be stale
    dm_key = f"dm_{'_'.join(sorted([me_id, owner_id]))}"
    _msg = {
        'id': uuid.uuid4().hex[:12],
        'dm_key': dm_key,
        'user_id': me_id,
        'content': f"📩 Replied to your story: {text}",
        'created_at': datetime.now().isoformat(),
        'reactions': {},
        'reply_to': None,
        'seen_at': None,
        'delivered_at': None,
    }
    stamp_expiry(db, dm_key, _msg)
    db.setdefault('direct_messages', {}).setdefault(dm_key, []).append(_msg)
    save_database(db)
    return jsonify({'success': True})


@app.route('/api/stories/<story_id>', methods=['DELETE'])
@login_required
def stories_delete(story_id):
    me_id = session['user_id']
    removed_url = None
    with stories_lock:
        data = _stories_load()
        s = data['stories'].get(story_id)
        if not s:
            return jsonify({'error': 'Story not found'}), 404
        if s['user_id'] != me_id:
            return jsonify({'error': 'Permission denied'}), 403
        removed_url = s.get('media_url')
        del data['stories'][story_id]
        _stories_save(data)
    _stories_remove_media(removed_url)
    return jsonify({'success': True})

@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    # بررسی پسوند فایل
    ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'jpg'
    _bad, ext = _check_upload(file, ext, request.form.get('type', 'image'))
    if _bad:
        return _bad
    if request.form.get('type') in ('ring_image', 'panel_bg'):
        return _save_user_visual(file, ext, request.form.get('type'))
    new_filename = f"{uuid.uuid4().hex}.{ext}"
    filepath = os.path.join(UPLOAD_DIR, new_filename)
    
    try:
        file.save(filepath)
    except Exception as e:
        return jsonify({'error': 'Failed to save file', 'details': str(e)}), 500

    file_type = request.form.get('type', 'image')
    url_path = f'/uploads/{new_filename}'
    db = load_database()
    user = db['users'].get(session['user_id'])

    # ---------------------------------------------------------
    # 👇 تغییر جدید: پشتیبانی از آپلود آیکون سرور
    # ---------------------------------------------------------
    if file_type == 'server_icon':
        server_id = request.form.get('server_id')
        if not server_id:
            return jsonify({'error': 'Server ID required for icon'}), 400
        
        server = db['servers'].get(server_id)
        if not server:
            return jsonify({'error': 'Server not found'}), 404
            
        # فقط صاحب سرور می‌تواند آیکون را تغییر دهد
        if session['user_id'] != server.get('owner_id'):
            return jsonify({'error': 'Permission denied'}), 403
            
        # ذخیره URL در دیتابیس برای فیلد icon
        server['icon'] = url_path
        save_database(db)
        return jsonify({'success': True, 'url': url_path})

    # ---------------------------------------------------------
    # کدهای قبلی برای بنر سرور و آواتار کاربر
    # ---------------------------------------------------------
    if file_type == 'server_banner':
        server_id = request.form.get('server_id')
        if not server_id:
            return jsonify({'error': 'Server ID required for banner'}), 400
        server = db['servers'].get(server_id)
        if not server:
            return jsonify({'error': 'Server not found'}), 404
        if session['user_id'] != server.get('owner_id'):
             return owner_only_response('Only the server owner can change the server banner')
        server['banner'] = url_path
        save_database(db)
        return jsonify({'success': True, 'url': url_path})

    if user:
        if file_type == 'avatar':
            user['avatar'] = url_path
            if ext in ['gif', 'webp']:
                user['is_animated'] = True
            else:
                user['is_animated'] = False
        elif file_type == 'banner':
            user['banner'] = url_path
        save_database(db)

    return jsonify({'success': True, 'url': url_path})

    # --- Send DM with Block Check ---
# --- Send DM with Block Check ---
@app.route('/api/dm/<user_id>/messages', methods=['POST'])
@login_required
def send_dm_message(user_id):
    # system conversations (Admin Warn / Discord) are read-only
    if is_system_dm_id(user_id):
        return jsonify({'error': SYSTEM_DM_LOCK_TEXT, 'code': 'SYSTEM_DM_LOCKED'}), 403
    # === بررسی Rate Limit ===
    allowed, wait_ms = check_message_rate_limit(session['user_id'])
    if not allowed:
        wait_seconds = wait_ms / 1000
        return jsonify({
            'error': f'Too many messages! Please wait {wait_seconds:.1f} seconds',
            'wait_ms': wait_ms
        }), 429
    # === پایان بررسی ===
    
    data = (request.get_json(silent=True) or {})
    content = data.get('content', '').strip()
    image_url = _clean_image_url(data.get('image_url'))
    attachment, location, poll, rich_error = parse_rich_payload(data)
    if rich_error:
        return rich_error
    if attachment and attachment['type'] == 'image' and not image_url:
        image_url = attachment['url']
    reply_to = data.get('reply_to')
    effect = data.get('effect', 'none')
    
    # اعتبارسنجی effect
    valid_effects = ['none', 'glow', 'shake', 'rainbow', 'fire', 'ice']
    if effect not in valid_effects:
        effect = 'none'
    
    # ============================================
    # ✅ بررسی محدودیت 200 کاراکتر
    # ============================================
    content, was_truncated, char_count = limit_message_length(content)
    if was_truncated:
        return jsonify({
            'error': f'Message exceeds {MAX_MESSAGE_LENGTH} characters limit',
            'char_count': char_count,
            'max_length': MAX_MESSAGE_LENGTH
        }), 400
    # ============================================
    
    if not content and not image_url and not (attachment or location or poll):
        return jsonify({'error': 'Message content required'}), 400
    
    db = load_database()
    
    if user_id not in db['users']:
        return jsonify({'error': 'User not found'}), 404
    
    if db['users'][user_id].get('is_deleted'):
        return jsonify({'error': 'This account was deleted. You can no longer message it.', 'code': 'ACCOUNT_DELETED'}), 403

    sender = db['users'].get(session['user_id'])
    receiver = db['users'].get(user_id)
    
    if sender and user_id in sender.get('blocked_users', []):
        return jsonify({'error': 'You have blocked this user'}), 403
    
    if receiver and session['user_id'] in receiver.get('blocked_users', []):
        notify_blocked_delivery(db, session['user_id'], user_id)
        save_database(db)
        return jsonify({
            'error': f"{receiver.get('username', 'This user')} has blocked you. Message not sent!",
            'code': 'BLOCKED_DELIVERY', 'blocked_by_them': True
        }), 403
    
    # بررسی تنظیمات حریم خصوصی کاربر مقصد
    privacy_settings = db.get('privacy_settings', {}).get(user_id, {})
    allow_dms = privacy_settings.get('allow_dms_from_strangers', True)
    if not allow_dms:
        receiver_data = db['users'].get(user_id, {})
        friends_list = receiver_data.get('friends', [])
        if session['user_id'] not in friends_list:
            return jsonify({
                'error': 'This user is not accepting DMs from non-friends',
                'code': 'DMS_DISABLED'
            }), 403
    
    dm_key = tuple(sorted([session['user_id'], user_id]))
    dm_key_str = f"dm_{'_'.join(dm_key)}"
    
    if dm_key_str not in db['direct_messages']:
        db['direct_messages'][dm_key_str] = []
    
    message_id = str(uuid.uuid4().hex[:12])
    message = {
        'id': message_id,
        'dm_key': dm_key_str,
        'user_id': session['user_id'],
        'content': content,
        'image_url': image_url,
        'attachment': attachment,
        'location': location,
        'poll': poll,
        'created_at': datetime.now().isoformat(),
        'reactions': {},
        'reply_to': reply_to,
        'effect': effect,
        'seen_at': None,
        'delivered_at': None
    }
    stamp_expiry(db, dm_key_str, message)
    message['status'] = 'delivered' if is_user_online(db, user_id) else 'sent'
    if message['status'] == 'delivered':
        message['delivered_at'] = datetime.now().isoformat()
    
    db['direct_messages'][dm_key_str].append(message)
    save_database(db)
    
    reply_info = None
    if reply_to:
        for m in db['direct_messages'].get(dm_key_str, []):
            if m.get('id') == reply_to:
                original_user = db['users'].get(m.get('user_id'), {})
                reply_info = {
                    'id': m['id'],
                    'content': (m.get('content') or '')[:100] + ('...' if len(m.get('content') or '') > 100 else ''),
                    'author': {
                        'id': original_user.get('id'),
                        'username': original_user.get('username', 'Unknown'),
                        'avatar': original_user.get('avatar'),
                        'avatar_color': original_user.get('avatar_color', '#7289da')
                    }
                }
                break
    
    user = db['users'].get(session['user_id'], {})
    return jsonify({
        **message,
        'reply_info': reply_info,
        'author': {
            'id': user.get('id'),
            'username': user.get('username', 'Unknown'),
            'avatar': user.get('avatar'),
            'avatar_color': user.get('avatar_color', '#7289da'),
            'is_premium': user.get('is_premium', False), 'verified': user_is_verified(user)
        }
    })

# --- Block User ---
@app.route('/api/users/block', methods=['POST'])
@login_required
def block_user():
    data = (request.get_json(silent=True) or {})
    target_user_id = data.get('user_id')
    
    if not target_user_id:
        return jsonify({'error': 'User ID required'}), 400
    
    db = load_database()
    user = db['users'].get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if 'blocked_users' not in user:
        user['blocked_users'] = []
    
    if target_user_id not in user['blocked_users']:
        user['blocked_users'].append(target_user_id)
        save_database(db)
    
    return jsonify({'success': True})

# --- Unblock User ---
@app.route('/api/users/unblock/<user_id>', methods=['POST'])
@login_required
def unblock_user(user_id):
    db = load_database()
    user = db['users'].get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if 'blocked_users' in user and user_id in user['blocked_users']:
        user['blocked_users'].remove(user_id)
        save_database(db)
    
    return jsonify({'success': True})

# --- Get Blocked Users List ---
@app.route('/api/users/blocked')
@login_required
def get_blocked_users():
    db = load_database()
    user = db['users'].get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    blocked_list = user.get('blocked_users', [])
    blocked_users_data = []
    
    for blocked_id in blocked_list:
        blocked_user = db['users'].get(blocked_id)
        if blocked_user:
            blocked_users_data.append(sanitize_user_for_viewer(db, session['user_id'], blocked_user))
    
    return jsonify(blocked_users_data)

# --- Check Block Status ---
@app.route('/api/users/is-blocked/<target_user_id>')
@login_required
def is_user_blocked(target_user_id):
    db = load_database()
    user = db['users'].get(session['user_id'])
    if not user:
        return jsonify({'blocked': False}), 200
    
    blocked_list = user.get('blocked_users', [])
    is_blocked = target_user_id in blocked_list
    
    return jsonify({'blocked': is_blocked})

# --- Routes ---
@app.route('/')
def index():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), 'index.html')

# --- Auth Routes ---
@app.route('/api/admin/emails', methods=['GET'])
@admin_required
def get_all_emails():
    """دریافت لیست تمام ایمیل‌های ثبت شده"""
    emails = load_emails()
    return jsonify(emails)

@app.route('/api/admin/emails/<email>/approve', methods=['POST'])
@admin_required
def approve_email(email):
    """تأیید ایمیل برای ورود"""
    emails = load_emails()
    emails[email.lower()] = {
        'email': email.lower(),
        'accept': True,
        'approved_by': session['user_id'],
        'approved_at': datetime.now().isoformat()
    }
    save_emails(emails)
    return jsonify({'success': True, 'message': f'Email {email} approved'})

@app.route('/api/admin/emails/<email>/reject', methods=['POST'])
@admin_required
def reject_email(email):
    """رد ایمیل"""
    emails = load_emails()
    emails[email.lower()] = {
        'email': email.lower(),
        'accept': False,
        'rejected_by': session['user_id'],
        'rejected_at': datetime.now().isoformat()
    }
    save_emails(emails)
    return jsonify({'success': True, 'message': f'Email {email} rejected'})

@app.route('/api/admin/emails/<email>', methods=['DELETE'])
@admin_required
def delete_email(email):
    """حذف ایمیل از لیست"""
    emails = load_emails()
    if email.lower() in emails:
        del emails[email.lower()]
        save_emails(emails)
        return jsonify({'success': True, 'message': f'Email {email} deleted'})
    return jsonify({'error': 'Email not found'}), 404

@app.route('/api/admin/emails/<email>/status', methods=['GET'])
@admin_required
def get_email_status(email):
    """بررسی وضعیت یک ایمیل"""
    emails = load_emails()
    email_lower = email.lower()
    if email_lower in emails:
        return jsonify(emails[email_lower])
    return jsonify({'email': email_lower, 'accept': False, 'status': 'not_found'})

# ============================================
# AUTO-REGISTER EMAIL ON REGISTRATION
# ============================================

# ============================================================
# MULTI-ACCOUNT SYSTEM
#   * up to MAX_ACCOUNTS (3) regular accounts per browser
#   * 1 temporary "incognito" account (no e-mail, hidden from user lists,
#     always offline, wiped when you leave it)
#   * switch between accounts without logging out
# The list of accounts lives in the signed Flask session cookie, so it can
# not be forged: you can only switch to accounts you really logged in to.
# ============================================================
MAX_ACCOUNTS = 3
INCOGNITO_STALE_DAYS = 7
INCOGNITO_NAME_RE = re.compile(r'^[A-Za-z0-9_.\- \u0600-\u06FF]{3,20}$')


def _session_account_ids():
    ids = session.get('accounts')
    ids = list(ids) if isinstance(ids, list) else []
    uid = session.get('user_id')
    if uid and uid not in ids:
        ids.append(uid)
    return ids


def _session_can_add_account(db, uid=None):
    ids = _session_account_ids()
    if uid is not None and uid in ids:
        return True
    regular = [i for i in ids if i in db['users'] and not db['users'][i].get('is_incognito')]
    return len(regular) < MAX_ACCOUNTS


def _session_add_account(uid, session_id=None, make_active=True):
    ids = _session_account_ids()
    if uid not in ids:
        ids.append(uid)
    sessions = dict(session.get('account_sessions') or {})
    if session_id:
        sessions[uid] = session_id
    session['accounts'] = ids
    session['account_sessions'] = sessions
    if make_active:
        session['user_id'] = uid
        session['session_id'] = sessions.get(uid, '')


def _activate_account(db, uid):
    """Make `uid` the active account of this browser (presence is updated too)."""
    prev = session.get('user_id')
    if prev and prev != uid:
        pu = db['users'].get(prev)
        if pu and not pu.get('is_incognito') and pu.get('status') in ('online', 'idle', 'dnd'):
            pu['status'] = 'offline'
    sessions = session.get('account_sessions') or {}
    session['user_id'] = uid
    session['session_id'] = sessions.get(uid, '')
    u = db['users'].get(uid)
    if u and not u.get('is_incognito') and u.get('status', 'offline') == 'offline':
        u['status'] = 'online'


def _purge_user_data(db, user_id, keep_dms=False):
    """Completely remove a user and everything that belongs to them
    (same clean-up as /api/account/delete, without the password check).
    keep_dms=True keeps the DM messages the user sent and turns the account into a
    "Deleted Account" tombstone instead of removing the record."""
    for server_id, server in list(db.get('servers', {}).items()):
        if server.get('owner_id') == user_id:
            chans = [c for c, ch in db.get('channels', {}).items() if ch.get('server_id') == server_id]
            for c in chans:
                db['channels'].pop(c, None)
            for m in [m for m, msg in db.get('all_messages', {}).items() if msg.get('channel_id') in chans]:
                db['all_messages'].pop(m, None)
            db.get('bans', {}).pop(server_id, None)
            db.get('mutes', {}).pop(server_id, None)
            for code in [c for c, inv in db.get('invites', {}).items() if inv.get('server_id') == server_id]:
                db['invites'].pop(code, None)
            for cid in [c for c, cat in db.get('categories', {}).items() if cat.get('server_id') == server_id]:
                db['categories'].pop(cid, None)
            for tid in [t for t, th in db.get('threads', {}).items() if th.get('server_id') == server_id]:
                db['threads'].pop(tid, None)
            db['servers'].pop(server_id, None)
        elif user_id in server.get('members', []):
            server['members'].remove(user_id)
            _strip_member_from_private_channels(db, server.get('id'), user_id)
            server.get('user_roles', {}).pop(user_id, None)

    for sid in list(db.get('bans', {}).keys()):
        if isinstance(db['bans'][sid], dict):
            db['bans'][sid].pop(user_id, None)
    for sid in list(db.get('mutes', {}).keys()):
        if isinstance(db['mutes'][sid], dict):
            db['mutes'][sid].pop(user_id, None)

    for m in [m for m, msg in db.get('all_messages', {}).items() if msg.get('user_id') == user_id]:
        db['all_messages'].pop(m, None)

    if not keep_dms:
        for dm_key in list(db.get('direct_messages', {}).keys()):
            if user_id in dm_key.replace('dm_', '').split('_'):
                db['direct_messages'][dm_key] = [x for x in db['direct_messages'][dm_key] if x.get('user_id') != user_id]
                if not db['direct_messages'][dm_key]:
                    del db['direct_messages'][dm_key]

    for other in db['users'].values():
        for field in ('blocked_users', 'friends'):
            if isinstance(other.get(field), list) and user_id in other[field]:
                other[field].remove(user_id)

    if isinstance(db.get('friend_requests'), list):
        db['friend_requests'] = [r for r in db['friend_requests']
                                 if r.get('from_user_id') != user_id and r.get('to_user_id') != user_id]
    db['notifications'] = [n for n in db.get('notifications', []) if n.get('user_id') != user_id]
    for code in [c for c, inv in db.get('invites', {}).items() if inv.get('created_by') == user_id]:
        db['invites'].pop(code, None)

    if keep_dms and user_id in db['users']:
        old = db['users'][user_id]
        db['users'][user_id] = {
            'id': user_id,
            'username': 'Deleted Account',
            'email': f'deleted-{user_id}@incognito.invalid',
            'password': generate_password_hash(uuid.uuid4().hex + uuid.uuid4().hex),
            'avatar': None, 'avatar_color': '#4f545c', 'banner': None, 'bio': '',
            'status': 'offline', 'is_admin': False, 'is_premium': False, 'coins': 0,
            'inventory': [], 'friends': [], 'blocked_users': [], 'devices': [],
            'created_at': old.get('created_at'), 'last_seen': None,
            'is_bot': False, 'is_active': False,
            'is_incognito': True, 'is_deleted': True,
        }
    else:
        db['users'].pop(user_id, None)

    try:
        _stories_remove_user(user_id)
    except Exception as e:
        print(f'⚠️ could not clear stories of {user_id}: {e}')
    try:
        with settings_lock:
            _all = _load_all_settings()
            if _all.pop(user_id, None) is not None:
                _save_all_settings(_all)
    except Exception as e:
        print(f'⚠️ could not clear settings of {user_id}: {e}')


def _remove_incognito(db, uid):
    """Delete an incognito account. If it ever sent a DM, its messages stay and the
    account becomes "Deleted Account" (nobody can message it); otherwise it is wiped."""
    user = db['users'].get(uid)
    if not user or user.get('is_deleted'):
        return
    sent_dm = any(
        uid in k.replace('dm_', '').split('_') and any(m.get('user_id') == uid for m in msgs)
        for k, msgs in db.get('direct_messages', {}).items()
    )
    _purge_user_data(db, uid, keep_dms=sent_dm)


def _session_remove_accounts(db, targets):
    """Remove accounts from this browser. Incognito accounts are wiped for good.
    Returns the id of the account that is active afterwards (or None).
    The caller must save the database."""
    ids = _session_account_ids()
    sessions = dict(session.get('account_sessions') or {})
    for uid in targets:
        user = db['users'].get(uid)
        if user:
            if user.get('is_incognito'):
                _remove_incognito(db, uid)
            else:
                user['status'] = 'offline'
        if uid in ids:
            ids.remove(uid)
        sessions.pop(uid, None)
    active = session.get('user_id')
    if active in targets or active not in ids:
        # prefer a real account over the incognito one
        active = next((i for i in ids if i in db['users'] and not db['users'][i].get('is_incognito')),
                      ids[0] if ids else None)
    session['accounts'] = ids
    session['account_sessions'] = sessions
    if active:
        session['user_id'] = active
        session['session_id'] = sessions.get(active, '')
        u = db['users'].get(active)
        if u and not u.get('is_incognito') and u.get('status', 'offline') == 'offline':
            u['status'] = 'online'
    else:
        session.pop('user_id', None)
        session.pop('session_id', None)
    return active


def _account_public(db, uid):
    u = db['users'].get(uid)
    if not u:
        return None
    inc = bool(u.get('is_incognito'))
    return {
        'id': uid,
        'username': u.get('username'),
        'avatar': u.get('avatar'),
        'avatar_color': u.get('avatar_color'),
        'email': None if inc else u.get('email'),
        'is_incognito': inc,
        'is_admin': bool(u.get('is_admin')),
        'active': uid == session.get('user_id'),
    }


@app.route('/api/accounts', methods=['GET'])
def list_accounts():
    db = load_database()
    gone = [i for i in _session_account_ids() if i not in db['users']]
    if gone:
        _session_remove_accounts(db, gone)
        save_database(db)
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    me = db['users'][session['user_id']]
    if me.get('is_incognito'):
        # keep-alive so abandoned incognito accounts can be told apart from used ones
        me['last_seen'] = datetime.now().isoformat()
        save_database(db)
    ids = _session_account_ids()
    accounts = [a for a in (_account_public(db, i) for i in ids) if a]
    regular = [a for a in accounts if not a['is_incognito']]
    incog = [a for a in accounts if a['is_incognito']]
    return jsonify({
        'accounts': accounts,
        'active': session['user_id'],
        'max': MAX_ACCOUNTS,
        'can_add': len(regular) < MAX_ACCOUNTS,
        'can_incognito': True,
        'incognito_id': incog[0]['id'] if incog else None,
    })


@app.route('/api/accounts/switch', methods=['POST'])
def switch_account():
    data = request.get_json(silent=True) or {}
    target = data.get('user_id')
    db = load_database()
    if target not in _session_account_ids() or target not in db['users']:
        return jsonify({'error': 'This account is not signed in on this device'}), 403
    _activate_account(db, target)
    save_database(db)
    return jsonify({'success': True, 'user_id': target})


@app.route('/api/accounts/remove', methods=['POST'])
def remove_account():
    data = request.get_json(silent=True) or {}
    target = data.get('user_id')
    if target not in _session_account_ids():
        return jsonify({'error': 'Account not found'}), 404
    db = load_database()
    before = session.get('user_id')
    active = _session_remove_accounts(db, [target])
    save_database(db)
    return jsonify({'success': True, 'next_user_id': active,
                    'active_changed': active != before,
                    'remaining': len(_session_account_ids())})


@app.route('/api/accounts/incognito', methods=['POST'])
def create_incognito_account():
    """Create a temporary anonymous account (no e-mail, no approval needed)."""
    data = request.get_json(silent=True) or {}
    db = load_database()

    # clean up abandoned incognito accounts
    cutoff = datetime.now() - timedelta(days=INCOGNITO_STALE_DAYS)
    for uid, u in list(db['users'].items()):
        if u.get('is_incognito') and not u.get('is_deleted'):
            try:
                seen = datetime.fromisoformat(u.get('last_seen') or u.get('created_at'))
            except Exception:
                seen = datetime.min
            if seen < cutoff:
                _remove_incognito(db, uid)

    # only one incognito account at a time: just switch to the existing one
    for i in _session_account_ids():
        if db['users'].get(i, {}).get('is_incognito') and not db['users'][i].get('is_deleted'):
            _activate_account(db, i)
            save_database(db)
            return jsonify({'success': True, 'user_id': i, 'existing': True})

    taken = {u.get('username', '').lower() for u in db['users'].values()}
    name = (data.get('name') or '').strip()
    if name:
        if not INCOGNITO_NAME_RE.match(name):
            return jsonify({'error': 'Name must be 3-20 characters (letters, numbers, space, . _ -)'}), 400
        if name.lower() in taken:
            return jsonify({'error': 'Username already taken'}), 400
    else:
        name = 'Incognito-' + uuid.uuid4().hex[:4]
        while name.lower() in taken:
            name = 'Incognito-' + uuid.uuid4().hex[:6]

    uid = str(uuid.uuid4())[:8]
    while uid in db['users']:
        uid = str(uuid.uuid4())[:8]
    now = datetime.now().isoformat()
    db['users'][uid] = {
        'id': uid,
        'username': name,
        'email': f'incognito-{uid}@incognito.invalid',
        'password': generate_password_hash(uuid.uuid4().hex + uuid.uuid4().hex),  # nobody can log in with it
        'avatar': None,
        'avatar_color': '#4f545c',
        'status': 'offline',           # incognito accounts always appear offline
        'bio': '',
        'is_admin': False,
        'is_premium': False,
        'premium_since': None,
        'coins': 0,
        'inventory': [],
        'friends': [],
        'created_at': now,
        'home_logo': None,
        'home_icon': 'fa-discord',
        'home_color': '#7289da',
        'home_bg_color': '#5865f2',
        'last_seen': now,
        'vip': False, 'staff': False, 'developer': False, 'verified': False,
        'nitro': False, 'partner': False, 'hypesquad_house': None,
        'early_supporter': False, 'bug_hunter': False, 'translator': False,
        'support': False, 'is_active': True, 'reputation': 0,
        'server_boost_level': 0, 'is_moderator': False, 'is_bot': False,
        'blocked_users': [], 'devices': [], 'banner': None,
        'is_animated': False, 'current_activity': None, 'is_nitro': False,
        'hypesquad_houses': None,
        'is_incognito': True,
    }
    _session_add_account(uid, uuid.uuid4().hex[:16], make_active=False)
    _activate_account(db, uid)
    save_database(db)
    return jsonify({'success': True, 'user_id': uid, 'username': name})


@app.route('/api/register', methods=['POST'])
def register():
    db = load_database()
    if not db['settings'].get('registration_enabled', True):
        return jsonify({'error': 'Registration is disabled'}), 400
    if not _session_can_add_account(db):
        return jsonify({'error': f'You can add up to {MAX_ACCOUNTS} accounts on this device'}), 400
    
    data = (request.get_json(silent=True) or {})
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    
    if not username or not email or not password:
        return jsonify({'error': 'All fields are required'}), 400
    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    if len(password) > 128:
        return jsonify({'error': 'Password is too long'}), 400
    if not EMAIL_RE.match(email) or len(email) > 254:
        return jsonify({'error': 'Invalid email address'}), 400
    if len(username) > 32 or '<' in username or '>' in username:
        return jsonify({'error': 'Username must be 3-32 characters and cannot contain < or >'}), 400
    
    # بررسی تکراری نبودن
    for uid, user in db['users'].items():
        if (user.get('email') or '').lower() == email.lower():
            return jsonify({'error': 'Email already registered'}), 400
        if user.get('username', '').lower() == username.lower():
            return jsonify({'error': 'Username already taken'}), 400
    
    # ثبت ایمیل
    emails = load_emails()
    email_lower = email.lower()
    if email_lower not in emails:
        emails[email_lower] = {
            'email': email_lower,
            'accept': False,
            'registered_at': datetime.now().isoformat(),
            'username': username
        }
        save_emails(emails)
    
    if not emails[email_lower].get('accept', False):
        return jsonify({
            'error': 'Email not activated by admin',
            'message': 'Your email must be approved by an administrator before you can register.'
        }), 403
    
    user_id = str(uuid.uuid4())[:8]
    avatar_colors = ['#7289da', '#43b581', '#faa61a', '#f04747', '#747e8c', '#9b59b6', '#e91e63', '#00bcd4']
    
    db['users'][user_id] = {
        'id': user_id,
        'username': username,
        'email': email,
        'password': generate_password_hash(password),
        'avatar': None,
        'avatar_color': avatar_colors[len(db['users']) % len(avatar_colors)],
        'status': 'offline',
        'bio': '',
        'is_admin': False,
        'is_premium': False,
        'premium_since': None,
        'coins': 100,
        'inventory': [],
        'friends': [],
        'created_at': datetime.now().isoformat(),
        'home_logo': None,
	'home_icon': 'fa-discord',
	'home_color': '#7289da',
	'home_bg_color': '#5865f2',
        'last_seen': datetime.now().isoformat(),
        
        # === فیلدهای Badge ===
        'vip': False,
        'staff': False,
        'developer': False,
        'verified': False,
        'nitro': False,
        'partner': False,
        'hypesquad_house': None,
        'early_supporter': False,
        'bug_hunter': False,
        'translator': False,
        'support': False,
        'is_active': True,
        'reputation': 0,
        'server_boost_level': 0,
        'is_moderator': False,
        'is_bot': False,
        'blocked_users': [],
        'devices': [],
        'banner': None,
        'is_animated': False,
        'current_activity': None,
        'is_nitro': False,
        'hypesquad_houses': None
    }
    
    _session_add_account(user_id, make_active=False)
    _activate_account(db, user_id)
    save_database(db)
    return jsonify({'success': True, 'user_id': user_id})

# ============================================
# MODIFIED LOGIN - Check Email Activation
# ============================================

# ============================================
# MODIFIED LOGIN - Auto-register email if not exists
# ============================================

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    email = str(data.get('email', '') or '').strip()
    password = str(data.get('password', '') or '')
    if not EMAIL_RE.match(email) or len(email) > 254:
        return jsonify({'error': 'Invalid credentials'}), 401
    _rl = _login_rate_check(email)
    if _rl:
        return _rl
    
    # ============================================
    # بررسی و ثبت ایمیل در صورت عدم وجود
    # ============================================
    emails = load_emails()
    email_lower = email.lower()
    
    # اگر ایمیل وجود ندارد، آن را ثبت کن (با accept: false)
    if email_lower not in emails and len(emails) >= 5000:
        return jsonify({'error': 'Email not activated by admin'}), 403
    if email_lower not in emails:
        emails[email_lower] = {
            'email': email_lower,
            'accept': False,
            'registered_at': datetime.now().isoformat(),
            'registered_by': 'login_attempt'
        }
        save_emails(emails)
    
    # بررسی فعال‌سازی ایمیل
    if not emails[email_lower].get('accept', False):
        return jsonify({
            'error': 'Email not activated by admin',
            'message': 'Your email must be approved by an administrator before you can login.'
        }), 403
    
    # ============================================
    # ادامه فرآیند لاگین
    # ============================================
    db = load_database()
    
    for uid, user in db['users'].items():
        if (user.get('email') or '').lower() == email.lower() and check_password_hash(user.get('password', ''), password):
            user['status'] = 'online'
            user['last_seen'] = datetime.now().isoformat()
            
            if not _session_can_add_account(db, uid):
                return jsonify({'error': f'You can add up to {MAX_ACCOUNTS} accounts on this device. Log out of one first.'}), 400

            session_id = str(uuid.uuid4().hex[:16])
            _session_add_account(uid, session_id, make_active=False)
            _activate_account(db, uid)
            session['session_id'] = session_id
            
            device_info = {
                'id': str(uuid.uuid4().hex[:12]),
                'session_id': session_id,
                'device_type': request.user_agent.platform or 'unknown',
                'browser': request.user_agent.browser or 'unknown',
                'location': request.remote_addr,
                'last_active': datetime.now().isoformat(),
                'created_at': datetime.now().isoformat()
            }
            
            if 'devices' not in user:
                user['devices'] = []
            
            device_exists = False
            for d in user['devices']:
                if d.get('browser') == device_info['browser'] and d.get('device_type') == device_info['device_type']:
                    d['session_id'] = session_id
                    d['last_active'] = datetime.now().isoformat()
                    device_exists = True
                    break
            
            if not device_exists:
                user['devices'].append(device_info)
            
            if len(user['devices']) > 5:
                user['devices'] = user['devices'][-5:]
            
            save_database(db)
            _login_clear(email)
            return jsonify({'success': True, 'user_id': uid})
    
    _login_record_fail(email)
    return jsonify({'error': 'Invalid credentials'}), 401



    # ==================== ACCOUNT DEVICES ====================

@app.route('/api/account/devices', methods=['GET'])
@login_required
def get_devices():
    """دریافت لیست دستگاه‌های فعال کاربر"""
    db = load_database()
    user = db['users'].get(session['user_id'])
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # دریافت دستگاه‌های کاربر
    devices = user.get('devices', [])
    
    # اضافه کردن اطلاعات کاربر به هر دستگاه
    for device in devices:
        device['is_current'] = device.get('session_id') == session.get('session_id', '')
    
    return jsonify({'devices': devices})


@app.route('/api/account/devices/<device_id>', methods=['DELETE'])
@login_required
def remove_device(device_id):
    """حذف یک دستگاه از لیست دستگاه‌های فعال"""
    db = load_database()
    user = db['users'].get(session['user_id'])
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    devices = user.get('devices', [])
    
    # پیدا کردن و حذف دستگاه
    device_found = None
    for i, device in enumerate(devices):
        if device.get('id') == device_id:
            device_found = devices.pop(i)
            break
    
    if not device_found:
        return jsonify({'error': 'Device not found'}), 404
    
    # جلوگیری از حذف دستگاه فعلی
    if device_found.get('is_current'):
        return jsonify({'error': 'Cannot remove current device'}), 400
    
    save_database(db)
    return jsonify({'success': True, 'message': 'Device removed successfully'})


@app.route('/api/account/devices/<device_id>/logout', methods=['POST'])
@login_required
def logout_device(device_id):
    """خروج از یک دستگاه خاص"""
    db = load_database()
    user = db['users'].get(session['user_id'])
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    devices = user.get('devices', [])
    
    # پیدا کردن دستگاه
    device_found = None
    for i, device in enumerate(devices):
        if device.get('id') == device_id:
            device_found = devices.pop(i)
            break
    
    if not device_found:
        return jsonify({'error': 'Device not found'}), 404
    
    save_database(db)
    return jsonify({'success': True, 'message': 'Logged out from device'})


@app.route('/api/account/devices/logout-all', methods=['POST'])
@login_required
def logout_all_devices():
    """خروج از تمام دستگاه‌ها به جز دستگاه فعلی"""
    db = load_database()
    user = db['users'].get(session['user_id'])
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    current_session = session.get('session_id')
    devices = user.get('devices', [])
    
    # نگه‌داشتن فقط دستگاه فعلی
    user['devices'] = [d for d in devices if d.get('session_id') == current_session]
    
    save_database(db)
    return jsonify({'success': True, 'message': 'Logged out from all other devices'})

@app.route('/api/logout', methods=['POST'])
def logout():
    data = request.get_json(silent=True) or {}
    db = load_database()
    if data.get('all'):
        targets = _session_account_ids()
    else:
        targets = [session['user_id']] if 'user_id' in session else []
    next_id = _session_remove_accounts(db, targets)
    save_database(db)
    return jsonify({'success': True, 'next_user_id': next_id})

@app.route('/api/me')
@login_required
def get_me():
    db = load_database()
    user = db['users'].get(session['user_id'], {})
    if user:
        user.pop('password', None)
        return jsonify(user)
    return jsonify({'error': 'User not found'}), 404

# ============================================
# USER SETTINGS  (stored per user in data/user_settings.json)
# Sound / media-download preferences, data-usage statistics,
# media "tap to load" memory and recent DMs live here instead of
# the browser's localStorage, so they follow the user to any device.
# ============================================
USER_SETTINGS_FILE = os.path.join(DATA_DIR, 'user_settings.json')
settings_lock = threading.Lock()
SETTINGS_KEYS = ('prefs', 'media_manual', 'data_usage', 'recent_dms', 'dm_delete_mode',
                 'media_recent', 'dismissed_announcements')
DM_DELETE_MODES = ('me', 'everyone')
MAX_DATA_USAGE_BYTES = 200000


def _load_all_settings():
    if not os.path.exists(USER_SETTINGS_FILE):
        return {}
    try:
        with open(USER_SETTINGS_FILE, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                return {}
            data = json.loads(content)
            return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _save_all_settings(all_settings):
    tmp_path = USER_SETTINGS_FILE + '.tmp'
    with open(tmp_path, 'w', encoding='utf-8') as f:
        json.dump(all_settings, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, USER_SETTINGS_FILE)


def _as_bool(value, default):
    return value if isinstance(value, bool) else default


def _sanitize_prefs(value):
    if not isinstance(value, dict):
        raise ValueError('prefs must be an object')
    snd = value.get('sound') if isinstance(value.get('sound'), dict) else {}
    med = value.get('media') if isinstance(value.get('media'), dict) else {}
    try:
        volume = float(snd.get('volume', 0.8))
    except (TypeError, ValueError):
        volume = 0.8
    if volume != volume:  # NaN
        volume = 0.8
    volume = max(0.0, min(1.0, volume))
    return {
        'sound': {
            'enabled': _as_bool(snd.get('enabled'), True),
            'channels': _as_bool(snd.get('channels'), True),
            'dms': _as_bool(snd.get('dms'), True),
            'volume': round(volume, 3),
            'choice': str(snd.get('choice', 'default'))[:32],
        },
        'media': {
            'image': _as_bool(med.get('image'), True),
            'gif': _as_bool(med.get('gif'), True),
            'video': _as_bool(med.get('video'), True),
            'audio': _as_bool(med.get('audio'), True),
        },
    }


def _sanitize_string_list(value, max_items, max_len):
    if not isinstance(value, list):
        raise ValueError('value must be a list')
    result = []
    seen = set()
    for item in value:
        if isinstance(item, str) and 0 < len(item) <= max_len and item not in seen:
            seen.add(item)
            result.append(item)
    return result[-max_items:]


def _sanitize_data_usage(value):
    if not isinstance(value, dict):
        raise ValueError('data_usage must be an object')
    cleaned = {
        'since': value.get('since') if isinstance(value.get('since'), (int, float)) else 0,
        'total': value.get('total') if isinstance(value.get('total'), dict) else {},
        'days': value.get('days') if isinstance(value.get('days'), dict) else {},
    }
    if len(cleaned['days']) > 62:
        for old_day in sorted(cleaned['days'].keys())[:-62]:
            del cleaned['days'][old_day]
    if len(json.dumps(cleaned)) > MAX_DATA_USAGE_BYTES:
        raise ValueError('data_usage is too large')
    return cleaned


def _sanitize_recent_media(value):
    """Recently used stickers/emoji: list of {k, p?, i}, newest first, max 24, no duplicates."""
    if not isinstance(value, list):
        raise ValueError('media_recent must be a list')
    out, seen = [], set()
    for e in value:
        if not isinstance(e, dict):
            continue
        k = str(e.get('k') or '')[:20]
        i = str(e.get('i') or '')[:100]
        p = str(e.get('p'))[:100] if e.get('p') not in (None, '') else ''
        if not k or not i:
            continue
        ident = (k, p, i)
        if ident in seen:
            continue
        seen.add(ident)
        entry = {'k': k, 'i': i}
        if p:
            entry['p'] = p
        out.append(entry)
    return out[:24]

def _sanitize_setting(key, value):
    """Returns the cleaned value, or None when the key should be removed."""
    if value is None:
        return None
    if key == 'prefs':
        return _sanitize_prefs(value)
    if key == 'media_manual':
        return _sanitize_string_list(value, 400, 500)
    if key == 'media_recent':
        return _sanitize_recent_media(value)
    if key == 'dismissed_announcements':
        return _sanitize_string_list(value, 100, 100)
    if key == 'dm_delete_mode':
        if value not in DM_DELETE_MODES:
            raise ValueError('dm_delete_mode must be "me" or "everyone"')
        return value
    if key == 'recent_dms':
        return _sanitize_string_list(value, 20, 100)
    if key == 'data_usage':
        return _sanitize_data_usage(value)
    raise ValueError('Unknown setting')


# ============================================
# DM DELETE MODE  ('me' = hide for me only | 'everyone' = remove for both sides)
# The mode is a per-user setting. Each DM message keeps a list 'hidden_for' of
# the users who deleted it for themselves.
# ============================================
def get_dm_delete_mode(user_id):
    with settings_lock:
        mode = (_load_all_settings().get(user_id, {}) or {}).get('dm_delete_mode')
    return mode if mode in DM_DELETE_MODES else 'me'

def _dm_scope(requested, user_id):
    return requested if requested in DM_DELETE_MODES else get_dm_delete_mode(user_id)

def dm_hide_for(msg, user_id):
    hidden = msg.setdefault('hidden_for', [])
    if user_id not in hidden:
        hidden.append(user_id)

def dm_visible_to(msg, user_id):
    return user_id not in (msg.get('hidden_for') or [])

def dm_hidden_since(db, user_id, other_id):
    """When user_id deleted the whole chat with other_id ('' = never). Only newer messages show it again."""
    return ((db.get('dm_hidden') or {}).get(user_id) or {}).get(other_id, '')

def dm_mark_chat_deleted(db, user_id, other_id):
    db.setdefault('dm_hidden', {}).setdefault(user_id, {})[other_id] = datetime.now().isoformat()

@app.route('/api/settings', methods=['GET'])
@login_required
def get_user_settings():
    with settings_lock:
        mine = _load_all_settings().get(session['user_id'], {})
    return jsonify(mine)


@app.route('/api/settings', methods=['PUT', 'POST'])
@login_required
def update_user_settings():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'Invalid request body'}), 400

    cleaned = {}
    for key in SETTINGS_KEYS:
        if key not in data:
            continue
        try:
            cleaned[key] = _sanitize_setting(key, data[key])
        except ValueError as e:
            return jsonify({'error': str(e), 'key': key}), 400

    user_id = session['user_id']
    with settings_lock:
        all_settings = _load_all_settings()
        mine = all_settings.get(user_id, {})
        for key, value in cleaned.items():
            if value is None:
                mine.pop(key, None)
            else:
                mine[key] = value
        if mine:
            all_settings[user_id] = mine
        else:
            all_settings.pop(user_id, None)
        _save_all_settings(all_settings)
    return jsonify({'success': True, 'settings': mine})


# --- Server Routes ---
@app.route('/api/servers')
@login_required
def get_servers():
    db = load_database()
    user_servers = []
    for sid, server in db['servers'].items():
        if session['user_id'] in server.get('members', []):
            # Check if banned
            server_bans = db['bans'].get(sid, {})
            if session['user_id'] not in server_bans:
                user_servers.append(server)
    return jsonify(user_servers)

    # ============================================
# SERVER EXPLORE/HUB API - همه سرورهای پلتفرم
# ============================================

@app.route('/api/explore/servers')
@login_required
def explore_servers():
    """دریافت همه سرورهای عمومی پلتفرم برای Server Hub"""
    db = load_database()
    all_servers = []
    
    for sid, server in db['servers'].items():
        # فقط سرورهای عمومی
        if not server.get('is_private', False):
            server_data = {
                'id': sid,
                'name': server.get('name', 'Unknown'),
                'description': server.get('description', ''),
                'icon': server.get('icon'),
                'banner': server.get('banner'),
                'color': server.get('color', '#5865f2'),
                'member_count': len(server.get('members', [])),
                'online_count': server.get('online_count', 0),
                'is_private': False,
                'owner_id': server.get('owner_id'),
                'created_at': server.get('created_at')
            }
            all_servers.append(server_data)
    
    # مرتب‌سازی بر اساس تعداد اعضا (بیشترین اول)
    all_servers.sort(key=lambda x: x['member_count'], reverse=True)
    
    return jsonify({
        'success': True,
        'servers': all_servers,
        'total': len(all_servers)
    })


@app.route('/api/explore/servers/all')
@login_required
def explore_all_servers():
    """دریافت همه سرورها (عمومی و خصوصی)"""
    db = load_database()
    all_servers = []
    
    for sid, server in db['servers'].items():
        if server.get('is_private') and session['user_id'] not in server.get('members', []):
            continue
        server_data = {
            'id': sid,
            'name': server.get('name', 'Unknown'),
            'description': server.get('description', ''),
            'icon': server.get('icon'),
            'banner': server.get('banner'),
            'color': server.get('color', '#5865f2'),
            'member_count': len(server.get('members', [])),
            'online_count': server.get('online_count', 0),
            'is_private': server.get('is_private', False),
            'owner_id': server.get('owner_id'),
            'created_at': server.get('created_at')
        }
        all_servers.append(server_data)
    
    all_servers.sort(key=lambda x: x['member_count'], reverse=True)
    
    return jsonify({
        'success': True,
        'servers': all_servers,
        'total': len(all_servers)
    })


@app.route('/api/explore/search')
@login_required
def explore_search():
    """جستجوی سرورها"""
    query = request.args.get('q', '').lower()
    if len(query) < 2:
        return jsonify({'success': True, 'servers': []})
    
    db = load_database()
    results = []
    
    for sid, server in db['servers'].items():
        name = server.get('name', '').lower()
        desc = server.get('description', '').lower()
        if server.get('is_private') and session['user_id'] not in server.get('members', []):
            continue
        
        if query in name or query in desc:
            results.append({
                'id': sid,
                'name': server.get('name', 'Unknown'),
                'description': server.get('description', ''),
                'icon': server.get('icon'),
                'member_count': len(server.get('members', [])),
                'is_private': server.get('is_private', False),
                'owner_id': server.get('owner_id')
            })
    
    return jsonify({
        'success': True,
        'servers': results,
        'total': len(results)
    })

@app.route('/api/servers', methods=['POST'])
@login_required
def create_server():
    data = (request.get_json(silent=True) or {})
    name = data.get('name', '').strip()
    
    if not name:
        return jsonify({'error': 'Server name is required'}), 400
    
    db = load_database()
    server_id = f"server_{uuid.uuid4().hex[:8]}"
    
    db['servers'][server_id] = {
        'id': server_id,
        'name': name,
        'owner_id': session['user_id'],
        'members': [session['user_id']],
        'icon': '🌐',
        'created_at': datetime.now().isoformat(),
        'boosts': [],
    	'user_boosts': {},
    	'has_blue_check': False,
        'roles': {
            'owner': {
                'id': 'owner',
                'name': 'Owner',
                'color': '#ED4245',
                'permissions': ['manage_server', 'kick', 'ban', 'unban', 'mute', 'manage_channels', 'manage_messages', 'send_messages', 'react']
            },
            'admin': {
                'id': 'admin',
                'name': 'Admin',
                'color': '#FEE75C',
                'permissions': ['kick', 'ban', 'unban', 'mute', 'manage_channels', 'manage_messages', 'send_messages', 'react']
            },
            'moderator': {
                'id': 'moderator',
                'name': 'Moderator',
                'color': '#57F287',
                'permissions': ['kick', 'mute', 'manage_messages', 'send_messages', 'react']
            },
            'member': {
                'id': 'member',
                'name': 'Member',
                'color': '#747e8c',
                'permissions': ['send_messages', 'react']
            }
        },
        'user_roles': {session['user_id']: ['owner']}
    }
    
    for channel_name in ['general', 'random']:
        channel_id = f"channel_{uuid.uuid4().hex[:8]}"
        db['channels'][channel_id] = {
            'id': channel_id,
            'server_id': server_id,
            'name': channel_name,
            'type': 'text',
            'category_id': None,
            'created_at': datetime.now().isoformat()
        }
    
    save_database(db)
    return jsonify({'success': True, 'server': db['servers'][server_id]})

@app.route('/api/servers/<server_id>')
@login_required
def get_server_details(server_id):
    db = load_database()
    server = db['servers'].get(server_id)
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    # Check if banned
    server_bans = db['bans'].get(server_id, {})
    if session['user_id'] in server_bans:
        return jsonify({'error': 'You are banned from this server'}), 403
    if session['user_id'] not in server.get('members', []):
        return jsonify({'error': 'Not a member of this server'}), 403
    
    members = []
    for uid in server.get('members', []):
        user = db['users'].get(uid, {})
        if user:
            u = sanitize_user_for_viewer(db, session['user_id'], user)
            u['roles'] = server.get('user_roles', {}).get(uid, ['member'])
            u['is_muted'] = uid in db['mutes'].get(server_id, {}) and db['mutes'][server_id][uid].get('muted_until') and \
                           datetime.fromisoformat(db['mutes'][server_id][uid]['muted_until']) > datetime.now()
            members.append(u)
            
    return jsonify({**server, 'members': members})

# app.py

@app.route('/api/servers/<server_id>/join', methods=['POST'])
@login_required
def join_server_without_invite(server_id):
    db = load_database()
    server = db['servers'].get(server_id)
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    if session['user_id'] in server.get('members', []):
        return jsonify({'error': 'Already a member'}), 400

    server_bans = db['bans'].get(server_id, {})
    if session['user_id'] in server_bans:
        return jsonify({'error': 'You are banned from this server'}), 403
    if server.get('is_private'):
        return jsonify({'error': 'This server is private. You need an invite link.'}), 403

    # اضافه کردن کاربر به سرور
    server['members'].append(session['user_id'])
    if session['user_id'] not in server.get('user_roles', {}):
        server.setdefault('user_roles', {})[session['user_id']] = ['member']

    # --- شروع کد جدید: ارسال پیام خوش‌آمدگویی ---
    send_welcome_message(db, server_id, session['user_id'])
    # --- پایان کد جدید ---

    # ارسال اطلاع‌رسانی به AntiBot (با مدیریت خطای صحیح)
    try:
        antibot_notify_url = f"{os.getenv('ANTIBOT_URL', 'http://localhost:4212')}/api/antibot/join"
        _antibot_post_later(antibot_notify_url, json={
            'server_id': server_id,
            'user_id': session['user_id'],
            'username': db['users'].get(session['user_id'], {}).get('username', 'Unknown')
        }, timeout=5)
    except Exception:
        # اگر خطایی در ارتباط با AntiBot رخ داد، فقط نادیده بگیریم و ادامه دهیم
        pass
    
    # ذخیره دیتابیس و برگرداندن پاسخ (این بخش باید همیشه اجرا شود)
    save_database(db)
    threading.Thread(target=botshop_fire_member_join, args=(server_id, session['user_id']), daemon=True).start()
    return jsonify({'success': True, 'server': server})

@app.route('/api/servers/<server_id>/transfer-owner', methods=['POST'])
@login_required
def transfer_server_ownership(server_id):
    """Hand the server to another member. Only the current owner, with their password.
    The old owner stays in the server as an admin (or member) and the new owner is notified."""
    data = request.get_json(silent=True) or {}
    target = str(data.get('user_id') or '')
    password = str(data.get('password') or '')
    db = load_database()
    server = db['servers'].get(server_id)
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    me = session['user_id']
    if server.get('owner_id') != me:
        return jsonify({'error': 'Only the server owner can transfer ownership'}), 403
    owner_user = db['users'].get(me) or {}
    if not check_password_hash(owner_user.get('password', ''), password):
        return jsonify({'error': 'Wrong password'}), 401
    if not target or target == me:
        return jsonify({'error': 'Choose another member as the new owner'}), 400
    if target not in server.get('members', []):
        return jsonify({'error': 'The new owner must be a member of this server'}), 400
    new_owner = db['users'].get(target) or {}
    if new_owner.get('is_deleted') or new_owner.get('is_incognito') or new_owner.get('is_bot'):
        return jsonify({'error': 'This account cannot own a server'}), 400

    roles = server.setdefault('roles', {})
    old_role = 'admin' if 'admin' in roles else ('member' if 'member' in roles else None)
    server['owner_id'] = target
    server.setdefault('user_roles', {})[me] = [old_role] if old_role else []
    if 'owner' in roles:
        server['user_roles'][target] = ['owner']
    for _ch in db['channels'].values():       # the old owner keeps only what was explicitly given to them
        if _ch.get('server_id') == server_id:
            _ch['creator_id'] = target
    db.setdefault('notifications', []).append({
        'id': uuid.uuid4().hex[:12],
        'user_id': target,
        'type': 'server_ownership',
        'title': 'You are now the owner',
        'message': f"{owner_user.get('username', 'The owner')} transferred ownership of \"{server.get('name', 'a server')}\" to you",
        'read': False,
        'created_at': datetime.now().isoformat(),
    })
    save_database(db)
    return jsonify({'success': True, 'owner_id': target})


@app.route('/api/servers/<server_id>/settings', methods=['PUT'])
@login_required
def update_server_settings(server_id):
    db = load_database()
    server = db['servers'].get(server_id)
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    # بررسی دسترسی (فقط ادمین/صاحب)
    if session['user_id'] != server.get('owner_id'):
        return owner_only_response('Only the server owner can change server settings')

    data = request.get_json(silent=True) or {}
    if 'name' in data:
        new_name = str(data.get('name') or '').strip()
        if not new_name:
            return jsonify({'error': 'Server name cannot be empty'}), 400
        server['name'] = new_name[:100]
    if 'description' in data:
        server['description'] = str(data.get('description') or '').strip()[:500]
    if 'icon' in data:
        icon = data['icon']
        if icon is not None and not isinstance(icon, str):
            return jsonify({'error': 'Invalid icon'}), 400
        server['icon'] = icon or '🌐'
    if 'banner' in data:
        banner = data['banner']
        if banner is not None and not isinstance(banner, str):
            return jsonify({'error': 'Invalid banner'}), 400
        server['banner'] = banner

    save_database(db)
    return jsonify({'success': True, 'server': server})

# --- Invite Routes ---
@app.route('/api/servers/<server_id>/invites', methods=['POST'])
@login_required
def create_invite(server_id):
    db = load_database()
    server = db['servers'].get(server_id)
    
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    if session['user_id'] not in server.get('members', []):
        return jsonify({'error': 'Not a member'}), 403
    
    invite_code = uuid.uuid4().hex[:8]
    db['invites'][invite_code] = {
        'code': invite_code,
        'server_id': server_id,
        'created_by': session['user_id'],
        'created_at': datetime.now().isoformat(),
        'max_uses': 0,
        'uses': 0,
        'expires_at': (datetime.now() + timedelta(days=7)).isoformat()
    }
    
    save_database(db)
    return jsonify({'success': True, 'invite_code': invite_code, 'invite_link': f'/join/{invite_code}'})

@app.route('/api/servers/<server_id>/invites')
@login_required
def get_invites(server_id):
    db = load_database()
    server = db['servers'].get(server_id)
    
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    if session['user_id'] != server.get('owner_id'):
        return owner_only_response('Only the server owner can see the invites')
    
    invites = [inv for inv in db['invites'].values() if inv['server_id'] == server_id]
    return jsonify(invites)

@app.route('/api/servers/<server_id>/invites/<code>', methods=['DELETE'])
@login_required
def revoke_invite(server_id, code):
    db = load_database()
    server = db['servers'].get(server_id)
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    if session['user_id'] != server.get('owner_id'):
        return owner_only_response('Only the server owner can revoke invites')
    inv = db['invites'].get(code)
    if not inv or inv.get('server_id') != server_id:
        return jsonify({'error': 'Invite not found'}), 404
    del db['invites'][code]
    save_database(db)
    return jsonify({'success': True})


@app.route('/api/join/<invite_code>')
@login_required
def join_server(invite_code):
    db = load_database()
    invite = db['invites'].get(invite_code)
    if not invite:
        return jsonify({'error': 'Invalid invite'}), 404
    _bad = _invite_problem(invite)
    if _bad:
        return jsonify({'error': _bad}), 400

    server_id = invite['server_id']
    server = db['servers'].get(server_id)
    if not server:
        return jsonify({'error': 'Server not found'}), 404

    if session['user_id'] in server.get('members', []):
        return jsonify({'error': 'Already a member'}), 400

    server_bans = db['bans'].get(server_id, {})
    if session['user_id'] in server_bans:
        return jsonify({'error': 'You are banned from this server'}), 403

    server['members'].append(session['user_id'])
    if session['user_id'] not in server.get('user_roles', {}):
        server.setdefault('user_roles', {})[session['user_id']] = ['member']
    
    invite['uses'] += 1
    
    # --- شروع کد جدید: ارسال پیام خوش‌آمدگویی ---
    send_welcome_message(db, server_id, session['user_id'])
    # --- پایان کد جدید ---
    threading.Thread(target=botshop_fire_member_join, args=(server_id, session['user_id']), daemon=True).start()
    # ارسال اطلاع‌رسانی به AntiBot
    try:
        antibot_notify_url = f"{os.getenv('ANTIBOT_URL', 'http://localhost:4212')}/api/antibot/join"
        _antibot_post_later(antibot_notify_url, json={
            'server_id': server_id,
            'user_id': session['user_id'],
            'username': db['users'].get(session['user_id'], {}).get('username', 'Unknown')
        }, timeout=5)
    except Exception:
        pass
    save_database(db)
    return jsonify({'success': True, 'server': server})

# ============================================
# SERVER PREVIEW API - برای پیش‌نمایش لینک سرور
# ============================================

@app.route('/api/invite/<invite_code>/info')
@login_required
def get_invite_info(invite_code):
    """دریافت اطلاعات سرور از کد دعوت برای نمایش پیش‌نمایش"""
    db = load_database()
    
    # جستجوی دعوت‌نامه
    invite = db['invites'].get(invite_code)
    
    if not invite:
        return jsonify({'error': 'Invite not found'}), 404
    
    server_id = invite['server_id']
    server = db['servers'].get(server_id)
    
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    # شمارش اعضا
    member_count = len(server.get('members', []))
    
    # بررسی عضویت کاربر فعلی
    is_member = session['user_id'] in server.get('members', [])
    
    # دریافت اطلاعات کاربران (برای تگ‌ها)
    users = db['users']
    
    # ساخت پاسخ
    response = {
        'success': True,
        'server': {
            'id': server_id,
            'name': server.get('name', 'Unknown Server'),
            'description': server.get('description', server.get('bio', '')),
            'icon': server.get('icon'),
            'banner': server.get('banner'),
            'member_count': member_count,
            'is_private': server.get('is_private', False),
            'tags': server.get('tags', []),
            'is_member': is_member,
            'invite_code': invite_code
        }
    }
    
    return jsonify(response)


@app.route('/api/invite/<invite_code>/join', methods=['POST'])
@login_required
def join_via_invite(invite_code):
    """عضویت در سرور با کد دعوت"""
    db = load_database()
    
    invite = db['invites'].get(invite_code)
    if not invite:
        return jsonify({'error': 'Invalid invite code'}), 404
    
    # بررسی انقضا
    if invite.get('expires_at'):
        expires = datetime.fromisoformat(invite['expires_at'])
        if datetime.now() > expires:
            return jsonify({'error': 'This invite has expired'}), 400
    
    # بررسی حداکثر استفاده
    if invite.get('max_uses', 0) > 0 and invite['uses'] >= invite['max_uses']:
        return jsonify({'error': 'This invite has reached its maximum uses'}), 400
    
    server_id = invite['server_id']
    server = db['servers'].get(server_id)
    
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    # بررسی عضویت قبلی
    if session['user_id'] in server.get('members', []):
        return jsonify({
            'success': True, 
            'message': 'Already a member',
            'server_id': server_id
        }), 200
    
    # بررسی بن شدن
    server_bans = db['bans'].get(server_id, {})
    if session['user_id'] in server_bans:
        ban_info = server_bans[session['user_id']]
        return jsonify({
            'error': 'You are banned from this server',
            'reason': ban_info.get('reason', 'No reason provided'),
            'banned_until': ban_info.get('expires_at')
        }), 403
    
    # افزودن عضو جدید
    server.setdefault('members', []).append(session['user_id'])
    server.setdefault('user_roles', {})[session['user_id']] = ['member']
    
    # افزایش تعداد استفاده
    invite['uses'] = invite.get('uses', 0) + 1
    
    # ارسال پیام خوش‌آمدگویی
    send_welcome_message(db, server_id, session['user_id'])
    
    save_database(db)
    
    return jsonify({
        'success': True,
        'server_id': server_id,
        'server_name': server.get('name')
    })


# ============================================
# جستجوی سرور با نام یا ID
# ============================================

@app.route('/api/servers/search')
@login_required
def search_servers():
    """جستجوی سرورهای عمومی"""
    db = load_database()
    query = request.args.get('q', '').lower()
    
    if len(query) < 2:
        return jsonify({'error': 'Search query too short'}), 400
    
    results = []
    for server_id, server in db['servers'].items():
        # فقط سرورهای عمومی
        if server.get('is_private', False):
            continue
        
        # بررسی تطابق نام
        name = server.get('name', '').lower()
        if query in name:
            member_count = len(server.get('members', []))
            is_member = session['user_id'] in server.get('members', [])
            
            results.append({
                'id': server_id,
                'name': server.get('name'),
                'description': server.get('description', ''),
                'icon': server.get('icon'),
                'banner': server.get('banner'),
                'member_count': member_count,
                'is_member': is_member,
                'tags': server.get('tags', [])
            })
    
    return jsonify(results)


# ============================================
# دریافت اطلاعات سرور (برای لینک‌های مستقیم)
# ============================================

@app.route('/api/servers/<server_id>/preview')
@login_required
def get_server_preview(server_id):
    """دریافت پیش‌نمایش سرور"""
    db = load_database()
    server = db['servers'].get(server_id)
    
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    member_count = len(server.get('members', []))
    is_member = session['user_id'] in server.get('members', [])
    
    return jsonify({
        'success': True,
        'server': {
            'id': server_id,
            'name': server.get('name', 'Unknown Server'),
            'description': server.get('description', server.get('bio', '')),
            'icon': server.get('icon'),
            'banner': server.get('banner'),
            'member_count': member_count,
            'is_private': server.get('is_private', False),
            'tags': server.get('tags', []),
            'is_member': is_member
        }
    })
@app.route('/api/servers/<server_id>/members', methods=['POST'])
@login_required
def add_member_to_server(server_id):
    db = load_database()
    
    # بررسی وجود سرور
    server = db['servers'].get(server_id)
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    current_user_id = session['user_id']
    
    # --- بررسی دسترسی ---
    # فقط مالک سرور یا ادمین می‌تواند کاربر اضافه کند
    is_owner = server.get('owner_id') == current_user_id
    is_admin = False      # site admins have no power over servers
    
    if not is_owner and not is_admin:
        return owner_only_response('Only the server owner can add members')
    
    # --- دریافت کاربر مقصد ---
    data = request.get_json() or {}
    target_user_id = data.get('user_id')
    
    if not target_user_id:
        return jsonify({'error': 'user_id is required'}), 400
    
    # بررسی وجود کاربر
    target_user = db['users'].get(target_user_id)
    if not target_user:
        return jsonify({'error': 'User not found'}), 404
    
    # --- بررسی‌های مختلف ---
    
    # ۱. آیا خودش می‌خواهد خودش را اضافه کند؟
    if target_user_id == current_user_id:
        return jsonify({'error': 'You cannot add yourself'}), 400
    
    # ۲. آیا از قبل عضو است؟
    if target_user_id in server.get('members', []):
        return jsonify({'error': 'User is already a member'}), 400
    
    # ۳. آیا بن شده؟
    server_bans = db['bans'].get(server_id, {})
    if target_user_id in server_bans:
        return jsonify({'error': 'This user is banned from the server'}), 403
    
    # ۴. تنظیم حریم خصوصی «چه کسی می‌تواند من را به گروه‌ها و کانال‌ها اضافه کند»
    if not privacy_allows(db, target_user_id, current_user_id, get_privacy(db, target_user_id).get('invites_visibility')):
        return jsonify({'error': 'This user\'s privacy settings do not allow you to add them to groups or channels', 'code': 'PRIVACY_INVITES'}), 403
    
    # --- افزودن کاربر ---
    server.setdefault('members', []).append(target_user_id)
    
    # تنظیم نقش پیش‌فرض
    server.setdefault('user_roles', {})[target_user_id] = ['member']
    
    # --- ارسال پیام خوش‌آمدگویی ---
    send_welcome_message(db, server_id, target_user_id)
    
    save_database(db)
    threading.Thread(target=botshop_fire_member_join, args=(server_id, target_user_id), daemon=True).start()
    
    return jsonify({
        'success': True,
        'message': f'{target_user.get("username", "User")} added to server',
        'member': {
            'id': target_user_id,
            'username': target_user.get('username'),
            'avatar': target_user.get('avatar'),
            'avatar_color': target_user.get('avatar_color'),
            'is_premium': target_user.get('is_premium', False)
        }
    })
    

# --- Member Management Routes ---
@app.route('/api/servers/<server_id>/kick/<user_id>', methods=['POST'])
@login_required
def kick_member(server_id, user_id):
    db = load_database()
    server = db['servers'].get(server_id)
    
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    if user_id not in server.get('members', []):
        return jsonify({'error': 'User not in server'}), 404
    
    if user_id == server.get('owner_id'):
        return jsonify({'error': 'Cannot kick owner'}), 403
    
    if session['user_id'] != server.get('owner_id') and not has_permission(db, session['user_id'], server_id, 'kick'):
        return jsonify({'error': 'Permission denied'}), 403
    
    server['members'].remove(user_id)
    _strip_member_from_private_channels(db, server.get('id'), user_id)
    if user_id in server.get('user_roles', {}):
        del server['user_roles'][user_id]
    
    # Remove from mutes
    if server_id in db['mutes'] and user_id in db['mutes'][server_id]:
        del db['mutes'][server_id][user_id]
    
    save_database(db)
    return jsonify({'success': True})

@app.route('/api/servers/<server_id>/ban/<user_id>', methods=['POST'])
@login_required
def ban_member(server_id, user_id):
    db = load_database()
    server = db['servers'].get(server_id)
    
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    if user_id not in server.get('members', []):
        return jsonify({'error': 'User not in server'}), 404
    
    if user_id == server.get('owner_id'):
        return jsonify({'error': 'Cannot ban owner'}), 403
    
    if session['user_id'] != server.get('owner_id') and not has_permission(db, session['user_id'], server_id, 'ban'):
        return jsonify({'error': 'Permission denied'}), 403
    
    data = (request.get_json(silent=True) or {}) or {}
    reason = data.get('reason', 'No reason provided')
    
    # Initialize bans dict for server if not exists
    if server_id not in db['bans']:
        db['bans'][server_id] = {}
    
    db['bans'][server_id][user_id] = {
        'banned_at': datetime.now().isoformat(),
        'banned_by': session['user_id'],
        'reason': reason
    }
    
    # Remove from members
    server['members'].remove(user_id)
    _strip_member_from_private_channels(db, server.get('id'), user_id)
    if user_id in server.get('user_roles', {}):
        del server['user_roles'][user_id]
    
    # Remove from mutes
    if server_id in db['mutes'] and user_id in db['mutes'][server_id]:
        del db['mutes'][server_id][user_id]
    
    save_database(db)
    return jsonify({'success': True})

@app.route('/api/servers/<server_id>/unban/<user_id>', methods=['POST'])
@login_required
def unban_member(server_id, user_id):
    db = load_database()
    server = db['servers'].get(server_id)
    
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    if session['user_id'] != server.get('owner_id') and not has_permission(db, session['user_id'], server_id, 'unban'):
        return jsonify({'error': 'Permission denied'}), 403
    
    if server_id not in db['bans'] or user_id not in db['bans'][server_id]:
        return jsonify({'error': 'User is not banned'}), 404
    
    del db['bans'][server_id][user_id]
    
    save_database(db)
    return jsonify({'success': True})

@app.route('/api/servers/<server_id>/bans')
@login_required
def get_bans(server_id):
    db = load_database()
    server = db['servers'].get(server_id)
    
    if not server:
        return jsonify({'error': 'Server not found'}), 404

    bans = db['bans'].get(server_id, {})
    _me = session['user_id']
    if _me not in server.get('members', []) and _me not in bans:
        return jsonify({'error': 'Not a member of this server'}), 403
    _staff = (_me == server.get('owner_id') or has_permission(db, _me, server_id, 'ban')
              or has_permission(db, _me, server_id, 'unban'))
    result = []
    is_banned = False
    
    for user_id, ban_info in bans.items():
        user = db['users'].get(user_id, {})
        # اگر کاربر فعلی در لیست بن‌ها باشد
        if user_id == session['user_id']:
            is_banned = True
            
        if user and _staff:
            result.append({
                'user': sanitize_user_for_viewer(db, session['user_id'], user),
                'banned_at': ban_info['banned_at'],
                'banned_by': ban_info['banned_by'],
                'reason': ban_info['reason']
            })
    
    # اضافه کردن وضعیت کاربر فعلی به پاسخ
    result.append({
        'is_current_user_banned': is_banned,
        'user_id': session['user_id']
    })

    return jsonify(result)

@app.route('/api/servers/<server_id>/mute/<user_id>', methods=['POST'])
@login_required
def mute_member(server_id, user_id):
    db = load_database()
    server = db['servers'].get(server_id)
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    if user_id not in server.get('members', []):
        return jsonify({'error': 'User not in server'}), 404
    if user_id == server.get('owner_id'):
        return jsonify({'error': 'Cannot mute owner'}), 403
    if session['user_id'] != server.get('owner_id') and not has_permission(db, session['user_id'], server_id, 'mute'):
        return jsonify({'error': 'Permission denied'}), 403
    
    data = (request.get_json(silent=True) or {}) or {}
    duration_minutes = data.get('duration', 60)
    
    # ✅ اعتبارسنجی و تبدیل امن
    if duration_minutes is None:
        duration_minutes = 60
    try:
        duration_minutes = int(duration_minutes)
    except (ValueError, TypeError):
        duration_minutes = 60
    
    # محدود کردن به حداقل و حداکثر مجاز
    duration_minutes = max(1, min(duration_minutes, 43200))  # حداکثر 30 روز
    
    reason = data.get('reason', 'No reason provided')
    
    if server_id not in db['mutes']:
        db['mutes'][server_id] = {}
    db['mutes'][server_id][user_id] = {
        'muted_at': datetime.now().isoformat(),
        'muted_until': (datetime.now() + timedelta(minutes=duration_minutes)).isoformat(),
        'muted_by': session['user_id'],
        'reason': reason
    }
    save_database(db)
    return jsonify({'success': True, 'muted_until': db['mutes'][server_id][user_id]['muted_until']})

@app.route('/api/servers/<server_id>/unmute/<user_id>', methods=['POST'])
@login_required
def unmute_member(server_id, user_id):
    db = load_database()
    server = db['servers'].get(server_id)
    
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    if session['user_id'] != server.get('owner_id') and not has_permission(db, session['user_id'], server_id, 'mute'):
        return jsonify({'error': 'Permission denied'}), 403
    
    if server_id not in db['mutes'] or user_id not in db['mutes'][server_id]:
        return jsonify({'error': 'User is not muted'}), 404
    
    del db['mutes'][server_id][user_id]
    
    save_database(db)
    return jsonify({'success': True})

@app.route('/api/servers/<server_id>/mutes')
@login_required
def get_mutes(server_id):
    db = load_database()
    server = db['servers'].get(server_id)
    
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    if session['user_id'] != server.get('owner_id') and not has_permission(db, session['user_id'], server_id, 'mute'):
        return jsonify({'error': 'Permission denied'}), 403
    
    mutes = db['mutes'].get(server_id, {})
    result = []
    now = datetime.now()
    
    for user_id, mute_info in mutes.items():
        if datetime.fromisoformat(mute_info['muted_until']) > now:
            user = db['users'].get(user_id, {})
            if user:
                result.append({
                    'user': sanitize_user_for_viewer(db, session['user_id'], user),
                    'muted_until': mute_info['muted_until'],
                    'muted_by': mute_info['muted_by'],
                    'reason': mute_info['reason']
                })
    
    return jsonify(result)
# --- Role Management ---
@app.route('/api/servers/<server_id>/roles', methods=['POST'])
@login_required
def create_role(server_id):
    db = load_database()
    server = db['servers'].get(server_id)
    
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    if session['user_id'] != server.get('owner_id'):
        return jsonify({'error': 'Only owner can manage roles'}), 403
    
    data = (request.get_json(silent=True) or {})
    role_name = data.get('name', '').strip()
    role_color = data.get('color', '#747e8c')
    
    if not role_name:
        return jsonify({'error': 'Role name required'}), 400
    
    role_id = f"role_{uuid.uuid4().hex[:8]}"
    server.setdefault('roles', {})[role_id] = {
        'id': role_id,
        'name': role_name,
        'color': role_color,
        'permissions': data.get('permissions', ['send_messages', 'react']),
        'hoist': data.get('hoist', False)
    }
    
    save_database(db)
    return jsonify({'success': True, 'role': server['roles'][role_id]})

@app.route('/api/servers/<server_id>/roles/<role_id>', methods=['PUT'])
@login_required
def update_role(server_id, role_id):
    db = load_database()
    server = db['servers'].get(server_id)
    
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    if session['user_id'] != server.get('owner_id'):
        return jsonify({'error': 'Only owner can manage roles'}), 403
    if role_id in LOCKED_ROLE_IDS:
        return jsonify({'error': "The owner role can't be changed"}), 403
    
    role = server.get('roles', {}).get(role_id)
    if not role:
        return jsonify({'error': 'Role not found'}), 404
    
    data = (request.get_json(silent=True) or {})
    if 'name' in data:
        role['name'] = data['name']
    if 'color' in data:
        role['color'] = data['color']
    if 'permissions' in data:
        role['permissions'] = data['permissions']
    if 'hoist' in data:
        role['hoist'] = data['hoist']
    
    save_database(db)
    return jsonify({'success': True, 'role': role})

@app.route('/api/servers/<server_id>/roles/<role_id>', methods=['DELETE'])
@login_required
def delete_role(server_id, role_id):
    db = load_database()
    server = db['servers'].get(server_id)
    
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    if role_id in LOCKED_ROLE_IDS:
        return jsonify({'error': "The owner role can't be deleted"}), 403
    if session['user_id'] != server.get('owner_id'):
        return jsonify({'error': 'Only owner can manage roles'}), 403
    
    role = server.get('roles', {}).get(role_id)
    if not role:
        return jsonify({'error': 'Role not found'}), 404
    
    # Cannot delete default roles
    if role_id in ['owner', 'admin', 'moderator', 'member']:
        return jsonify({'error': 'Cannot delete default roles'}), 400
    
    # Remove role from all members
    user_roles = server.get('user_roles', {})
    for uid, roles in user_roles.items():
        if role_id in roles:
            roles.remove(role_id)
            if not roles:
                user_roles[uid] = ['member']
    
    # Delete the role
    del server['roles'][role_id]
    
    save_database(db)
    return jsonify({'success': True})

@app.route('/api/servers/<server_id>/members/<user_id>/role', methods=['PUT'])
@login_required
def set_member_role(server_id, user_id):
    db = load_database()
    server = db['servers'].get(server_id)
    
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    if session['user_id'] != server.get('owner_id'):
        return jsonify({'error': 'Only owner can manage roles'}), 403
    if user_id == server.get('owner_id'):
        return jsonify({'error': "The server owner's roles can't be changed"}), 403
    
    if user_id not in server.get('members', []):
        return jsonify({'error': 'User not in server'}), 404
    
    data = (request.get_json(silent=True) or {})
    role_ids = data.get('roles', ['member'])
    
    server.setdefault('user_roles', {})[user_id] = role_ids
    
    save_database(db)
    return jsonify({'success': True})

# --- Category & Channel Routes ---
@app.route('/api/servers/<server_id>/categories', methods=['POST'])
@login_required
def create_category(server_id):
    data = (request.get_json(silent=True) or {})
    name = data.get('name', '').strip()
    
    if not name:
        return jsonify({'error': 'Category name is required'}), 400
    
    db = load_database()
    server = db['servers'].get(server_id)
    
    if not server or session['user_id'] not in server.get('members', []):
        return jsonify({'error': 'Unauthorized'}), 403
    
    if session['user_id'] != server.get('owner_id'):
        return owner_only_response('Only the server owner can create channels and categories')

    name = name[:50]
    cat_id = f"cat_{uuid.uuid4().hex[:8]}"
    db['categories'][cat_id] = {
        'id': cat_id,
        'server_id': server_id,
        'name': name,
        'created_at': datetime.now().isoformat()
    }
    save_database(db)
    return jsonify({'success': True, 'category': db['categories'][cat_id]})

@app.route('/api/servers/<server_id>/categories')
@login_required
def get_categories(server_id):
    db = load_database()
    _srv = db['servers'].get(server_id)
    if not _srv:
        return jsonify({'error': 'Server not found'}), 404
    if session['user_id'] not in _srv.get('members', []):
        return jsonify({'error': 'Not a member of this server'}), 403
    categories = [c for sid, c in db['categories'].items() if c.get('server_id') == server_id]
    return jsonify(categories)

def _can_manage_server_channels(db, uid, server_id):
    server = db['servers'].get(server_id) or {}
    return bool(uid and server.get('owner_id') == uid)


@app.route('/api/categories/<cat_id>', methods=['PUT'])
@login_required
def update_category(cat_id):
    db = load_database()
    cat = db['categories'].get(cat_id)
    if not cat:
        return jsonify({'error': 'Category not found'}), 404
    if not _can_manage_server_channels(db, session['user_id'], cat.get('server_id')):
        return jsonify({'error': 'Permission denied'}), 403
    name = str((request.get_json(silent=True) or {}).get('name') or '').strip()[:50]
    if not name:
        return jsonify({'error': 'Category name is required'}), 400
    cat['name'] = name
    save_database(db)
    return jsonify({'success': True, 'category': cat})


@app.route('/api/categories/<cat_id>', methods=['DELETE'])
@login_required
def delete_category(cat_id):
    db = load_database()
    cat = db['categories'].get(cat_id)
    if not cat:
        return jsonify({'error': 'Category not found'}), 404
    if not _can_manage_server_channels(db, session['user_id'], cat.get('server_id')):
        return jsonify({'error': 'Permission denied'}), 403
    for ch in db['channels'].values():          # keep the channels, just move them out
        if ch.get('category_id') == cat_id:
            ch['category_id'] = None
    del db['categories'][cat_id]
    save_database(db)
    return jsonify({'success': True})


CHANNEL_PASSWORD_MIN = 4
CHANNEL_PASSWORD_MAX = 50
_HIDDEN_CHANNEL_FIELDS = ('password_hash', 'unlocked_users')
_unlock_attempts = {}      # (user_id, channel_id) -> [unix times of wrong passwords]


def _password_error(pw):
    if not (CHANNEL_PASSWORD_MIN <= len(pw) <= CHANNEL_PASSWORD_MAX):
        return f'Password must be {CHANNEL_PASSWORD_MIN}-{CHANNEL_PASSWORD_MAX} characters'
    return None


def _channel_is_staff(db, channel, uid):
    server = db['servers'].get(channel.get('server_id')) or {}
    if server.get('owner_id') == uid:
        return True
    return has_permission(db, uid, channel.get('server_id'), 'manage_messages')


def _is_private_member(channel, uid):
    """Private channels: the people chosen by the owner (and a legacy creator)."""
    return (uid == channel.get('creator_id')
            or uid in (channel.get('private_members') or [])
            or uid in (channel.get('view_only_members') or []))


def _is_channel_owner(db, channel, uid):
    oid = (db['servers'].get(channel.get('server_id')) or {}).get('owner_id')
    return bool(uid and oid and uid == oid)


def channel_access(db, channel, uid):
    """What this user may do in the channel:
       visible    - private channels: owner + chosen members only (site admins get nothing extra)
       view_only  - chosen as "can see, can't chat"
       locked     - a password is set and they have not entered it yet
       can_write  - may post. Read-only channels: staff only. View-only members: never.
       The SERVER OWNER always passes: visible, never locked, never view-only, can always write."""
    if _is_channel_owner(db, channel, uid):
        return {'visible': True, 'staff': True, 'locked': False,
                'view_only': False, 'can_write': True, 'owner': True}
    staff = _channel_is_staff(db, channel, uid)
    visible = (not channel.get('private')) or _is_private_member(channel, uid)
    view_only = bool(channel.get('private')) and uid in (channel.get('view_only_members') or []) \
        and uid not in (channel.get('private_members') or []) and uid != channel.get('creator_id')
    locked = bool(channel.get('password_hash')) and uid not in (channel.get('unlocked_users') or [])
    if view_only or not visible:
        can_write = False
    else:
        can_write = (not locked) and (staff or not channel.get('read_only'))
    return {'visible': visible, 'staff': staff, 'locked': locked,
            'view_only': view_only, 'can_write': can_write, 'owner': False}


def public_channel(db, channel, uid):
    """Channel as sent to the browser: never the password hash or the unlock list."""
    out = {k: v for k, v in channel.items() if k not in _HIDDEN_CHANNEL_FIELDS}
    acc = channel_access(db, channel, uid)
    out['private'] = bool(channel.get('private'))
    out['private_members'] = list(channel.get('private_members') or []) if (acc['owner'] or acc['visible']) else []
    out['view_only_members'] = list(channel.get('view_only_members') or []) if (acc['owner'] or acc['visible']) else []
    out['view_only'] = acc['view_only']
    out['read_only'] = bool(channel.get('read_only'))
    out['has_password'] = bool(channel.get('password_hash'))
    out['locked'] = acc['locked']
    out['can_write'] = acc['can_write']
    out['owner_access'] = acc['owner']
    return out


def channel_visible_to(db, channel, uid):
    """Normal channels: every server member. Private channels: owner + chosen members only."""
    return channel_access(db, channel, uid)['visible']


def _clean_member_ids(db, server, ids):
    """Only real members of the server, no duplicates, max 50."""
    out = []
    if not isinstance(ids, list):
        return out
    for uid in ids:
        if isinstance(uid, str) and uid in server.get('members', []) and uid not in out and uid != server.get('owner_id'):
            out.append(uid)
    return out[:50]


@app.route('/api/channels/<channel_id>/private-members', methods=['POST'])
@login_required
def set_channel_private_member(channel_id):
    """Add/remove a member of a private channel. kind='chat' (can see and chat) or 'view' (can see only).
    Only the creator or someone with manage_channels can do this, and only if they can see the channel."""
    data = request.get_json(silent=True) or {}
    target = str(data.get('user_id') or '')
    action = data.get('action')
    kind = data.get('kind', 'chat')
    db = load_database()
    channel = db['channels'].get(channel_id)
    if not channel:
        return jsonify({'error': 'Channel not found'}), 404
    server = db['servers'].get(channel['server_id'])
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    uid = session['user_id']
    if uid != server.get('owner_id'):
        return owner_only_response('Only the server owner can change who can see a private channel')
    if target not in server.get('members', []):
        return jsonify({'error': 'User is not a member of this server'}), 400
    if target == server.get('owner_id'):      # the owner always has access, nothing to store
        return jsonify({'success': True, 'private_members': channel.get('private_members', []),
                        'view_only_members': channel.get('view_only_members', [])})
    if action not in ('add', 'remove') or kind not in ('chat', 'view'):
        return jsonify({'error': 'action must be add/remove and kind chat/view'}), 400
    key = 'private_members' if kind == 'chat' else 'view_only_members'
    other = 'view_only_members' if kind == 'chat' else 'private_members'
    members = channel.setdefault(key, [])
    if action == 'add':
        if target not in members:
            members.append(target)
        if target in (channel.get(other) or []):
            channel[other].remove(target)
    elif target in members:
        members.remove(target)
    save_database(db)
    return jsonify({'success': True, 'private_members': channel.get('private_members', []),
                    'view_only_members': channel.get('view_only_members', [])})


@app.route('/api/channels', methods=['POST'])
@login_required
def create_channel():
    data = (request.get_json(silent=True) or {})
    server_id = data.get('server_id')
    name = data.get('name', '').strip()
    channel_type = data.get('type', 'text')
    category_id = data.get('category_id')
    
    if not server_id or not name:
        return jsonify({'error': 'Server ID and channel name are required'}), 400
    if data.get('password') and _password_error(str(data.get('password'))):
        return jsonify({'error': _password_error(str(data.get('password')))}), 400
    
    db = load_database()
    server = db['servers'].get(server_id)
    
    if not server or session['user_id'] not in server.get('members', []):
        return jsonify({'error': 'Not a member'}), 403
    
    if session['user_id'] != server.get('owner_id'):
        return owner_only_response('Only the server owner can create channels and categories')
    
    channel_id = f"channel_{uuid.uuid4().hex[:8]}"
    db['channels'][channel_id] = {
        'id': channel_id,
        'server_id': server_id,
        'name': name,
        'type': channel_type,
        'category_id': category_id,
        'description': str(data.get('description', '') or '').strip()[:500],
        'private': bool(data.get('private')),
        'private_members': _clean_member_ids(db, server, data.get('private_members')),
        'view_only_members': [u for u in _clean_member_ids(db, server, data.get('view_only_members'))
                              if u not in (data.get('private_members') or [])],
        'creator_id': session['user_id'],
        'nitro': False,
        'created_at': datetime.now().isoformat()
    }
    
    db['channels'][channel_id]['read_only'] = bool(data.get('read_only'))
    if data.get('password'):
        db['channels'][channel_id]['password_hash'] = generate_password_hash(str(data.get('password')))
    save_database(db)
    return jsonify({'success': True, 'channel': public_channel(db, db['channels'][channel_id], session['user_id'])})

@app.route('/api/channels/<channel_id>/unlock', methods=['POST'])
@login_required
def unlock_channel(channel_id):
    """Enter the channel password once. Wrong guesses: 5 per 5 minutes per user and channel."""
    uid = session['user_id']
    db = load_database()
    channel = db['channels'].get(channel_id)
    if not channel:
        return jsonify({'error': 'Channel not found'}), 404
    acc = channel_access(db, channel, uid)
    if not acc['visible']:
        return jsonify({'error': 'Channel not found'}), 404
    if not channel.get('password_hash') or not acc['locked']:
        return jsonify({'success': True, 'unlocked': True})
    key = (uid, channel_id)
    now = datetime.now().timestamp()
    tries = [t for t in _unlock_attempts.get(key, []) if now - t < 300]
    if len(tries) >= 5:
        return jsonify({'error': 'Too many wrong passwords. Wait 5 minutes.'}), 429
    pw = str((request.get_json(silent=True) or {}).get('password') or '')
    if not check_password_hash(channel['password_hash'], pw):
        tries.append(now)
        _unlock_attempts[key] = tries
        return jsonify({'error': 'Wrong password'}), 403
    _unlock_attempts.pop(key, None)
    unlocked = channel.setdefault('unlocked_users', [])
    if uid not in unlocked:
        unlocked.append(uid)
    save_database(db)
    return jsonify({'success': True, 'unlocked': True})


@app.route('/api/servers/<server_id>/channels')
@login_required
def get_channels(server_id):
    db = load_database()
    uid = session['user_id']
    _srv = db['servers'].get(server_id)
    if not _srv:
        return jsonify({'error': 'Server not found'}), 404
    if uid not in _srv.get('members', []):
        return jsonify({'error': 'Not a member of this server'}), 403
    channels = [public_channel(db, ch, uid) for sid, ch in db['channels'].items()
                if ch.get('server_id') == server_id and channel_visible_to(db, ch, uid)]
    return jsonify(channels)

@app.route('/api/channels/<channel_id>', methods=['DELETE'])
@login_required
def delete_channel(channel_id):
    db = load_database()
    channel = db['channels'].get(channel_id)
    
    if not channel:
        return jsonify({'error': 'Channel not found'}), 404
    
    server = db['servers'].get(channel['server_id'])
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    if session['user_id'] != server.get('owner_id'):
        return owner_only_response('Only the server owner can delete channels')
    
    del db['channels'][channel_id]
    for tid in [t for t, th in (db.get('threads') or {}).items() if th.get('channel_id') == channel_id]:
        db['threads'].pop(tid, None)
    (db.get('message_pins') or {}).pop('ch_' + channel_id, None)
    # remove the channel's messages + auto-delete timer so nothing is left orphaned
    for mid in [m for m, msg in db['all_messages'].items() if msg.get('channel_id') == channel_id]:
        del db['all_messages'][mid]
    db.get('auto_delete', {}).pop(channel_id, None)
    save_database(db)
    return jsonify({'success': True})

@app.route('/api/channels/<channel_id>/messages')
@login_required
def get_messages(channel_id):
    db = load_database()
    if purge_expired_messages(db):
        save_database(db)
    channel = db['channels'].get(channel_id)
    
    if not channel:
        return jsonify({'error': 'Channel not found'}), 404
    
    server = db['servers'].get(channel['server_id'])
    if not server or session['user_id'] not in server.get('members', []):
        return jsonify({'error': 'Not a member'}), 403
    
    if not channel_visible_to(db, channel, session['user_id']):
        return jsonify({'error': 'Channel not found'}), 404
    acc = channel_access(db, channel, session['user_id'])
    if acc['locked']:
        return jsonify({'error': 'This channel is locked. Enter the password first.', 'code': 'CHANNEL_LOCKED'}), 403
    # Check if muted
    mutes = db['mutes'].get(channel['server_id'], {})
    if session['user_id'] in mutes:
        mute_info = mutes[session['user_id']]
        if datetime.fromisoformat(mute_info['muted_until']) > datetime.now():
            return jsonify({'error': 'You are muted in this server', 'muted_until': mute_info['muted_until']}), 403
    
    messages = [msg for msg_id, msg in db['all_messages'].items() if msg.get('channel_id') == channel_id]
    messages.sort(key=lambda x: x.get('created_at', ''))
    
    enriched_messages = []
    for msg in messages:
        user = db['users'].get(msg.get('user_id'), {})
        
        # === ساخت reply_info ===
        reply_info = None
        if msg.get('reply_to'):
            original_msg = db['all_messages'].get(msg['reply_to'])
            if original_msg:
                original_user = db['users'].get(original_msg.get('user_id'), {})
                reply_info = {
                    'id': original_msg['id'],
                    'content': (original_msg.get('content') or '')[:100] + ('...' if len(original_msg.get('content') or '') > 100 else ''),
                    'author': {
                        'id': original_user.get('id'),
                        'username': original_user.get('username', 'Unknown'),
                        'avatar': original_user.get('avatar'),
                        'avatar_color': original_user.get('avatar_color', '#7289da')
                    }
                }
        
        enriched_messages.append({
            **msg,
            'reply_info': reply_info,  # ← اضافه شد
            'author': {
                'id': user.get('id'),
                'username': user.get('username', 'Unknown'),
                'avatar': user.get('avatar'),
                'avatar_color': user.get('avatar_color', '#7289da'),
                'is_premium': user.get('is_premium', False), 'verified': user_is_verified(user)
            }
        })
    
    return jsonify(enriched_messages)


@app.route('/api/dm/<user_id>/messages')
@login_required
def get_dm_messages(user_id):
    try:
        db = load_database()
        
        # system conversations: read-only, mark as read when opened
        if is_system_dm_id(user_id):
            if system_dm_mark_read(db, session['user_id'], user_id):
                save_database(db)
            return jsonify(system_dm_enrich(db, session['user_id'], user_id))
        
        if purge_expired_messages(db):
            save_database(db)
        
        # Check if both users exist
        if user_id not in db['users']:
            return jsonify({'error': 'User not found'}), 404
        
        # (blocked users can still be opened: the client swaps the input box for an "Unblock" button)
        # NOTE: when the other user blocked *you* the chat still opens (no overlay);
        # sending then fails and "Discord Message Delivery" explains why.
        dm_key = tuple(sorted([session['user_id'], user_id]))
        dm_key_str = f"dm_{'_'.join(dm_key)}"
        
        messages = db['direct_messages'].get(dm_key_str, [])
        messages = [m for m in messages if dm_visible_to(m, session['user_id'])]
        enriched = []
        _status_changed = False
        
        for msg in messages:
            user = db['users'].get(msg.get('user_id'), {})
            # sent / delivered / seen ticks for MY messages
            if msg.get('user_id') == session['user_id']:
                _before = msg.get('delivered_at')
                msg['status'] = dm_message_status(db, msg, user_id)
                if msg.get('delivered_at') != _before:
                    _status_changed = True
            
            # === ساخت reply_info ===
            reply_info = None
            if msg.get('reply_to'):
                # جستجو در پیام‌های DM برای پیدا کردن پیام اصلی
                original_msg = find_dm_message_by_id(db, dm_key_str, msg['reply_to'])
                if original_msg:
                    original_user = db['users'].get(original_msg.get('user_id'), {})
                    reply_info = {
                        'id': original_msg['id'],
                        'content': (original_msg.get('content') or '')[:100] + ('...' if len(original_msg.get('content') or '') > 100 else ''),
                        'author': {
                            'id': original_user.get('id'),
                            'username': original_user.get('username', 'Unknown'),
                            'avatar': original_user.get('avatar'),
                            'avatar_color': original_user.get('avatar_color', '#7289da')
                        }
                    }
            
            enriched.append({
                **msg,
                'reply_info': reply_info,  # ← اضافه شد
                'author': {
                    'id': user.get('id'),
                    'username': user.get('username', 'Unknown'),
                    'avatar': user.get('avatar'),
                    'avatar_color': user.get('avatar_color', '#7289da'),
                    'is_premium': user.get('is_premium', False), 'verified': user_is_verified(user),
                    'is_deleted': user.get('is_deleted', False)
                }
            })
        
        if _status_changed:
            save_database(db)
        return jsonify(enriched)
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/api/dm/<user_id>/seen', methods=['POST'])
@login_required
def dm_mark_seen(user_id):
    """The viewer opened the chat: every message the other user sent becomes SEEN (green tick for them)."""
    if is_system_dm_id(user_id):
        return jsonify({'success': True, 'marked': 0})
    db = load_database()
    if user_id not in db['users']:
        return jsonify({'error': 'User not found'}), 404
    dm_key = tuple(sorted([session['user_id'], user_id]))
    dm_key_str = f"dm_{'_'.join(dm_key)}"
    now = datetime.now().isoformat()
    marked = 0
    for m in db['direct_messages'].get(dm_key_str, []):
        if m.get('user_id') == user_id and not m.get('seen_at'):
            m['seen_at'] = now
            if not m.get('delivered_at'):
                m['delivered_at'] = now
            marked += 1
    if marked:
        save_database(db)
    return jsonify({'success': True, 'marked': marked})


def find_dm_message_by_id(db, dm_key_str, message_id):
    """پیدا کردن پیام DM با ID"""
    messages = db['direct_messages'].get(dm_key_str, [])
    for msg in messages:
        if msg.get('id') == message_id:
            return msg
    return None

@app.route('/api/messages/<message_id>/edit', methods=['PUT'])
@login_required
def edit_message(message_id):
    data = (request.get_json(silent=True) or {})
    new_content = data.get('content', '').strip()
    if len(new_content) > MAX_MESSAGE_LENGTH:
        return jsonify({'error': f'Message exceeds {MAX_MESSAGE_LENGTH} characters limit'}), 400
    
    db = load_database()
    msg = db['all_messages'].get(message_id)
    
    if not msg:
        return jsonify({'error': 'Message not found'}), 404
        
    if msg['user_id'] != session['user_id']:
        return jsonify({'error': 'Not your message'}), 403
    if msg.get('deleted'):
        return jsonify({'error': 'This message was deleted'}), 410
    _ch_e = db['channels'].get(msg.get('channel_id'))
    if _ch_e and channel_access(db, _ch_e, session['user_id'])['view_only']:
        return jsonify({'error': "You can't edit messages in this channel", 'code': 'CHANNEL_VIEW_ONLY'}), 403
        
    msg['content'] = new_content
    msg['edited_at'] = datetime.now().isoformat()
    
    save_database(db)
    return jsonify({'success': True})

@app.route('/api/messages/<message_id>', methods=['DELETE'])
@login_required
def delete_message(message_id):
    db = load_database()
    msg = db['all_messages'].get(message_id)
    
    if not msg:
        return jsonify({'error': 'Message not found'}), 404
    
    channel = db['channels'].get(msg['channel_id'])
    server = db['servers'].get(channel['server_id']) if channel else None
    
    # Allow delete if own message or has permission
    if msg['user_id'] != session['user_id']:
        if not server or (session['user_id'] != server.get('owner_id') and not has_permission(db, session['user_id'], channel['server_id'], 'manage_messages')):
            return jsonify({'error': 'Permission denied'}), 403
        
    if not msg.get('deleted'):
        soft_delete_message(msg, session['user_id'])
        save_database(db)
    return jsonify({'success': True, 'deleted': True})

@app.route('/api/messages/<message_id>/react', methods=['POST'])
@login_required
def react_to_message(message_id):
    data = (request.get_json(silent=True) or {})
    emoji = data.get('emoji', '👍')
    if not isinstance(emoji, str) or not emoji or len(emoji) > 16:
        return jsonify({'error': 'Invalid emoji'}), 400
    
    db = load_database()
    msg = db['all_messages'].get(message_id)
    
    if not msg or msg.get('deleted'):
        return jsonify({'error': 'Message not found'}), 404
    ch_of_msg = db['channels'].get(msg.get('channel_id'))
    if ch_of_msg and channel_access(db, ch_of_msg, session['user_id'])['locked']:
        return jsonify({'error': 'This channel is locked', 'code': 'CHANNEL_LOCKED'}), 403
    if ch_of_msg and channel_access(db, ch_of_msg, session['user_id'])['view_only']:
        return jsonify({'error': "You can't react in this channel", 'code': 'CHANNEL_VIEW_ONLY'}), 403
    
    if emoji not in msg['reactions']:
        msg['reactions'][emoji] = []
        
    if session['user_id'] in msg['reactions'][emoji]:
        msg['reactions'][emoji].remove(session['user_id'])
        if not msg['reactions'][emoji]:
            del msg['reactions'][emoji]
    else:
        msg['reactions'][emoji].append(session['user_id'])
        
    save_database(db)
    return jsonify({'success': True, 'reactions': msg['reactions']})

@app.route('/api/users')
@login_required
@privacy_filtered
def get_all_userss():
    db = load_database()
    users = []
    for uid, user in db['users'].items():
        if user.get('is_incognito') and uid != session.get('user_id'):
            continue
        u = user.copy()
        u.pop('password', None)
        users.append(u)
        # app.py - Part 2 (ادامه)
    return jsonify(users)

# --- Thread Support ---
@app.route('/api/channels/<channel_id>/threads', methods=['POST'])
@login_required
def create_thread(channel_id):
    data = (request.get_json(silent=True) or {})
    name = data.get('name', '').strip()
    
    if not name:
        return jsonify({'error': 'Thread name required'}), 400
        
    db = load_database()
    channel = db['channels'].get(channel_id)
    if not channel:
        return jsonify({'error': 'Channel not found'}), 404
        
    server = db['servers'].get(channel['server_id'])
    if not server or session['user_id'] not in server.get('members', []):
        return jsonify({'error': 'Unauthorized'}), 403
    if channel_access(db, channel, session['user_id'])['view_only']:
        return jsonify({'error': "You can't start threads in this channel", 'code': 'CHANNEL_VIEW_ONLY'}), 403
        
    thread_id = f"thread_{uuid.uuid4().hex[:8]}"
    db['threads'][thread_id] = {
        'id': thread_id,
        'channel_id': channel_id,
        'server_id': channel['server_id'],
        'name': name,
        'creator_id': session['user_id'],
        'members': [session['user_id']],
        'created_at': datetime.now().isoformat()
    }
    
    save_database(db)
    return jsonify({'success': True, 'thread': db['threads'][thread_id]})

@app.route('/api/threads/<thread_id>')
@login_required
def get_thread(thread_id):
    db = load_database()
    thread = db['threads'].get(thread_id)
    if not thread:
        return jsonify({'error': 'Thread not found'}), 404
        
    messages = [msg for msg_id, msg in db['all_messages'].items() if msg.get('channel_id') == thread_id]
    messages.sort(key=lambda x: x.get('created_at', ''))
    
    enriched = []
    for msg in messages:
        user = db['users'].get(msg.get('user_id'), {})
        enriched.append({**msg, 'author': {
            'id': user.get('id'), 'username': user.get('username'), 
            'avatar': user.get('avatar'), 'avatar_color': user.get('avatar_color'),
            'is_premium': user.get('is_premium')
        }})
        
    return jsonify({**thread, 'messages': enriched})

# --- Profile & Store ---
# --- Profile & Store ---
# --- Profile & Store ---
@app.route('/api/profile', methods=['PUT'])
@login_required
def update_profile():
    data = (request.get_json(silent=True) or {})
    db = load_database()
    
    user = db['users'].get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # ✅ اضافه کردن banner و is_animated به فیلدهای مجاز
    updates = {}
    if 'username' in data:
        new_name = str(data.get('username') or '').strip()
        if not (3 <= len(new_name) <= 32) or '<' in new_name or '>' in new_name:
            return jsonify({'error': 'Username must be 3-32 characters and cannot contain < or >'}), 400
        if any(o.get('id') != user.get('id') and (o.get('username') or '').lower() == new_name.lower()
               for o in db['users'].values()):
            return jsonify({'error': 'Username already taken'}), 400
        updates['username'] = new_name
    if 'bio' in data:
        updates['bio'] = str(data.get('bio') or '')[:500]
    for _key in ('avatar', 'banner'):
        if _key in data:
            v = data[_key]
            if v in (None, ''):
                updates[_key] = None
            elif isinstance(v, str) and len(v) <= 2000000 and (
                    (len(v) <= 500 and v.startswith(('/uploads/', 'https://', 'http://')))
                    or re.match(r'^data:image/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/=]+$', v)):
                updates[_key] = v
            else:
                return jsonify({'error': f'Invalid {_key}'}), 400
    if 'avatar_color' in data:
        if not re.fullmatch(r'#[0-9a-fA-F]{3,8}', str(data.get('avatar_color') or '')):
            return jsonify({'error': 'Invalid color'}), 400
        updates['avatar_color'] = data['avatar_color']
    if 'status' in data:
        if data['status'] not in ('online', 'idle', 'dnd', 'offline', 'invisible'):
            return jsonify({'error': 'Invalid status'}), 400
        updates['status'] = data['status']
    if 'current_activity' in data:
        act = data['current_activity']
        if act is None or (isinstance(act, str) and len(act) <= 128) or (isinstance(act, dict) and len(json.dumps(act)) <= 1000):
            updates['current_activity'] = act
        else:
            return jsonify({'error': 'Invalid activity'}), 400
    if 'is_animated' in data:
        updates['is_animated'] = bool(data['is_animated'])
    user.update(updates)
    if 'phone' in data:
        phone = re.sub(r'[\s\-()]', '', str(data.get('phone') or ''))
        if phone and not re.fullmatch(r'\+?\d{7,15}', phone):
            return jsonify({'error': 'Invalid phone number'}), 400
        user['phone'] = phone
    if 'birthdate' in data:
        bd = str(data.get('birthdate') or '').strip()
        if bd:
            try:
                parsed = datetime.strptime(bd, '%Y-%m-%d')
            except ValueError:
                return jsonify({'error': 'Invalid birth date'}), 400
            if parsed > datetime.now() or parsed.year < 1900:
                return jsonify({'error': 'Invalid birth date'}), 400
        user['birthdate'] = bd
            
    save_database(db)
    user.pop('password', None)
    return jsonify({'success': True, 'user': user})

@app.route('/api/store/items')
def get_store_items():
    db = load_database()
    items = list(db['store_items'].values())
    return jsonify(items)

    # ============================================
# DM MESSAGE EDIT & DELETE ENDPOINTS
# ============================================

@app.route('/api/dm/<user_id>/messages/<message_id>', methods=['PUT'])
@login_required
def edit_dm_message(user_id, message_id):
    """ویرایش پیام DM"""
    data = (request.get_json(silent=True) or {})
    new_content = data.get('content', '').strip()
    if len(new_content) > MAX_MESSAGE_LENGTH:
        return jsonify({'error': f'Message exceeds {MAX_MESSAGE_LENGTH} characters limit'}), 400
    
    if not new_content:
        return jsonify({'error': 'Message content is required'}), 400
    
    db = load_database()
    
    # ساختن dm_key
    dm_key = tuple(sorted([session['user_id'], user_id]))
    dm_key_str = f"dm_{'_'.join(dm_key)}"
    
    # پیدا کردن پیام
    messages = db['direct_messages'].get(dm_key_str, [])
    msg_found = None
    msg_index = None
    
    for i, msg in enumerate(messages):
        if msg.get('id') == message_id:
            msg_found = msg
            msg_index = i
            break
    
    if not msg_found:
        return jsonify({'error': 'Message not found'}), 404
    
    # بررسی مالکیت پیام
    if msg_found['user_id'] != session['user_id']:
        return jsonify({'error': 'You can only edit your own messages'}), 403
    if msg_found.get('deleted'):
        return jsonify({'error': 'This message was deleted'}), 410
    
    # ویرایش پیام
    db['direct_messages'][dm_key_str][msg_index]['content'] = new_content
    db['direct_messages'][dm_key_str][msg_index]['edited_at'] = datetime.now().isoformat()
    
    save_database(db)
    
    return jsonify({
        'success': True,
        'message': db['direct_messages'][dm_key_str][msg_index]
    })


@app.route('/api/dm/<user_id>/messages/<message_id>', methods=['DELETE'])
@login_required
def delete_dm_message(user_id, message_id):
    """حذف پیام DM: scope='me' فقط برای خودم پنهان می‌شود، scope='everyone' برای هر دو طرف (فقط پیام خودم)"""
    if is_system_dm_id(user_id):
        return jsonify({'error': SYSTEM_DM_LOCK_TEXT, 'code': 'SYSTEM_DM_LOCKED'}), 403
    body = request.get_json(silent=True) or {}
    scope = _dm_scope(body.get('scope') or request.args.get('scope'), session['user_id'])

    db = load_database()
    dm_key_str = f"dm_{'_'.join(sorted([session['user_id'], user_id]))}"
    msg = next((m for m in db['direct_messages'].get(dm_key_str, []) if m.get('id') == message_id), None)
    if not msg:
        return jsonify({'error': 'Message not found'}), 404

    if scope == 'me':
        dm_hide_for(msg, session['user_id'])
        save_database(db)
        return jsonify({'success': True, 'deleted': True, 'scope': 'me'})

    if msg['user_id'] != session['user_id']:
        return jsonify({'error': 'You can only delete your own messages for everyone'}), 403
    if not msg.get('deleted'):
        soft_delete_message(msg, session['user_id'])
        save_database(db)
    return jsonify({'success': True, 'deleted': True, 'scope': 'everyone'})

    # ============================================
    # REPLY TO MESSAGE
    # ============================================
@app.route('/api/channels/<channel_id>/messages', methods=['POST'])
@login_required
def send_message(channel_id):
    # === بررسی Rate Limit ===
    allowed, wait_ms = check_message_rate_limit(session['user_id'])
    if not allowed:
        wait_seconds = wait_ms / 1000
        return jsonify({
            'error': f'Too many messages! Please wait {wait_seconds:.1f} seconds',
            'wait_ms': wait_ms
        }), 429
    # === پایان بررسی ===
    
    data = (request.get_json(silent=True) or {})
    content = data.get('content', '').strip()
    image_url = _clean_image_url(data.get('image_url'))
    attachment, location, poll, rich_error = parse_rich_payload(data)
    if rich_error:
        return rich_error
    if attachment and attachment['type'] == 'image' and not image_url:
        image_url = attachment['url']
    reply_to = data.get('reply_to')
    effect = data.get('effect', 'none')
    
    # اعتبارسنجی effect
    valid_effects = ['none', 'glow', 'shake', 'rainbow', 'fire', 'ice']
    if effect not in valid_effects:
        effect = 'none'
    
    # ============================================
    # ✅ بررسی محدودیت 200 کاراکتر
    # ============================================
    content, was_truncated, char_count = limit_message_length(content)
    if was_truncated:
        return jsonify({
            'error': f'Message exceeds {MAX_MESSAGE_LENGTH} characters limit',
            'char_count': char_count,
            'max_length': MAX_MESSAGE_LENGTH
        }), 400
    # ============================================
    
    if not content and not image_url and not (attachment or location or poll):
        return jsonify({'error': 'Message content or image is required'}), 400
    
    db = load_database()
    channel = db['channels'].get(channel_id)
    if not channel:
        return jsonify({'error': 'Channel not found'}), 404
    
    server = db['servers'].get(channel['server_id'])
    if not server or session['user_id'] not in server.get('members', []):
        return jsonify({'error': 'Not a member of this server'}), 403
    
    if not channel_visible_to(db, channel, session['user_id']):
        return jsonify({'error': 'Channel not found'}), 404
    acc = channel_access(db, channel, session['user_id'])
    if acc['locked']:
        return jsonify({'error': 'This channel is locked. Enter the password first.', 'code': 'CHANNEL_LOCKED'}), 403
    if acc['view_only']:
        return jsonify({'error': "You can't send messages in this channel", 'code': 'CHANNEL_VIEW_ONLY'}), 403
    if not acc['can_write']:
        return jsonify({'error': 'This channel is read only', 'code': 'CHANNEL_READ_ONLY'}), 403
    # Check if muted
    mutes = db['mutes'].get(channel['server_id'], {})
    if session['user_id'] in mutes:
        mute_info = mutes[session['user_id']]
        if datetime.fromisoformat(mute_info['muted_until']) > datetime.now():
            return jsonify({'error': 'You are muted until ' + mute_info['muted_until']}), 403
    
    if session['user_id'] != server.get('owner_id') and not has_permission(db, session['user_id'], channel['server_id'], 'send_messages'):
        return jsonify({'error': 'Permission denied'}), 403

    # slowmode (owner / moderators / site admins are exempt)
    slow = int(channel.get('slowmode') or 0)
    if (slow > 0 and session['user_id'] != server.get('owner_id')
            and not has_permission(db, session['user_id'], channel['server_id'], 'manage_messages')):
        mine = [x.get('created_at', '') for x in db['all_messages'].values()
                if x.get('channel_id') == channel_id and x.get('user_id') == session['user_id']
                and not x.get('deleted')]
        if mine:
            try:
                elapsed = (datetime.now() - datetime.fromisoformat(max(mine))).total_seconds()
            except ValueError:
                elapsed = slow
            if elapsed < slow:
                wait = int(slow - elapsed) + 1
                return jsonify({'error': f'Slowmode is on. Wait {wait}s before sending another message.',
                                'retry_after': wait}), 429
    
    message_id = str(uuid.uuid4().hex[:12])
    message = {
        'id': message_id,
        'channel_id': channel_id,
        'user_id': session['user_id'],
        'content': content,
        'image_url': image_url,
        'attachment': attachment,
        'location': location,
        'poll': poll,
        'created_at': datetime.now().isoformat(),
        'edited_at': None,
        'reactions': {},
        'type': 'message',
        'reply_to': reply_to,
        'effect': effect
    }
    stamp_expiry(db, channel_id, message)
    
    db['all_messages'][message_id] = message
    # @username / @everyone / @here -> a persistent notification for every mentioned member
    try:
        create_mention_notifications(db, message, channel, server)
    except Exception as _mention_err:
        print(f"⚠️ mention notifications failed: {_mention_err}")
    save_database(db)
    # BotShop: let the installed bots see this message (runs in the background)
    threading.Thread(target=botshop_handle_message, args=(message_id,), daemon=True).start()
    
    user = db['users'].get(session['user_id'], {})
    
    reply_info = None
    if reply_to:
        original_msg = db['all_messages'].get(reply_to)
        if original_msg:
            original_user = db['users'].get(original_msg.get('user_id'), {})
            reply_info = {
                'id': original_msg['id'],
                'content': original_msg['content'][:100] + ('...' if len(original_msg['content']) > 100 else ''),
                'author': {
                    'id': original_user.get('id'),
                    'username': original_user.get('username', 'Unknown'),
                    'avatar': original_user.get('avatar'),
                    'avatar_color': original_user.get('avatar_color', '#7289da')
                }
            }
    
    return jsonify({
        **message,
        'author': {
            'id': user.get('id'),
            'username': user.get('username', 'Unknown'),
            'avatar': user.get('avatar'),
            'avatar_color': user.get('avatar_color', '#7289da'),
            'is_premium': user.get('is_premium', False), 'verified': user_is_verified(user)
        },
        'reply_info': reply_info
    })


# ============================================
# FORWARD MESSAGE
# ============================================
@app.route('/api/messages/<message_id>/forward', methods=['POST'])
@login_required
def forward_message(message_id):
    """Forward a message to another channel or DM"""
    data = (request.get_json(silent=True) or {})
    target_type = data.get('target_type')  # 'channel' یا 'dm'
    target_id = data.get('target_id')  # channel_id یا user_id
    
    if target_type not in ['channel', 'dm']:
        return jsonify({'error': 'Invalid target type'}), 400
    
    if not target_id:
        return jsonify({'error': 'Target ID required'}), 400
    
    db = load_database()
    
    # پیدا کردن پیام اصلی
    original_msg = db['all_messages'].get(message_id)
    if not original_msg or original_msg.get('deleted'):
        return jsonify({'error': 'Message not found'}), 404
    
    original_user = db['users'].get(original_msg.get('user_id'), {})
    
    if target_type == 'channel':
        # ارسال به کانال
        channel = db['channels'].get(target_id)
        if not channel:
            return jsonify({'error': 'Channel not found'}), 404
        
        server = db['servers'].get(channel['server_id'])
        if not server or session['user_id'] not in server.get('members', []):
            return jsonify({'error': 'Not a member of this server'}), 403
        
        _acc = channel_access(db, channel, session['user_id'])
        if not _acc['visible']:
            return jsonify({'error': 'Channel not found'}), 404
        if _acc['locked']:
            return jsonify({'error': 'The target channel is locked', 'code': 'CHANNEL_LOCKED'}), 403
        if not _acc['can_write']:
            return jsonify({'error': "You can't send messages in the target channel", 'code': 'CHANNEL_READ_ONLY'}), 403
        
        message_id_new = str(uuid.uuid4().hex[:12])
        forwarded_msg = {
            'id': message_id_new,
            'channel_id': target_id,
            'user_id': session['user_id'],
            'content': original_msg.get('content', ''),
            'image_url': original_msg.get('image_url'),
            **forward_rich_fields(original_msg),
            'created_at': datetime.now().isoformat(),
            'edited_at': None,
            'reactions': {},
            'type': 'message',
            'reply_to': None,
            'forwarded_from': {
                'message_id': message_id,
                'original_author': forward_author_name(db, original_user, session['user_id']),
                'original_channel': channel.get('name') if channel else None
            }
        }
        
        stamp_expiry(db, target_id, forwarded_msg)
        db['all_messages'][message_id_new] = forwarded_msg
        save_database(db)
        
        user = db['users'].get(session['user_id'], {})
        return jsonify({
            **forwarded_msg,
            'author': {
                'id': user.get('id'),
                'username': user.get('username', 'Unknown'),
                'avatar': user.get('avatar'),
                'avatar_color': user.get('avatar_color', '#7289da'),
                'is_premium': user.get('is_premium', False), 'verified': user_is_verified(user)
            }
        })
    
    else:  # target_type == 'dm'
        # ارسال به DM
        if target_id not in db['users']:
            return jsonify({'error': 'User not found'}), 404
        if db['users'][target_id].get('is_deleted'):
            return jsonify({'error': 'This account was deleted. You can no longer message it.', 'code': 'ACCOUNT_DELETED'}), 403
        
        # Check block status
        sender = db['users'].get(session['user_id'])
        if target_id in sender.get('blocked_users', []):
            return jsonify({'error': 'You have blocked this user'}), 403
        
        receiver = db['users'].get(target_id)
        if session['user_id'] in receiver.get('blocked_users', []):
            notify_blocked_delivery(db, session['user_id'], target_id)
            save_database(db)
            return jsonify({
                'error': f"{receiver.get('username', 'This user')} has blocked you. Message not sent!",
                'code': 'BLOCKED_DELIVERY', 'blocked_by_them': True
            }), 403
        
        dm_key = tuple(sorted([session['user_id'], target_id]))
        dm_key_str = f"dm_{'_'.join(dm_key)}"
        
        if dm_key_str not in db['direct_messages']:
            db['direct_messages'][dm_key_str] = []
        
        message_id_new = str(uuid.uuid4().hex[:12])
        forwarded_msg = {
            'id': message_id_new,
            'dm_key': dm_key_str,
            'user_id': session['user_id'],
            'content': original_msg.get('content', ''),
            'image_url': original_msg.get('image_url'),
            **forward_rich_fields(original_msg),
            'created_at': datetime.now().isoformat(),
            'reactions': {},
            'forwarded_from': {
                'message_id': message_id,
                'original_author': forward_author_name(db, original_user, session['user_id'])
            }
        }
        
        stamp_expiry(db, dm_key_str, forwarded_msg)
        db['direct_messages'][dm_key_str].append(forwarded_msg)
        save_database(db)
        
        user = db['users'].get(session['user_id'], {})
        return jsonify({
            **forwarded_msg,
            'author': {
                'id': user.get('id'),
                'username': user.get('username', 'Unknown'),
                'avatar': user.get('avatar'),
                'avatar_color': user.get('avatar_color', '#7289da'),
                'is_premium': user.get('is_premium', False), 'verified': user_is_verified(user)
            }
        })


# ============================================
# REACTIONS FOR DM MESSAGES
# ============================================
@app.route('/api/dm/<user_id>/messages/<message_id>/react', methods=['POST'])
@login_required
def react_dm_message(user_id, message_id):
    """Add/remove reaction on DM message"""
    data = (request.get_json(silent=True) or {})
    emoji = data.get('emoji', '👍')
    if not isinstance(emoji, str) or not emoji or len(emoji) > 16:
        return jsonify({'error': 'Invalid emoji'}), 400
    
    db = load_database()
    
    dm_key = tuple(sorted([session['user_id'], user_id]))
    dm_key_str = f"dm_{'_'.join(dm_key)}"
    
    messages = db['direct_messages'].get(dm_key_str, [])
    msg_found = None
    msg_index = None
    
    for i, msg in enumerate(messages):
        if msg.get('id') == message_id:
            msg_found = msg
            msg_index = i
            break
    
    if not msg_found or msg_found.get('deleted'):
        return jsonify({'error': 'Message not found'}), 404
    
    if 'reactions' not in msg_found:
        msg_found['reactions'] = {}
    
    if emoji not in msg_found['reactions']:
        msg_found['reactions'][emoji] = []
    
    if session['user_id'] in msg_found['reactions'][emoji]:
        msg_found['reactions'][emoji].remove(session['user_id'])
        if not msg_found['reactions'][emoji]:
            del msg_found['reactions'][emoji]
    else:
        msg_found['reactions'][emoji].append(session['user_id'])
    
    save_database(db)
    return jsonify({'success': True, 'reactions': msg_found['reactions']})

@app.route('/api/store/items', methods=['POST'])
@admin_required
def add_store_item():
    data = (request.get_json(silent=True) or {})
    db = load_database()
    
    item_id = str(uuid.uuid4().hex[:8])
    item = {
        'id': item_id,
        'name': data.get('name', ''),
        'description': data.get('description', ''),
        'price': data.get('price', 0),
        'type': data.get('type', 'badge'),
        'icon': data.get('icon', '🎁'),
        'active': True,
        'created_at': datetime.now().isoformat()
    }
    
    db['store_items'][item_id] = item
    save_database(db)
    return jsonify({'success': True, 'item': item})

@app.route('/api/store/items/<item_id>', methods=['DELETE'])
@admin_required
def delete_store_item(item_id):
    db = load_database()
    if item_id in db['store_items']:
        del db['store_items'][item_id]
        save_database(db)
        return jsonify({'success': True})
    return jsonify({'error': 'Item not found'}), 404

@app.route('/api/store/buy/<item_id>', methods=['POST'])
@login_required
def buy_item(item_id):
    db = load_database()
    item = db['store_items'].get(item_id)
    
    if not item:
        return jsonify({'error': 'Item not found'}), 404
    
    user = db['users'].get(session['user_id'])
    
    if user['coins'] < item['price']:
        return jsonify({'error': 'Not enough coins'}), 400
    
    if item_id in user.get('inventory', []):
        return jsonify({'error': 'Already owned'}), 400
    
    user['coins'] -= item['price']
    if 'inventory' not in user:
        user['inventory'] = []
    user['inventory'].append(item_id)
    
    # Apply premium if item is premium
    if item.get('type') == 'premium':
        user['is_premium'] = True
        user['premium_since'] = datetime.now().isoformat()
    
    save_database(db)
    return jsonify({'success': True, 'coins': user['coins']})

# --- Admin & Stats ---
@app.route('/api/admin/users')
@admin_required
def get_all_users():
    db = load_database()
    users = []
    for uid, user in db['users'].items():
        u = user.copy()
        u.pop('password', None)
        users.append(u)
    return jsonify(users)

@app.route('/api/admin/stats')
@admin_required
def get_stats():
    db = load_database()
    return jsonify({
        'total_users': len(db['users']),
        'total_servers': len(db['servers']),
        'total_channels': len(db['channels']),
        'total_messages': len(db['all_messages']),
        'total_store_items': len(db['store_items']),
        'premium_users': sum(1 for u in db['users'].values() if u.get('is_premium'))
    })

@app.route('/api/admin/settings', methods=['PUT'])
@admin_required
def update_settings():
    data = (request.get_json(silent=True) or {})
    db = load_database()
    
    if 'registration_enabled' in data:
        db['settings']['registration_enabled'] = data['registration_enabled']
    if 'store_enabled' in data:
        db['settings']['store_enabled'] = data['store_enabled']
        
    save_database(db)
    return jsonify({'success': True, 'settings': db['settings']})

@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    """
    حذف اکانت کاربر توسط ادمین
    همراه با حذف تمام سرورهای ساخته شده توسط این کاربر
    """
    db = load_database()
    
    # بررسی وجود کاربر
    if user_id not in db['users']:
        return jsonify({'error': 'User not found'}), 404
    
    # جلوگیری از حذف خود ادمین
    if user_id == session['user_id']:
        return jsonify({'error': 'Cannot delete yourself'}), 400
    
    user = db['users'].get(user_id, {})
    username = user.get('username', 'Unknown')
    
    # ============================================
    # بررسی: آیا این اکانت خاص (محافظت شده) است؟
    # ============================================
    protected_usernames = ['admin', 'Aminsoft356']
    
    if username.lower() in [u.lower() for u in protected_usernames]:
        return jsonify({
            'error': 'Cannot delete this account',
            'reason': 'This is a protected system account and cannot be deleted'
        }), 403
    
    # ============================================
    # حذف سرورهای ساخته شده توسط این کاربر
    # ============================================
    servers_to_delete = []
    for server_id, server in list(db['servers'].items()):
        if server.get('owner_id') == user_id:
            servers_to_delete.append(server_id)
    
    deleted_servers_count = 0
    for server_id in servers_to_delete:
        # حذف کانال‌های سرور
        channels_to_delete = [ch_id for ch_id, ch in db['channels'].items()
                              if ch.get('server_id') == server_id]
        for ch_id in channels_to_delete:
            del db['channels'][ch_id]
        
        # حذف پیام‌های سرور
        messages_to_delete = [msg_id for msg_id, msg in db['all_messages'].items()
                              if msg.get('channel_id') in channels_to_delete]
        for msg_id in messages_to_delete:
            del db['all_messages'][msg_id]
        
        # حذف بن‌ها و میوت‌ها
        if server_id in db.get('bans', {}):
            del db['bans'][server_id]
        if server_id in db.get('mutes', {}):
            del db['mutes'][server_id]
        
        # حذف اینوایت‌ها
        invites_to_delete = [inv_code for inv_code, inv in db['invites'].items()
                             if inv.get('server_id') == server_id]
        for inv_code in invites_to_delete:
            del db['invites'][inv_code]
        
        # حذف دسته‌بندی‌ها
        cats_to_delete = [cat_id for cat_id, cat in db['categories'].items()
                          if cat.get('server_id') == server_id]
        for cat_id in cats_to_delete:
            del db['categories'][cat_id]
        
        # حذف تردها
        threads_to_delete = [t_id for t_id, t in db['threads'].items()
                             if t.get('server_id') == server_id]
        for t_id in threads_to_delete:
            del db['threads'][t_id]
        
        # حذف سرور
        del db['servers'][server_id]
        deleted_servers_count += 1
    
    # ============================================
    # حذف کاربر از سرورهایی که فقط عضو آنهاست
    # ============================================
    for server_id, server in list(db['servers'].items()):
        if user_id in server.get('members', []):
            server['members'].remove(user_id)
            _strip_member_from_private_channels(db, server.get('id'), user_id)
        if user_id in server.get('user_roles', {}):
            del server['user_roles'][user_id]
    
    # ============================================
    # حذف از لیست بن‌های تمام سرورها
    # ============================================
    for server_id in list(db.get('bans', {}).keys()):
        if user_id in db['bans'][server_id]:
            del db['bans'][server_id][user_id]
    
    # ============================================
    # حذف از لیست میوت‌های تمام سرورها
    # ============================================
    for server_id in list(db.get('mutes', {}).keys()):
        if user_id in db['mutes'][server_id]:
            del db['mutes'][server_id][user_id]
    
    # ============================================
    # حذف پیام‌های کاربر در سرورها
    # ============================================
    messages_to_delete = [msg_id for msg_id, msg in db['all_messages'].items()
                          if msg.get('user_id') == user_id]
    for msg_id in messages_to_delete:
        del db['all_messages'][msg_id]
    
    # ============================================
    # حذف DM‌ها
    # ============================================
    dm_keys_to_clear = []
    for dm_key, messages in db.get('direct_messages', {}).items():
        user_ids_in_dm = dm_key.replace('dm_', '').split('_')
        if user_id in user_ids_in_dm:
            dm_keys_to_clear.append(dm_key)
    
    for dm_key in dm_keys_to_clear:
        db['direct_messages'][dm_key] = [
            msg for msg in db['direct_messages'][dm_key]
            if msg.get('user_id') != user_id
        ]
        if not db['direct_messages'][dm_key]:
            del db['direct_messages'][dm_key]
    
    # ============================================
    # حذف از لیست blocked_users سایر کاربران
    # ============================================
    for uid, other_user in db['users'].items():
        if 'blocked_users' in other_user and user_id in other_user['blocked_users']:
            other_user['blocked_users'].remove(user_id)
    
    # ============================================
    # حذف از notifications
    # ============================================
    db['notifications'] = [n for n in db.get('notifications', [])
                           if n.get('user_id') != user_id]
    
    # ============================================
    # حذف از اینوایت‌های ساخته شده
    # ============================================
    invites_to_delete = [inv_code for inv_code, inv in db['invites'].items()
                         if inv.get('created_by') == user_id]
    for inv_code in invites_to_delete:
        del db['invites'][inv_code]
    
    # ============================================
    # حذف خود کاربر
    # ============================================
    if user_id in db['users']:
        del db['users'][user_id]

    _stories_remove_user(user_id)
    # حذف تنظیمات ذخیره‌شده‌ی کاربر (user_settings.json)
    with settings_lock:
        _all_settings = _load_all_settings()
        if _all_settings.pop(user_id, None) is not None:
            _save_all_settings(_all_settings)
    
    # ذخیره دیتابیس
    save_database(db)
    
    return jsonify({
        'success': True,
        'message': f'User "{username}" deleted successfully',
        'deleted_servers_count': deleted_servers_count
    })

@app.route('/api/coins/add', methods=['POST'])
@admin_required
def add_coins():
    data = (request.get_json(silent=True) or {})
    user_id = data.get('user_id')
    amount = data.get('amount', 0)
    
    db = load_database()
    user = db['users'].get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    try:
        amount = int(amount)
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid amount'}), 400
    user['coins'] = user.get('coins', 0) + amount
    save_database(db)
    return jsonify({'success': True, 'coins': user['coins']})

# ============================================
# COINS: transfers between users (web/API + BotShop "economy" bots)
# ============================================
COIN_TRANSFER_MIN = 1
COIN_TRANSFER_MAX = 1_000_000


def parse_coin_amount(raw):
    """A whole number of coins, or None when the value is not a valid transfer amount."""
    if isinstance(raw, bool):
        return None
    try:
        value = int(float(raw))
    except (TypeError, ValueError, OverflowError):
        return None
    if value < COIN_TRANSFER_MIN or value > COIN_TRANSFER_MAX:
        return None
    return value


def coin_transfer(db, from_id, to_id, amount):
    """Moves `amount` coins from one user to another.
    Returns (status, error, sender_balance). The caller saves the database when error is None."""
    if not from_id or not to_id:
        return 400, 'Recipient is required', None
    if from_id == to_id:
        return 400, "You can't send coins to yourself", None
    sender = db['users'].get(from_id)
    receiver = db['users'].get(to_id)
    if not sender or not receiver or sender.get('is_deleted') or receiver.get('is_deleted'):
        return 404, 'User not found', None
    if receiver.get('is_bot'):
        return 400, 'Coins cannot be sent to bots', None
    if from_id in (receiver.get('blocked_users') or []):
        return 403, 'You cannot send coins to this user', None
    balance = int(sender.get('coins', 0) or 0)
    if balance < amount:
        return 400, 'Not enough coins', None
    sender['coins'] = balance - amount
    receiver['coins'] = int(receiver.get('coins', 0) or 0) + amount
    return 200, None, sender['coins']


@app.route('/api/coins/me')
@login_required
def coins_me():
    db = load_database()
    me = db['users'].get(session['user_id'], {})
    return jsonify({
        'success': True,
        'coins': int(me.get('coins', 0) or 0),
        'transfer_limits': {'min': COIN_TRANSFER_MIN, 'max': COIN_TRANSFER_MAX},
    })


@app.route('/api/coins/transfer', methods=['POST'])
@login_required
def coins_transfer():
    """Body: {"amount": 100, "to_user_id": "..."}  or  {"amount": 100, "username": "ali"}"""
    data = request.get_json(silent=True) or {}
    amount = parse_coin_amount(data.get('amount'))
    if amount is None:
        return jsonify({'error': f'Amount must be a whole number between {COIN_TRANSFER_MIN} and {COIN_TRANSFER_MAX}'}), 400
    db = load_database()
    to_id = str(data.get('to_user_id') or '').strip()
    if not to_id and data.get('username'):
        wanted = str(data['username']).strip().lstrip('@').lower()
        to_id = next((u['id'] for u in db['users'].values()
                      if str(u.get('username', '')).lower() == wanted and not u.get('is_deleted')), '')
    status, error, balance = coin_transfer(db, session['user_id'], to_id, amount)
    if error:
        return jsonify({'error': error}), status
    save_database(db)
    return jsonify({'success': True, 'sent': amount, 'coins': balance, 'to_user_id': to_id})


@app.route('/api/premium/give', methods=['POST'])
@admin_required
def give_premium():
    data = (request.get_json(silent=True) or {})
    user_id = data.get('user_id')
    duration = data.get('duration', 30)  # days
    
    db = load_database()
    user = db['users'].get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user['is_premium'] = True
    user['premium_since'] = datetime.now().isoformat()
    user['premium_expires'] = (datetime.now() + timedelta(days=duration)).isoformat()
    save_database(db)
    return jsonify({'success': True})

@app.route('/api/premium/revoke', methods=['POST'])
@admin_required
def revoke_premium():
    data = (request.get_json(silent=True) or {})
    user_id = data.get('user_id')
    
    db = load_database()
    user = db['users'].get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user['is_premium'] = False
    user['premium_expires'] = None
    save_database(db)
    return jsonify({'success': True})

# --- Notifications ---
@app.route('/api/notifications')
@login_required
def get_notifications():
    db = load_database()
    notifications = [n for n in db.get('notifications', []) if n.get('user_id') == session['user_id']]
    notifications.sort(key=lambda n: n.get('created_at') or '', reverse=True)
    return jsonify(notifications[:300])

@app.route('/api/notifications/<notif_id>', methods=['DELETE'])
@login_required
def dismiss_notification(notif_id):
    db = load_database()
    db['notifications'] = [n for n in db.get('notifications', []) if n.get('id') != notif_id or n.get('user_id') != session['user_id']]
    save_database(db)
    return jsonify({'success': True})

# --- Get Server Members ---
@app.route('/api/servers/<server_id>/members')
@login_required
@privacy_filtered
def get_server_members_api(server_id):
    db = load_database()
    server = db['servers'].get(server_id)
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    # Check if user is a member
    if session['user_id'] not in server.get('members', []):
        return jsonify({'error': 'Not a member of this server'}), 403
    
    members = []
    for uid in server.get('members', []):
        user = db['users'].get(uid, {})
        if user:
            u = user.copy()
            u.pop('password', None)
            u['roles'] = server.get('user_roles', {}).get(uid, ['member'])
            members.append(u)
    
    return jsonify(members)

# ============================================
# SELECT & DELETE SEVERAL MESSAGES
# ============================================
def _clean_ids(data):
    ids = (data or {}).get('ids') or []
    if not isinstance(ids, list):
        return []
    out, seen = [], set()
    for i in ids:
        if isinstance(i, str) and i and i not in seen:
            seen.add(i)
            out.append(i)
    return out[:200]


@app.route('/api/dm/<user_id>/messages/bulk-delete', methods=['POST'])
@login_required
def bulk_delete_dm_messages(user_id):
    """Delete the selected DM messages. Mode 'me' hides them for you; 'everyone' removes your own messages for both."""
    if is_system_dm_id(user_id):
        return jsonify({'error': SYSTEM_DM_LOCK_TEXT, 'code': 'SYSTEM_DM_LOCKED'}), 403
    body = request.get_json(silent=True)
    ids = _clean_ids(body)
    if not ids:
        return jsonify({'error': 'No messages selected'}), 400
    scope = _dm_scope((body or {}).get('scope'), session['user_id'])
    db = load_database()
    if user_id not in db['users']:
        return jsonify({'error': 'User not found'}), 404
    dm_key_str = f"dm_{'_'.join(sorted([session['user_id'], user_id]))}"
    by_id = {m.get('id'): m for m in db['direct_messages'].get(dm_key_str, [])}
    deleted, skipped = [], 0
    for mid in ids:
        m = by_id.get(mid)
        if not m:
            skipped += 1
        elif scope == 'me':
            dm_hide_for(m, session['user_id'])
            deleted.append(mid)
        elif m.get('user_id') != session['user_id']:
            skipped += 1
        else:
            if not m.get('deleted'):
                soft_delete_message(m, session['user_id'])
            deleted.append(mid)
    if deleted:
        save_database(db)
    return jsonify({'success': True, 'deleted': deleted, 'skipped': skipped, 'scope': scope})


@app.route('/api/dm/<user_id>/delete-chat', methods=['POST'])
@login_required
def delete_dm_chat(user_id):
    """Delete a whole DM from the list. 'me': every message is hidden for you only. 'everyone': the chat is emptied for both."""
    if is_system_dm_id(user_id):
        return jsonify({'error': SYSTEM_DM_LOCK_TEXT, 'code': 'SYSTEM_DM_LOCKED'}), 403
    body = request.get_json(silent=True) or {}
    scope = _dm_scope(body.get('scope'), session['user_id'])
    db = load_database()
    if user_id not in db['users']:
        return jsonify({'error': 'User not found'}), 404
    dm_key_str = f"dm_{'_'.join(sorted([session['user_id'], user_id]))}"
    msgs = db.setdefault('direct_messages', {}).get(dm_key_str, [])
    count = len(msgs)
    if scope == 'me':
        for m in msgs:
            dm_hide_for(m, session['user_id'])
        dm_mark_chat_deleted(db, session['user_id'], user_id)
    else:
        db['direct_messages'][dm_key_str] = []
        dm_mark_chat_deleted(db, session['user_id'], user_id)
        dm_mark_chat_deleted(db, user_id, session['user_id'])
    save_database(db)
    return jsonify({'success': True, 'scope': scope, 'deleted_count': count})


@app.route('/api/channels/<channel_id>/messages/bulk-delete', methods=['POST'])
@login_required
def bulk_delete_channel_messages(channel_id):
    """Delete the selected messages of a channel: your own, or any when you own the server / can manage messages."""
    ids = _clean_ids(request.get_json(silent=True))
    if not ids:
        return jsonify({'error': 'No messages selected'}), 400
    db = load_database()
    channel = db['channels'].get(channel_id)
    if not channel:
        return jsonify({'error': 'Channel not found'}), 404
    server = db['servers'].get(channel['server_id'])
    if not server or session['user_id'] not in server.get('members', []):
        return jsonify({'error': 'Not a member'}), 403
    can_manage = (session['user_id'] == server.get('owner_id')
                  or has_permission(db, session['user_id'], channel['server_id'], 'manage_messages'))
    deleted, skipped = [], 0
    for mid in ids:
        m = db['all_messages'].get(mid)
        if not m or m.get('channel_id') != channel_id:
            skipped += 1
        elif m.get('user_id') != session['user_id'] and not can_manage:
            skipped += 1
        elif m.get('deleted'):
            deleted.append(mid)
        else:
            soft_delete_message(m, session['user_id'])
            deleted.append(mid)
    if deleted:
        save_database(db)
    return jsonify({'success': True, 'deleted': deleted, 'skipped': skipped})


# ============================================
# DELETE-MESSAGE TIMER  (new messages of a chat disappear after N seconds)
# ============================================
@app.route('/api/dm/<user_id>/auto-delete', methods=['GET', 'PUT'])
@login_required
def dm_auto_delete(user_id):
    if is_system_dm_id(user_id):
        return jsonify({'error': SYSTEM_DM_LOCK_TEXT, 'code': 'SYSTEM_DM_LOCKED'}), 403
    db = load_database()
    if user_id not in db['users']:
        return jsonify({'error': 'User not found'}), 404
    dm_key_str = f"dm_{'_'.join(sorted([session['user_id'], user_id]))}"
    if request.method == 'GET':
        return jsonify({'seconds': get_auto_delete_seconds(db, dm_key_str), 'can_edit': True,
                        'choices': list(AUTO_DELETE_CHOICES)})
    me = db['users'].get(session['user_id']) or {}
    if user_id in me.get('blocked_users', []):
        return jsonify({'error': 'You have blocked this user'}), 403
    if session['user_id'] in (db['users'][user_id].get('blocked_users') or []):
        return jsonify({'error': 'This user has blocked you'}), 403
    try:
        secs = int((request.get_json(silent=True) or {}).get('seconds', 0))
    except (TypeError, ValueError):
        secs = -1
    if secs not in AUTO_DELETE_CHOICES:
        return jsonify({'error': 'Invalid timer'}), 400
    timers = db.setdefault('auto_delete', {})
    if secs:
        timers[dm_key_str] = secs
    else:
        timers.pop(dm_key_str, None)
    save_database(db)
    return jsonify({'success': True, 'seconds': secs})


@app.route('/api/channels/<channel_id>/auto-delete', methods=['GET', 'PUT'])
@login_required
def channel_auto_delete(channel_id):
    db = load_database()
    channel = db['channels'].get(channel_id)
    if not channel:
        return jsonify({'error': 'Channel not found'}), 404
    server = db['servers'].get(channel['server_id'])
    if not server or session['user_id'] not in server.get('members', []):
        return jsonify({'error': 'Not a member'}), 403
    can_edit = (session['user_id'] == server.get('owner_id'))
    if request.method == 'GET':
        return jsonify({'seconds': get_auto_delete_seconds(db, channel_id), 'can_edit': bool(can_edit),
                        'choices': list(AUTO_DELETE_CHOICES)})
    if not can_edit:
        return jsonify({'error': 'Permission denied'}), 403
    try:
        secs = int((request.get_json(silent=True) or {}).get('seconds', 0))
    except (TypeError, ValueError):
        secs = -1
    if secs not in AUTO_DELETE_CHOICES:
        return jsonify({'error': 'Invalid timer'}), 400
    timers = db.setdefault('auto_delete', {})
    if secs:
        timers[channel_id] = secs
    else:
        timers.pop(channel_id, None)
    save_database(db)
    return jsonify({'success': True, 'seconds': secs})


# ============================================
# DELETE ALL DM MESSAGES
# ============================================
@app.route('/api/dm/<user_id>/messages/all', methods=['DELETE'])
@login_required
def delete_all_dm_messages(user_id):
    """Delete all messages in a DM conversation"""
    db = load_database()
    
    # Check if target user exists
    if user_id not in db['users']:
        return jsonify({'error': 'User not found'}), 404
    
    # Check block status
    sender = db['users'].get(session['user_id'])
    if sender and user_id in sender.get('blocked_users', []):
        return jsonify({'error': 'You have blocked this user'}), 403
    
    receiver = db['users'].get(user_id)
    if receiver and session['user_id'] in receiver.get('blocked_users', []):
        return jsonify({'error': 'This user has blocked you'}), 403
    
    # Build DM key
    dm_key = tuple(sorted([session['user_id'], user_id]))
    dm_key_str = f"dm_{'_'.join(dm_key)}"
    
    # Count messages before deletion
    messages = db['direct_messages'].get(dm_key_str, [])
    deleted_count = len(messages)
    
    # Delete all messages
    if dm_key_str in db['direct_messages']:
        db['direct_messages'][dm_key_str] = []
    
    save_database(db)
    
    return jsonify({
        'success': True,
        'deleted_count': deleted_count
    })

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_get_all_users():
    """
    این روت توسط ربات استفاده می‌شود تا لیست کاربران را بگیرد.
    اگر می‌خواهید ربات مستقیماً به دیتابیس دسترسی داشته باشد، می‌توانید این روت را حذف کنید
    و مستقیماً db را در متدهای ربات استفاده کنید، اما برای امنیت بیشتر بهتر است از API استفاده شود.
    """
    return account_manager.get_all_users()

# 2. دریافت اطلاعات یک کاربر خاص
@app.route('/api/admin/users/<user_id>', methods=['GET'])
@admin_required
def admin_get_user_info(user_id):
    """دریافت اطلاعات یک کاربر توسط ربات یا ادمین"""
    # ربات از متد خود استفاده می‌کند، اما اینجا برای دسترسی مستقیم ادمین‌ها هم قرار می‌دهیم
    db = load_database()
    user = db['users'].get(user_id)
    if user:
        user.pop('password', None)
        return jsonify(user)
    return jsonify({'error': 'User not found'}), 404

# 3. حذف اکانت کاربر (توسط ربات)
@app.route('/api/admin/users/<user_id>/delete', methods=['DELETE'])
@admin_required
def admin_delete_user_account_api(user_id):
    """
    روت حذف اکانت. ربات از طریق این روت اکانت را حذف می‌کند.
    params: ?reason=...
    """
    reason = request.args.get('reason', '')
    # گرفتن ID ادمین درخواست‌دهنده از session
    admin_id = session.get('user_id')
    
    success, message = account_manager.delete_user_account(admin_id, user_id, reason)
    if success:
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'success': False, 'error': message}), 400

# 4. تغییر وضعیت اکانت (توسط ربات)
@app.route('/api/admin/users/<user_id>/account-status', methods=['PUT'])
@admin_required
def admin_set_account_status_api(user_id):
    """
    روت تغییر وضعیت اکانت.
    body: {"status": "limited", "reason": "..."}
    """
    data = (request.get_json(silent=True) or {})
    status = data.get('status')
    reason = data.get('reason', '')
    admin_id = session.get('user_id')
    
    success, message = account_manager.set_account_status(admin_id, user_id, status, reason)
    if success:
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'success': False, 'error': message}), 400

# 5. تنظیم کنترل والدین (توسط ربات)
@app.route('/api/admin/users/<user_id>/parental-control', methods=['PUT'])
@admin_required
def admin_set_parental_control_api(user_id):
    """
    روت تنظیم کنترل والدین.
    body: {"daily_limit_minutes": 120, "blocked_tags": [...]}
    """
    data = (request.get_json(silent=True) or {})
    admin_id = session.get('user_id')
    
    success, message = account_manager.set_parental_control(admin_id, user_id, data)
    if success:
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'success': False, 'error': message}), 400

# 6. دریافت تنظیمات کنترل والدین یک کاربر
@app.route('/api/admin/users/<user_id>/parental-control', methods=['GET'])
@admin_required
def admin_get_parental_control_api(user_id):
    """دریافت تنظیمات کنترل والدین برای یک کاربر"""
    settings = account_manager.get_parental_control_settings(user_id)
    if settings:
        return jsonify(settings)
    return jsonify({'error': 'Settings not found'}), 404

# 7. تنظیم محدودیت زمانی (توسط ربات)
@app.route('/api/admin/users/<user_id>/time-limit', methods=['PUT'])
@admin_required
def admin_set_time_limit_api(user_id):
    """
    روت تنظیم محدودیت زمانی.
    body: {"daily_limit_minutes": 120, "reason": "..."}
    """
    data = (request.get_json(silent=True) or {})
    minutes = data.get('daily_limit_minutes')
    reason = data.get('reason', '')
    admin_id = session.get('user_id')
    
    success, message = account_manager.set_time_limit(admin_id, user_id, minutes, reason)
    if success:
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'success': False, 'error': message}), 400

# 8. تنظیم ساعات مجاز (توسط ربات)
@app.route('/api/admin/users/<user_id>/allowed-hours', methods=['PUT'])
@admin_required
def admin_set_allowed_hours_api(user_id):
    """
    روت تنظیم ساعات مجاز.
    body: {"start_hour": 8, "end_hour": 22, "reason": "..."}
    """
    data = (request.get_json(silent=True) or {})
    start = data.get('start_hour')
    end = data.get('end_hour')
    reason = data.get('reason', '')
    admin_id = session.get('user_id')
    
    success, message = account_manager.set_allowed_hours(admin_id, user_id, start, end, reason)
    if success:
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'success': False, 'error': message}), 400

# 9. تنظیم فیلتر محتوا (توسط ربات)
@app.route('/api/admin/users/<user_id>/content-filter', methods=['PUT'])
@admin_required
def admin_set_content_filter_api(user_id):
    """
    روت تنظیم فیلتر محتوا.
    body: {"blocked_tags": ["adult"], "allowed_tags": []}
    """
    data = (request.get_json(silent=True) or {})
    blocked_tags = data.get('blocked_tags', [])
    allowed_tags = data.get('allowed_tags', [])
    admin_id = session.get('user_id')
    
    success, message = account_manager.set_content_filter(admin_id, user_id, blocked_tags, allowed_tags)
    if success:
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'success': False, 'error': message}), 400

# 10. تغییر قابلیت‌ها (توسط ربات)
@app.route('/api/admin/users/<user_id>/feature-toggle', methods=['PUT'])
@admin_required
def admin_toggle_feature_api(user_id):
    """
    روت تغییر قابلیت‌ها.
    body: {"feature": "dm_with_strangers", "enabled": false}
    """
    data = (request.get_json(silent=True) or {})
    feature = data.get('feature')
    enabled = data.get('enabled')
    admin_id = session.get('user_id')
    
    success, message = account_manager.toggle_feature(admin_id, user_id, feature, enabled)
    if success:
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'success': False, 'error': message}), 400

# 11. دریافت گزارش کامل کاربر (توسط ربات)
@app.route('/api/admin/users/<user_id>/full-report', methods=['GET'])
@admin_required
def admin_get_user_report_api(user_id):
    """دریافت گزارش کامل وضعیت یک کاربر توسط ربات"""
    admin_id = session.get('user_id')
    report_text = account_manager.get_user_report(admin_id, user_id)
    return jsonify({'report': report_text})

# 12. دریافت وضعیت اکانت یک کاربر (توسط ربات)
@app.route('/api/admin/users/<user_id>/account-status', methods=['GET'])
@admin_required
def admin_get_account_status_api(user_id):
    """دریافت وضعیت اکانت یک کاربر"""
    status = account_manager.get_user_account_status(user_id)
    if status:
        return jsonify(status)
    return jsonify({'error': 'Status not found'}), 404

# ============================================
# DELETE ACCOUNT
# ============================================
@app.route('/api/account/delete', methods=['POST'])
@login_required
def delete_account():
    """
    حذف اکانت کاربر به همراه تمام داده‌های مرتبط
    """
    data = (request.get_json(silent=True) or {})
    password = data.get('password', '')
    confirm_text = data.get('confirm', '')
    
    # اعتبارسنجی اولیه
    if confirm_text.upper() != 'DELETE':
        return jsonify({'error': 'Please type DELETE to confirm'}), 400
    if not password:
        return jsonify({'error': 'Password is required'}), 400
    
    db = load_database()
    user_id = session['user_id']
    user = db['users'].get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # ============================================
    # بررسی: آیا این اکانت خاص است؟
    # ============================================
    protected_usernames = ['admin', 'Aminsoft356']
    username = user.get('username', '').lower()
    
    if username in [u.lower() for u in protected_usernames]:
        return jsonify({
            'error': 'This account cannot be deleted',
            'reason': 'This is a protected system account'
        }), 403
    
    # بررسی صحت رمز عبور
    if not check_password_hash(user.get('password', ''), password):
        return jsonify({'error': 'Invalid password'}), 401
    
    # --- حذف کاربر از تمام سرورها ---
    for server_id, server in list(db['servers'].items()):
        # اگر کاربر صاحب سرور است، سرور را حذف کن
        if server.get('owner_id') == user_id:
            # حذف کانال‌های سرور
            channels_to_delete = [ch_id for ch_id, ch in db['channels'].items()
                                  if ch.get('server_id') == server_id]
            for ch_id in channels_to_delete:
                del db['channels'][ch_id]
            # حذف پیام‌های سرور
            messages_to_delete = [msg_id for msg_id, msg in db['all_messages'].items()
                                  if msg.get('channel_id') in channels_to_delete]
            for msg_id in messages_to_delete:
                del db['all_messages'][msg_id]
            # حذف بن‌ها و میوت‌ها
            if server_id in db.get('bans', {}):
                del db['bans'][server_id]
            if server_id in db.get('mutes', {}):
                del db['mutes'][server_id]
            # حذف اینوایت‌ها
            invites_to_delete = [inv_code for inv_code, inv in db['invites'].items()
                                 if inv.get('server_id') == server_id]
            for inv_code in invites_to_delete:
                del db['invites'][inv_code]
            # حذف دسته‌بندی‌ها
            cats_to_delete = [cat_id for cat_id, cat in db['categories'].items()
                              if cat.get('server_id') == server_id]
            for cat_id in cats_to_delete:
                del db['categories'][cat_id]
            # حذف تردها
            threads_to_delete = [t_id for t_id, t in db['threads'].items()
                                 if t.get('server_id') == server_id]
            for t_id in threads_to_delete:
                del db['threads'][t_id]
            # حذف سرور
            del db['servers'][server_id]
        # اگر کاربر فقط عضو است، از سرور حذف شود
        elif user_id in server.get('members', []):
            server['members'].remove(user_id)
            _strip_member_from_private_channels(db, server.get('id'), user_id)
            if user_id in server.get('user_roles', {}):
                del server['user_roles'][user_id]
    
    # --- حذف از لیست بن‌های تمام سرورها ---
    for server_id in list(db.get('bans', {}).keys()):
        if user_id in db['bans'][server_id]:
            del db['bans'][server_id][user_id]
    
    # --- حذف از لیست میوت‌های تمام سرورها ---
    for server_id in list(db.get('mutes', {}).keys()):
        if user_id in db['mutes'][server_id]:
            del db['mutes'][server_id][user_id]
    
    # --- حذف پیام‌های کاربر در سرورها ---
    messages_to_delete = [msg_id for msg_id, msg in db['all_messages'].items()
                          if msg.get('user_id') == user_id]
    for msg_id in messages_to_delete:
        del db['all_messages'][msg_id]
    
    # --- حذف DM‌ها ---
    dm_keys_to_clear = []
    for dm_key, messages in db.get('direct_messages', {}).items():
        user_ids_in_dm = dm_key.replace('dm_', '').split('_')
        if user_id in user_ids_in_dm:
            dm_keys_to_clear.append(dm_key)
    
    for dm_key in dm_keys_to_clear:
        db['direct_messages'][dm_key] = [
            msg for msg in db['direct_messages'][dm_key]
            if msg.get('user_id') != user_id
        ]
        if not db['direct_messages'][dm_key]:
            del db['direct_messages'][dm_key]
    
    # --- حذف از لیست blocked_users سایر کاربران ---
    for uid, other_user in db['users'].items():
        if 'blocked_users' in other_user and user_id in other_user['blocked_users']:
            other_user['blocked_users'].remove(user_id)
    
    # --- حذف از notifications ---
    db['notifications'] = [n for n in db.get('notifications', [])
                           if n.get('user_id') != user_id]
    
    # --- حذف از اینوایت‌ها ---
    invites_to_delete = [inv_code for inv_code, inv in db['invites'].items()
                         if inv.get('created_by') == user_id]
    for inv_code in invites_to_delete:
        del db['invites'][inv_code]
    
    # --- حذف خود کاربر ---
    if user_id in db['users']:
        del db['users'][user_id]

    _stories_remove_user(user_id)
    # حذف تنظیمات ذخیره‌شده‌ی کاربر (user_settings.json)
    with settings_lock:
        _all_settings = _load_all_settings()
        if _all_settings.pop(user_id, None) is not None:
            _save_all_settings(_all_settings)
    
    # ذخیره دیتابیس
    save_database(db)
    
    # فقط همین اکانت از سشن خارج شود (بقیه اکانت‌ها سر جایشان می‌مانند)
    _session_remove_accounts(db, [user_id])
    save_database(db)
    
    return jsonify({
        'success': True,
        'message': 'Account deleted successfully'
    })

# --- Search ---
@app.route('/api/search')
@login_required
def search():
    db = load_database()
    query = request.args.get('q', '').lower()
    results = {'users': [], 'servers': []}
    
    for uid, user in db['users'].items():
        if user.get('is_incognito') and uid != session.get('user_id'):
            continue
        if query in user.get('username', '').lower():
            results['users'].append(sanitize_user_for_viewer(db, session['user_id'], user))
    
    for sid, server in db['servers'].items():
        if query in server.get('name', '').lower():
            results['servers'].append(server)
    
    return jsonify(results)
    # ==================== ACCOUNT PRIVACY & PARENTAL CONTROL ====================

@app.route('/api/account/privacy', methods=['GET'])
@login_required
def get_privacy_settings():
    """دریافت تنظیمات حریم خصوصی"""
    try:
        db = load_database()
        user = db['users'].get(session['user_id'])
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # تنظیمات پیش‌فرض
        default_settings = {
            'profile_visibility': 'everyone',
            'show_online_status': True,
            'allow_friend_requests': True,
            'allow_dms_from_strangers': True,
            'show_activity_status': True,
            'allow_analytics': False
        }
        
        privacy_settings = get_privacy(db, user['id'])
        
        return jsonify({'privacy_settings': privacy_settings})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/account/privacy', methods=['PUT'])
@login_required
def save_privacy_settings():
    """ذخیره تنظیمات حریم خصوصی (شامل تنظیمات Stories)"""
    try:
        data = (request.get_json(silent=True) or {}) or {}
        db = load_database()
        user = db['users'].get(session['user_id'])

        if not user:
            return jsonify({'error': 'User not found'}), 404

        uid = user['id']

        # مقادیر مجاز برای فیلدهای visibility
        VALID_VISIBILITIES = ('everyone', 'friends', 'nobody')
        # مقادیر مجاز برای فیلدهای Telegram-style و Story
        VALID_CONTACT_VISIBILITIES = ('everyone', 'contacts', 'nobody')
        VALID_STORY_VISIBILITIES = ('everyone', 'contacts', 'close_friends', 'server', 'nobody')

        # ---------------------------------------------------------
        # 1) profile_visibility  (مقادیر: everyone / friends / nobody)
        # ---------------------------------------------------------
        profile_visibility = data.get('profile_visibility', 'everyone')
        if profile_visibility not in VALID_VISIBILITIES:
            return jsonify({'error': 'Invalid visibility setting'}), 400

        # ---------------------------------------------------------
        # 2) تنظیمات پایه (Boolean)
        # ---------------------------------------------------------
        base_settings = {
            'profile_visibility': profile_visibility,
            'show_online_status': bool(data.get('show_online_status', True)),
            'allow_friend_requests': bool(data.get('allow_friend_requests', True)),
            'allow_dms_from_strangers': bool(data.get('allow_dms_from_strangers', True)),
            'show_activity_status': bool(data.get('show_activity_status', True)),
            'allow_analytics': bool(data.get('allow_analytics', False)),
        }

        # ---------------------------------------------------------
        # 3) تنظیمات Telegram-style (everyone / contacts / nobody)
        #    + story_visibility (everyone / contacts / close_friends / server / nobody)
        # ---------------------------------------------------------
        contact_visibility_fields = (
            'phone_visibility',
            'last_seen_visibility',
            'avatar_visibility',
            'birthdate_visibility',
            'forwards_visibility',
            'invites_visibility',
        )
        story_visibility_field = 'story_visibility'

        # مقدار فعلی ذخیره‌شده (برای حفظ مقدار در صورت ارسال نشدن از فرانت)
        current = get_privacy(db, uid)
        contact_settings = {}

        for key in contact_visibility_fields:
            if key in data:
                value = data[key]
                if value == 'friends':
                    value = 'contacts'
                if value not in VALID_CONTACT_VISIBILITIES:
                    return jsonify({'error': f'Invalid value for {key}'}), 400
                contact_settings[key] = value
            else:
                # اگر فرانت ارسال نکرد، مقدار قبلی (یا پیش‌فرض) حفظ شود
                contact_settings[key] = current.get(key, PRIVACY_DEFAULTS.get(key))

        # --- مهم‌ترین بخش: story_visibility ---
        if story_visibility_field in data:
            story_value = data[story_visibility_field]
            # پشتیبانی از مقدار قدیمی 'friends' → 'contacts'
            if story_value == 'friends':
                story_value = 'contacts'
            if story_value not in VALID_STORY_VISIBILITIES:
                return jsonify({'error': 'Invalid value for story_visibility'}), 400
        else:
            story_value = current.get(story_visibility_field, PRIVACY_DEFAULTS.get(story_visibility_field, 'everyone'))
            if story_value == 'friends':
                story_value = 'contacts'
            if story_value not in VALID_STORY_VISIBILITIES:
                story_value = 'everyone'

        # ---------------------------------------------------------
        # 4) ذخیره در دیتابیس
        # ---------------------------------------------------------
        if 'privacy_settings' not in db:
            db['privacy_settings'] = {}

        merged = {}
        merged.update(base_settings)
        merged.update(contact_settings)
        merged[story_visibility_field] = story_value
        merged['updated_at'] = datetime.now().isoformat()

        db['privacy_settings'][uid] = merged

        save_database(db)

        # بعد از ذخیره، مقدار برگشتی از get_privacy() باید شامل story_visibility جدید باشد
        return jsonify({
            'success': True,
            'privacy_settings': get_privacy(db, uid),
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/account/parental-control', methods=['GET'])
@login_required
def get_parental_control():
    """دریافت تنظیمات کنترل والدین"""
    try:
        db = load_database()
        user = db['users'].get(session['user_id'])
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # تنظیمات پیش‌فرض
        default_settings = {
            'daily_limit_minutes': 0,
            'allowed_start_hour': 0,
            'allowed_end_hour': 23,
            'blocked_tags': [],
            'block_adult_content': False
        }
        
        parental_control = db.get('parental_control', {}).get(user['id'], default_settings)
        
        return jsonify({'parental_control': parental_control})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# =================================================================
# AntiBot API Routes - نیاز به اهراز هویت ندارند
# =================================================================

ANTIBOT_TOKEN = os.getenv('ANTIBOT_TOKEN', '')


@app.before_request
def _antibot_token_guard():
    """The bot API can kick members and post anywhere. It needs the header X-Antibot-Token.
    When ANTIBOT_TOKEN is not set it only accepts requests from this machine (127.0.0.1).
    Behind a reverse proxy ALWAYS set ANTIBOT_TOKEN."""
    if not request.path.startswith('/api/antibot/'):
        return None
    if ANTIBOT_TOKEN:
        import hmac
        if not hmac.compare_digest(request.headers.get('X-Antibot-Token', ''), ANTIBOT_TOKEN):
            return jsonify({'error': 'Bot token required'}), 401
    elif request.remote_addr not in ('127.0.0.1', '::1') or any(request.headers.get(h) for h in ('X-Forwarded-For', 'X-Real-IP', 'Forwarded')):
        return jsonify({'error': 'Bot API is local only. Set ANTIBOT_TOKEN.'}), 403
    return None


@app.route('/api/antibot/join', methods=['POST'])
def antibot_join():
    """
    اطلاع‌رسانی عضویت کاربر جدید به ربات
    این API توسط سرور هنگام عضویت کاربر صدا زده می‌شود
    """
    data = (request.get_json(silent=True) or {})
    server_id = data.get('server_id')
    user_id = data.get('user_id')
    username = data.get('username')
    
    if not all([server_id, user_id, username]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # ذخیره در دیتابیس برای پردازش توسط ربات
    db = load_database()
    
    if 'antibot_pending' not in db:
        db['antibot_pending'] = []
    
    db['antibot_pending'].append({
        'server_id': server_id,
        'user_id': user_id,
        'username': username,
        'timestamp': datetime.now().isoformat()
    })
    
    # محدود کردن تعداد
    if len(db['antibot_pending']) > 100:
        db['antibot_pending'] = db['antibot_pending'][-100:]
    
    save_database(db)
    
    return jsonify({'success': True})


@app.route('/api/antibot/pending', methods=['GET'])
def get_antibot_pending():
    """
    دریافت لیست کاربران در انتظار تأیید
    این API توسط ربات استفاده می‌شود
    """
    db = load_database()
    pending = db.get('antibot_pending', [])
    
    # پاکسازی موارد قدیمی (بالای 10 دقیقه)
    current_time = datetime.now()
    cleaned = []
    for item in pending:
        item_time = datetime.fromisoformat(item['timestamp'])
        if (current_time - item_time).total_seconds() < 600:
            cleaned.append(item)
    
    db['antibot_pending'] = cleaned
    save_database(db)
    
    return jsonify(cleaned)


@app.route('/api/antibot/verify', methods=['POST'])
def antibot_verify():
    """
    تأیید کاربر توسط ربات
    """
    data = (request.get_json(silent=True) or {})
    user_id = data.get('user_id')
    server_id = data.get('server_id')
    
    if not user_id:
        return jsonify({'error': 'user_id required'}), 400
    
    db = load_database()
    
    # حذف از لیست pending
    if 'antibot_pending' in db:
        db['antibot_pending'] = [
            p for p in db['antibot_pending']
            if p.get('user_id') != user_id
        ]
    
    save_database(db)
    
    return jsonify({'success': True})


@app.route('/api/antibot/kick', methods=['POST'])
def antibot_kick():
    """
    درخواست کیک کاربر توسط ربات
    """
    data = (request.get_json(silent=True) or {})
    user_id = data.get('user_id')
    server_id = data.get('server_id')
    reason = data.get('reason', 'تأیید عضویت انجام نشد')
    
    if not user_id or not server_id:
        return jsonify({'error': 'user_id and server_id required'}), 400
    
    db = load_database()
    server = db['servers'].get(server_id)
    
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    if user_id not in server.get('members', []):
        return jsonify({'error': 'User not in server'}), 400
    if user_id == server.get('owner_id'):
        return jsonify({'error': 'The server owner cannot be kicked'}), 403
    
    # حذف کاربر
    server['members'].remove(user_id)
    _strip_member_from_private_channels(db, server.get('id'), user_id)
    if user_id in server.get('user_roles', {}):
        del server['user_roles'][user_id]
    
    # حذف از لیست pending
    if 'antibot_pending' in db:
        db['antibot_pending'] = [
            p for p in db['antibot_pending']
            if p.get('user_id') != user_id
        ]
    
    save_database(db)
    
    return jsonify({'success': True})


@app.route('/api/antibot/servers', methods=['GET'])
def get_antibot_servers():
    """
    دریافت لیست سرورها (برای ربات)
    """
    db = load_database()
    servers = []
    
    for sid, server in db['servers'].items():
        # فقط سرورهایی که AUTH channel دارند
        auth_channel = None
        for ch_id, ch in db['channels'].items():
            if ch.get('server_id') == sid and ch.get('name', '').lower() == 'auth':
                auth_channel = {
                    'id': ch_id,
                    'name': ch.get('name')
                }
                break
        
        if auth_channel:
            servers.append({
                'id': sid,
                'name': server.get('name'),
                'auth_channel': auth_channel,
                'member_count': len(server.get('members', []))
            })
    
    return jsonify(servers)


@app.route('/api/antibot/channels/<server_id>/messages', methods=['GET'])
def get_antibot_channel_messages(server_id):
    """
    دریافت پیام‌های کانال (برای ربات)
    """
    channel_name = request.args.get('channel', 'auth').lower()
    limit = int(request.args.get('limit', 50))
    
    db = load_database()
    
    # پیدا کردن کانال
    channel = None
    for ch_id, ch in db['channels'].items():
        if ch.get('server_id') == server_id and ch.get('name', '').lower() == channel_name:
            channel = ch
            break
    
    if not channel:
        return jsonify([])
    
    # دریافت پیام‌ها
    messages = []
    for msg_id, msg in db['all_messages'].items():
        if msg.get('channel_id') == channel['id']:
            messages.append({
                'id': msg_id,
                'content': msg.get('content'),
                'reactions': msg.get('reactions', {}),
                'user_id': msg.get('user_id')
            })
    
    # مرتب‌سازی بر اساس زمان
    messages.sort(key=lambda x: x.get('id', ''))
    
    return jsonify(messages[-limit:])


@app.route('/api/antibot/channels/<channel_id>/messages', methods=['POST'])
def antibot_send_message(channel_id):
    """
    ارسال پیام به کانال (توسط ربات)
    """
    data = (request.get_json(silent=True) or {})
    content = data.get('content', '')
    
    if not content:
        return jsonify({'error': 'Content required'}), 400
    
    db = load_database()
    channel = db['channels'].get(channel_id)
    
    if not channel:
        return jsonify({'error': 'Channel not found'}), 404
    
    message_id = str(uuid.uuid4().hex[:12])
    
    db['all_messages'][message_id] = {
        'id': message_id,
        'channel_id': channel_id,
        'user_id': 'antibot',
        'content': content,
        'created_at': datetime.now().isoformat(),
        'reactions': {}
    }
    
    save_database(db)
    
    return jsonify({
        'id': message_id,
        'content': content,
        'channel_id': channel_id
    })


@app.route('/api/antibot/users/<user_id>/verified', methods=['GET', 'POST', 'PUT', 'DELETE'])
def antibot_set_verified(user_id):
    """
    Verified tick for the JS bot (header X-Antibot-Token, same as the other /api/antibot routes).
      GET    -> {"verified": bool}
      POST   {"verified": true|false}  (missing body = give the tick)
      DELETE -> remove the tick
    """
    db = load_database()
    user = db['users'].get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    if request.method == 'GET':
        return jsonify({'success': True, 'user_id': user_id, 'verified': user_is_verified(user)})
    if request.method == 'DELETE':
        value = False
    else:
        data = request.get_json(silent=True) or {}
        value = bool(data.get('verified', True))
    user['verified'] = value
    user['is_verified'] = value
    db.setdefault('badge_history', {}).setdefault(user_id, []).append({
        'action': 'verified_on' if value else 'verified_off',
        'badges': ['verified'], 'by': 'antibot', 'at': datetime.now().isoformat()
    })
    save_database(db)
    return jsonify({'success': True, 'user_id': user_id, 'verified': value})


@app.route('/api/antibot/dm/<user_id>', methods=['POST'])
def antibot_send_dm(user_id):
    """
    ارسال DM به کاربر (توسط ربات)
    """
    data = (request.get_json(silent=True) or {})
    content = data.get('content', '')
    
    if not content:
        return jsonify({'error': 'Content required'}), 400
    
    db = load_database()
    
    if user_id not in db['users']:
        return jsonify({'error': 'User not found'}), 404
    
    dm_key = tuple(sorted(['antibot', user_id]))
    dm_key_str = f"dm_{'_'.join(dm_key)}"
    
    if dm_key_str not in db['direct_messages']:
        db['direct_messages'][dm_key_str] = []
    
    message_id = str(uuid.uuid4().hex[:12])
    
    db['direct_messages'][dm_key_str].append({
        'id': message_id,
        'dm_key': dm_key_str,
        'user_id': 'antibot',
        'content': content,
        'created_at': datetime.now().isoformat(),
        'reactions': {}
    })
    
    save_database(db)
    
    return jsonify({'success': True, 'message_id': message_id})


@app.route('/api/antibot/dm/<user_id>/messages', methods=['GET'])
def get_antibot_dm_messages(user_id):
    """
    دریافت پیام‌های DM (برای ربات)
    """
    db = load_database()
    
    dm_key = tuple(sorted(['antibot', user_id]))
    dm_key_str = f"dm_{'_'.join(dm_key)}"
    
    messages = db['direct_messages'].get(dm_key_str, [])
    
    return jsonify(messages)


@app.route('/api/antibot/messages/<message_id>/react', methods=['POST'])
def antibot_add_reaction(message_id):
    """
    افزودن ریاکشن به پیام
    """
    data = (request.get_json(silent=True) or {})
    emoji = data.get('emoji', '✅')
    
    db = load_database()
    
    # جستجو در پیام‌های کانال
    msg = db['all_messages'].get(message_id)
    
    if msg:
        if 'reactions' not in msg:
            msg['reactions'] = {}
        if emoji not in msg['reactions']:
            msg['reactions'][emoji] = []
        if 'antibot' not in msg['reactions'][emoji]:
            msg['reactions'][emoji].append('antibot')
        save_database(db)
        return jsonify({'success': True})
    
    # جستجو در DM‌ها
    for dm_key, messages in db.get('direct_messages', {}).items():
        for m in messages:
            if m.get('id') == message_id:
                if 'reactions' not in m:
                    m['reactions'] = {}
                if emoji not in m['reactions']:
                    m['reactions'][emoji] = []
                if 'antibot' not in m['reactions'][emoji]:
                    m['reactions'][emoji].append('antibot')
                save_database(db)
                return jsonify({'success': True})
    
    return jsonify({'error': 'Message not found'}), 404


@app.route('/api/antibot/servers/<server_id>/members', methods=['GET'])
def get_antibot_server_members(server_id):
    """
    دریافت اعضای سرور (برای ربات)
    """
    db = load_database()
    server = db['servers'].get(server_id)
    
    if not server:
        return jsonify([])
    
    members = []
    for uid in server.get('members', []):
        user = db['users'].get(uid)
        if user:
            members.append({
                'id': uid,
                'username': user.get('username'),
                'roles': server.get('user_roles', {}).get(uid, ['member'])
            })
    
    return jsonify(members)


@app.route('/api/antibot/servers/<server_id>/kick/<user_id>', methods=['POST'])
def antibot_kick_member(server_id, user_id):
    """
    کیک کردن عضو (توسط ربات)
    """
    db = load_database()
    server = db['servers'].get(server_id)
    
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    if user_id not in server.get('members', []):
        return jsonify({'error': 'User not in server'}), 400
    
    if user_id == server.get('owner_id'):
        return jsonify({'error': 'Cannot kick owner'}), 403
    
    server['members'].remove(user_id)
    _strip_member_from_private_channels(db, server.get('id'), user_id)
    if user_id in server.get('user_roles', {}):
        del server['user_roles'][user_id]
    
    save_database(db)
    
    return jsonify({'success': True})


@app.route('/api/antibot/servers/<server_id>', methods=['GET'])
def get_antibot_server(server_id):
    """
    دریافت اطلاعات سرور (برای ربات)
    """
    db = load_database()
    server = db['servers'].get(server_id)
    
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    return jsonify({
        'id': server_id,
        'name': server.get('name'),
        'owner_id': server.get('owner_id'),
        'members': server.get('members', []),
        'user_roles': server.get('user_roles', {})
    })
# ============================================
# DELETE USER MESSAGES IN CHANNEL
# ============================================
@app.route('/api/channels/<channel_id>/messages/user/<user_id>', methods=['DELETE'])
@login_required
def delete_user_messages_in_channel(channel_id, user_id):
    """حذف تمام پیام‌های یک کاربر خاص در یک کانال"""
    db = load_database()
    channel = db['channels'].get(channel_id)
    if not channel:
        return jsonify({'error': 'Channel not found'}), 404
    server = db['servers'].get(channel['server_id'])
    if not server or session['user_id'] not in server.get('members', []):
        return jsonify({'error': 'Not a member'}), 403
    # بررسی دسترسی: فقط صاحب پیام، صاحب سرور، یا کسی که دسترسی manage_messages دارد
    is_owner = session['user_id'] == server.get('owner_id')
    can_manage = has_permission(db, session['user_id'], channel['server_id'], 'manage_messages')  # ← renamed variable
    is_message_owner = user_id == session['user_id']
    if not is_owner and not can_manage and not is_message_owner:  # ← use renamed variable
        return jsonify({'error': 'Permission denied'}), 403
    # پیدا کردن و حذف پیام‌های آن کاربر
    messages_to_delete = [
        msg_id for msg_id, msg in db['all_messages'].items()
        if msg.get('channel_id') == channel_id and msg.get('user_id') == user_id and not msg.get('deleted')
    ]
    deleted_count = len(messages_to_delete)
    for msg_id in messages_to_delete:
        soft_delete_message(db['all_messages'][msg_id], session['user_id'])
    save_database(db)
    return jsonify({
        'success': True,
        'deleted_count': deleted_count
    })

# ============================================
# DELETE ALL MESSAGES IN CHANNEL
# ============================================
@app.route('/api/channels/<channel_id>/messages/all', methods=['DELETE'])
@login_required
def delete_all_channel_messages(channel_id):
    """حذف تمام پیام‌های یک کانال"""
    db = load_database()
    
    channel = db['channels'].get(channel_id)
    if not channel:
        return jsonify({'error': 'Channel not found'}), 404
    
    server = db['servers'].get(channel['server_id'])
    if not server or session['user_id'] not in server.get('members', []):
        return jsonify({'error': 'Not a member'}), 403
    
    # بررسی دسترسی: فقط صاحب سرور یا کسی که دسترسی manage_messages دارد
    if session['user_id'] != server.get('owner_id') and not has_permission(db, session['user_id'], channel['server_id'], 'manage_messages'):
        return jsonify({'error': 'Permission denied'}), 403
    
    # پیدا کردن و حذف تمام پیام‌های آن کانال
    messages_to_delete = [
        msg_id for msg_id, msg in db['all_messages'].items()
        if msg.get('channel_id') == channel_id
    ]
    
    deleted_count = len(messages_to_delete)
    for msg_id in messages_to_delete:
        del db['all_messages'][msg_id]
    
    save_database(db)
    
    return jsonify({
        'success': True,
        'deleted_count': deleted_count
    })
@app.route('/api/account/parental-control', methods=['PUT'])
@login_required
def save_parental_control():
    """ذخیره تنظیمات کنترل والدین"""
    try:
        data = (request.get_json(silent=True) or {}) or {}
        db = load_database()
        user = db['users'].get(session['user_id'])
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # اعتبارسنجی داده‌ها
        daily_limit = int(data.get('daily_limit_minutes', 0) or 0)
        start_hour = int(data.get('allowed_start_hour', 0) or 0)
        end_hour = int(data.get('allowed_end_hour', 23) or 23)
        blocked_tags = data.get('blocked_tags', [])
        if not isinstance(blocked_tags, list):
            blocked_tags = []
        blocked_tags = [str(t).strip()[:32] for t in blocked_tags if str(t).strip()][:50]
        block_adult = bool(data.get('block_adult_content', False))
        
        # اعتبارسنجی محدوده ساعات
        if not (0 <= start_hour <= 23 and 0 <= end_hour <= 23):
            return jsonify({'error': 'Invalid hour range'}), 400
        
        if start_hour > end_hour:
            return jsonify({'error': 'Start hour must be before end hour'}), 400
        
        # اعتبارسنجی محدودیت زمانی
        if daily_limit < 0 or daily_limit > 1440:
            return jsonify({'error': 'Invalid time limit'}), 400
        
        # اطمینان از وجود ساختار
        if 'parental_control' not in db:
            db['parental_control'] = {}
        
        # ذخیره تنظیمات
        db['parental_control'][user['id']] = {
            'daily_limit_minutes': daily_limit,
            'allowed_start_hour': start_hour,
            'allowed_end_hour': end_hour,
            'blocked_tags': blocked_tags,
            'block_adult_content': block_adult,
            'updated_at': datetime.now().isoformat()
        }
        
        save_database(db)
        return jsonify({'success': True, 'parental_control': db['parental_control'][user['id']]})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# ============================================
# BOOST SYSTEM - BACKEND ENDPOINTS
# ============================================

# --- Get Boost Info ---
@app.route('/api/servers/<server_id>/boosts', methods=['GET'])
@login_required
def get_server_boosts(server_id):
    """دریافت اطلاعات بوست‌های سرور"""
    db = load_database()
    server = db['servers'].get(server_id)
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    if session['user_id'] not in server.get('members', []):
        return jsonify({'error': 'Not a member of this server'}), 403
    
    # شمارش کل بوست‌ها
    boost_count = len(server.get('boosts', []))
    
    # محاسبه سطح سرور
    boost_level = 0
    for level in range(12, 0, -1):
        if boost_count >= BOOST_CONFIG['levels'].get(level, 0):
            boost_level = level
            break
    
    # اطلاعات بوست کاربر فعلی
    user_boosts = server.get('user_boosts', {}).get(session['user_id'], [])
    user_boost_count = len(user_boosts)
    
    # لیست بوسترها
    boosters = []
    user_boosts_data = server.get('user_boosts', {})
    for uid, boosts in user_boosts_data.items():
        if boosts:  # اگر کاربر بوست دارد
            user = db['users'].get(uid)
            if user:
                boosters.append({
                    'user_id': uid,
                    'username': user.get('username'),
                    'avatar': user.get('avatar'),
                    'avatar_color': user.get('avatar_color', '#7289da'),
                    'boost_count': len(boosts),
                    'created_at': boosts[0] if boosts else None
                })
    
    # مرتب‌سازی بر اساس زمان (جدیدترین اول)
    boosters.sort(key=lambda x: x.get('created_at') or '', reverse=True)
    
    # بررسی اینکه آیا کاربر فعلی بوست دارد
    user_has_boosted = user_boost_count > 0
    
    # آیا تیک آبی فعال شده؟
    has_blue_check = boost_level >= 12
    
    return jsonify({
        'success': True,
        'boostCount': boost_count,
        'boostLevel': boost_level,
        'userBoostCount': user_boost_count,
        'maxBoostsPerUser': BOOST_CONFIG['maxBoostsPerUser'],
        'userHasBoosted': user_has_boosted,
        'hasBlueCheck': has_blue_check,
        'boosters': boosters[:20]  # حداکثر 20 بوستر
    })

# --- Boost Server ---
@app.route('/api/servers/<server_id>/boost', methods=['POST'])
@login_required
def boost_server_api(server_id):
    """بوست کردن سرور"""
    db = load_database()
    server = db['servers'].get(server_id)
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    if session['user_id'] not in server.get('members', []):
        return jsonify({'error': 'Not a member'}), 403
    
    user = db['users'].get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # بررسی کوین‌ها
    cost = BOOST_CONFIG['costPerBoost']
    if user.get('coins', 0) < cost:
        return jsonify({'error': 'Not enough coins'}), 400
    
    # بررسی حداکثر بوست
    user_boosts = server.setdefault('user_boosts', {}).setdefault(session['user_id'], [])
    if len(user_boosts) >= BOOST_CONFIG['maxBoostsPerUser']:
        return jsonify({'error': 'Maximum boosts reached'}), 400
    
    # کسر کوین‌ها
    user['coins'] -= cost
    
    # اضافه کردن بوست
    boost_time = datetime.now().isoformat()
    user_boosts.append(boost_time)
    server.setdefault('boosts', []).append({
        'user_id': session['user_id'],
        'boosted_at': boost_time
    })
    
    # محاسبه سطح جدید
    boost_count = len(server.get('boosts', []))
    boost_level = 0
    for level in range(12, 0, -1):
        if boost_count >= BOOST_CONFIG['levels'].get(level, 0):
            boost_level = level
            break
    
    # بررسی تیک آبی
    has_blue_check = boost_level >= 12
    if has_blue_check and not server.get('has_blue_check'):
        server['has_blue_check'] = True
    
    save_database(db)
    
    return jsonify({
        'success': True,
        'coinsSpent': cost,
        'remainingCoins': user['coins'],
        'boostLevel': boost_level,
        'hasBlueCheck': has_blue_check
    })

# --- Unboost Server ---
@app.route('/api/servers/<server_id>/unboost', methods=['POST'])
@login_required
def unboost_server_api(server_id):
    """برداشتن بوست از سرور"""
    db = load_database()
    server = db['servers'].get(server_id)
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    if session['user_id'] not in server.get('members', []):
        return jsonify({'error': 'Not a member'}), 403
    
    user = db['users'].get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user_boosts = server.get('user_boosts', {}).get(session['user_id'], [])
    if not user_boosts:
        return jsonify({'error': 'No boost to remove'}), 400
    
    # حذف آخرین بوست
    removed_boost = user_boosts.pop()
    
    # حذف از لیست کل بوست‌ها
    server['boosts'] = [b for b in server.get('boosts', []) 
                        if b.get('user_id') != session['user_id'] or b.get('boosted_at') != removed_boost]
    
    # محاسبه ریفاند (50%)
    refund_amount = BOOST_CONFIG['costPerBoost'] // 2
    user['coins'] = (user.get('coins', 0)) + refund_amount
    
    # پاک کردن اگر خالی شد
    if not user_boosts:
        if session['user_id'] in server.get('user_boosts', {}):
            del server['user_boosts'][session['user_id']]
    
    save_database(db)
    
    return jsonify({
        'success': True,
        'refundAmount': refund_amount,
        'remainingCoins': user['coins']
    })

# ============================================
# COIN BOOST SYSTEM (per server / per channel)
# - هر کاربر روی هر سرور یا کانال فقط یک بار می‌تواند بوست کند
# - مقدار کوین دلخواه است (حداقل BOOST_MIN_AMOUNT و حداکثر موجودی کاربر)
# - نوار پیشرفت بر اساس مجموع کوین‌های بوست‌شده و سطح‌ها محاسبه می‌شود
# ============================================
BOOST_MIN_AMOUNT = 10
BOOST_COIN_LEVELS = {
    1: 100, 2: 300, 3: 600, 4: 1000, 5: 1600, 6: 2400,
    7: 3400, 8: 4600, 9: 6000, 10: 8000, 11: 10500, 12: 14000
}
boost_lock = threading.Lock()


def _boost_resolve(db, target_type, target_id):
    """returns (target_dict, server_dict) or (None, None)"""
    if target_type == 'server':
        server = db['servers'].get(target_id)
        return (server, server) if server else (None, None)
    if target_type == 'channel':
        channel = db['channels'].get(target_id)
        if not channel:
            return None, None
        server = db['servers'].get(channel.get('server_id'))
        return (channel, server) if server else (None, None)
    return None, None


def _boost_level_info(total):
    level = 0
    for lvl in sorted(BOOST_COIN_LEVELS):
        if total >= BOOST_COIN_LEVELS[lvl]:
            level = lvl
    max_level = max(BOOST_COIN_LEVELS)
    cur_at = BOOST_COIN_LEVELS.get(level, 0)
    if level >= max_level:
        return {'level': level, 'maxLevel': max_level, 'currentLevelAt': cur_at,
                'nextLevelAt': None, 'percent': 100.0}
    next_at = BOOST_COIN_LEVELS[level + 1]
    span = max(next_at - cur_at, 1)
    percent = max(0.0, min(100.0, (total - cur_at) * 100.0 / span))
    return {'level': level, 'maxLevel': max_level, 'currentLevelAt': cur_at,
            'nextLevelAt': next_at, 'percent': round(percent, 1)}


def _boost_payload(db, target, uid):
    data = target.get('coin_boost') or {}
    by_user = data.get('by_user') or {}
    total = int(data.get('total', 0) or 0)
    info = _boost_level_info(total)
    mine = by_user.get(uid)
    user = db['users'].get(uid) or {}

    boosters = []
    for b_uid, rec in by_user.items():
        b_user = db['users'].get(b_uid)
        if not b_user:
            continue
        boosters.append({
            'user_id': b_uid,
            'username': b_user.get('username'),
            'avatar': b_user.get('avatar'),
            'avatar_color': b_user.get('avatar_color', '#7289da'),
            'amount': rec.get('amount', 0),
            'boosted_at': rec.get('at')
        })
    boosters.sort(key=lambda x: x['amount'], reverse=True)

    payload = {
        'success': True,
        'total': total,
        'boostersCount': len(by_user),
        'userBoost': mine,
        'userHasBoosted': bool(mine),
        'minAmount': BOOST_MIN_AMOUNT,
        'userCoins': int(user.get('coins', 0) or 0),
        'levels': BOOST_COIN_LEVELS,
        'boosters': boosters[:20]
    }
    payload.update(info)
    return payload


@app.route('/api/boost/<target_type>/<target_id>', methods=['GET'])
@login_required
def get_coin_boost(target_type, target_id):
    db = load_database()
    target, server = _boost_resolve(db, target_type, target_id)
    if not target:
        return jsonify({'error': 'Not found'}), 404
    if session['user_id'] not in server.get('members', []):
        return jsonify({'error': 'Not a member of this server'}), 403
    return jsonify(_boost_payload(db, target, session['user_id']))


@app.route('/api/boost/<target_type>/<target_id>', methods=['POST'])
@login_required
def do_coin_boost(target_type, target_id):
    data = request.get_json(silent=True) or {}
    raw = data.get('amount')
    if isinstance(raw, bool):
        return jsonify({'error': 'Invalid amount'}), 400
    try:
        amount = int(float(raw))
    except (TypeError, ValueError, OverflowError):
        return jsonify({'error': 'Invalid amount'}), 400
    if amount < BOOST_MIN_AMOUNT:
        return jsonify({'error': f'Minimum boost is {BOOST_MIN_AMOUNT} coins'}), 400

    uid = session['user_id']
    with boost_lock:
        db = load_database()
        target, server = _boost_resolve(db, target_type, target_id)
        if not target:
            return jsonify({'error': 'Not found'}), 404
        if uid not in server.get('members', []):
            return jsonify({'error': 'Not a member of this server'}), 403

        user = db['users'].get(uid)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        cb = target.setdefault('coin_boost', {'total': 0, 'by_user': {}})
        cb.setdefault('by_user', {})
        if uid in cb['by_user']:
            return jsonify({'error': 'You have already boosted this ' + target_type}), 400

        if int(user.get('coins', 0) or 0) < amount:
            return jsonify({'error': 'Not enough coins'}), 400

        user['coins'] = int(user.get('coins', 0) or 0) - amount
        cb['by_user'][uid] = {'amount': amount, 'at': datetime.now().isoformat()}
        cb['total'] = int(cb.get('total', 0) or 0) + amount

        # سطح ۱۲ سرور = تیک آبی (مثل سیستم قبلی)
        if target_type == 'server' and _boost_level_info(cb['total'])['level'] >= max(BOOST_COIN_LEVELS):
            server['has_blue_check'] = True

        save_database(db)
        payload = _boost_payload(db, target, uid)

    payload['coinsSpent'] = amount
    payload['remainingCoins'] = user['coins']
    return jsonify(payload)


# ============================================
# SAVED MESSAGES SYSTEM - BACKEND ENDPOINTS
# - bookmark: ذخیره‌ی ارجاع به پیام کانال/DM
# - note:     پیام شخصی که کاربر مستقیماً داخل Saved Messages می‌فرستد (متن / عکس / ویدیو / صدا / لوکیشن)
# ============================================
SAVED_NOTE_MAX_LEN = 4000
SAVED_MAX_ENTRIES = 5000
saved_lock = threading.Lock()


def _sv_user_brief(db, uid):
    u = db['users'].get(uid) or {}
    return {
        'id': u.get('id', uid),
        'username': u.get('username', 'Unknown'),
        'avatar': u.get('avatar'),
        'avatar_color': u.get('avatar_color', '#7289da')
    }


def _sv_dm_members(dm_key):
    if not isinstance(dm_key, str) or not dm_key.startswith('dm_'):
        return []
    return dm_key[3:].split('_')


def _sv_channel_msg_access(db, uid, msg):
    """(channel, server) اگر کاربر هنوز عضو سرور است، وگرنه (None, None)"""
    channel = db['channels'].get(msg.get('channel_id'))
    if not channel:
        return None, None
    server = db['servers'].get(channel.get('server_id'))
    if not server or uid not in server.get('members', []):
        return None, None
    _acc = channel_access(db, channel, uid)
    if not _acc['visible'] or _acc['locked']:
        return None, None
    return channel, server


def _sv_find_original(db, uid, saved):
    """returns (original_msg, source_name, source_server_id) یا (None, None, None)"""
    st = saved.get('source_type')
    mid = saved.get('message_id')
    if st == 'channel':
        msg = db['all_messages'].get(mid)
        if not msg or msg.get('deleted'):
            return None, None, None
        channel, server = _sv_channel_msg_access(db, uid, msg)
        if not channel:
            return None, None, None
        return msg, channel.get('name'), server.get('id')
    if st == 'dm':
        dm_key = saved.get('dm_key')
        if uid not in _sv_dm_members(dm_key):
            return None, None, None
        for m in db.get('direct_messages', {}).get(dm_key, []):
            if m.get('id') == mid and not m.get('deleted'):
                other = db['users'].get(saved.get('other_user_id'), {})
                return m, other.get('username', 'User'), None
    return None, None, None


def _sv_enrich(db, uid, saved):
    st = saved.get('source_type')
    item = {
        'id': saved.get('id'),
        'message_id': saved.get('message_id'),
        'original_message_id': saved.get('message_id'),
        'source_type': st,
        'source_id': saved.get('source_id'),
        'source_name': None,
        'source_server_id': None,
        'content': '',
        'image_url': None,
        'attachment': None,
        'location': None,
        'poll': None,
        'author': None,
        'created_at': saved.get('created_at') or saved.get('saved_at'),
        'saved_at': saved.get('saved_at'),
        'edited_at': saved.get('edited_at'),
        'deleted': False
    }
    if st == 'note':
        item.update({
            'content': saved.get('content', ''),
            'image_url': saved.get('image_url'),
            'attachment': saved.get('attachment'),
            'location': saved.get('location'),
            'author': _sv_user_brief(db, uid)
        })
        return item

    original, source_name, server_id = _sv_find_original(db, uid, saved)
    if not original:
        item['deleted'] = True
        return item
    item.update({
        'source_name': source_name,
        'source_server_id': server_id,
        'content': original.get('content', ''),
        'image_url': original.get('image_url'),
        'attachment': original.get('attachment'),
        'location': original.get('location'),
        'poll': original.get('poll'),
        'author': _sv_user_brief(db, original.get('user_id')),
        'created_at': original.get('created_at')
    })
    return item


# --- Get Saved Messages ---
@app.route('/api/saved-messages', methods=['GET'])
@login_required
def get_saved_messages():
    """لیست پیام‌های ذخیره‌شده + یادداشت‌های شخصی کاربر (قدیمی‌ترین اول)"""
    db = load_database()
    uid = session['user_id']
    user_saved = (db.get('saved_messages') or {}).get(uid, [])
    messages = [_sv_enrich(db, uid, saved) for saved in user_saved]
    return jsonify({'success': True, 'messages': messages})


# --- Save (bookmark) a message ---
@app.route('/api/saved-messages', methods=['POST'])
@login_required
def save_message_api():
    """ذخیره یک پیام کانال یا DM"""
    data = request.get_json(silent=True) or {}
    message_id = data.get('message_id')
    if not message_id or not isinstance(message_id, str):
        return jsonify({'error': 'Message ID required'}), 400

    uid = session['user_id']
    with saved_lock:
        db = load_database()

        source_type = None
        source_id = None
        dm_key = None
        other_user_id = None

        original = db['all_messages'].get(message_id)
        if original and not original.get('deleted'):
            channel, server = _sv_channel_msg_access(db, uid, original)
            if not channel:
                return jsonify({'error': 'Not a member of this server'}), 403
            source_type = 'channel'
            source_id = channel['id']
        else:
            original = None
            # فقط DM هایی که خود کاربر عضوشان است جستجو می‌شود
            for key, msgs in db.get('direct_messages', {}).items():
                members = _sv_dm_members(key)
                if uid not in members:
                    continue
                for m in msgs:
                    if m.get('id') == message_id and not m.get('deleted'):
                        original = m
                        dm_key = key
                        others = [x for x in members if x != uid]
                        other_user_id = others[0] if others else uid
                        break
                if original:
                    break
            if not original:
                return jsonify({'error': 'Message not found'}), 404
            source_type = 'dm'
            source_id = other_user_id

        user_saved = db.setdefault('saved_messages', {}).setdefault(uid, [])
        if any(x.get('message_id') == message_id for x in user_saved):
            return jsonify({'error': 'Message already saved'}), 400
        if len(user_saved) >= SAVED_MAX_ENTRIES:
            return jsonify({'error': 'Saved messages limit reached'}), 400

        saved_id = uuid.uuid4().hex[:12]
        user_saved.append({
            'id': saved_id,
            'message_id': message_id,
            'source_type': source_type,
            'source_id': source_id,
            'dm_key': dm_key,
            'other_user_id': other_user_id,
            'saved_at': datetime.now().isoformat()
        })
        save_database(db)

    return jsonify({'success': True, 'saved_id': saved_id})


# --- Send a personal note into Saved Messages ---
@app.route('/api/saved-messages/note', methods=['POST'])
@login_required
def add_saved_note():
    """ارسال پیام شخصی داخل Saved Messages"""
    data = request.get_json(silent=True) or {}

    content = data.get('content', '')
    content = content.strip() if isinstance(content, str) else ''
    if len(content) > SAVED_NOTE_MAX_LEN:
        return jsonify({'error': f'Note exceeds {SAVED_NOTE_MAX_LEN} characters'}), 400

    if data.get('poll'):
        return jsonify({'error': 'Polls are not supported in Saved Messages'}), 400

    image_url = data.get('image_url')
    if image_url:
        if not isinstance(image_url, str) or not MEDIA_URL_RE.match(image_url):
            return jsonify({'error': 'Invalid image'}), 400
    else:
        image_url = None

    attachment, location, _poll, rich_error = parse_rich_payload(data)
    if rich_error:
        return rich_error
    if attachment and attachment.get('type') == 'image' and not image_url:
        image_url = attachment.get('url')

    if not content and not image_url and not attachment and not location:
        return jsonify({'error': 'Note content is required'}), 400

    uid = session['user_id']
    with saved_lock:
        db = load_database()
        user_saved = db.setdefault('saved_messages', {}).setdefault(uid, [])
        if len(user_saved) >= SAVED_MAX_ENTRIES:
            return jsonify({'error': 'Saved messages limit reached'}), 400

        now = datetime.now().isoformat()
        entry = {
            'id': uuid.uuid4().hex[:12],
            'message_id': None,
            'source_type': 'note',
            'source_id': None,
            'content': content,
            'image_url': image_url,
            'attachment': attachment,
            'location': location,
            'created_at': now,
            'saved_at': now,
            'edited_at': None
        }
        user_saved.append(entry)
        save_database(db)
        result = _sv_enrich(db, uid, entry)

    return jsonify({'success': True, 'message': result})


# --- Edit a personal note ---
@app.route('/api/saved-messages/<saved_id>', methods=['PUT'])
@login_required
def edit_saved_note(saved_id):
    data = request.get_json(silent=True) or {}
    content = data.get('content', '')
    content = content.strip() if isinstance(content, str) else ''
    if len(content) > SAVED_NOTE_MAX_LEN:
        return jsonify({'error': f'Note exceeds {SAVED_NOTE_MAX_LEN} characters'}), 400

    uid = session['user_id']
    with saved_lock:
        db = load_database()
        user_saved = (db.get('saved_messages') or {}).get(uid, [])
        entry = next((x for x in user_saved if x.get('id') == saved_id), None)
        if not entry:
            return jsonify({'error': 'Saved message not found'}), 404
        if entry.get('source_type') != 'note':
            return jsonify({'error': 'Only your own notes can be edited'}), 400
        if not content and not (entry.get('image_url') or entry.get('attachment') or entry.get('location')):
            return jsonify({'error': 'Note content is required'}), 400
        entry['content'] = content
        entry['edited_at'] = datetime.now().isoformat()
        save_database(db)
        result = _sv_enrich(db, uid, entry)

    return jsonify({'success': True, 'message': result})


# --- Remove Saved Message / note ---
@app.route('/api/saved-messages/<saved_id>', methods=['DELETE'])
@login_required
def remove_saved_message(saved_id):
    uid = session['user_id']
    with saved_lock:
        db = load_database()
        user_saved = (db.get('saved_messages') or {}).get(uid, [])
        idx = next((i for i, x in enumerate(user_saved) if x.get('id') == saved_id), None)
        if idx is None:
            return jsonify({'error': 'Saved message not found'}), 404
        user_saved.pop(idx)
        save_database(db)
    return jsonify({'success': True})


# --- Forward Saved Message ---
@app.route('/api/saved-messages/<saved_id>/forward', methods=['POST'])
@login_required
def forward_saved_message(saved_id):
    """فوروارد پیام ذخیره‌شده یا یادداشت به DM یک کاربر"""
    data = request.get_json(silent=True) or {}
    target_type = data.get('target_type')
    target_id = data.get('target_id')
    if target_type != 'dm' or not target_id or not isinstance(target_id, str):
        return jsonify({'error': 'Invalid target'}), 400

    uid = session['user_id']
    db = load_database()
    user_saved = (db.get('saved_messages') or {}).get(uid, [])
    saved = next((x for x in user_saved if x.get('id') == saved_id), None)
    if not saved:
        return jsonify({'error': 'Saved message not found'}), 404

    if saved.get('source_type') == 'note':
        original = saved
    else:
        original, _n, _s = _sv_find_original(db, uid, saved)
    if not original:
        return jsonify({'error': 'Original message not found'}), 404

    sender = db['users'].get(uid) or {}
    receiver = db['users'].get(target_id)
    if not receiver:
        return jsonify({'error': 'User not found'}), 404
    if target_id in sender.get('blocked_users', []):
        return jsonify({'error': 'You have blocked this user'}), 403
    if uid in receiver.get('blocked_users', []):
        return jsonify({'error': 'This user has blocked you'}), 403

    dm_key_str = "dm_" + "_".join(sorted([uid, target_id]))
    db['direct_messages'].setdefault(dm_key_str, [])

    original_author = db['users'].get(original.get('user_id') or uid, {})
    forwarded_msg = {
        'id': uuid.uuid4().hex[:12],
        'dm_key': dm_key_str,
        'user_id': uid,
        'content': original.get('content', ''),
        'image_url': original.get('image_url'),
        'created_at': datetime.now().isoformat(),
        'reactions': {},
        'forwarded_from': {
            'message_id': saved.get('message_id'),
            'original_author': forward_author_name(db, original_author, uid)
        }
    }
    forwarded_msg.update(forward_rich_fields(original))
    db['direct_messages'][dm_key_str].append(forwarded_msg)
    save_database(db)

    return jsonify({**forwarded_msg, 'author': {**_sv_user_brief(db, uid), 'is_premium': sender.get('is_premium', False)}})


# ============================================
# DM CONVERSATIONS LIST API
# ============================================
@app.route('/api/dm/conversations', methods=['GET'])
@login_required
def get_dm_conversations():
    """دریافت لیست مکالمات DM کاربر با اطلاعات کامل"""
    db = load_database()
    
    current_user_id = session['user_id']
    current_user = db['users'].get(current_user_id, {})
    conversations = []
    
    # بررسی تمام DM‌های کاربر
    for dm_key, messages in db.get('direct_messages', {}).items():
        # استخراج user_id‌ها از dm_key
        # فرمت: dm_{user1}_{user2}
        try:
            user_ids = dm_key.replace('dm_', '').split('_')
        except:
            continue
        
        # بررسی اینکه کاربر فعلی در این DM هست
        if current_user_id not in user_ids:
            continue
        
        # پیدا کردن کاربر دیگر
        other_user_id = user_ids[0] if len(user_ids) > 1 and user_ids[1] == current_user_id else (user_ids[1] if len(user_ids) > 1 else None)
        
        if not other_user_id:
            continue
        
        # بررسی بن شدن
        other_user = db['users'].get(other_user_id)
        
        if not other_user:
            continue
        
        if other_user_id in current_user.get('blocked_users', []):
            continue
        
        if current_user_id in other_user.get('blocked_users', []):
            continue
        
        # chat deleted by me: only messages newer than that moment count; nothing left -> not listed
        hidden_since = dm_hidden_since(db, current_user_id, other_user_id)
        if hidden_since:
            messages = [x for x in messages if (x.get('created_at') or '') > hidden_since]
        messages = [x for x in messages if dm_visible_to(x, current_user_id)]
        if hidden_since and not messages:
            continue
        # پیدا کردن آخرین پیام
        last_message = None
        last_message_at = None
        
        if messages:
            last_message = messages[-1]
            last_message_at = last_message.get('created_at', '')
        
        # شمارش پیام‌های خوانده نشده
        # (پیام‌هایی که مال کاربر دیگر هستند و هنوز خوانده نشده‌اند)
        unread_count = 0
        for msg in messages:
            if msg.get('user_id') not in (current_user_id, 'system') and not msg.get('seen_at'):
                # برای سادگی، همه پیام‌های کاربر دیگر را شمارش می‌کنیم
                # اگر سیستم خوانده شده دارید، اینجا اضافه کنید
                unread_count += 1
        
        # محدود کردن unread به حداکثر 99+
        if unread_count > 99:
            unread_count = 99
        
        conversations.append({
            'user_id': other_user_id,
            'username': other_user.get('username', 'Unknown User'),
            'avatar': apply_privacy_to_user(db, current_user_id, other_user).get('avatar'),
            'avatar_color': other_user.get('avatar_color', '#7289da'),
            'last_message_at': last_message_at,
            'unread_count': unread_count,
            'verified': user_is_verified(other_user),
            'is_online': apply_privacy_to_user(db, current_user_id, other_user).get('status') == 'online'
        })
    
    # مرتب‌سازی بر اساس زمان آخرین پیام (جدیدترین اول)
    conversations.sort(key=lambda x: x.get('last_message_at') or '', reverse=True)
    
    # pinned system conversations (Admin Warn / Discord) always stay on top
    conversations = system_dm_conversations(db, current_user_id) + conversations
    
    return jsonify(conversations)

# ============================================
# FRIEND SYSTEM - Complete Implementation
# ============================================

# --- Friend Request Routes ---

# ============================================
# FRIEND SYSTEM - Complete Implementation
# ============================================
# --- Friend Request Routes ---
@app.route('/api/friends/request', methods=['POST'])
@login_required
def send_friend_request():
    """
    ارسال درخواست دوستی
    """
    data = (request.get_json(silent=True) or {})
    target_user_id = data.get('user_id')
    if not target_user_id:
        return jsonify({'error': 'User ID required'}), 400
    if target_user_id == session['user_id']:
        return jsonify({'error': 'Cannot send friend request to yourself'}), 400
    
    db = load_database()
    current_user_id = session['user_id']
    
    # بررسی وجود کاربر مقصد
    target_user = db['users'].get(target_user_id)
    if not target_user:
        return jsonify({'error': 'User not found'}), 404
    
    current_user = db['users'].get(current_user_id)
    
    # ============================================
    # بررسی تنظیمات حریم خصوصی کاربر مقصد
    # ============================================
    privacy_settings = db.get('privacy_settings', {}).get(target_user_id, {})
    if not privacy_settings.get('allow_friend_requests', True):
        return jsonify({
            'error': 'This user is not accepting friend requests',
            'code': 'FRIEND_REQUESTS_DISABLED'
        }), 403
    
    # ============================================
    # بررسی بن شدن متقابل
    # ============================================
    if target_user_id in current_user.get('blocked_users', []):
        return jsonify({'error': 'You have blocked this user'}), 403
    if current_user_id in target_user.get('blocked_users', []):
        return jsonify({'error': 'This user has blocked you'}), 403
    
    # بررسی اینکه از قبل دوست هستند
    if 'friends' not in current_user:
        current_user['friends'] = []
    if target_user_id in current_user['friends']:
        return jsonify({'error': 'Already friends'}), 400
    
    if 'friend_requests' not in db:
        db['friend_requests'] = []
    
    # ============================================
    # ✅ اصلاح: بررسی فقط درخواست‌های pending
    # ============================================
    # بررسی درخواست ارسال شده از طرف این کاربر (فقط pending)
    for req in db['friend_requests']:
        if req['from_user_id'] == current_user_id and req['to_user_id'] == target_user_id and req['status'] == 'pending':
            return jsonify({'error': 'Friend request already sent'}), 400
    
    # auto_accept_mutual: if the other side already sent us a request, only auto-accept when enabled
    reverse_pending = any(
        req['from_user_id'] == target_user_id and req['to_user_id'] == current_user_id and req['status'] == 'pending'
        for req in db['friend_requests']
    )
    if reverse_pending and not get_friends_prefs(db, current_user_id).get('auto_accept_mutual', True):
        return jsonify({'error': 'This user already sent you a friend request. Accept it from your requests list.'}), 400

    # بررسی درخواست معکوس (فقط pending) - اگر طرف مقابل درخواست داده، مستقیم دوست شوند
    for req in db['friend_requests']:
        if req['from_user_id'] == target_user_id and req['to_user_id'] == current_user_id and req['status'] == 'pending':
            # تأیید خودکار درخواست معکوس
            req['status'] = 'accepted'
            req['accepted_at'] = datetime.now().isoformat()
            
            # اضافه کردن به لیست دوستان هر دو کاربر
            if 'friends' not in db['users'][target_user_id]:
                db['users'][target_user_id]['friends'] = []
            if 'friends' not in current_user:
                current_user['friends'] = []
            
            if current_user_id not in db['users'][target_user_id]['friends']:
                db['users'][target_user_id]['friends'].append(current_user_id)
            if target_user_id not in current_user['friends']:
                current_user['friends'].append(target_user_id)
            
            # ایجاد DM خودکار
            dm_key = tuple(sorted([current_user_id, target_user_id]))
            dm_key_str = f"dm_{'_'.join(dm_key)}"
            if dm_key_str not in db['direct_messages']:
                db['direct_messages'][dm_key_str] = []
            
            # ارسال پیام سیستمی
            system_message_id = str(uuid.uuid4().hex[:12])
            db['direct_messages'][dm_key_str].append({
                'id': system_message_id,
                'dm_key': dm_key_str,
                'user_id': 'system',
                'content': f"**{current_user.get('username')}** and **{target_user.get('username')}** are now friends! 🎉",
                'created_at': datetime.now().isoformat(),
                'reactions': {},
                'type': 'system'
            })
            
            save_database(db)
            return jsonify({
                'success': True,
                'message': 'Friend request accepted automatically',
                'status': 'friends'
            })
    
    # ایجاد درخواست جدید
    request_id = str(uuid.uuid4().hex[:12])
    new_request = {
        'id': request_id,
        'from_user_id': current_user_id,
        'to_user_id': target_user_id,
        'status': 'pending',
        'created_at': datetime.now().isoformat(),
        'from_username': current_user.get('username'),
        'from_avatar': current_user.get('avatar'),
        'from_avatar_color': current_user.get('avatar_color', '#7289da')
    }
    db['friend_requests'].append(new_request)
    if get_friends_prefs(db, target_user_id).get('request_notifications', True):
        db.setdefault('notifications', []).append({
            'id': str(uuid.uuid4().hex[:12]),
            'user_id': target_user_id,
            'type': 'friend_request',
            'title': 'New friend request',
            'message': f"{current_user.get('username')} sent you a friend request",
            'from_user_id': current_user_id,
            'request_id': request_id,
            'read': False,
            'created_at': datetime.now().isoformat(),
        })
    save_database(db)
    
    return jsonify({
        'success': True,
        'message': 'Friend request sent',
        'request_id': request_id
    })


@app.route('/api/friends/request/<request_id>/accept', methods=['POST'])
@login_required
def accept_friend_request(request_id):
    """
    قبول درخواست دوستی
    """
    db = load_database()
    current_user_id = session['user_id']
    
    if 'friend_requests' not in db:
        return jsonify({'error': 'Friend request not found'}), 404
    
    # پیدا کردن درخواست
    request_found = None
    request_index = None
    for i, req in enumerate(db['friend_requests']):
        if req['id'] == request_id and req['to_user_id'] == current_user_id:
            request_found = req
            request_index = i
            break
    
    if not request_found:
        return jsonify({'error': 'Friend request not found'}), 404
    
    if request_found['status'] != 'pending':
        return jsonify({'error': 'Request already processed'}), 400
    
    from_user_id = request_found['from_user_id']
    from_user = db['users'].get(from_user_id)
    current_user = db['users'].get(current_user_id)
    
    # به‌روزرسانی وضعیت درخواست
    db['friend_requests'][request_index]['status'] = 'accepted'
    db['friend_requests'][request_index]['accepted_at'] = datetime.now().isoformat()
    
    # اضافه کردن به لیست دوستان
    if 'friends' not in current_user:
        current_user['friends'] = []
    if 'friends' not in from_user:
        from_user['friends'] = []
    
    if from_user_id not in current_user['friends']:
        current_user['friends'].append(from_user_id)
    if current_user_id not in from_user['friends']:
        from_user['friends'].append(current_user_id)
    
    # ایجاد DM خودکار
    dm_key = tuple(sorted([current_user_id, from_user_id]))
    dm_key_str = f"dm_{'_'.join(dm_key)}"
    if dm_key_str not in db['direct_messages']:
        db['direct_messages'][dm_key_str] = []
    
    # پیام سیستمی
    system_message_id = str(uuid.uuid4().hex[:12])
    db['direct_messages'][dm_key_str].append({
        'id': system_message_id,
        'dm_key': dm_key_str,
        'user_id': 'system',
        'content': f"**{current_user.get('username')}** and **{from_user.get('username')}** are now friends! 🎉",
        'created_at': datetime.now().isoformat(),
        'reactions': {},
        'type': 'system'
    })
    
    save_database(db)
    
    return jsonify({
        'success': True,
        'message': 'Friend request accepted',
        'friend': {
            'id': from_user_id,
            'username': from_user.get('username'),
            'avatar': from_user.get('avatar'),
            'avatar_color': from_user.get('avatar_color', '#7289da'),
            'status': from_user.get('status', 'offline')
        }
    })


@app.route('/api/friends/request/<request_id>/reject', methods=['POST'])
@login_required
def reject_friend_request(request_id):
    """
    رد درخواست دوستی
    """
    db = load_database()
    current_user_id = session['user_id']
    
    if 'friend_requests' not in db:
        return jsonify({'error': 'Friend request not found'}), 404
    
    # پیدا کردن درخواست
    request_found = None
    request_index = None
    for i, req in enumerate(db['friend_requests']):
        if req['id'] == request_id and req['to_user_id'] == current_user_id:
            request_found = req
            request_index = i
            break
    
    if not request_found:
        return jsonify({'error': 'Friend request not found'}), 404
    
    if request_found['status'] != 'pending':
        return jsonify({'error': 'Request already processed'}), 400
    
    # به‌روزرسانی وضعیت درخواست
    db['friend_requests'][request_index]['status'] = 'rejected'
    db['friend_requests'][request_index]['rejected_at'] = datetime.now().isoformat()
    
    save_database(db)
    
    return jsonify({
        'success': True,
        'message': 'Friend request rejected'
    })


@app.route('/api/friends/request/<request_id>/cancel', methods=['POST'])
@login_required
def cancel_friend_request(request_id):
    """
    لغو درخواست دوستی ارسال شده
    """
    db = load_database()
    current_user_id = session['user_id']
    
    if 'friend_requests' not in db:
        return jsonify({'error': 'Friend request not found'}), 404
    
    # پیدا کردن درخواست
    request_found = None
    request_index = None
    for i, req in enumerate(db['friend_requests']):
        if req['id'] == request_id and req['from_user_id'] == current_user_id:
            request_found = req
            request_index = i
            break
    
    if not request_found:
        return jsonify({'error': 'Friend request not found'}), 404
    
    # حذف درخواست
    db['friend_requests'].pop(request_index)
    
    save_database(db)
    
    return jsonify({
        'success': True,
        'message': 'Friend request cancelled'
    })


@app.route('/api/friends/requests/incoming')
@login_required
@privacy_filtered
def get_incoming_friend_requests():
    """
    دریافت لیست درخواست‌های دوستی دریافتی
    """
    db = load_database()
    current_user_id = session['user_id']
    
    if 'friend_requests' not in db:
        return jsonify([])
    
    incoming_requests = []
    for req in db['friend_requests']:
        if req['to_user_id'] == current_user_id and req['status'] == 'pending':
            incoming_requests.append({
                'id': req['id'],
                'from_user_id': req['from_user_id'],
                'from_username': req['from_username'],
                'from_avatar': req['from_avatar'],
                'from_avatar_color': req['from_avatar_color'],
                'created_at': req['created_at']
            })
    
    # مرتب‌سازی بر اساس زمان (جدیدترین اول)
    incoming_requests.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    
    return jsonify(incoming_requests)


@app.route('/api/friends/requests/outgoing')
@login_required
@privacy_filtered
def get_outgoing_friend_requests():
    """
    دریافت لیست درخواست‌های دوستی ارسالی
    """
    db = load_database()
    current_user_id = session['user_id']
    
    if 'friend_requests' not in db:
        return jsonify([])
    
    outgoing_requests = []
    for req in db['friend_requests']:
        if req['from_user_id'] == current_user_id and req['status'] == 'pending':
            to_user = db['users'].get(req['to_user_id'], {})
            outgoing_requests.append({
                'id': req['id'],
                'to_user_id': req['to_user_id'],
                'to_username': to_user.get('username', 'Unknown'),
                'to_avatar': to_user.get('avatar'),
                'to_avatar_color': to_user.get('avatar_color', '#7289da'),
                'created_at': req['created_at']
            })
    
    outgoing_requests.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    
    return jsonify(outgoing_requests)


@app.route('/api/friends')
@login_required
@privacy_filtered
def get_friends_list():
    """
    دریافت لیست دوستان
    """
    db = load_database()
    current_user_id = session['user_id']
    current_user = db['users'].get(current_user_id)
    
    if not current_user:
        return jsonify({'error': 'User not found'}), 404
    
    friends = current_user.get('friends', [])
    friends_list = []
    
    for friend_id in friends:
        friend = db['users'].get(friend_id)
        if friend:
            friends_list.append({
                'id': friend_id,
                'username': friend.get('username'),
                'avatar': friend.get('avatar'),
                'avatar_color': friend.get('avatar_color', '#7289da'),
                'status': friend.get('status', 'offline'),
                'is_premium': friend.get('is_premium', False),
                'last_seen': friend.get('last_seen')
            })
    
    # مرتب‌سازی: آنلاین اول، سپس بر اساس نام
    friends_list.sort(key=lambda x: (
        x['status'] != 'online',  # آنلاین‌ها اول (False < True)
        x['username'].lower()
    ))
    
    return jsonify({
        'friends': friends_list,
        'total': len(friends_list)
    })


@app.route('/api/friends/<friend_id>', methods=['DELETE'])
@login_required
def remove_friend(friend_id):
    """
    حذف دوست
    """
    db = load_database()
    current_user_id = session['user_id']
    
    current_user = db['users'].get(current_user_id)
    friend_user = db['users'].get(friend_id)
    
    if not current_user or not friend_user:
        return jsonify({'error': 'User not found'}), 404
    
    # حذف از لیست دوستان هر دو کاربر
    if 'friends' not in current_user:
        current_user['friends'] = []
    if 'friends' not in friend_user:
        friend_user['friends'] = []
    
    if current_user_id in friend_user['friends']:
        friend_user['friends'].remove(current_user_id)
    if friend_id in current_user['friends']:
        current_user['friends'].remove(friend_id)
    
    save_database(db)
    
    return jsonify({
        'success': True,
        'message': f'Removed {friend_user.get("username")} from friends'
    })


@app.route('/api/friends/status/<user_id>')
@login_required
def get_friendship_status(user_id):
    """
    بررسی وضعیت دوستی با یک کاربر
    Returns: none, pending_incoming, pending_outgoing, friends, blocked
    """
    db = load_database()
    current_user_id = session['user_id']
    
    if user_id == current_user_id:
        return jsonify({'status': 'self'})
    
    current_user = db['users'].get(current_user_id)
    target_user = db['users'].get(user_id)
    
    if not target_user:
        return jsonify({'error': 'User not found'}), 404
    
    # بررسی بن شدن
    if user_id in current_user.get('blocked_users', []):
        return jsonify({'status': 'blocked', 'direction': 'you_blocked'})
    if current_user_id in target_user.get('blocked_users', []):
        return jsonify({'status': 'blocked', 'direction': 'they_blocked'})
    
    # بررسی دوستی
    if 'friends' not in current_user:
        current_user['friends'] = []
    if user_id in current_user['friends']:
        return jsonify({'status': 'friends'})
    
    # بررسی درخواست‌های دوستی
    if 'friend_requests' not in db:
        db['friend_requests'] = []
    
    # بررسی درخواست ارسالی از طرف ما
    for req in db['friend_requests']:
        if req['from_user_id'] == current_user_id and req['to_user_id'] == user_id and req['status'] == 'pending':
            return jsonify({'status': 'pending_outgoing'})
    
    # بررسی درخواست دریافتی
    for req in db['friend_requests']:
        if req['from_user_id'] == user_id and req['to_user_id'] == current_user_id and req['status'] == 'pending':
            return jsonify({'status': 'pending_incoming', 'request_id': req['id']})
    
    return jsonify({'status': 'none'})


@app.route('/api/friends/suggestions')
@login_required
@privacy_filtered
def get_friend_suggestions():
    """
    پیشنهاد دوستان (کاربرانی که ممکن است بشناسید)
    بر اساس: دوستان دوستان، کاربران آنلاین
    """
    db = load_database()
    current_user_id = session['user_id']
    current_user = db['users'].get(current_user_id)
    
    if not current_user:
        return jsonify({'error': 'User not found'}), 404
    
    current_friends = set(current_user.get('friends', []))
    current_friends.add(current_user_id)  # خودش را اضافه نکنیم
    
    # کاربران مسدود شده
    blocked_users = set(current_user.get('blocked_users', []))
    
    suggestions = []
    
    # 1. کاربران آنلاین که دوست نیستند
    for uid, user in db['users'].items():
        if uid in current_friends or uid in blocked_users:
            continue
        
        # بررسی اینکه درخواست دوستی قبلاً ارسال نشده
        has_pending_request = False
        for req in db.get('friend_requests', []):
            if req['from_user_id'] == current_user_id and req['to_user_id'] == uid and req['status'] == 'pending':
                has_pending_request = True
                break
            if req['from_user_id'] == uid and req['to_user_id'] == current_user_id and req['status'] == 'pending':
                has_pending_request = True
                break
        
        if has_pending_request:
            continue
        
        # امتیازدهی
        score = 0
        
        # کاربران آنلاین امتیاز بیشتری دارند
        if user.get('status') == 'online':
            score += 10
        
        # Premium users
        if user.get('is_premium'):
            score += 5
        
        # دوستان مشترک
        user_friends = set(user.get('friends', []))
        mutual_friends = current_friends & user_friends
        score += len(mutual_friends) * 3
        
        suggestions.append({
            'id': uid,
            'username': user.get('username'),
            'avatar': user.get('avatar'),
            'avatar_color': user.get('avatar_color', '#7289da'),
            'status': user.get('status', 'offline'),
            'is_premium': user.get('is_premium', False), 'verified': user_is_verified(user),
            'mutual_friends_count': len(mutual_friends),
            'score': score
        })
    
    # مرتب‌سازی بر اساس امتیاز
    suggestions.sort(key=lambda x: x['score'], reverse=True)
    
    return jsonify({
        'suggestions': suggestions[:20],  # حداکثر 20 پیشنهاد
        'total': len(suggestions)
    })


@app.route('/api/friends/search')
@login_required
@privacy_filtered
def search_friends():
    """
    جستجو در لیست دوستان
    """
    db = load_database()
    current_user_id = session['user_id']
    query = request.args.get('q', '').lower()
    
    if len(query) < 1:
        return jsonify({'error': 'Query too short'}), 400
    
    current_user = db['users'].get(current_user_id)
    if not current_user:
        return jsonify({'error': 'User not found'}), 404
    
    friends = current_user.get('friends', [])
    results = []
    
    for friend_id in friends:
        friend = db['users'].get(friend_id)
        if friend and query in friend.get('username', '').lower():
            results.append({
                'id': friend_id,
                'username': friend.get('username'),
                'avatar': friend.get('avatar'),
                'avatar_color': friend.get('avatar_color', '#7289da'),
                'status': friend.get('status', 'offline')
            })
    
    return jsonify(results)


@app.route('/api/friends/requests/count')
@login_required
def get_friend_requests_count():
    """
    تعداد درخواست‌های دوستی دریافتی (برای نمایش نوتیفیکیشن)
    """
    db = load_database()
    current_user_id = session['user_id']
    
    count = 0
    for req in db.get('friend_requests', []):
        if req['to_user_id'] == current_user_id and req['status'] == 'pending':
            count += 1
    
    return jsonify({'count': count})


@app.route('/api/friends/requests/accept-all', methods=['POST'])
@login_required
def accept_all_friend_requests():
    """
    قبول همه درخواست‌های دوستی
    """
    db = load_database()
    current_user_id = session['user_id']
    current_user = db['users'].get(current_user_id)
    
    if 'friend_requests' not in db:
        return jsonify({'success': True, 'accepted_count': 0})
    
    accepted_count = 0
    
    for i, req in enumerate(db['friend_requests']):
        if req['to_user_id'] == current_user_id and req['status'] == 'pending':
            from_user_id = req['from_user_id']
            from_user = db['users'].get(from_user_id)
            
            # به‌روزرسانی وضعیت
            db['friend_requests'][i]['status'] = 'accepted'
            db['friend_requests'][i]['accepted_at'] = datetime.now().isoformat()
            
            # اضافه کردن به لیست دوستان
            if 'friends' not in current_user:
                current_user['friends'] = []
            if 'friends' not in from_user:
                from_user['friends'] = []
            
            if from_user_id not in current_user['friends']:
                current_user['friends'].append(from_user_id)
            if current_user_id not in from_user['friends']:
                from_user['friends'].append(current_user_id)
            
            # ایجاد DM خودکار
            dm_key = tuple(sorted([current_user_id, from_user_id]))
            dm_key_str = f"dm_{'_'.join(dm_key)}"
            if dm_key_str not in db['direct_messages']:
                db['direct_messages'][dm_key_str] = []
            
            system_message_id = str(uuid.uuid4().hex[:12])
            db['direct_messages'][dm_key_str].append({
                'id': system_message_id,
                'dm_key': dm_key_str,
                'user_id': 'system',
                'content': f"**{current_user.get('username')}** and **{from_user.get('username')}** are now friends! 🎉",
                'created_at': datetime.now().isoformat(),
                'reactions': {},
                'type': 'system'
            })
            
            accepted_count += 1
    
    save_database(db)
    
    return jsonify({
        'success': True,
        'accepted_count': accepted_count
    })


@app.route('/api/friends/requests/reject-all', methods=['POST'])
@login_required
def reject_all_friend_requests():
    """
    رد همه درخواست‌های دوستی
    """
    db = load_database()
    current_user_id = session['user_id']
    
    if 'friend_requests' not in db:
        return jsonify({'success': True, 'rejected_count': 0})
    
    rejected_count = 0
    
    for i, req in enumerate(db['friend_requests']):
        if req['to_user_id'] == current_user_id and req['status'] == 'pending':
            db['friend_requests'][i]['status'] = 'rejected'
            db['friend_requests'][i]['rejected_at'] = datetime.now().isoformat()
            rejected_count += 1
    
    save_database(db)
    
    return jsonify({
        'success': True,
        'rejected_count': rejected_count
    })
# --- دریافت تمام Badge های یک کاربر ---
@app.route('/api/users/<user_id>/badges')
@login_required
def get_user_badges(user_id):
    """دریافت لیست Badge های یک کاربر"""
    db = load_database()
    user = db['users'].get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    badges = {}
    for field in BADGE_FIELDS:
        badges[field] = user.get(field, False)
    
    # تاریخچه Badge ها
    badge_history = db.get('badge_history', {}).get(user_id, [])
    
    return jsonify({
        'badges': badges,
        'history': badge_history[-20:]  # آخرین 20 مورد
    })


# --- مدیریت کامل Badge ها (توسط ادمین) ---
@app.route('/api/admin/users/<user_id>/badges', methods=['PUT'])
@admin_required
def update_user_badges(user_id):
    """مدیریت Badge های کاربر"""
    data = (request.get_json(silent=True) or {})
    db = load_database()
    user = db['users'].get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # تاریخچه تغییرات
    if 'badge_history' not in db:
        db['badge_history'] = {}
    if user_id not in db['badge_history']:
        db['badge_history'][user_id] = []
    
    updated_badges = {}
    for field in BADGE_FIELDS:
        if field in data:
            old_value = user.get(field, False)
            new_value = data[field]
            
            # فقط اگر تغییر کرده باشد ثبت کن
            if old_value != new_value:
                user[field] = new_value
                updated_badges[field] = {
                    'old': old_value,
                    'new': new_value
                }
                # ثبت در تاریخچه
                db['badge_history'][user_id].append({
                    'action': 'update',
                    'badge': field,
                    'old_value': old_value,
                    'new_value': new_value,
                    'by': session['user_id'],
                    'at': datetime.now().isoformat()
                })
    
    save_database(db)
    return jsonify({
        'success': True,
        'updated': updated_badges,
        'all_badges': {k: user.get(k, False) for k in BADGE_FIELDS}
    })


# --- فعال/غیرفعال کردن یک Badge ---
@app.route('/api/admin/users/<user_id>/badges/<badge_type>/toggle', methods=['POST'])
@admin_required
def toggle_user_badge(user_id, badge_type):
    """فعال/غیرفعال کردن یک Badge خاص"""
    if badge_type not in BADGE_FIELDS:
        return jsonify({'error': 'Invalid badge type'}), 400
    
    db = load_database()
    user = db['users'].get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    old_value = user.get(badge_type, False)
    user[badge_type] = not old_value
    new_value = user[badge_type]
    
    # ثبت در تاریخچه
    if 'badge_history' not in db:
        db['badge_history'] = {}
    if user_id not in db['badge_history']:
        db['badge_history'][user_id] = []
    
    db['badge_history'][user_id].append({
        'action': 'toggle',
        'badge': badge_type,
        'old_value': old_value,
        'new_value': new_value,
        'by': session['user_id'],
        'at': datetime.now().isoformat()
    })
    
    save_database(db)
    
    return jsonify({
        'success': True,
        'badge': badge_type,
        'old_value': old_value,
        'new_value': new_value
    })


# --- تنظیم HypeSquad House ---
@app.route('/api/admin/users/<user_id>/hypesquad', methods=['PUT'])
@admin_required
def set_hypesquad_house(user_id):
    """تنظیم HypeSquad House"""
    data = (request.get_json(silent=True) or {})
    house = data.get('house')  # 'bravery', 'brilliance', 'balance', یا null
    
    valid_houses = ['bravery', 'brilliance', 'balance', None]
    if house not in valid_houses:
        return jsonify({'error': 'Invalid house. Must be: bravery, brilliance, balance, or null'}), 400
    
    db = load_database()
    user = db['users'].get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    old_house = user.get('hypesquad_house')
    user['hypesquad_house'] = house
    
    # ثبت در تاریخچه
    if 'badge_history' not in db:
        db['badge_history'] = {}
    if user_id not in db['badge_history']:
        db['badge_history'][user_id] = []
    
    db['badge_history'][user_id].append({
        'action': 'set_hypesquad',
        'old_house': old_house,
        'new_house': house,
        'by': session['user_id'],
        'at': datetime.now().isoformat()
    })
    
    save_database(db)
    
    return jsonify({
        'success': True,
        'old_house': old_house,
        'hypesquad_house': house
    })


# --- مدیریت Reputation ---
@app.route('/api/admin/users/<user_id>/reputation', methods=['PUT'])
@admin_required
def update_user_reputation(user_id):
    """مدیریت امتیاز اعتبار کاربر"""
    data = (request.get_json(silent=True) or {})
    amount = data.get('amount', 0)
    action = data.get('action', 'set')  # 'set', 'add', 'remove'
    
    db = load_database()
    user = db['users'].get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    old_reputation = user.get('reputation', 0)
    
    if action == 'set':
        user['reputation'] = max(0, amount)
    elif action == 'add':
        user['reputation'] = max(0, old_reputation + amount)
    elif action == 'remove':
        user['reputation'] = max(0, old_reputation - amount)
    
    # ثبت در تاریخچه
    if 'badge_history' not in db:
        db['badge_history'] = {}
    if user_id not in db['badge_history']:
        db['badge_history'][user_id] = []
    
    db['badge_history'][user_id].append({
        'action': 'reputation_change',
        'old_value': old_reputation,
        'new_value': user['reputation'],
        'change_amount': amount,
        'action_type': action,
        'by': session['user_id'],
        'at': datetime.now().isoformat()
    })
    
    save_database(db)
    
    return jsonify({
        'success': True,
        'old_reputation': old_reputation,
        'reputation': user['reputation'],
        'change': user['reputation'] - old_reputation
    })


# --- مدیریت Server Boost Level ---
@app.route('/api/admin/users/<user_id>/boost-level', methods=['PUT'])
@admin_required
def update_boost_level(user_id):
    """تنظیم سطح Boost سرور کاربر"""
    data = (request.get_json(silent=True) or {})
    level = data.get('level', 0)
    
    if not (0 <= level <= 15):
        return jsonify({'error': 'Level must be between 0 and 15'}), 400
    
    db = load_database()
    user = db['users'].get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user['server_boost_level'] = level
    save_database(db)
    
    return jsonify({
        'success': True,
        'server_boost_level': level
    })


# --- Verified tick (admin) ---
@app.route('/api/admin/users/<user_id>/verified', methods=['PUT', 'POST'])
@admin_required
def admin_set_verified(user_id):
    """Give / take the verified tick. Body: {"verified": true|false} (missing = toggle)."""
    data = request.get_json(silent=True) or {}
    db = load_database()
    user = db['users'].get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    value = bool(data['verified']) if 'verified' in data else not user_is_verified(user)
    user['verified'] = value
    user['is_verified'] = value
    db.setdefault('badge_history', {}).setdefault(user_id, []).append({
        'action': 'verified_on' if value else 'verified_off',
        'badges': ['verified'], 'by': session['user_id'], 'at': datetime.now().isoformat()
    })
    save_database(db)
    return jsonify({'success': True, 'user_id': user_id, 'verified': value})


# --- دادن چند Badge همزمان ---
@app.route('/api/admin/users/<user_id>/badges/grant', methods=['POST'])
@admin_required
def grant_badges(user_id):
    """دادن چند Badge همزمان"""
    data = (request.get_json(silent=True) or {})
    badges_to_grant = data.get('badges', [])  # لیست نام Badge ها
    
    db = load_database()
    user = db['users'].get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    granted = []
    for badge in badges_to_grant:
        if badge in BADGE_FIELDS:
            if not user.get(badge, False):
                user[badge] = True
                granted.append(badge)
    
    if granted:
        # ثبت در تاریخچه
        if 'badge_history' not in db:
            db['badge_history'] = {}
        if user_id not in db['badge_history']:
            db['badge_history'][user_id] = []
        
        db['badge_history'][user_id].append({
            'action': 'grant_multiple',
            'badges': granted,
            'by': session['user_id'],
            'at': datetime.now().isoformat()
        })
        
        save_database(db)
    
    return jsonify({
        'success': True,
        'granted': granted,
        'all_badges': {k: user.get(k, False) for k in BADGE_FIELDS}
    })


# --- گرفتن چند Badge همزمان ---
@app.route('/api/admin/users/<user_id>/badges/revoke', methods=['POST'])
@admin_required
def revoke_badges(user_id):
    """گرفتن چند Badge همزمان"""
    data = (request.get_json(silent=True) or {})
    badges_to_revoke = data.get('badges', [])  # لیست نام Badge ها
    
    db = load_database()
    user = db['users'].get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    revoked = []
    for badge in badges_to_revoke:
        if badge in BADGE_FIELDS:
            if user.get(badge, False):
                user[badge] = False
                revoked.append(badge)
    
    if revoked:
        # ثبت در تاریخچه
        if 'badge_history' not in db:
            db['badge_history'] = {}
        if user_id not in db['badge_history']:
            db['badge_history'][user_id] = []
        
        db['badge_history'][user_id].append({
            'action': 'revoke_multiple',
            'badges': revoked,
            'by': session['user_id'],
            'at': datetime.now().isoformat()
        })
        
        save_database(db)
    
    return jsonify({
        'success': True,
        'revoked': revoked,
        'all_badges': {k: user.get(k, False) for k in BADGE_FIELDS}
    })


# --- دریافت تاریخچه Badge ها ---
@app.route('/api/admin/users/<user_id>/badge-history')
@admin_required
def get_badge_history(user_id):
    """دریافت تاریخچه تغییرات Badge ها"""
    db = load_database()
    history = db.get('badge_history', {}).get(user_id, [])
    
    # تبدیل ID ادمین به نام
    enriched_history = []
    for item in history:
        admin = db['users'].get(item.get('by'), {})
        enriched_history.append({
            **item,
            'admin_name': admin.get('username', 'Unknown')
        })
    
    return jsonify(enriched_history)


# --- کاربر: تغییر HypeSquad خودش ---
@app.route('/api/profile/hypesquad', methods=['PUT'])
@login_required
def update_own_hypesquad():
    """کاربر می‌تواند HypeSquad خود را تغییر دهد"""
    data = (request.get_json(silent=True) or {})
    house = data.get('house')
    
    valid_houses = ['bravery', 'brilliance', 'balance', None]
    if house not in valid_houses:
        return jsonify({'error': 'Invalid house'}), 400
    
    db = load_database()
    user = db['users'].get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user['hypesquad_house'] = house
    save_database(db)
    
    return jsonify({
        'success': True,
        'hypesquad_house': house
    })


# --- کاربر: فعال/غیرفعال کردن is_active ---
@app.route('/api/profile/active-status', methods=['PUT'])
@login_required
def update_own_active_status():
    """کاربر می‌تواند وضعیت فعال بودن خود را تغییر دهد"""
    data = (request.get_json(silent=True) or {})
    is_active = data.get('is_active', True)
    
    db = load_database()
    user = db['users'].get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user['is_active'] = bool(is_active)
    save_database(db)
    
    return jsonify({
        'success': True,
        'is_active': user['is_active']
    })


# --- دریافت لیست کاربران با Badge خاص ---
@app.route('/api/admin/badges/<badge_type>/users')
@admin_required
def get_users_with_badge(badge_type):
    """دریافت لیست کاربرانی که یک Badge خاص دارند"""
    if badge_type not in BADGE_FIELDS:
        return jsonify({'error': 'Invalid badge type'}), 400
    
    db = load_database()
    users_with_badge = []
    
    for uid, user in db['users'].items():
        if user.get(badge_type, False):
            users_with_badge.append({
                'id': uid,
                'username': user.get('username'),
                'avatar': user.get('avatar'),
                'avatar_color': user.get('avatar_color', '#7289da'),
                'email': user.get('email')
            })
    
    return jsonify({
        'badge': badge_type,
        'count': len(users_with_badge),
        'users': users_with_badge
    })


# --- آمار Badge ها ---
@app.route('/api/admin/badges/stats')
@admin_required
def get_badge_stats():
    """آمار کلی Badge ها"""
    db = load_database()
    
    stats = {}
    for badge in BADGE_FIELDS:
        count = sum(1 for u in db['users'].values() if u.get(badge, False))
        stats[badge] = count
    
    # کاربران با بیشترین Reputation
    top_reputation = []
    sorted_users = sorted(
        [(uid, u.get('username'), u.get('reputation', 0)) for uid, u in db['users'].items()],
        key=lambda x: x[2],
        reverse=True
    )[:10]
    
    for uid, username, rep in sorted_users:
        top_reputation.append({
            'id': uid,
            'username': username,
            'reputation': rep
        })
    
    return jsonify({
        'badge_counts': stats,
        'total_users': len(db['users']),
        'top_reputation': top_reputation
    })


# --- جستجوی کاربران با Badge ---
@app.route('/api/admin/badges/search')
@admin_required
def search_users_by_badges():
    """جستجوی کاربران بر اساس Badge ها"""
    badges = request.args.getlist('badges')  # ?badges=vip&badges=verified
    match_all = request.args.get('match_all', 'false').lower() == 'true'
    
    db = load_database()
    matching_users = []
    
    for uid, user in db['users'].items():
        if match_all:
            # همه Badge ها باید وجود داشته باشند
            if all(user.get(b, False) for b in badges if b in BADGE_FIELDS):
                matching_users.append({
                    'id': uid,
                    'username': user.get('username'),
                    'avatar': user.get('avatar'),
                    'avatar_color': user.get('avatar_color', '#7289da'),
                    'badges': {b: user.get(b, False) for b in BADGE_FIELDS}
                })
        else:
            # حداقل یکی از Badge ها کافی است
            if any(user.get(b, False) for b in badges if b in BADGE_FIELDS):
                matching_users.append({
                    'id': uid,
                    'username': user.get('username'),
                    'avatar': user.get('avatar'),
                    'avatar_color': user.get('avatar_color', '#7289da'),
                    'badges': {b: user.get(b, False) for b in BADGE_FIELDS}
                })
    
    return jsonify({
        'search_criteria': badges,
        'match_all': match_all,
        'count': len(matching_users),
        'users': matching_users
    })

# ============================================
# PERSONALIZATION API
# ============================================

@app.route('/api/user/personalization', methods=['GET'])
@login_required
def get_personalization():
    db = load_database()
    user = db['users'].get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'home_logo': user.get('home_logo'),
        'home_icon': user.get('home_icon', 'fab fa-discord'),  # ← اصلاح شد
        'home_color': user.get('home_color', '#7289da'),
        'home_bg_color': user.get('home_bg_color', '#5865f2')
    })

@app.route('/api/user/personalization', methods=['POST'])
@login_required
def save_personalization():
    """ذخیره تنظیمات شخصی‌سازی کاربر"""
    data = (request.get_json(silent=True) or {})
    db = load_database()
    user = db['users'].get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # لیست کامل آیکون‌های مجاز (شامل fab, fas, far)
    valid_icons = [
        # Brand
        'fab fa-discord', 'fab fa-twitter', 'fab fa-facebook', 'fab fa-instagram', 
        'fab fa-github', 'fab fa-steam', 'fab fa-twitch', 'fab fa-youtube', 'fab fa-spotify',
        # Solid
        'fas fa-home', 'fas fa-server', 'fas fa-users', 'fas fa-comments', 
        'fas fa-envelope', 'fas fa-heart', 'fas fa-star', 'fas fa-bolt', 
        'fas fa-rocket', 'fas fa-gamepad', 'fas fa-music', 'fas fa-globe', 
        'fas fa-fire', 'fas fa-gem', 'fas fa-crown',
        # Regular
        'far fa-comment', 'far fa-envelope', 'far fa-heart', 'far fa-star'
    ]

    if 'home_logo' in data:
        user['home_logo'] = data['home_logo']
    
    if 'home_icon' in data:
        if data['home_icon'] in valid_icons:
            user['home_icon'] = data['home_icon']
        else:
            # اگر آیکون نامعتبر بود، به پیش‌فرض برگردان یا نادیده بگیر
            print(f"Invalid icon: {data['home_icon']}")
            return jsonify({'error': 'Invalid icon'}), 400

    if 'home_color' in data:
        import re
        if re.match(r'^#[0-9A-Fa-f]{6}$', data['home_color']):
            user['home_color'] = data['home_color']

    if 'home_bg_color' in data:
        import re
        if re.match(r'^#[0-9A-Fa-f]{6}$', data['home_bg_color']):
            user['home_bg_color'] = data['home_bg_color']

    save_database(db)
    return jsonify({
        'success': True,
        'home_logo': user.get('home_logo'),
        'home_icon': user.get('home_icon'),
        'home_color': user.get('home_color'),
        'home_bg_color': user.get('home_bg_color')
    })

# ============================================
# FRIENDS SETTINGS API
# ============================================

def _friends_settings_payload(db, uid):
    p = get_friends_prefs(db, uid)
    s = get_privacy(db, uid)
    return {
        'allow_friend_requests': bool(s['allow_friend_requests']),
        'show_online_status': bool(s['show_online_status']),
        'show_activity': bool(s['show_activity_status']),
        'auto_accept_mutual': bool(p['auto_accept_mutual']),
        'request_notifications': bool(p['request_notifications']),
        'show_shared_servers': bool(p['show_shared_servers']),
    }

@app.route('/api/friends/settings', methods=['GET'])
@login_required
def get_friends_settings():
    db = load_database()
    uid = session['user_id']
    if uid not in db['users']:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(_friends_settings_payload(db, uid))

@app.route('/api/friends/settings', methods=['POST', 'PUT'])
@login_required
def update_friends_settings():
    data = request.get_json(silent=True) or {}
    db = load_database()
    uid = session['user_id']
    if uid not in db['users']:
        return jsonify({'error': 'User not found'}), 404

    priv = dict(get_privacy(db, uid))
    key_map = {
        'allow_friend_requests': 'allow_friend_requests',
        'show_online_status': 'show_online_status',
        'show_activity': 'show_activity_status',
        'show_activity_status': 'show_activity_status',
    }
    for src, dst in key_map.items():
        if src in data:
            priv[dst] = bool(data[src])
    db.setdefault('privacy_settings', {})[uid] = priv

    prefs = dict(get_friends_prefs(db, uid))
    for k in FRIENDS_PREF_DEFAULTS:
        if k in data:
            prefs[k] = bool(data[k])
    db.setdefault('friends_settings', {})[uid] = prefs

    save_database(db)
    return jsonify({'success': True, 'settings': _friends_settings_payload(db, uid)})

@app.route('/api/user/personalization/reset', methods=['POST'])
@login_required
def reset_personalization():
    """بازنشانی تنظیمات شخصی‌سازی به حالت پیش‌فرض"""
    db = load_database()
    user = db['users'].get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user['home_logo'] = None
    user['home_icon'] = 'fa-discord'
    user['home_color'] = '#7289da'
    user['home_bg_color'] = '#5865f2'
    
    save_database(db)
    
    return jsonify({
        'success': True,
        'message': 'Personalization reset to defaults'
    })

# ============================================
# INVITE LINK PAGE - HTML Templates
# ============================================

INVITE_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>دعوت به {{ server.name }}</title>
    <link rel="stylesheet" href="https://lib.arvancloud.ir/font-awesome/6.3.0/css/all.min.css">
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect fill='%235865F2' width='24' height='24' rx='5'/%3E%3Cpath fill='white' d='M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z'/%3E%3C/svg%3E">

    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .invite-container {
            width: 100%;
            max-width: 420px;
        }
        .invite-card {
            background: #2c2f33;
            border-radius: 16px;
            padding: 40px 32px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4);
            text-align: center;
        }
        .server-banner {
            width: 100%;
            height: 100px;
            border-radius: 12px 12px 0 0;
            margin: -40px -32px 24px;
            background: linear-gradient(135deg, #5865f2, #7289da);
            overflow: hidden;
        }
        .server-banner img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        .server-icon {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            margin: -50px auto 16px;
            background: linear-gradient(135deg, #5865f2, #7289da);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 48px;
            border: 6px solid #2c2f33;
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
        }
        .server-icon img {
            width: 100%;
            height: 100%;
            border-radius: 50%;
            object-fit: cover;
        }
        .server-name {
            font-size: 26px;
            font-weight: 700;
            color: #fff;
            margin-bottom: 8px;
        }
        .server-meta {
            color: #b9bbbe;
            font-size: 14px;
            margin-bottom: 16px;
        }
        .server-meta i {
            margin-left: 4px;
            color: #72767d;
        }
        .server-description {
            color: #dcddde;
            font-size: 15px;
            line-height: 1.6;
            margin-bottom: 24px;
            padding: 16px;
            background: #23272a;
            border-radius: 8px;
        }
        .server-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            justify-content: center;
            margin-bottom: 24px;
        }
        .tag {
            background: #4f545c;
            color: #dcddde;
            padding: 6px 12px;
            border-radius: 16px;
            font-size: 12px;
        }
        .alert-box {
            padding: 14px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .alert-box i {
            font-size: 18px;
        }
        .alert-error {
            background: rgba(240, 71, 71, 0.15);
            border: 1px solid #ed4245;
            color: #ed4245;
        }
        .alert-success {
            background: rgba(67, 181, 129, 0.15);
            border: 1px solid #43b581;
            color: #43b581;
        }
        .alert-warning {
            background: rgba(250, 166, 26, 0.15);
            border: 1px solid #faa61a;
            color: #faa61a;
        }
        .join-btn {
            width: 100%;
            padding: 14px 24px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }
        .join-btn-primary {
            background: linear-gradient(135deg, #5865f2, #4752c4);
            color: white;
        }
        .join-btn-primary:hover {
            background: linear-gradient(135deg, #4752c4, #3c45a5);
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(88, 101, 242, 0.4);
        }
        .join-btn:disabled {
            background: #4f545c;
            color: #72767d;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        .login-prompt {
            color: #b9bbbe;
            font-size: 14px;
            margin-top: 16px;
        }
        .login-prompt a {
            color: #00aff4;
            text-decoration: none;
            font-weight: 600;
        }
        .login-prompt a:hover {
            text-decoration: underline;
        }
        .footer-text {
            color: #72767d;
            font-size: 12px;
            margin-top: 24px;
        }
        .invite-code {
            font-family: monospace;
            background: #23272a;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            color: #72767d;
        }
    </style>
</head>
<body>
    <div class="invite-container">
        <div class="invite-card">
            {% if server.banner %}
            <div class="server-banner">
                <img src="{{ server.banner }}" alt="Banner">
            </div>
            {% else %}
            <div class="server-banner"></div>
            {% endif %}
            
            <h1 class="server-name">{{ server.name }}</h1>
            <div class="server-meta">
                <i class="fas fa-users"></i>
                {{ server.member_count }} عضو
            </div>
            
            {% if server.description %}
            <div class="server-description">{{ server.description }}</div>
            {% endif %}
            
            {% if server.tags %}
            <div class="server-tags">
                {% for tag in server.tags %}
                <span class="tag">{{ tag }}</span>
                {% endfor %}
            </div>
            {% endif %}
            
            {% if error %}
            <div class="alert-box alert-error">
                <i class="fas fa-exclamation-circle"></i>
                {{ error }}
            </div>
            {% endif %}
            
            {% if success %}
            <div class="alert-box alert-success">
                <i class="fas fa-check-circle"></i>
                {{ success }}
            </div>
            {% endif %}
            
            {% if already_member %}
            <div class="alert-box alert-warning">
                <i class="fas fa-info-circle"></i>
                شما از قبل عضو این سرور هستید!
            </div>
            {% endif %}
            
            {% if is_logged_in %}
            <form action="/invite/{{ invite_code }}/join" method="POST">
                <button type="submit" class="join-btn join-btn-primary" 
                        {% if already_member or is_banned %}disabled{% endif %}>
                    {% if already_member %}
                    <i class="fas fa-check"></i>
                    عضو هستید
                    {% elif is_banned %}
                    <i class="fas fa-ban"></i>
                    بن شده‌اید
                    {% else %}
                    <i class="fas fa-sign-in-alt"></i>
                    عضویت در سرور
                    {% endif %}
                </button>
            </form>
            {% else %}
            <a href="/login?next=/invite/{{ invite_code }}" class="join-btn join-btn-primary" 
               style="text-decoration: none;">
                <i class="fas fa-user"></i>
                ورود برای عضویت
            </a>
            <p class="login-prompt">
                حساب کاربری ندارید؟ <a href="/register">ثبت‌نام کنید</a>
            </p>
            {% endif %}
            
            <p class="footer-text">
                کد دعوت: <span class="invite-code">{{ invite_code }}</span>
            </p>
        </div>
    </div>
</body>
</html>
"""

EXPIRED_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>دعوت‌نامه منقضی شده</title>
     <link rel="stylesheet" href="https://lib.arvancloud.ir/font-awesome/6.3.0/css/all.min.css">
        <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect fill='%235865F2' width='24' height='24' rx='5'/%3E%3Cpath fill='white' d='M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z'/%3E%3C/svg%3E">

    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .expired-container {
            text-align: center;
            max-width: 400px;
        }
        .icon-wrapper {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background: rgba(240, 71, 71, 0.15);
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 24px;
        }
        .icon-wrapper i {
            font-size: 56px;
            color: #ed4245;
        }
        h1 {
            color: #fff;
            font-size: 28px;
            margin-bottom: 16px;
        }
        p {
            color: #b9bbbe;
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 32px;
        }
        .home-btn {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            padding: 14px 32px;
            background: linear-gradient(135deg, #5865f2, #4752c4);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            font-size: 16px;
            transition: all 0.2s ease;
        }
        .home-btn:hover {
            background: linear-gradient(135deg, #4752c4, #3c45a5);
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(88, 101, 242, 0.4);
        }
    </style>
</head>
<body>
    <div class="expired-container">
        <div class="icon-wrapper">
            <i class="fas fa-link-slash"></i>
        </div>
        <h1>دعوت‌نامه نامعتبر است</h1>
        <p>{{ error_message }}</p>
        <a href="/" class="home-btn">
            <i class="fas fa-home"></i>
            بازگشت به صفحه اصلی
        </a>
    </div>
</body>
</html>
"""

# ============================================
# INVITE LINK PAGE ROUTES
# ============================================

@app.route('/join/<invite_code>')
def invite_link_page(invite_code):
    """
    نمایش صفحه لینک دعوت سرور
    """
    db = load_database()
    
    # بررسی وجود دعوت‌نامه
    invite = db['invites'].get(invite_code)
    if not invite:
        return render_template_string(
            EXPIRED_PAGE_TEMPLATE,
            error_message="این دعوت‌نامه وجود ندارد یا حذف شده است."
        )
    
    server_id = invite['server_id']
    server = db['servers'].get(server_id)
    if not server:
        return render_template_string(
            EXPIRED_PAGE_TEMPLATE,
            error_message="سرور مورد نظر یافت نشد."
        )
    
    # بررسی انقضای دعوت‌نامه
    if invite.get('expires_at'):
        try:
            expires = datetime.fromisoformat(invite['expires_at'])
            if datetime.now() > expires:
                return render_template_string(
                    EXPIRED_PAGE_TEMPLATE,
                    error_message="این دعوت‌نامه منقضی شده است."
                )
        except:
            pass
    
    # بررسی حداکثر استفاده
    if invite.get('max_uses', 0) > 0 and invite.get('uses', 0) >= invite['max_uses']:
        return render_template_string(
            EXPIRED_PAGE_TEMPLATE,
            error_message="این دعوت‌نامه به حداکثر تعداد استفاده رسیده است."
        )
    
    # بررسی عضویت کاربر
    is_logged_in = 'user_id' in session
    user_id = session.get('user_id')
    already_member = False
    is_banned = False
    ban_reason = None
    
    if is_logged_in:
        if user_id in server.get('members', []):
            already_member = True
        
        # بررسی بن شدن
        server_bans = db['bans'].get(server_id, {})
        if user_id in server_bans:
            is_banned = True
            ban_reason = server_bans[user_id].get('reason', 'بدون دلیل')
    
    # اطلاعات سرور
    server_info = {
        'id': server_id,
        'name': server.get('name', 'سرور ناشناس'),
        'description': server.get('description', server.get('bio', '')),
        'icon': server.get('icon', '🌐'),
        'banner': server.get('banner'),
        'member_count': len(server.get('members', [])),
        'is_private': server.get('is_private', False),
        'tags': server.get('tags', [])
    }
    
    return render_template_string(
        INVITE_PAGE_TEMPLATE,
        invite_code=invite_code,
        server=server_info,
        is_logged_in=is_logged_in,
        already_member=already_member,
        is_banned=is_banned,
        error=None,
        success=None
    )


@app.route('/join/<invite_code>/join', methods=['POST'])
def join_via_invite_link(invite_code):
    """
    عضویت در سرور از طریق لینک دعوت
    """
    # بررسی لاگین
    if 'user_id' not in session:
        return redirect(url_for('login', next=f'/invite/{invite_code}'))
    
    db = load_database()
    
    # بررسی وجود دعوت‌نامه
    invite = db['invites'].get(invite_code)
    if not invite:
        return render_template_string(
            EXPIRED_PAGE_TEMPLATE,
            error_message="این دعوت‌نامه وجود ندارد."
        ), 404
    
    server_id = invite['server_id']
    server = db['servers'].get(server_id)
    if not server:
        return render_template_string(
            EXPIRED_PAGE_TEMPLATE,
            error_message="سرور مورد نظر یافت نشد."
        ), 404
    
    # بررسی انقضا
    if invite.get('expires_at'):
        try:
            expires = datetime.fromisoformat(invite['expires_at'])
            if datetime.now() > expires:
                return render_template_string(
                    EXPIRED_PAGE_TEMPLATE,
                    error_message="این دعوت‌نامه منقضی شده است."
                ), 400
        except:
            pass
    
    # بررسی حداکثر استفاده
    if invite.get('max_uses', 0) > 0 and invite.get('uses', 0) >= invite['max_uses']:
        return render_template_string(
            EXPIRED_PAGE_TEMPLATE,
            error_message="این دعوت‌نامه به حداکثر تعداد استفاده رسیده است."
        ), 400
    
    user_id = session['user_id']
    
    # بررسی عضویت قبلی
    if user_id in server.get('members', []):
        return render_template_string(
            INVITE_PAGE_TEMPLATE,
            invite_code=invite_code,
            server={
                'id': server_id,
                'name': server.get('name', 'سرور ناشناس'),
                'description': server.get('description', ''),
                'icon': server.get('icon', '🌐'),
                'banner': server.get('banner'),
                'member_count': len(server.get('members', [])),
                'tags': server.get('tags', [])
            },
            is_logged_in=True,
            already_member=True,
            is_banned=False,
            error=None,
            success=None
        )
    
    # بررسی بن شدن
    server_bans = db['bans'].get(server_id, {})
    if user_id in server_bans:
        ban_reason = server_bans[user_id].get('reason', 'بدون دلیل')
        return render_template_string(
            INVITE_PAGE_TEMPLATE,
            invite_code=invite_code,
            server={
                'id': server_id,
                'name': server.get('name', 'سرور ناشناس'),
                'description': server.get('description', ''),
                'icon': server.get('icon', '🌐'),
                'banner': server.get('banner'),
                'member_count': len(server.get('members', [])),
                'tags': server.get('tags', [])
            },
            is_logged_in=True,
            already_member=False,
            is_banned=True,
            error=f"شما از این سرور بن شده‌اید. دلیل: {ban_reason}",
            success=None
        )
    
    # افزودن عضو جدید
    server.setdefault('members', []).append(user_id)
    server.setdefault('user_roles', {})[user_id] = ['member']
    
    # افزایش تعداد استفاده
    invite['uses'] = invite.get('uses', 0) + 1
    
    # ارسال پیام خوش‌آمدگویی
    send_welcome_message(db, server_id, user_id)
    
    save_database(db)
    
    # نمایش صفحه موفقیت
    return render_template_string(
        INVITE_PAGE_TEMPLATE,
        invite_code=invite_code,
        server={
            'id': server_id,
            'name': server.get('name', 'سرور ناشناس'),
            'description': server.get('description', ''),
            'icon': server.get('icon', '🌐'),
            'banner': server.get('banner'),
            'member_count': len(server.get('members', [])),
            'tags': server.get('tags', [])
        },
        is_logged_in=True,
        already_member=True,
        is_banned=False,
        error=None,
        success="تبریک! شما با موفقیت به سرور پیوستید."
    )


@app.route('/join/<invite_code>/preview')
def invite_preview(invite_code):
    """
    پیش‌نمایش اطلاعات سرور (API JSON)
    """
    db = load_database()
    
    invite = db['invites'].get(invite_code)
    if not invite:
        return jsonify({'error': 'Invite not found'}), 404
    
    server_id = invite['server_id']
    server = db['servers'].get(server_id)
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    # بررسی انقضا
    is_expired = False
    if invite.get('expires_at'):
        try:
            expires = datetime.fromisoformat(invite['expires_at'])
            if datetime.now() > expires:
                is_expired = True
        except:
            pass
    
    # بررسی حداکثر استفاده
    max_reached = False
    if invite.get('max_uses', 0) > 0 and invite.get('uses', 0) >= invite['max_uses']:
        max_reached = True
    
    return jsonify({
        'valid': not is_expired and not max_reached,
        'expired': is_expired,
        'max_reached': max_reached,
        'server': {
            'id': server_id,
            'name': server.get('name'),
            'description': server.get('description', ''),
            'icon': server.get('icon'),
            'banner': server.get('banner'),
            'member_count': len(server.get('members', [])),
            'tags': server.get('tags', [])
        }
    })
# ============================================
# IMPORT DISCORD SERVER API - ذخیره در JSON
# ============================================
@app.route('/api/import-discord', methods=['POST'])
@login_required
def import_discord_server():
    """
    دریافت درخواست ایمپورت سرور دسکورد و ذخیره آن در فایل JSON
    """
    data = (request.get_json(silent=True) or {})
    server_name = data.get('server_name', '').strip()
    discord_invite = data.get('discord_invite', '').strip()
    
    if not discord_invite:
        return jsonify({'error': 'Discord Invite Link or Server ID is required'}), 400

    db = load_database()
    current_user = db['users'].get(session['user_id'], {})
    username = current_user.get('username', 'Unknown')
    user_id = session['user_id']
    
    # بارگذاری درخواست‌های موجود
    requests_list = load_import_requests()
    
    # ساخت درخواست جدید
    new_request = {
        'id': str(uuid.uuid4().hex[:12]),
        'user_id': user_id,
        'username': username,
        'server_name': server_name if server_name else 'Unnamed Server',
        'discord_invite': discord_invite,
        'status': 'pending',  # pending, approved, rejected
        'created_at': datetime.now().isoformat(),
        'approved_by': None,
        'approved_at': None
    }
    
    # اضافه کردن به لیست
    requests_list.append(new_request)
    
    # ذخیره در فایل JSON
    save_import_requests(requests_list)
    
    return jsonify({
        'success': True,
        'message': 'Import request submitted successfully',
        'request_id': new_request['id']
    })

# ============================================
# روت‌های ادمین برای مدیریت درخواست‌ها
# ============================================

@app.route('/api/admin/import-requests', methods=['GET'])
@login_required  # تغییر از @admin_required به @login_required
def get_import_requests():
    """
    دریافت لیست درخواست‌های ایمپورت
    - ادمین‌ها تمام درخواست‌ها را می‌بینند
    - کاربران عادی فقط درخواست‌های خودشان را می‌بینند
    """
    # بارگذاری درخواست‌ها
    requests_list = load_import_requests()
    
    # بارگذاری دیتابیس برای بررسی نقش کاربر
    db = load_database()
    current_user = db['users'].get(session['user_id'], {})
    is_admin = current_user.get('is_admin', False)
    
    # اگر کاربر ادمین است، همه درخواست‌ها را برگردان
    if is_admin:
        return jsonify({
            'success': True,
            'requests': requests_list
        })
    
    # اگر کاربر عادی است، فقط درخواست‌های خودش را برگردان
    user_requests = [req for req in requests_list if req.get('user_id') == session['user_id']]
    
    return jsonify({
        'success': True,
        'requests': user_requests
    })
@app.route('/api/admin/import-requests/<request_id>/approve', methods=['POST'])
@admin_required
def approve_import_request(request_id):
    """تأیید یک درخواست ایمپورت"""
    requests_list = load_import_requests()
    request_found = None
    request_index = None
    
    for i, req in enumerate(requests_list):
        if req['id'] == request_id:
            request_found = req
            request_index = i
            break
            
    if not request_found:
        return jsonify({'error': 'Request not found'}), 404
        
    if request_found['status'] != 'pending':
        return jsonify({'error': 'Request already processed'}), 400
        
    # به‌روزرسانی وضعیت
    requests_list[request_index]['status'] = 'approved'
    requests_list[request_index]['approved_by'] = session['user_id']
    requests_list[request_index]['approved_at'] = datetime.now().isoformat()
    
    save_import_requests(requests_list)
    
    return jsonify({
        'success': True,
        'message': 'Import request approved'
    })

@app.route('/api/admin/import-requests/<request_id>/reject', methods=['POST'])
@admin_required
def reject_import_request(request_id):
    """رد یک درخواست ایمپورت"""
    requests_list = load_import_requests()
    request_found = None
    request_index = None
    
    for i, req in enumerate(requests_list):
        if req['id'] == request_id:
            request_found = req
            request_index = i
            break
            
    if not request_found:
        return jsonify({'error': 'Request not found'}), 404
        
    if request_found['status'] != 'pending':
        return jsonify({'error': 'Request already processed'}), 400
        
    # به‌روزرسانی وضعیت
    requests_list[request_index]['status'] = 'rejected'
    requests_list[request_index]['approved_by'] = session['user_id']
    requests_list[request_index]['approved_at'] = datetime.now().isoformat()
    
    save_import_requests(requests_list)
    
    return jsonify({
        'success': True,
        'message': 'Import request rejected'
    })

# اضافه کردن به انتهای فایل اول (app.py) - قبل از if __name__ == '__main__'

@app.route('/api/external/users', methods=['GET'])
def get_external_users():
    """API خارجی برای دریافت لیست کاربران (برای لانچر)"""
    # بررسی توکن امنیتی
    auth_token = request.headers.get('X-Auth-Token')
    if auth_token != 'YOUR_SECRET_SHARED_TOKEN':
        return jsonify({'error': 'Unauthorized'}), 401
    
    db = load_database()
    users = []
    for uid, user in db['users'].items():
        users.append({
            'id': uid,
            'username': user.get('username'),
            'email': user.get('email'),
            'avatar': user.get('avatar'),
            'avatar_color': user.get('avatar_color', '#7289da'),
            'is_premium': user.get('is_premium', False), 'verified': user_is_verified(user),
            'created_at': user.get('created_at')
        })
    
    return jsonify({'users': users, 'total': len(users)})

@app.route('/api/external/user/<user_id>', methods=['GET'])
def get_external_user(user_id):
    """API خارجی برای دریافت اطلاعات یک کاربر خاص"""
    auth_token = request.headers.get('X-Auth-Token')
    if auth_token != 'YOUR_SECRET_SHARED_TOKEN':
        return jsonify({'error': 'Unauthorized'}), 401
    
    db = load_database()
    user = db['users'].get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'id': user_id,
        'username': user.get('username'),
        'email': user.get('email'),
        'avatar': user.get('avatar'),
        'avatar_color': user.get('avatar_color', '#7289da'),
        'is_premium': user.get('is_premium', False), 'verified': user_is_verified(user),
        'reputation': user.get('reputation', 0),
        'badges': {k: user.get(k, False) for k in ['vip', 'staff', 'developer', 'verified', 'nitro', 'partner']}
    })


# =============================================================================
#  BotShop (Bot Store)
#  - The site admin uploads bots as .js files (BotShop tab -> Admin).
#  - Server owners / members with the "Manage Server" permission install a bot on their own server
#    (all channels, or only the channels they pick) and members use its commands in chat.
#  - Bots run on the server inside Node.js (isolated worker + vm sandbox, see data/botshop/runner.js).
#    Node.js must be installed (https://nodejs.org). The bot file format is explained in the Admin tab.
# =============================================================================
import re, shutil, subprocess, time

BOTSHOP_DIR = os.path.join(DATA_DIR, 'botshop')
BOTSHOP_BOTS_DIR = os.path.join(BOTSHOP_DIR, 'bots')          # <bot id>.js
BOTSHOP_STORAGE_DIR = os.path.join(BOTSHOP_DIR, 'storage')    # <install id>.json (per server data of a bot)
BOTSHOP_RUNNER_FILE = os.path.join(BOTSHOP_DIR, 'runner.js')
BOT_CODE_MAX = 200_000          # bytes per bot file
BOT_MSGS_PER_MINUTE = 30        # messages one installed bot may send per minute
for _d in (BOTSHOP_DIR, BOTSHOP_BOTS_DIR, BOTSHOP_STORAGE_DIR):
    os.makedirs(_d, exist_ok=True)

BOTSHOP_RUNNER_SOURCE = r''''use strict';
/* BotShop runner: runs uploaded .js bots in isolated worker threads + vm contexts.
   Protocol (one JSON object per line):
     in : {id, op: 'describe' | 'event', code, payload}      (payload = JSON string, only for 'event')
     out: {id, ok, ...result}                                  */
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const vm = require('vm');

const TIMEOUT_MS = 5000;     // hard limit per event (the worker is killed after this)
const MAX_WORKERS = 6;       // events running at the same time

// Runs INSIDE the bot's vm context. Only strings cross the boundary (no host objects, so nothing to escape through).
const PRELUDE = `(function () {
  'use strict';
  const commands = Object.create(null), aliasMap = Object.create(null);
  const handlers = { message: [], memberJoin: [] };
  const logs = [];
  const NAME_RE = /^[a-z0-9_-]{1,32}$/;
  const bot = {
    prefix: null,
    command(name, a, b) {
      let opts = {}, fn = b;
      if (typeof a === 'function') fn = a; else if (a && typeof a === 'object') opts = a;
      if (typeof name !== 'string' || !NAME_RE.test(name.toLowerCase())) throw new Error('Invalid command name: ' + name);
      if (typeof fn !== 'function') throw new Error('Command "' + name + '" needs a handler function');
      name = name.toLowerCase();
      const aliases = (Array.isArray(opts.aliases) ? opts.aliases : []).map(x => String(x).toLowerCase()).filter(x => NAME_RE.test(x)).slice(0, 5);
      commands[name] = { name, description: String(opts.description || '').slice(0, 200), usage: String(opts.usage || '').slice(0, 200), aliases, adminOnly: !!opts.adminOnly, fn };
      for (const al of aliases) aliasMap[al] = name;
    },
    on(ev, fn) {
      if (!handlers[ev]) throw new Error('Unknown event "' + ev + '" (use "message" or "memberJoin")');
      if (typeof fn !== 'function') throw new Error('Event handler must be a function');
      handlers[ev].push(fn);
    }
  };
  globalThis.bot = bot;
  const fmt = (a) => a.map(x => { try { return typeof x === 'string' ? x : JSON.stringify(x); } catch (e) { return String(x); } }).join(' ').slice(0, 300);
  globalThis.console = { log: (...a) => { if (logs.length < 30) logs.push(fmt(a)); }, warn: (...a) => { if (logs.length < 30) logs.push(fmt(a)); }, error: (...a) => { if (logs.length < 30) logs.push(fmt(a)); } };

  function builtinHelp() {
    return { name: 'help', description: 'Show the commands of this bot', usage: '', aliases: [], adminOnly: false, builtin: true,
      fn: (ctx) => {
        const list = Object.keys(commands).map(n => commands[n]);
        if (!commands.help) list.push({ name: 'help', description: 'Show the commands of this bot', usage: '' });
        const lines = list.map(c => '\`' + ctx.prefix + c.name + (c.usage ? ' ' + c.usage : '') + '\`' + (c.description ? ' - ' + c.description : '') + (c.adminOnly ? ' (admin)' : ''));
        return ctx.reply('**' + ctx.bot.name + ' commands**\\n' + lines.join('\\n'));
      } };
  }

  function describe() {
    const list = Object.keys(commands).map(n => { const c = commands[n]; return { name: c.name, description: c.description, usage: c.usage, aliases: c.aliases, adminOnly: c.adminOnly }; });
    if (!commands.help) list.push({ name: 'help', description: 'Show the commands of this bot', usage: '', aliases: [], adminOnly: false, builtin: true });
    const events = Object.keys(handlers).filter(k => handlers[k].length);
    return JSON.stringify({ commands: list, events, prefix: typeof bot.prefix === 'string' ? bot.prefix.slice(0, 3) : null });
  }

  async function dispatch(json) {
    const p = JSON.parse(json);
    const actions = [], errors = [];
    const store = (p.storage && typeof p.storage === 'object') ? p.storage : {};
    let sends = 0, channelsMade = 0, adminOps = 0;
    const S = (v, n) => String(v === undefined || v === null ? '' : v).slice(0, n);
    const asObj = (x) => (x && typeof x === 'object') ? x : {};
    const admin = (op, args) => { if (adminOps >= 10 || actions.length >= 20) return; adminOps++; actions.push(Object.assign({ type: 'admin', op: op }, args)); };
    const only = (x, spec) => { const out = {}; const src = asObj(x); for (const k of Object.keys(spec)) { if (src[k] !== undefined) out[k] = spec[k](src[k]); } return out; };
    const tStr = (n) => (v) => (v === null ? '' : S(v, n));
    const tBool = (v) => !!v;
    const tNum = (v) => Number(v) || 0;
    const tPerms = (v) => (Array.isArray(v) ? v : []).slice(0, 20).map((s) => S(s, 30));
    const clip = (t) => String(t === undefined || t === null ? '' : t).slice(0, 2000);
    const ctx = {
      event: p.event, prefix: p.prefix, bot: p.bot, user: p.user, channel: p.channel, server: p.server, message: p.message,
      command: null, args: [], rawArgs: '',
      storage: {
        get: (k) => store[String(k)],
        set: (k, v) => { store[String(k)] = v; },
        delete: (k) => { delete store[String(k)]; },
        list: () => Object.keys(store)
      },
      send(text, channelId) { if (sends++ < 5 && clip(text).trim()) actions.push({ type: 'send', content: clip(text), channel_id: channelId || null }); },
      reply(text) { if (sends++ < 5 && clip(text).trim()) actions.push({ type: 'send', content: clip(text), reply_to: p.message ? p.message.id : null }); },
      react(emoji) { if (p.message && actions.length < 20) actions.push({ type: 'react', message_id: p.message.id, emoji: String(emoji).slice(0, 16) }); },
      createChannel(name, opts) {
        const n = String(name === undefined || name === null ? '' : name).trim();
        if (!n || channelsMade >= 3) return;
        channelsMade++;
        const o = (opts && typeof opts === 'object') ? opts : {};
        actions.push({ type: 'createChannel', name: n.slice(0, 50), channel_type: o.type === 'voice' ? 'voice' : 'text',
          category: (o.category === undefined || o.category === null) ? null : String(o.category).slice(0, 50),
          description: String(o.description || '').slice(0, 500), private: !!o.private,
          message: o.message ? clip(o.message) : null });
      },
      editChannel(ref, opts) { admin('editChannel', Object.assign({ ref: S(ref, 50) }, only(opts, { name: tStr(50), description: tStr(500), category: tStr(50), slowmode: tNum, nsfw: tBool, private: tBool, readOnly: tBool }))); },
      deleteChannel(ref) { admin('deleteChannel', { ref: S(ref, 50) }); },
      createCategory(name) { admin('createCategory', { name: S(name, 50) }); },
      renameCategory(ref, name) { admin('renameCategory', { ref: S(ref, 50), name: S(name, 50) }); },
      deleteCategory(ref) { admin('deleteCategory', { ref: S(ref, 50) }); },
      createRole(name, opts) { admin('createRole', Object.assign({ name: S(name, 50) }, only(opts, { color: tStr(9), hoist: tBool, permissions: tPerms }))); },
      editRole(ref, opts) { admin('editRole', Object.assign({ ref: S(ref, 50) }, only(opts, { name: tStr(50), color: tStr(9), hoist: tBool, permissions: tPerms }))); },
      deleteRole(ref) { admin('deleteRole', { ref: S(ref, 50) }); },
      giveRole(user, role) { admin('giveRole', { user: S(user, 60), role: S(role, 50) }); },
      removeRole(user, role) { admin('removeRole', { user: S(user, 60), role: S(role, 50) }); },
      kick(user, reason) { admin('kick', { user: S(user, 60), reason: S(reason, 200) }); },
      ban(user, reason) { admin('ban', { user: S(user, 60), reason: S(reason, 200) }); },
      unban(user) { admin('unban', { user: S(user, 60) }); },
      mute(user, minutes, reason) { admin('mute', { user: S(user, 60), minutes: Number(minutes) || 60, reason: S(reason, 200) }); },
      unmute(user) { admin('unmute', { user: S(user, 60) }); },
      verify(user) { admin('verify', { user: S(user, 60) }); },
      unverify(user) { admin('unverify', { user: S(user, 60) }); },
      editServer(opts) { admin('editServer', only(opts, { name: tStr(100), description: tStr(500) })); },
      deleteMessage(id) { admin('deleteMessage', { message_id: S(id, 40) }); },
      purge(count) { admin('purge', { count: Math.max(1, Math.min(100, Number(count) || 1)) }); },
      createTicket(name, opts) {
        const o = asObj(opts);
        if (actions.some((a) => a.type === 'ticket' && a.op === 'create')) return;
        actions.push({ type: 'ticket', op: 'create', name: S(name, 50), category: (o.category === undefined || o.category === null) ? null : S(o.category, 50),
          subject: S(o.subject, 200), message: o.message ? clip(o.message) : null });
      },
      closeTicket(ref, opts) { if (actions.length < 20) actions.push({ type: 'ticket', op: 'close', ref: (ref === undefined || ref === null) ? null : S(ref, 50), del: !!asObj(opts).delete }); },
      reopenTicket(ref) { if (actions.length < 20) actions.push({ type: 'ticket', op: 'reopen', ref: (ref === undefined || ref === null) ? null : S(ref, 50) }); },
      ticketAddMember(user, ref) { if (actions.length < 20) actions.push({ type: 'ticket', op: 'add', user: S(user, 60), ref: (ref === undefined || ref === null) ? null : S(ref, 50) }); },
      ticketRemoveMember(user, ref) { if (actions.length < 20) actions.push({ type: 'ticket', op: 'remove', user: S(user, 60), ref: (ref === undefined || ref === null) ? null : S(ref, 50) }); },
      giveCoins(user, amount) {
        const amt = Math.floor(Number(amount));
        if (p.event !== 'message' || !(amt > 0) || actions.length >= 20) return;
        actions.push({ type: 'coins', to: S(user, 60), amount: amt });
      },
      findUser(text) {
        const t = S(text, 60).replace(/[<>@!]/g, '').trim().toLowerCase();
        const list = (p.server && p.server.members) || [];
        return list.find((m) => String(m.id).toLowerCase() === t) || list.find((m) => String(m.username).toLowerCase() === t) || null;
      }
    };
    const run = async (fn) => { try { await fn(ctx, ctx.args); } catch (e) { errors.push(String(e && e.message || e).slice(0, 300)); } };

    if (p.event === 'message') {
      const content = (p.message && p.message.content) || '';
      if (p.prefix && content.startsWith(p.prefix)) {
        const m = content.slice(p.prefix.length).match(/^(\\S+)(?:\\s+([\\s\\S]*))?$/);
        if (m) {
          const nm = m[1].toLowerCase();
          let cmd = commands[nm] || commands[aliasMap[nm]];
          if (!cmd && nm === 'help') cmd = builtinHelp();
          if (cmd) {
            ctx.command = cmd.name; ctx.rawArgs = (m[2] || '').trim(); ctx.args = ctx.rawArgs ? ctx.rawArgs.split(/\\s+/) : [];
            if (cmd.adminOnly && !(p.user && p.user.canManage)) ctx.reply('You need the Manage Server permission to use this command.');
            else await run(cmd.fn);
          }
        }
      }
      for (const h of handlers.message) await run(h);
    } else if (p.event === 'memberJoin') {
      for (const h of handlers.memberJoin) await run(h);
    }
    let storageJson = JSON.stringify(store);
    if (storageJson.length > 100000) { errors.push('Storage is over 100 KB, changes were not saved'); storageJson = null; }
    return JSON.stringify({ actions, storage: storageJson === null ? null : store, logs, errors });
  }
  return { describe, dispatch };
})()`;

async function runInSandbox(req) {
  const ctx = vm.createContext(Object.create(null), { codeGeneration: { strings: false, wasm: false } });
  const api = new vm.Script(PRELUDE, { filename: 'botshop-prelude.js' }).runInContext(ctx, { timeout: 1000 });
  try {
    new vm.Script(String(req.code), { filename: 'bot.js' }).runInContext(ctx, { timeout: 1000 });
  } catch (e) {
    return { id: req.id, ok: false, error: 'Bot file error: ' + String(e && e.message || e).slice(0, 300) };
  }
  if (req.op === 'describe') return Object.assign({ id: req.id, ok: true }, JSON.parse(await api.describe()));
  const out = JSON.parse(await api.dispatch(String(req.payload)));
  return Object.assign({ id: req.id, ok: true }, out);
}

if (isMainThread) {
  const rl = require('readline').createInterface({ input: process.stdin });
  const queue = []; let running = 0;
  const send = (o) => process.stdout.write(JSON.stringify(o) + '\n');

  function pump() {
    while (running < MAX_WORKERS && queue.length) {
      const req = queue.shift(); running++;
      let done = false;
      const finish = (res) => { if (done) return; done = true; clearTimeout(timer); running--; send(res); try { w.terminate(); } catch (e) {} pump(); };
      const w = new Worker(__filename, { workerData: req, resourceLimits: { maxOldGenerationSizeMb: 64, maxYoungGenerationSizeMb: 16 } });
      const timer = setTimeout(() => finish({ id: req.id, ok: false, error: 'Bot took longer than ' + (TIMEOUT_MS / 1000) + 's and was stopped' }), TIMEOUT_MS);
      w.on('message', finish);
      w.on('error', (e) => finish({ id: req.id, ok: false, error: 'Bot crashed: ' + String(e && e.message || e).slice(0, 200) }));
      w.on('exit', () => finish({ id: req.id, ok: false, error: 'Bot stopped unexpectedly' }));
    }
  }
  rl.on('line', (line) => {
    let req; try { req = JSON.parse(line); } catch (e) { return; }
    if (req.op === 'ping') return send({ id: req.id, ok: true, node: process.version });
    queue.push(req); pump();
  });
  rl.on('close', () => process.exit(0));
} else {
  runInSandbox(workerData)
    .then((r) => parentPort.postMessage(r))
    .catch((e) => parentPort.postMessage({ id: workerData.id, ok: false, error: String(e && e.message || e).slice(0, 300) }));
}
'''

BOTSHOP_SAMPLE_BOTS = [
r'''// @name: Utility Bot
// @icon: 🛠️
// @color: #5865f2
// @author: BotShop
// @version: 1.0.0
// @description: Everyday commands: ping, roll, coinflip, 8ball, choose, serverinfo and userinfo.
bot.prefix = '!';

const rand = (n) => Math.floor(Math.random() * n);

bot.command('ping', { description: 'Check that the bot is alive' }, (ctx) => ctx.reply('🏓 Pong!'));

bot.command('roll', { description: 'Roll dice, e.g. 2d6 (default 1d6)', usage: '[NdM]' }, (ctx) => {
  const m = /^(\d{1,2})d(\d{1,4})$/i.exec(ctx.args[0] || '1d6');
  if (!m) return ctx.reply('Use the format `NdM`, for example `2d6`.');
  const n = +m[1], sides = +m[2];
  if (!n || sides < 2) return ctx.reply('Dice need at least 2 sides.');
  const rolls = Array.from({ length: n }, () => 1 + rand(sides));
  ctx.reply('🎲 ' + rolls.join(' + ') + (n > 1 ? ' = **' + rolls.reduce((a, b) => a + b, 0) + '**' : ''));
});

bot.command('coinflip', { description: 'Flip a coin', aliases: ['flip'] }, (ctx) => {
  ctx.reply(rand(2) ? '🪙 Heads!' : '🪙 Tails!');
});

bot.command('8ball', { description: 'Ask the magic 8-ball', usage: '<question>' }, (ctx) => {
  if (!ctx.rawArgs) return ctx.reply('Ask a question first.');
  const answers = ['Yes.', 'No.', 'Definitely!', 'Not a chance.', 'Ask again later.', 'Most likely.', 'I would not count on it.', 'It is certain.'];
  ctx.reply('🎱 ' + answers[rand(answers.length)]);
});

bot.command('choose', { description: 'Pick one of several options', usage: 'a | b | c' }, (ctx) => {
  const options = ctx.rawArgs.split('|').map((s) => s.trim()).filter(Boolean);
  if (options.length < 2) return ctx.reply('Give me at least two options separated by `|`.');
  ctx.reply('🤔 I choose: **' + options[rand(options.length)] + '**');
});

bot.command('serverinfo', { description: 'Show information about this server' }, (ctx) => {
  ctx.reply('**' + ctx.server.name + '**\nMembers: ' + ctx.server.memberCount + '\nChannels: ' + ctx.server.channels.length);
});

bot.command('userinfo', { description: 'Show information about you' }, (ctx) => {
  ctx.reply('**' + ctx.user.username + '**\nID: `' + ctx.user.id + '`\nManage Server: ' + (ctx.user.canManage ? 'yes' : 'no'));
});
''',
r'''// @name: Welcome Bot
// @icon: 👋
// @color: #3ba55d
// @author: BotShop
// @version: 1.0.0
// @description: Greets new members. Admins can change the text with !setwelcome ({user} and {server} are replaced).
bot.prefix = '!';

const DEFAULT_TEXT = 'Welcome to **{server}**, {user}! 🎉';
const fill = (text, ctx) => text.replace(/\{user\}/g, ctx.user.username).replace(/\{server\}/g, ctx.server.name);

bot.on('memberJoin', (ctx) => {
  ctx.storage.set('joins', (ctx.storage.get('joins') || 0) + 1);
  ctx.send(fill(ctx.storage.get('text') || DEFAULT_TEXT, ctx));
});

bot.command('setwelcome', { description: 'Set the welcome text', usage: '<text>', adminOnly: true }, (ctx) => {
  if (!ctx.rawArgs) return ctx.reply('Usage: `' + ctx.prefix + 'setwelcome Welcome {user} to {server}!`');
  const text = ctx.rawArgs.slice(0, 300);
  ctx.storage.set('text', text);
  ctx.reply('✅ Welcome message saved. Preview:\n' + fill(text, ctx));
});

bot.command('resetwelcome', { description: 'Go back to the default welcome text', adminOnly: true }, (ctx) => {
  ctx.storage.delete('text');
  ctx.reply('✅ Welcome message reset.');
});

bot.command('welcome', { description: 'Show the current welcome message' }, (ctx) => {
  ctx.reply(fill(ctx.storage.get('text') || DEFAULT_TEXT, ctx) + '\n_(' + (ctx.storage.get('joins') || 0) + ' members greeted so far)_');
});
''',
r'''// @name: Level Bot
// @icon: ⭐
// @color: #faa61a
// @author: BotShop
// @version: 1.0.0
// @description: Members earn XP by chatting. Commands: !rank and !top.
bot.prefix = '!';

const levelOf = (xp) => Math.floor(Math.sqrt(xp / 50));

bot.on('message', (ctx) => {
  if (ctx.message.content.startsWith(ctx.prefix)) return;
  const all = ctx.storage.get('xp') || {};
  const me = all[ctx.user.id] || { n: ctx.user.username, xp: 0, t: 0 };
  const now = Date.now();
  if (now - me.t < 20000) return;                 // at most one XP gain every 20 seconds
  const before = levelOf(me.xp);
  me.n = ctx.user.username; me.t = now; me.xp += 5 + Math.floor(Math.random() * 11);
  all[ctx.user.id] = me;
  const ids = Object.keys(all);
  if (ids.length > 300) {                          // keep the storage small: drop the lowest scores
    ids.sort((a, b) => all[a].xp - all[b].xp).slice(0, ids.length - 300).forEach((id) => delete all[id]);
  }
  ctx.storage.set('xp', all);
  if (levelOf(me.xp) > before) ctx.send('⭐ **' + me.n + '** reached level **' + levelOf(me.xp) + '**!');
});

bot.command('rank', { description: 'Show your level and XP' }, (ctx) => {
  const me = (ctx.storage.get('xp') || {})[ctx.user.id];
  if (!me) return ctx.reply('You have no XP yet. Chat a bit first!');
  ctx.reply('⭐ **' + ctx.user.username + '** - level ' + levelOf(me.xp) + ', ' + me.xp + ' XP');
});

bot.command('top', { description: 'Show the top 5 members' }, (ctx) => {
  const all = ctx.storage.get('xp') || {};
  const rows = Object.keys(all).map((id) => all[id]).sort((a, b) => b.xp - a.xp).slice(0, 5);
  if (!rows.length) return ctx.reply('Nobody has XP yet.');
  ctx.reply('🏆 **Top members**\n' + rows.map((r, i) => (i + 1) + '. ' + r.n + ' - level ' + levelOf(r.xp) + ' (' + r.xp + ' XP)').join('\n'));
});
'''
]


class _BotRunner:
    """Keeps one Node.js process alive and talks to it with one JSON line per request/answer."""

    def __init__(self):
        self.proc = None
        self.lock = threading.Lock()
        self.pending = {}
        self.counter = 0
        self.error = None
        self.version = None

    @staticmethod
    def find_node():
        return shutil.which('node') or shutil.which('nodejs')

    def _start(self):
        node = self.find_node()
        if not node:
            self.error = 'Node.js was not found. Install it from https://nodejs.org (version 18 or newer) and restart the app.'
            return False
        with open(BOTSHOP_RUNNER_FILE, 'w', encoding='utf-8', newline='\n') as f:
            f.write(BOTSHOP_RUNNER_SOURCE)
        flags = 0x08000000 if os.name == 'nt' else 0   # no console window on Windows
        try:
            self.proc = subprocess.Popen([node, BOTSHOP_RUNNER_FILE], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL, text=True, encoding='utf-8', bufsize=1, creationflags=flags)
        except Exception as e:
            self.error = f'Could not start Node.js: {e}'
            self.proc = None
            return False
        self.error = None
        threading.Thread(target=self._reader, args=(self.proc,), daemon=True, name='botshop-reader').start()
        return True

    def _reader(self, proc):
        try:
            for line in proc.stdout:
                try:
                    res = json.loads(line)
                except ValueError:
                    continue
                slot = self.pending.pop(res.get('id'), None)
                if slot:
                    slot[1] = res
                    slot[0].set()
        except Exception:
            pass
        # the process ended: wake everybody who is still waiting
        for rid in list(self.pending):
            slot = self.pending.pop(rid, None)
            if slot:
                slot[1] = {'ok': False, 'error': 'The bot runner stopped'}
                slot[0].set()

    def call(self, req, timeout=9):
        with self.lock:
            if not self.proc or self.proc.poll() is not None:
                if not self._start():
                    return {'ok': False, 'error': self.error}
            self.counter += 1
            rid = self.counter
            slot = [threading.Event(), None]
            self.pending[rid] = slot
            try:
                self.proc.stdin.write(json.dumps(dict(req, id=rid)) + '\n')   # ASCII-only JSON: one safe line
                self.proc.stdin.flush()
            except Exception:
                self.pending.pop(rid, None)
                self.proc = None
                return {'ok': False, 'error': 'The bot runner is not available'}
        if not slot[0].wait(timeout):
            self.pending.pop(rid, None)
            return {'ok': False, 'error': 'The bot runner did not answer in time'}
        return slot[1] or {'ok': False, 'error': 'No answer from the bot runner'}

    def status(self):
        res = self.call({'op': 'ping'}, timeout=5)
        if res.get('ok'):
            self.version = res.get('node')
            return {'ok': True, 'node': self.version}
        return {'ok': False, 'error': res.get('error') or self.error or 'Node.js is not available'}


_bot_runner = _BotRunner()
_bs_rate = {}                      # install id -> [timestamps of the last minute]
_bs_rate_lock = threading.Lock()


# ---------- helpers ----------
def _bs(db):
    bs = db.setdefault('botshop', {})
    bs.setdefault('bots', {})        # bot id (slug) -> bot info (the code lives in data/botshop/bots/<id>.js)
    bs.setdefault('installs', {})    # install id -> {bot_id, server_id, channel_ids, prefix, enabled, ...}
    bs.setdefault('seeded', False)
    return bs


def _bot_parse_meta(code):
    meta = {}
    for line in code.split('\n')[:60]:
        m = re.match(r'^\s*//\s*@(\w+)\s*:?\s*(.*?)\s*$', line)
        if m and m.group(1).lower() not in meta:
            meta[m.group(1).lower()] = m.group(2)
    return meta


def _bot_slug(meta):
    raw = (meta.get('id') or meta.get('name') or '').lower()
    slug = re.sub(r'[^a-z0-9]+', '-', raw).strip('-')[:40]
    if not slug:   # e.g. a name written only in non-latin letters: derive a stable id from it
        import hashlib
        slug = 'bot-' + hashlib.sha1((meta.get('name') or '').encode('utf-8')).hexdigest()[:8]
    return slug


def _bs_read_code(bot_id):
    try:
        with open(os.path.join(BOTSHOP_BOTS_DIR, bot_id + '.js'), 'r', encoding='utf-8') as f:
            return f.read()
    except OSError:
        return None


def _bs_storage_path(install_id):
    return os.path.join(BOTSHOP_STORAGE_DIR, re.sub(r'[^a-zA-Z0-9_-]', '', install_id) + '.json')


def _bs_read_storage(install_id):
    try:
        with open(_bs_storage_path(install_id), 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _bs_write_storage(install_id, data):
    try:
        with open(_bs_storage_path(install_id), 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False)
    except OSError as e:
        print(f'BotShop: could not save storage: {e}')


def _bs_can_manage(db, user_id, server):
    """Site admin, server owner, or a member whose role has the Manage Server permission."""
    if not server:
        return False
    return server.get('owner_id') == user_id


def _bs_text_channels(db, server_id):
    chans = [c for c in db['channels'].values() if c.get('server_id') == server_id and c.get('type', 'text') == 'text']
    chans.sort(key=lambda c: c.get('created_at', ''))
    return chans


def _bs_ensure_bot_user(db, bot):
    """Every bot has its own account (bot_<id>) so its messages show a name, colour and the BOT badge."""
    uid = 'bot_' + bot['id']
    u = db['users'].get(uid)
    if not u:
        now = datetime.now().isoformat()
        u = {
            'id': uid, 'username': bot['name'], 'email': f'{uid}@bots.invalid', 'password': '!',   # '!' can never match a password
            'avatar': None, 'avatar_color': bot.get('color') or '#5865f2', 'status': 'online', 'bio': (bot.get('description') or '')[:190],
            'is_admin': False, 'is_premium': False, 'premium_since': None, 'coins': 0, 'inventory': [], 'friends': [],
            'created_at': now, 'last_seen': now, 'home_logo': None, 'home_icon': 'fa-discord', 'home_color': '#7289da', 'home_bg_color': '#5865f2',
            'vip': False, 'staff': False, 'developer': False, 'verified': False, 'nitro': False, 'partner': False, 'hypesquad_house': None,
            'early_supporter': False, 'bug_hunter': False, 'translator': False, 'support': False, 'is_active': True, 'reputation': 0,
            'server_boost_level': 0, 'is_moderator': False, 'is_bot': True, 'blocked_users': [], 'devices': [], 'banner': None,
            'is_animated': False, 'current_activity': None, 'is_nitro': False, 'hypesquad_houses': None,
        }
        db['users'][uid] = u
    else:
        u['username'] = bot['name']
        u['avatar_color'] = bot.get('color') or u.get('avatar_color')
        u['bio'] = (bot.get('description') or '')[:190]
        u['is_bot'] = True
    return uid


def _bs_post(db, bot_uid, channel_id, content, reply_to=None):
    mid = uuid.uuid4().hex[:12]
    db['all_messages'][mid] = {
        'id': mid, 'channel_id': channel_id, 'user_id': bot_uid, 'content': content[:2000], 'image_url': None,
        'created_at': datetime.now().isoformat(), 'edited_at': None, 'reactions': {}, 'type': 'message',
        'reply_to': reply_to, 'effect': 'none',
    }
    return mid


def _bs_rate_ok(install_id):
    now = time.time()
    with _bs_rate_lock:
        stamps = [t for t in _bs_rate.get(install_id, []) if now - t < 60]
        if len(stamps) >= BOT_MSGS_PER_MINUTE:
            _bs_rate[install_id] = stamps
            return False
        stamps.append(now)
        _bs_rate[install_id] = stamps
        return True


def _bs_public_bot(bot, installs_count=0):
    return {
        'id': bot['id'], 'name': bot['name'], 'description': bot.get('description', ''), 'icon': bot.get('icon', ''),
        'color': bot.get('color', '#5865f2'), 'author': bot.get('author', ''), 'version': bot.get('version', ''),
        'prefix': bot.get('prefix', '!'), 'commands': bot.get('commands', []), 'events': bot.get('events', []),
        'permissions': bot.get('permissions', []),
        'installs': installs_count, 'updated_at': bot.get('updated_at'),
    }


def _bs_upsert_bot(db, code, uploader_name):
    """Validate an uploaded bot file and store it. Returns (bot, error)."""
    if not isinstance(code, str) or not code.strip():
        return None, 'The file is empty.'
    code = code.lstrip('\ufeff').replace('\r\n', '\n')
    if '\x00' in code:
        return None, 'This does not look like a text/JavaScript file.'
    if len(code.encode('utf-8')) > BOT_CODE_MAX:
        return None, f'The file is too big (max {BOT_CODE_MAX // 1000} KB).'
    meta = _bot_parse_meta(code)
    name = (meta.get('name') or '').strip()[:40]
    if not name:
        return None, 'The file needs a "// @name: My Bot" line at the top.'
    res = _bot_runner.call({'op': 'describe', 'code': code}, timeout=9)
    if not res.get('ok'):
        return None, res.get('error') or 'The bot could not be loaded.'
    own_cmds = [c for c in res.get('commands', []) if not c.get('builtin')]
    if not own_cmds and not res.get('events'):
        return None, 'The bot does nothing yet: register at least one bot.command(...) or bot.on(...).'

    slug = _bot_slug(meta)
    bs = _bs(db)
    old = bs['bots'].get(slug)
    now = datetime.now().isoformat()
    color = meta.get('color', '').strip()
    prefix = (res.get('prefix') or meta.get('prefix') or '!').strip()[:3] or '!'
    bot = {
        'id': slug, 'name': name, 'description': (meta.get('description') or '')[:300],
        'icon': (meta.get('icon') or '')[:30], 'color': color if re.match(r'^#[0-9a-fA-F]{6}$', color) else '#5865f2',
        'author': (meta.get('author') or uploader_name or '')[:40], 'version': (meta.get('version') or '1.0.0')[:20],
        'prefix': prefix, 'commands': res.get('commands', []), 'events': res.get('events', []),
        'permissions': _bs_parse_permissions(meta.get('permissions')),
        'created_at': (old or {}).get('created_at', now), 'updated_at': now,
    }
    with open(os.path.join(BOTSHOP_BOTS_DIR, slug + '.js'), 'w', encoding='utf-8', newline='\n') as f:
        f.write(code)
    bs['bots'][slug] = bot
    _bs_ensure_bot_user(db, bot)
    return bot, None


def _bs_seed_if_needed():
    """First start: publish three example bots so the store is not empty (the admin can delete them)."""
    try:
        db = load_database()
        bs = _bs(db)
        if bs['seeded']:
            return
        if not _bot_runner.status().get('ok'):
            return   # Node.js missing: try again on the next start
        for code in BOTSHOP_SAMPLE_BOTS:
            bot, err = _bs_upsert_bot(db, code, 'BotShop')
            if err:
                print(f'BotShop: sample bot skipped: {err}')
        bs['seeded'] = True
        save_database(db)
    except Exception as e:
        print(f'BotShop: seeding failed: {e}')


def _bs_remove_install(db, install_id):
    bs = _bs(db)
    inst = bs['installs'].pop(install_id, None)
    if not inst:
        return
    try:
        os.remove(_bs_storage_path(install_id))
    except OSError:
        pass
    # last install of this bot on this server: the bot leaves the member list
    if not any(i['bot_id'] == inst['bot_id'] and i['server_id'] == inst['server_id'] for i in bs['installs'].values()):
        server = db['servers'].get(inst['server_id'])
        uid = 'bot_' + inst['bot_id']
        if server:
            if uid in server.get('members', []):
                server['members'].remove(uid)
            server.get('user_roles', {}).pop(uid, None)


# ---------- bots creating channels ----------
BOT_CHANNELS_PER_HOUR = 10          # channels one installed bot may create per hour
BOT_SERVER_CHANNEL_CAP = 200        # a bot never pushes a server over this many channels
_bs_chan_rate = {}                  # install id -> [timestamps of the last hour]


def _bs_chan_rate_ok(install_id):
    now = time.time()
    with _bs_rate_lock:
        stamps = [t for t in _bs_chan_rate.get(install_id, []) if now - t < 3600]
        if len(stamps) >= BOT_CHANNELS_PER_HOUR:
            _bs_chan_rate[install_id] = stamps
            return False
        stamps.append(now)
        _bs_chan_rate[install_id] = stamps
        return True


def _bs_create_channel(db, server, bot_uid, inst_id, event, user_info, act):
    """Creates a channel for a bot. Returns (channel or None, error text)."""
    # Commands / messages: only people with Manage Server can make a bot create channels.
    # memberJoin has no command: the person who installed the bot decided it may do this.
    if event != 'memberJoin' and not user_info.get('canManage'):
        return None, 'You need the Manage Server permission to make this bot create channels.'
    name = re.sub(r'\s+', '-', str(act.get('name') or '').strip())
    name = ''.join(ch for ch in name if ch not in '<>\\"\'`')[:50].strip('-')      # quotes would break the channel list in the browser
    if not name:
        return None, 'The channel name is empty.'
    ctype = 'voice' if act.get('channel_type') == 'voice' else 'text'
    sid = server['id']
    if sum(1 for c in db['channels'].values() if c.get('server_id') == sid) >= BOT_SERVER_CHANNEL_CAP:
        return None, f'This server already has {BOT_SERVER_CHANNEL_CAP} channels.'
    if any(c.get('server_id') == sid and c.get('type', 'text') == ctype and c.get('name', '').lower() == name.lower()
           for c in db['channels'].values()):
        return None, f'A channel named "{name}" already exists.'
    category_id = None
    want = act.get('category')
    if want:
        want = str(want).strip()
        for cat in (db.get('categories') or {}).values():
            if cat.get('server_id') == sid and (cat.get('id') == want or cat.get('name', '').lower() == want.lower()):
                category_id = cat['id']
                break
    if not _bs_chan_rate_ok(inst_id):
        return None, f'This bot may create at most {BOT_CHANNELS_PER_HOUR} channels per hour.'
    private = bool(act.get('private'))
    channel_id = f"channel_{uuid.uuid4().hex[:8]}"
    db['channels'][channel_id] = {
        'id': channel_id, 'server_id': sid, 'name': name, 'type': ctype, 'category_id': category_id,
        'description': str(act.get('description') or '').strip()[:500],
        'private': private,
        'private_members': _clean_member_ids(db, server, [user_info.get('id')]) if private else [],
        'view_only_members': [],
        'creator_id': bot_uid, 'nitro': False, 'read_only': False,
        'created_at': datetime.now().isoformat(),
    }
    return db['channels'][channel_id], None


# ---------- bots managing the server ----------
# A bot declares what it may manage with "// @permissions: channels, roles, ..." in its file.
# The server owner approves those permissions when installing (saved in the install, see _bs_install_one).
BOT_ADMIN_GROUPS = {
    'channels': ('createChannel', 'editChannel', 'deleteChannel'),
    'categories': ('createCategory', 'renameCategory', 'deleteCategory'),
    'roles': ('createRole', 'editRole', 'deleteRole', 'giveRole', 'removeRole'),
    'members': ('kick', 'ban', 'unban', 'mute', 'unmute'),
    'messages': ('deleteMessage', 'purge'),
    'server': ('editServer',),
    'tickets': ('ticket',),
    'economy': ('transferCoins',),      # bots may move coins FROM the command author (see _bs_coins_run)
    'verify': ('verify', 'unverify'),      # verified tick (platform admins only, command only)
}
BOT_ADMIN_OP_GROUP = {op: g for g, ops in BOT_ADMIN_GROUPS.items() for op in ops}
BOT_JOIN_OPS = ('createChannel', 'createCategory', 'giveRole', 'removeRole', 'kick', 'ban', 'mute')   # allowed when a member joins
BOT_ROLE_PERMS = ('manage_server', 'kick', 'ban', 'unban', 'mute', 'manage_channels', 'manage_messages', 'send_messages', 'react')
BOT_SAFE_ROLE_PERMS = ('send_messages', 'react')
BOT_ADMIN_PER_HOUR = 60             # management actions one installed bot may run per hour
BOT_MAX_CATEGORIES = 50
BOT_MAX_ROLES = 50
_bs_admin_rate = {}                 # install id -> [timestamps of the last hour]


def _bs_parse_permissions(raw):
    words = {w for w in re.split(r'[,\s]+', str(raw or '').lower()) if w}
    return [g for g in BOT_ADMIN_GROUPS if 'all' in words or g in words]


def _bs_admin_rate_ok(install_id):
    now = time.time()
    with _bs_rate_lock:
        stamps = [t for t in _bs_admin_rate.get(install_id, []) if now - t < 3600]
        if len(stamps) >= BOT_ADMIN_PER_HOUR:
            _bs_admin_rate[install_id] = stamps
            return False
        stamps.append(now)
        _bs_admin_rate[install_id] = stamps
        return True


def _bs_admin_gate(bot, inst, event, user_info, op):
    """Is this bot allowed to run this management action right now? Returns None, or the reason why not."""
    group = BOT_ADMIN_OP_GROUP.get(op)
    if not group:
        return 'Unknown management action.'
    declared = bot.get('permissions') or []
    if group not in declared:
        return f'This bot did not declare the "{group}" permission (add "// @permissions: {group}" to the bot file).'
    if group not in (inst.get('permissions') or []):
        return f'The server owner has not approved the "{group}" permission yet (My Bots > Configure > save).'
    if event == 'memberJoin':
        if op not in BOT_JOIN_OPS:
            return 'This action cannot run when a member joins.'
    elif not user_info.get('canManage'):
        return 'You need the Manage Server permission to make this bot manage the server.'
    if not _bs_admin_rate_ok(inst['id']):
        return f'This bot may run at most {BOT_ADMIN_PER_HOUR} management actions per hour.'
    return None


def _bs_plain(v, n=50):
    """Names of roles / categories: no characters that could break the HTML of the page."""
    return ''.join(ch for ch in str(v if v is not None else '').strip() if ch not in '<>\\"\'`')[:n].strip()


def _bs_channel_name(v):
    name = re.sub(r'\s+', '-', str(v if v is not None else '').strip())
    return ''.join(ch for ch in name if ch not in '<>\\"\'`')[:50].strip('-')


def _bs_ref(v):
    return str(v if v is not None else '').strip().lstrip('#@')


def _bs_find_channel(db, sid, ref):
    ref = _bs_ref(ref)
    if not ref:
        return None
    ch = db['channels'].get(ref)
    if ch and ch.get('server_id') == sid:
        return ch
    low = ref.lower()
    return next((c for c in db['channels'].values() if c.get('server_id') == sid and str(c.get('name', '')).lower() == low), None)


def _bs_find_category(db, sid, ref):
    ref = _bs_ref(ref)
    if not ref:
        return None
    cats = [c for c in (db.get('categories') or {}).values() if c.get('server_id') == sid]
    low = ref.lower()
    return next((c for c in cats if c.get('id') == ref), None) or next((c for c in cats if str(c.get('name', '')).lower() == low), None)


def _bs_find_role(server, ref):
    ref = _bs_ref(ref)
    if not ref:
        return None, None
    roles = server.get('roles') or {}
    if ref in roles:
        return ref, roles[ref]
    low = ref.lower()
    for rid, r in roles.items():
        if str(r.get('name', '')).lower() == low:
            return rid, r
    return None, None


def _bs_find_member(db, server, ref):
    ref = re.sub(r'[<>@!]', '', str(ref if ref is not None else '')).strip()
    if not ref:
        return None
    members = server.get('members', [])
    if ref in members:
        return ref
    low = ref.lower()
    return next((u for u in members if str(db['users'].get(u, {}).get('username', '')).lower() == low), None)


def _bs_target(db, server, bot_uid, event, user_info, ref):
    """The member a moderation action is aimed at. Returns (user id, error)."""
    uid = _bs_find_member(db, server, ref)
    if not uid:
        return None, 'Member not found.'
    if uid == server.get('owner_id'):
        return None, 'The server owner cannot be targeted.'
    if uid == bot_uid or db['users'].get(uid, {}).get('is_bot'):
        return None, 'Bots cannot be targeted.'
    if event == 'memberJoin' and uid != user_info.get('id'):
        return None, 'When a member joins, the bot may only act on that member.'
    return uid, None


def _bs_drop_messages(db, ids):
    gone = set(ids)
    for mid in gone:
        db['all_messages'].pop(mid, None)
    pins = db.get('message_pins') or {}
    for key, val in list(pins.items()):
        if isinstance(val, list):
            pins[key] = [x for x in val if (x.get('message_id') if isinstance(x, dict) else x) not in gone]


def _bs_admin_run(db, server, bot_uid, event, user_info, act, channel_id):
    """Runs ONE management action (already allowed by _bs_admin_gate). Returns None when it worked, else a short error."""
    op = act.get('op')
    sid = server['id']

    # ----- verified tick (global badge: only a site admin may run it through a bot) -----
    if op in ('verify', 'unverify'):
        actor = db['users'].get(user_info.get('id'), {})
        if not actor.get('is_admin'):
            return 'Only a site admin can give or remove the verified tick.'
        uid = _bs_find_member(db, server, act.get('user'))
        target = db['users'].get(uid) if uid else None
        if not target:
            return 'Member not found.'
        value = (op == 'verify')
        target['verified'] = value
        target['is_verified'] = value
        db.setdefault('badge_history', {}).setdefault(uid, []).append({
            'action': 'verified_on' if value else 'verified_off',
            'badges': ['verified'], 'by': 'bot:' + str(bot_uid), 'at': datetime.now().isoformat()})
        return None

    # ----- channels -----
    if op == 'editChannel':
        ch = _bs_find_channel(db, sid, act.get('ref'))
        if not ch:
            return 'Channel not found.'
        cat = None
        if 'category' in act and act.get('category'):
            cat = _bs_find_category(db, sid, act['category'])
            if not cat:
                return 'Category not found.'
        slow = 0
        if 'slowmode' in act:
            try:
                slow = int(act['slowmode'])
            except (TypeError, ValueError):
                return 'Invalid slowmode.'
            if slow not in SLOWMODE_CHOICES:
                return 'Slowmode must be one of: ' + ', '.join(str(s) for s in SLOWMODE_CHOICES) + ' seconds.'
        if 'name' in act:
            nm = _bs_channel_name(act['name'])
            if not nm:
                return 'The channel name is empty.'
            ch['name'] = nm
        if 'description' in act:
            ch['description'] = str(act['description']).strip()[:500]
        if 'category' in act:
            ch['category_id'] = cat['id'] if cat else None
        if 'slowmode' in act:
            ch['slowmode'] = slow
        if 'nsfw' in act:
            ch['nsfw'] = bool(act['nsfw'])
        if 'private' in act:
            ch['private'] = bool(act['private'])
        if 'readOnly' in act:
            ch['read_only'] = bool(act['readOnly'])
        return None

    if op == 'deleteChannel':
        ch = _bs_find_channel(db, sid, act.get('ref'))
        if not ch:
            return 'Channel not found.'
        if ch.get('type', 'text') == 'text' and len(_bs_text_channels(db, sid)) <= 1:
            return 'The last text channel of a server cannot be deleted.'
        cid = ch['id']
        del db['channels'][cid]
        for tid in [t for t, th in (db.get('threads') or {}).items() if th.get('channel_id') == cid]:
            db['threads'].pop(tid, None)
        (db.get('message_pins') or {}).pop('ch_' + cid, None)
        for mid in [m for m, msg in db['all_messages'].items() if msg.get('channel_id') == cid]:
            del db['all_messages'][mid]
        db.get('auto_delete', {}).pop(cid, None)
        return None

    # ----- categories -----
    if op == 'createCategory':
        name = _bs_plain(act.get('name'))
        if not name:
            return 'The category name is empty.'
        cats = [c for c in (db.get('categories') or {}).values() if c.get('server_id') == sid]
        if len(cats) >= BOT_MAX_CATEGORIES:
            return f'This server already has {BOT_MAX_CATEGORIES} categories.'
        if any(str(c.get('name', '')).lower() == name.lower() for c in cats):
            return f'A category named "{name}" already exists.'
        cat_id = f"cat_{uuid.uuid4().hex[:8]}"
        db.setdefault('categories', {})[cat_id] = {'id': cat_id, 'server_id': sid, 'name': name, 'created_at': datetime.now().isoformat()}
        return None

    if op in ('renameCategory', 'deleteCategory'):
        cat = _bs_find_category(db, sid, act.get('ref'))
        if not cat:
            return 'Category not found.'
        if op == 'renameCategory':
            name = _bs_plain(act.get('name'))
            if not name:
                return 'The category name is empty.'
            cat['name'] = name
            return None
        for ch in db['channels'].values():          # keep the channels, just move them out
            if ch.get('category_id') == cat['id']:
                ch['category_id'] = None
        del db['categories'][cat['id']]
        return None

    # ----- roles -----
    if op in ('createRole', 'editRole'):
        perms = None
        if 'permissions' in act:
            perms = [x for x in dict.fromkeys(act.get('permissions') or []) if x in BOT_ROLE_PERMS]
        color = None
        if 'color' in act:
            color = str(act['color']).strip()
            if not re.match(r'^#[0-9a-fA-F]{6}$', color):
                return 'The colour must look like #5865f2.'
        roles = server.setdefault('roles', {})
        if op == 'createRole':
            name = _bs_plain(act.get('name'))
            if not name:
                return 'The role name is empty.'
            if len(roles) >= BOT_MAX_ROLES:
                return f'This server already has {BOT_MAX_ROLES} roles.'
            if any(str(r.get('name', '')).lower() == name.lower() for r in roles.values()):
                return f'A role named "{name}" already exists.'
            rid = f"role_{uuid.uuid4().hex[:8]}"
            roles[rid] = {'id': rid, 'name': name, 'color': color or '#747e8c',
                          'permissions': perms if perms is not None else ['send_messages', 'react'], 'hoist': bool(act.get('hoist'))}
            return None
        rid, role = _bs_find_role(server, act.get('ref'))
        if not role:
            return 'Role not found.'
        if rid in LOCKED_ROLE_IDS:
            return "The owner role can't be changed."
        if 'name' in act:
            nm = _bs_plain(act['name'])
            if not nm:
                return 'The role name is empty.'
            role['name'] = nm
        if color:
            role['color'] = color
        if perms is not None:
            role['permissions'] = perms
        if 'hoist' in act:
            role['hoist'] = bool(act['hoist'])
        return None

    if op == 'deleteRole':
        rid, role = _bs_find_role(server, act.get('ref'))
        if not role:
            return 'Role not found.'
        if rid in LOCKED_ROLE_IDS or rid in ('owner', 'admin', 'moderator', 'member'):
            return 'The default roles cannot be deleted.'
        user_roles = server.get('user_roles', {})
        for uid, rl in user_roles.items():
            if rid in rl:
                rl.remove(rid)
                if not rl:
                    user_roles[uid] = ['member']
        del server['roles'][rid]
        return None

    if op in ('giveRole', 'removeRole'):
        uid, err = _bs_target(db, server, bot_uid, event, user_info, act.get('user'))
        if err:
            return err
        rid, role = _bs_find_role(server, act.get('role'))
        if not role:
            return 'Role not found.'
        if rid in LOCKED_ROLE_IDS:
            return "The owner role can't be given or removed."
        if event == 'memberJoin' and any(x not in BOT_SAFE_ROLE_PERMS for x in (role.get('permissions') or [])):
            return 'When a member joins, a bot may only hand out roles without moderation permissions.'
        ur = server.setdefault('user_roles', {})
        cur = list(ur.get(uid) or ['member'])
        if op == 'giveRole':
            if rid not in cur:
                cur.append(rid)
        else:
            cur = [x for x in cur if x != rid] or ['member']
        ur[uid] = cur
        return None

    # ----- members -----
    if op in ('kick', 'ban', 'mute'):
        uid, err = _bs_target(db, server, bot_uid, event, user_info, act.get('user'))
        if err:
            return err
        reason = str(act.get('reason') or 'No reason provided')[:200]
        if op == 'mute':
            try:
                minutes = int(act.get('minutes') or 60)
            except (TypeError, ValueError):
                minutes = 60
            minutes = max(1, min(minutes, 43200))
            now = datetime.now()
            db.setdefault('mutes', {}).setdefault(sid, {})[uid] = {
                'muted_at': now.isoformat(), 'muted_until': (now + timedelta(minutes=minutes)).isoformat(),
                'muted_by': bot_uid, 'reason': reason}
            return None
        if op == 'ban':
            db.setdefault('bans', {}).setdefault(sid, {})[uid] = {
                'banned_at': datetime.now().isoformat(), 'banned_by': bot_uid, 'reason': reason}
        server['members'].remove(uid)
        _strip_member_from_private_channels(db, sid, uid)
        server.get('user_roles', {}).pop(uid, None)
        (db.get('mutes') or {}).get(sid, {}).pop(uid, None)
        return None

    if op == 'unban':
        bans = (db.get('bans') or {}).get(sid, {})
        ref = re.sub(r'[<>@!]', '', str(act.get('user') or '')).strip()
        uid = ref if ref in bans else next((u for u in bans if str(db['users'].get(u, {}).get('username', '')).lower() == ref.lower()), None)
        if not uid or not ref:
            return 'That user is not banned.'
        del bans[uid]
        return None

    if op == 'unmute':
        uid = _bs_find_member(db, server, act.get('user'))
        mutes = (db.get('mutes') or {}).get(sid, {})
        if not uid or uid not in mutes:
            return 'That member is not muted.'
        del mutes[uid]
        return None

    # ----- server -----
    if op == 'editServer':
        if 'name' in act:
            nm = str(act['name']).strip()[:100]
            if not nm:
                return 'The server name cannot be empty.'
            server['name'] = nm
        if 'description' in act:
            server['description'] = str(act['description']).strip()[:500]
        return None

    # ----- messages -----
    if op == 'deleteMessage':
        m = db['all_messages'].get(str(act.get('message_id') or ''))
        if not m or db['channels'].get(m.get('channel_id'), {}).get('server_id') != sid:
            return 'Message not found.'
        _bs_drop_messages(db, [m['id']])
        return None

    if op == 'purge':
        if not channel_id or db['channels'].get(channel_id, {}).get('server_id') != sid:
            return 'There is no channel to clear.'
        try:
            count = max(1, min(100, int(act.get('count') or 1)))
        except (TypeError, ValueError):
            count = 1
        newest = sorted((m for m in db['all_messages'].values() if m.get('channel_id') == channel_id),
                        key=lambda m: m.get('created_at', ''), reverse=True)[:count]
        _bs_drop_messages(db, [m['id'] for m in newest])
        return None

    return 'Unknown management action.'


# ---------- tickets (private support channels made by bots with the "tickets" permission) ----------
BOT_TICKETS_MAX_OPEN = 3            # open tickets one member may have on one server


def _bs_ticket_gate(bot, inst):
    if 'tickets' not in (bot.get('permissions') or []):
        return 'This bot did not declare the "tickets" permission (add "// @permissions: tickets" to the bot file).'
    if 'tickets' not in (inst.get('permissions') or []):
        return 'The server owner has not approved the "tickets" permission yet (My Bots > Configure > save).'
    return None


def _bs_find_ticket(db, sid, ref, channel_id):
    ch = _bs_find_channel(db, sid, ref) if ref else db['channels'].get(channel_id)
    if not ch or ch.get('server_id') != sid or not ch.get('ticket_owner_id'):
        return None
    return ch


def _bs_ticket_run(db, server, bot_uid, inst_id, user_info, act, channel_id):
    """Runs ONE ticket action. Returns (error text or None, id of a channel to greet in or None)."""
    op = act.get('op')
    sid = server['id']
    uid = user_info.get('id')
    manage = bool(user_info.get('canManage'))

    if op == 'create':
        name = _bs_channel_name(act.get('name'))
        if not name:
            return 'The ticket name is empty.', None
        open_now = [c for c in db['channels'].values() if c.get('server_id') == sid and c.get('ticket_owner_id') == uid and not c.get('ticket_closed')]
        if len(open_now) >= BOT_TICKETS_MAX_OPEN:
            return f'You already have {len(open_now)} open tickets. Close one first.', None
        if sum(1 for c in db['channels'].values() if c.get('server_id') == sid) >= BOT_SERVER_CHANNEL_CAP:
            return f'This server already has {BOT_SERVER_CHANNEL_CAP} channels.', None
        if any(c.get('server_id') == sid and c.get('type', 'text') == 'text' and c.get('name', '').lower() == name.lower() for c in db['channels'].values()):
            return f'A channel named "{name}" already exists.', None
        category_id = None
        want = str(act.get('category') or '').strip()
        if want:
            for cat in (db.get('categories') or {}).values():
                if cat.get('server_id') == sid and (cat.get('id') == want or cat.get('name', '').lower() == want.lower()):
                    category_id = cat['id']
                    break
        if not _bs_chan_rate_ok(inst_id):
            return f'This bot may create at most {BOT_CHANNELS_PER_HOUR} channels per hour.', None
        cid = f"channel_{uuid.uuid4().hex[:8]}"
        subject = _bs_plain(act.get('subject'), 200)
        db['channels'][cid] = {
            'id': cid, 'server_id': sid, 'name': name, 'type': 'text', 'category_id': category_id,
            'description': ('Ticket: ' + subject)[:500] if subject else 'Ticket',
            'private': True,
            'private_members': _clean_member_ids(db, server, [uid]),
            'view_only_members': [],
            'creator_id': bot_uid, 'nitro': False, 'read_only': False,
            'ticket_owner_id': uid, 'ticket_closed': False, 'ticket_subject': subject,
            'created_at': datetime.now().isoformat(),
        }
        first = str(act.get('message') or '').strip()
        if first:
            _bs_post(db, bot_uid, cid, first)
        return None, None

    ch = _bs_find_ticket(db, sid, act.get('ref'), channel_id)
    if not ch:
        return 'This is not a ticket channel.', None
    is_owner = (uid == ch.get('ticket_owner_id'))

    if op == 'close':
        if act.get('del'):
            if not manage:
                return 'You need the Manage Server permission to delete a ticket.', None
            cid = ch['id']
            for tid in [t for t, th in (db.get('threads') or {}).items() if th.get('channel_id') == cid]:
                db['threads'].pop(tid, None)
            (db.get('message_pins') or {}).pop('ch_' + cid, None)
            _bs_drop_messages(db, [m for m, msg in db['all_messages'].items() if msg.get('channel_id') == cid])
            db.get('auto_delete', {}).pop(cid, None)
            del db['channels'][cid]
            return None, None
        if not (is_owner or manage):
            return 'Only the person who opened this ticket or the server owner can close it.', None
        ch['ticket_closed'] = True
        ch['read_only'] = True
        return None, None

    if op == 'reopen':
        if not (is_owner or manage):
            return 'Only the person who opened this ticket or the server owner can reopen it.', None
        ch['ticket_closed'] = False
        ch['read_only'] = False
        return None, None

    if op in ('add', 'remove'):
        if not manage:
            return 'You need the Manage Server permission to change who is in a ticket.', None
        target = _bs_find_member(db, server, act.get('user'))
        if not target:
            return 'Member not found.', None
        if target == server.get('owner_id') or db['users'].get(target, {}).get('is_bot'):
            return 'This member cannot be added or removed.', None
        members = ch.setdefault('private_members', [])
        if op == 'add':
            if target not in members:
                members.append(target)
            return None, None
        if target == ch.get('ticket_owner_id'):
            return 'The person who opened the ticket cannot be removed.', None
        ch['private_members'] = [m for m in members if m != target]
        ch['view_only_members'] = [m for m in (ch.get('view_only_members') or []) if m != target]
        return None, None

    return 'Unknown ticket action.', None



def _bs_admin_failed(db, live, bot_uid, event, channel, trigger_msg_id, why):
    """A management action was refused: remember it for the owner and tell the people in the channel."""
    live['last_error'] = why[:200]
    if event == 'message' and channel['id'] in db['channels']:
        _bs_post(db, bot_uid, channel['id'], '⚠️ ' + why, trigger_msg_id)


# ---------- running bots ----------
def _bs_server_info(db, server):
    members = [m for m in server.get('members', []) if not db['users'].get(m, {}).get('is_bot')]
    sid = server['id']
    chans = sorted((c for c in db['channels'].values() if c.get('server_id') == sid), key=lambda c: c.get('created_at', ''))
    cats = [c for c in (db.get('categories') or {}).values() if c.get('server_id') == sid]
    return {
        'id': sid, 'name': server.get('name', ''), 'ownerId': server.get('owner_id'), 'memberCount': len(members),
        'channels': [{'id': c['id'], 'name': c.get('name', ''), 'type': c.get('type', 'text'), 'categoryId': c.get('category_id'),
                      'ticketOwnerId': c.get('ticket_owner_id'), 'ticketClosed': bool(c.get('ticket_closed'))} for c in chans],
        'categories': [{'id': c['id'], 'name': c.get('name', '')} for c in cats],
        'roles': [{'id': rid, 'name': r.get('name', '')} for rid, r in (server.get('roles') or {}).items()],
        'members': [{'id': m, 'username': db['users'].get(m, {}).get('username', '')} for m in members[:500]],
    }


def _bs_coins_gate(bot, inst, event, user_info):
    if 'economy' not in (bot.get('permissions') or []):
        return 'This bot did not declare the "economy" permission (add "// @permissions: economy" to the bot file).'
    if 'economy' not in (inst.get('permissions') or []):
        return 'The server owner has not approved the "economy" permission yet (My Bots > Configure > save).'
    if event != 'message':
        return 'Coins can only be sent from a command.'
    if not _bs_admin_rate_ok(inst['id']):
        return f'This bot may run at most {BOT_ADMIN_PER_HOUR} management or coin actions per hour.'
    return None


def _bs_coins_run(db, srv, bot_uid, channel_id, user_info, act):
    """A bot can only send coins FROM the person who typed the command, to a member of the server."""
    amount = parse_coin_amount(act.get('amount'))
    if amount is None:
        return f'Invalid coin amount (use a whole number from {COIN_TRANSFER_MIN} to {COIN_TRANSFER_MAX}).'
    ref = str(act.get('to') or '').strip().replace('<', '').replace('>', '').replace('@', '').replace('!', '')
    wanted = ref.lower()
    target_id = None
    for m in srv.get('members', []):
        u = db['users'].get(m, {})
        if u.get('is_bot'):
            continue
        if m == ref or str(u.get('username', '')).lower() == wanted:
            target_id = m
            break
    if not target_id:
        return 'The receiver must be a member of this server.'
    _status, error, _balance = coin_transfer(db, user_info['id'], target_id, amount)
    if error:
        return error
    sender_name = db['users'].get(user_info['id'], {}).get('username', 'User')
    receiver_name = db['users'][target_id].get('username', 'User')
    _bs_post(db, bot_uid, channel_id, f'💰 {sender_name} sent {amount:,} coins to {receiver_name}.')
    return None


def _bs_run_jobs(jobs, event, user_info, server_info, channel, message, trigger_msg_id):
    """jobs = [(install, bot, prefix, matched_command)]. Runs the bots, then applies what they asked for."""
    results = []
    for inst, bot, prefix, matched in jobs:
        code = _bs_read_code(bot['id'])
        if code is None:
            continue
        # permissions are read from the bot file itself, so an older upload still works after the server was updated
        bot = dict(bot, permissions=_bs_parse_permissions(_bot_parse_meta(code).get('permissions')))
        old_storage = _bs_read_storage(inst['id'])
        payload = {
            'event': event, 'prefix': prefix, 'bot': {'id': bot['id'], 'name': bot['name']}, 'user': user_info,
            'server': server_info, 'channel': {'id': channel['id'], 'name': channel.get('name', '')},
            'message': message, 'storage': old_storage,
        }
        res = _bot_runner.call({'op': 'event', 'code': code, 'payload': json.dumps(payload, ensure_ascii=False)}, timeout=9)
        results.append((inst, bot, matched, old_storage, res))
    if not results:
        return

    db = load_database()          # fresh copy: apply the answers right before saving
    bs = _bs(db)
    changed = False
    for inst, bot, matched, old_storage, res in results:
        live = bs['installs'].get(inst['id'])
        if not live:
            continue              # uninstalled while the bot was thinking
        bot_uid = _bs_ensure_bot_user(db, bot)
        allowed = live.get('channel_ids') or []
        problem = (not res.get('ok')) or res.get('errors')
        if problem:
            live['last_error'] = (res.get('error') or (res.get('errors') or ['error'])[0])[:200]
            changed = True
        if not res.get('ok'):
            print(f"BotShop: {bot['name']}: {res.get('error')}")
            if matched and channel['id'] in db['channels']:
                _bs_post(db, bot_uid, channel['id'], '⚠️ Something went wrong while running this command.', trigger_msg_id)
            continue
        for act in (res.get('actions') or [])[:20]:
            kind = act.get('type')
            if kind == 'send':
                content = str(act.get('content') or '').strip()
                target = act.get('channel_id') or channel['id']
                tc = db['channels'].get(target)
                if not content or not tc or tc.get('server_id') != server_info['id']:
                    continue
                if allowed and target not in allowed and not (tc.get('ticket_owner_id') and 'tickets' in (live.get('permissions') or [])):
                    continue
                if not _bs_rate_ok(inst['id']):
                    break
                reply_to = act.get('reply_to')
                if reply_to and db['all_messages'].get(reply_to, {}).get('channel_id') != target:
                    reply_to = None
                _bs_post(db, bot_uid, target, content, reply_to)
                changed = True
            elif kind == 'createChannel':
                srv = db['servers'].get(server_info['id'])
                why = _bs_admin_gate(bot, live, event, user_info, 'createChannel') if srv else 'Server not found.'
                new_ch = None
                if not why:
                    new_ch, why = _bs_create_channel(db, srv, bot_uid, inst['id'], event, user_info, act)
                if new_ch:
                    changed = True
                    first = str(act.get('message') or '').strip()
                    if first and new_ch.get('type') == 'text' and _bs_rate_ok(inst['id']):
                        _bs_post(db, bot_uid, new_ch['id'], first)
                else:
                    changed = True
                    _bs_admin_failed(db, live, bot_uid, event, channel, trigger_msg_id, why)
            elif kind == 'admin':
                srv = db['servers'].get(server_info['id'])
                why = _bs_admin_gate(bot, live, event, user_info, act.get('op')) if srv else 'Server not found.'
                if not why:
                    why = _bs_admin_run(db, srv, bot_uid, event, user_info, act, channel['id'])
                changed = True
                if why:
                    _bs_admin_failed(db, live, bot_uid, event, channel, trigger_msg_id, why)
            elif kind == 'ticket':
                srv = db['servers'].get(server_info['id'])
                why = _bs_ticket_gate(bot, live) if srv else 'Server not found.'
                if not why and event != 'message':
                    why = 'Tickets can only be handled from a command.'
                if not why:
                    why, _x = _bs_ticket_run(db, srv, bot_uid, inst['id'], user_info, act, channel['id'])
                changed = True
                if why:
                    _bs_admin_failed(db, live, bot_uid, event, channel, trigger_msg_id, why)
            elif kind == 'coins':
                srv = db['servers'].get(server_info['id'])
                why = _bs_coins_gate(bot, live, event, user_info) if srv else 'Server not found.'
                if not why:
                    why = _bs_coins_run(db, srv, bot_uid, channel['id'], user_info, act)
                changed = True
                if why:
                    _bs_admin_failed(db, live, bot_uid, event, channel, trigger_msg_id, why)
            elif kind == 'react':
                m = db['all_messages'].get(act.get('message_id'))
                emoji = str(act.get('emoji') or '')[:16]
                if m and emoji and db['channels'].get(m.get('channel_id'), {}).get('server_id') == server_info['id']:
                    users = m.setdefault('reactions', {}).setdefault(emoji, [])
                    if bot_uid not in users:
                        users.append(bot_uid)
                        changed = True
        new_storage = res.get('storage')
        if isinstance(new_storage, dict) and new_storage != old_storage:
            _bs_write_storage(inst['id'], new_storage)
    if changed:
        save_database(db)


def botshop_handle_message(message_id):
    """Called (in a thread) after a user message was saved: runs the commands / message handlers of the installed bots."""
    try:
        db = load_database()
        msg = db['all_messages'].get(message_id)
        if not msg:
            return
        author = db['users'].get(msg.get('user_id'))
        if not author or author.get('is_bot'):
            return                    # bots never trigger bots (no loops)
        channel = db['channels'].get(msg.get('channel_id'))
        server = db['servers'].get(channel['server_id']) if channel else None
        if not server:
            return
        bs = _bs(db)
        content = msg.get('content') or ''
        jobs = []
        for inst in bs['installs'].values():
            if inst['server_id'] != server['id'] or not inst.get('enabled', True):
                continue
            if inst.get('channel_ids') and channel['id'] not in inst['channel_ids'] \
                    and not (channel.get('ticket_owner_id') and 'tickets' in (inst.get('permissions') or [])):
                continue
            bot = bs['bots'].get(inst['bot_id'])
            if not bot:
                continue
            prefix = inst.get('prefix') or bot.get('prefix') or '!'
            matched = None
            if content.startswith(prefix):
                parts = content[len(prefix):].split(None, 1)
                if parts:
                    word = parts[0].lower()
                    for c in bot.get('commands', []):
                        if word == c['name'] or word in c.get('aliases', []):
                            matched = c['name']
                            break
            if matched or 'message' in bot.get('events', []):
                jobs.append((inst, bot, prefix, matched))
        if not jobs:
            return
        uid = msg['user_id']
        user_info = {'id': uid, 'username': author.get('username', 'User'), 'canManage': _bs_can_manage(db, uid, server),
                     'isOwner': server.get('owner_id') == uid}
        _bs_run_jobs(jobs, 'message', user_info, _bs_server_info(db, server), channel,
                     {'id': msg['id'], 'content': content}, msg['id'])
    except Exception as e:
        print(f'BotShop: error while handling a message: {e}')


def botshop_fire_member_join(server_id, user_id):
    """Called (in a thread) when somebody joins a server: runs the memberJoin handlers of its bots."""
    try:
        time.sleep(0.5)               # let the request that added the member finish saving first
        db = load_database()
        server = db['servers'].get(server_id)
        user = db['users'].get(user_id)
        if not server or not user or user.get('is_bot'):
            return
        bs = _bs(db)
        todo = []
        for inst in bs['installs'].values():
            if inst['server_id'] != server_id or not inst.get('enabled', True):
                continue
            bot = bs['bots'].get(inst['bot_id'])
            if not bot or 'memberJoin' not in bot.get('events', []):
                continue
            allowed = [c for c in _bs_text_channels(db, server_id) if not inst.get('channel_ids') or c['id'] in inst['channel_ids']]
            if not allowed:
                continue
            channel = next((c for c in allowed if c.get('name', '').lower() == 'general'), allowed[0])
            todo.append(((inst, bot, inst.get('prefix') or bot.get('prefix') or '!', None), channel))
        if not todo:
            return
        user_info = {'id': user_id, 'username': user.get('username', 'User'), 'canManage': _bs_can_manage(db, user_id, server),
                     'isOwner': server.get('owner_id') == user_id}
        server_info = _bs_server_info(db, server)
        for job, channel in todo:
            _bs_run_jobs([job], 'memberJoin', user_info, server_info, channel, None, None)
    except Exception as e:
        print(f'BotShop: error in memberJoin: {e}')


# ---------- API ----------
@app.route('/api/botshop/runtime')
@login_required
def botshop_runtime():
    return jsonify(_bot_runner.status())


@app.route('/api/botshop/bots')
@login_required
def botshop_list_bots():
    _bs_seed_if_needed()
    db = load_database()
    bs = _bs(db)
    counts = {}
    for inst in bs['installs'].values():
        counts[inst['bot_id']] = counts.get(inst['bot_id'], 0) + 1
    bots = [_bs_public_bot(b, counts.get(b['id'], 0)) for b in bs['bots'].values()]
    bots.sort(key=lambda b: (-b['installs'], b['name'].lower()))
    return jsonify({'bots': bots})


@app.route('/api/botshop/servers')
@login_required
def botshop_my_servers():
    """Servers the current user may install bots on, with their text channels and installed bots."""
    db = load_database()
    bs = _bs(db)
    out = []
    for server in db['servers'].values():
        if not _bs_can_manage(db, session['user_id'], server):
            continue
        out.append({
            'id': server['id'], 'name': server.get('name', ''), 'icon': server.get('icon'),
            'channels': [{'id': c['id'], 'name': c.get('name', '')} for c in _bs_text_channels(db, server['id'])],
            'installs': [{'id': i['id'], 'bot_id': i['bot_id'], 'channel_ids': i.get('channel_ids') or [], 'prefix': i.get('prefix') or '',
                          'enabled': i.get('enabled', True), 'last_error': i.get('last_error'),
                         'permissions': i.get('permissions') or []}
                         for i in bs['installs'].values() if i['server_id'] == server['id'] and i['bot_id'] in bs['bots']],
        })
    out.sort(key=lambda s: s['name'].lower())
    return jsonify({'servers': out})


def _bs_install_one(db, bot, server, user_id, channel_ids, prefix=None, enabled=None):
    """Install a bot on ONE server, or update the existing install (in memory - the caller saves the db).
    prefix=None / enabled=None keep the current value of an existing install.
    Returns (install, created, error_message)."""
    if not _bs_can_manage(db, user_id, server):
        return None, False, 'Only the server owner can install bots'

    valid = {c['id'] for c in _bs_text_channels(db, server['id'])}
    wanted = [c for c in (channel_ids or []) if c in valid]
    if channel_ids and not wanted:
        return None, False, 'Pick at least one valid channel (or choose all channels)'
    if prefix is not None:
        prefix = str(prefix).strip()
        if prefix and (len(prefix) > 3 or re.search(r'\s', prefix)):
            return None, False, 'The prefix must be 1 to 3 characters without spaces'

    bs = _bs(db)
    inst = next((i for i in bs['installs'].values() if i['bot_id'] == bot['id'] and i['server_id'] == server['id']), None)
    is_new = inst is None
    if is_new:
        iid = uuid.uuid4().hex[:12]
        inst = {'id': iid, 'bot_id': bot['id'], 'server_id': server['id'], 'installed_by': user_id,
                'installed_at': datetime.now().isoformat()}
        bs['installs'][iid] = inst
    inst['channel_ids'] = wanted
    _code = _bs_read_code(bot['id'])
    if _code:
        bot['permissions'] = _bs_parse_permissions(_bot_parse_meta(_code).get('permissions'))
    inst['permissions'] = list(bot.get('permissions') or [])      # saving the install dialog = the owner approves what the bot declares
    if prefix is not None or is_new:
        inst['prefix'] = prefix or ''
    if enabled is not None or is_new:
        inst['enabled'] = True if enabled is None else bool(enabled)
    inst.pop('last_error', None)

    bot_uid = _bs_ensure_bot_user(db, bot)
    if bot_uid not in server.setdefault('members', []):
        server['members'].append(bot_uid)
    server.setdefault('user_roles', {})[bot_uid] = ['member']

    if is_new:
        allowed = [c for c in _bs_text_channels(db, server['id']) if not wanted or c['id'] in wanted]
        if allowed:
            target = next((c for c in allowed if c.get('name', '').lower() == 'general'), allowed[0])
            who = db['users'].get(user_id, {}).get('username', 'Someone')
            _bs_post(db, bot_uid, target['id'],
                     f"👋 **{bot['name']}** was added by **{who}**. Type `{inst['prefix'] or bot.get('prefix') or '!'}help` to see what I can do.")
    return inst, is_new, None


@app.route('/api/botshop/install', methods=['POST'])
@login_required
def botshop_install():
    """Install / update a bot on a single server (kept for backwards compatibility)."""
    data = request.get_json(silent=True) or {}
    db = load_database()
    bs = _bs(db)
    bot = bs['bots'].get(data.get('bot_id'))
    server = db['servers'].get(data.get('server_id'))
    if not bot:
        return jsonify({'error': 'Bot not found'}), 404
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    inst, is_new, err = _bs_install_one(db, bot, server, session['user_id'], data.get('channel_ids'),
                                        data.get('prefix', ''), data.get('enabled', True))
    if err:
        return jsonify({'error': err}), (403 if err.startswith('Only the server owner') else 400)
    save_database(db)
    return jsonify({'success': True, 'install_id': inst['id'], 'created': is_new})


BOTSHOP_BULK_MAX = 100


@app.route('/api/botshop/install-bulk', methods=['POST'])
@login_required
def botshop_install_bulk():
    """Install / update one bot on MANY servers in one request.
    body: {bot_id, prefix?, enabled?, targets: [{server_id, channel_ids: []}]}   (channel_ids [] = all channels)
    Every server is checked on its own: one failing server never blocks the others."""
    data = request.get_json(silent=True) or {}
    targets = data.get('targets')
    if not isinstance(targets, list) or not targets:
        return jsonify({'error': 'Pick at least one server'}), 400
    if len(targets) > BOTSHOP_BULK_MAX:
        return jsonify({'error': f'Too many servers at once (max {BOTSHOP_BULK_MAX})'}), 400

    db = load_database()
    bs = _bs(db)
    bot = bs['bots'].get(data.get('bot_id'))
    if not bot:
        return jsonify({'error': 'Bot not found'}), 404
    prefix = data['prefix'] if 'prefix' in data else None     # absent = keep what each server already uses
    enabled = data['enabled'] if 'enabled' in data else None

    results, seen = [], set()
    for t in targets:
        if not isinstance(t, dict):
            continue
        sid = t.get('server_id')
        if not isinstance(sid, str) or sid in seen:
            continue
        seen.add(sid)
        server = db['servers'].get(sid)
        if not server:
            results.append({'server_id': sid, 'server_name': '', 'ok': False, 'error': 'Server not found'})
            continue
        ch = t.get('channel_ids')
        inst, is_new, err = _bs_install_one(db, bot, server, session['user_id'], ch if isinstance(ch, list) else [], prefix, enabled)
        if err:
            results.append({'server_id': sid, 'server_name': server.get('name', ''), 'ok': False, 'error': err})
        else:
            results.append({'server_id': sid, 'server_name': server.get('name', ''), 'ok': True,
                            'created': is_new, 'install_id': inst['id']})

    done = [r for r in results if r['ok']]
    if not done:
        first = results[0]['error'] if results else 'Pick at least one server'
        return jsonify({'error': first, 'results': results}), 400
    save_database(db)
    return jsonify({'success': True, 'results': results,
                    'installed': sum(1 for r in done if r['created']),
                    'updated': sum(1 for r in done if not r['created']),
                    'failed': len(results) - len(done)})


@app.route('/api/botshop/uninstall-bulk', methods=['POST'])
@login_required
def botshop_uninstall_bulk():
    """Remove a bot from many servers at once. body: {install_ids: []}"""
    data = request.get_json(silent=True) or {}
    ids = data.get('install_ids')
    if not isinstance(ids, list) or not ids:
        return jsonify({'error': 'Nothing selected'}), 400
    db = load_database()
    bs = _bs(db)
    removed, denied = [], []
    for iid in list(dict.fromkeys(i for i in ids if isinstance(i, str)))[:BOTSHOP_BULK_MAX]:
        inst = bs['installs'].get(iid)
        if not inst:
            continue
        server = db['servers'].get(inst['server_id'])
        if not _bs_can_manage(db, session['user_id'], server):
            denied.append(iid)
            continue
        _bs_remove_install(db, iid)
        removed.append(iid)
    if removed:
        save_database(db)
    if not removed and denied:
        return jsonify({'error': 'Permission denied'}), 403
    return jsonify({'success': True, 'removed': len(removed), 'denied': len(denied)})


@app.route('/api/botshop/installs/<install_id>', methods=['PUT', 'DELETE'])
@login_required
def botshop_install_manage(install_id):
    db = load_database()
    bs = _bs(db)
    inst = bs['installs'].get(install_id)
    if not inst:
        return jsonify({'error': 'Install not found'}), 404
    server = db['servers'].get(inst['server_id'])
    if not _bs_can_manage(db, session['user_id'], server):
        return jsonify({'error': 'Permission denied'}), 403
    if request.method == 'DELETE':
        _bs_remove_install(db, install_id)
        save_database(db)
        return jsonify({'success': True})
    data = request.get_json(silent=True) or {}
    if 'enabled' in data:
        inst['enabled'] = bool(data['enabled'])
    save_database(db)
    return jsonify({'success': True})


@app.route('/api/botshop/bots', methods=['POST'])
@admin_required
def botshop_upload_bot():
    data = request.get_json(silent=True) or {}
    db = load_database()
    bot, err = _bs_upsert_bot(db, data.get('code'), db['users'].get(session['user_id'], {}).get('username', ''))
    if err:
        return jsonify({'error': err}), 400
    save_database(db)
    return jsonify({'success': True, 'bot': _bs_public_bot(bot)})


@app.route('/api/botshop/bots/<bot_id>/code')
@admin_required
def botshop_bot_code(bot_id):
    code = _bs_read_code(re.sub(r'[^a-z0-9-]', '', bot_id))
    if code is None:
        return jsonify({'error': 'Bot not found'}), 404
    return jsonify({'code': code})


@app.route('/api/botshop/bots/<bot_id>', methods=['DELETE'])
@admin_required
def botshop_delete_bot(bot_id):
    db = load_database()
    bs = _bs(db)
    if bot_id not in bs['bots']:
        return jsonify({'error': 'Bot not found'}), 404
    for iid in [i for i, inst in bs['installs'].items() if inst['bot_id'] == bot_id]:
        _bs_remove_install(db, iid)
    del bs['bots'][bot_id]
    try:
        os.remove(os.path.join(BOTSHOP_BOTS_DIR, re.sub(r'[^a-z0-9-]', '', bot_id) + '.js'))
    except OSError:
        pass
    save_database(db)
    return jsonify({'success': True})


@app.route('/api/botshop/channels/<channel_id>/commands')
@login_required
def botshop_channel_commands(channel_id):
    """Commands the current user can use in a channel (powers the suggestion list above the chat input)."""
    db = load_database()
    channel = db['channels'].get(channel_id)
    server = db['servers'].get(channel['server_id']) if channel else None
    if not server or session['user_id'] not in server.get('members', []):
        return jsonify({'error': 'Not a member'}), 403
    can_manage = _bs_can_manage(db, session['user_id'], server)
    bs = _bs(db)
    out = []
    for inst in bs['installs'].values():
        if inst['server_id'] != server['id'] or not inst.get('enabled', True):
            continue
        if inst.get('channel_ids') and channel_id not in inst['channel_ids']:
            continue
        bot = bs['bots'].get(inst['bot_id'])
        if not bot:
            continue
        prefix = inst.get('prefix') or bot.get('prefix') or '!'
        for c in bot.get('commands', []):
            if c.get('adminOnly') and not can_manage:
                continue
            out.append({'bot_id': bot['id'], 'bot': bot['name'], 'icon': bot.get('icon', ''), 'color': bot.get('color', '#5865f2'),
                        'prefix': prefix, 'name': c['name'], 'aliases': c.get('aliases', []), 'description': c.get('description', ''),
                        'usage': c.get('usage', ''), 'adminOnly': bool(c.get('adminOnly'))})
    return jsonify({'commands': out})


# ============================================================
# RICH MESSAGES: MEDIA (image / video / audio / voice) + LOCATION + POLL
# Works for server channels AND direct messages (DM).
# ============================================================
import math as _math
import re as _re_rich
import time as _time_rich
import mimetypes as _mimetypes_rich

_mimetypes_rich.add_type('audio/webm', '.weba')
_mimetypes_rich.add_type('audio/ogg', '.opus')
_mimetypes_rich.add_type('audio/mp4', '.m4a')

# Allowed extensions + max size (MB) for every media type
MEDIA_RULES = {
    'image': {'ext': {'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'avif'}, 'max_mb': 10},
    'video': {'ext': {'mp4', 'webm', 'mov', 'm4v', 'ogv', 'mkv'}, 'max_mb': 50},
    'audio': {'ext': {'mp3', 'wav', 'ogg', 'oga', 'm4a', 'aac', 'flac', 'opus', 'weba', 'webm'}, 'max_mb': 20},
    'voice': {'ext': {'webm', 'ogg', 'oga', 'opus', 'm4a', 'mp4', 'wav', 'weba', 'mp3'}, 'max_mb': 10},
}
MEDIA_URL_RE = _re_rich.compile(r'^/uploads/([0-9a-f]{32})\.([a-z0-9]{2,5})$')

POLL_MAX_QUESTION = 200
POLL_MAX_OPTION = 80
POLL_MIN_OPTIONS = 2
POLL_MAX_OPTIONS = 10
POLL_MAX_DURATION_MIN = 60 * 24 * 30   # 30 days

poll_lock = threading.Lock()


def _clean_text(value, max_len):
    """Trim, drop control characters and cut to max_len."""
    value = str(value if value is not None else '')
    value = _re_rich.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value).strip()
    return value[:max_len]


# ---------------------------------------------------------------
# Upload endpoint (images / videos / audio files / voice messages)
# ---------------------------------------------------------------
@app.route('/api/upload/media', methods=['POST'])
@login_required
def upload_media():
    db = load_database()
    if not db.get('settings', {}).get('upload_enabled', True):
        return jsonify({'error': 'Uploads are disabled'}), 403

    media_type = (request.form.get('type') or '').lower()
    rule = MEDIA_RULES.get(media_type)
    if not rule:
        return jsonify({'error': 'Invalid media type'}), 400

    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if not file or not file.filename:
        return jsonify({'error': 'No selected file'}), 400

    max_bytes = rule['max_mb'] * 1024 * 1024
    if request.content_length and request.content_length > max_bytes + 1024 * 1024:
        return jsonify({'error': f'File too large (max {rule["max_mb"]} MB for {media_type})'}), 413

    original = file.filename
    ext = original.rsplit('.', 1)[1].lower() if '.' in original else ''
    if ext not in rule['ext']:
        return jsonify({'error': f'File type .{ext or "?"} is not allowed for {media_type}'}), 400

    filename = f"{uuid.uuid4().hex}.{ext}"
    path = os.path.join(UPLOAD_DIR, filename)
    try:
        file.save(path)
    except Exception as e:
        return jsonify({'error': 'Failed to save file', 'details': str(e)}), 500

    size = os.path.getsize(path)
    if size == 0 or size > max_bytes:
        try:
            os.remove(path)
        except OSError:
            pass
        if size == 0:
            return jsonify({'error': 'Empty file'}), 400
        return jsonify({'error': f'File too large (max {rule["max_mb"]} MB for {media_type})'}), 413

    try:
        duration = float(request.form.get('duration') or 0)
        if not _math.isfinite(duration) or duration < 0:
            duration = 0
        duration = min(duration, 6 * 3600)
    except (TypeError, ValueError):
        duration = 0

    name = 'Voice message' if media_type == 'voice' else (_clean_text(os.path.basename(original.replace('\\', '/')), 100) or filename)
    return jsonify({
        'success': True,
        'attachment': {
            'type': media_type,
            'url': f'/uploads/{filename}',
            'name': name,
            'size': size,
            'mime': _mimetypes_rich.guess_type(filename)[0] or 'application/octet-stream',
            'duration': round(duration, 1) if duration else None,
        }
    })


# ---------------------------------------------------------------
# Validation / sanitising of the payload sent by the client
# ---------------------------------------------------------------
def sanitize_attachment(att):
    """Returns (attachment_dict | None, error | None). Only files uploaded through /api/upload/media are accepted."""
    if not att:
        return None, None
    if not isinstance(att, dict):
        return None, 'Invalid attachment'
    atype = str(att.get('type', '')).lower()
    rule = MEDIA_RULES.get(atype)
    if not rule:
        return None, 'Invalid attachment type'
    m = MEDIA_URL_RE.match(str(att.get('url', '')))
    if not m:
        return None, 'Invalid attachment URL'
    ext = m.group(2)
    if ext not in rule['ext']:
        return None, 'Attachment extension does not match its type'
    filename = f'{m.group(1)}.{ext}'
    path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.isfile(path):
        return None, 'Attachment file not found'
    try:
        duration = float(att.get('duration') or 0)
        if not _math.isfinite(duration) or duration < 0:
            duration = 0
        duration = min(duration, 6 * 3600)
    except (TypeError, ValueError):
        duration = 0
    name = 'Voice message' if atype == 'voice' else (_clean_text(att.get('name'), 100) or filename)
    return {
        'type': atype,
        'url': f'/uploads/{filename}',
        'name': name,
        'size': os.path.getsize(path),
        'mime': _mimetypes_rich.guess_type(filename)[0] or 'application/octet-stream',
        'duration': round(duration, 1) if duration else None,
    }, None


def sanitize_location(loc):
    """Returns (location_dict | None, error | None)."""
    if not loc:
        return None, None
    if not isinstance(loc, dict):
        return None, 'Invalid location'
    try:
        lat = float(loc.get('lat'))
        lng = float(loc.get('lng'))
    except (TypeError, ValueError):
        return None, 'Invalid coordinates'
    if not (_math.isfinite(lat) and _math.isfinite(lng)) or not (-90 <= lat <= 90) or not (-180 <= lng <= 180):
        return None, 'Coordinates out of range'
    return {
        'lat': round(lat, 6),
        'lng': round(lng, 6),
        'label': _clean_text(loc.get('label'), 100),
    }, None


def sanitize_poll(p):
    """Returns (new_poll_dict | None, error | None). Votes always start empty."""
    if not p:
        return None, None
    if not isinstance(p, dict):
        return None, 'Invalid poll'
    question = _clean_text(p.get('question'), POLL_MAX_QUESTION)
    if not question:
        return None, 'Poll question is required'
    raw_options = p.get('options')
    if not isinstance(raw_options, list):
        return None, 'Poll options are required'

    texts, seen = [], set()
    for item in raw_options:
        text = item.get('text') if isinstance(item, dict) else item
        text = _clean_text(text, POLL_MAX_OPTION)
        if not text:
            continue
        key = text.lower()
        if key in seen:
            return None, 'Poll options must be unique'
        seen.add(key)
        texts.append(text)
    if len(texts) < POLL_MIN_OPTIONS:
        return None, f'A poll needs at least {POLL_MIN_OPTIONS} options'
    if len(texts) > POLL_MAX_OPTIONS:
        return None, f'A poll can have at most {POLL_MAX_OPTIONS} options'

    options = [{'id': f'o{i + 1}', 'text': t} for i, t in enumerate(texts)]
    now = datetime.now()
    closes_at, closes_ts = None, None
    try:
        minutes = int(p.get('duration_minutes') or 0)
    except (TypeError, ValueError):
        minutes = 0
    if minutes > 0:
        minutes = min(minutes, POLL_MAX_DURATION_MIN)
        closes_at = (now + timedelta(minutes=minutes)).isoformat()
        closes_ts = int(_time_rich.time() * 1000) + minutes * 60 * 1000

    return {
        'question': question,
        'options': options,
        'multiple': bool(p.get('multiple')),
        'closes_at': closes_at,
        'closes_ts': closes_ts,      # epoch ms (UTC) -> timezone independent check on the client
        'closed': False,
        'votes': {o['id']: [] for o in options},
    }, None


def parse_rich_payload(data):
    """
    Reads attachment / location / poll from a send-message request.
    Returns (attachment, location, poll, error_response). error_response is None when everything is fine.
    Only one of the three may be present in a single message.
    """
    raw_att = data.get('attachment')
    raw_loc = data.get('location')
    raw_poll = data.get('poll')
    if sum(1 for x in (raw_att, raw_loc, raw_poll) if x) > 1:
        return None, None, None, (jsonify({'error': 'Only one of attachment, location or poll can be sent in one message'}), 400)

    attachment, err = sanitize_attachment(raw_att)
    if err:
        return None, None, None, (jsonify({'error': err}), 400)
    location, err = sanitize_location(raw_loc)
    if err:
        return None, None, None, (jsonify({'error': err}), 400)
    poll, err = sanitize_poll(raw_poll)
    if err:
        return None, None, None, (jsonify({'error': err}), 400)
    return attachment, location, poll, None


def forward_rich_fields(msg):
    """Fields copied when a message is forwarded (a forwarded poll starts with fresh votes)."""
    poll = msg.get('poll')
    fresh = None
    if poll:
        fresh, _ = sanitize_poll({
            'question': poll.get('question'),
            'options': [o.get('text') for o in poll.get('options', [])],
            'multiple': poll.get('multiple'),
        })
    return {
        'attachment': msg.get('attachment'),
        'location': msg.get('location'),
        'poll': fresh,
    }


# ---------------------------------------------------------------
# Poll helpers
# ---------------------------------------------------------------
def poll_is_closed(poll):
    if poll.get('closed'):
        return True
    ts = poll.get('closes_ts')
    return bool(ts) and int(_time_rich.time() * 1000) >= ts


def apply_poll_vote(poll, user_id, option_ids):
    """Replaces the user's selection. Returns an error string or None."""
    if poll_is_closed(poll):
        return 'This poll is closed'
    valid = {o['id'] for o in poll.get('options', [])}
    chosen = [oid for oid in dict.fromkeys(option_ids) if isinstance(oid, str) and oid in valid]
    if not poll.get('multiple') and len(chosen) > 1:
        chosen = chosen[:1]
    votes = poll.setdefault('votes', {})
    for oid in valid:
        lst = votes.setdefault(oid, [])
        if user_id in lst:
            lst.remove(user_id)
    for oid in chosen:
        votes[oid].append(user_id)
    return None


def _poll_json(msg):
    return jsonify({'success': True, 'message_id': msg['id'], 'poll': msg['poll']})


def _dm_context(db, other_user_id):
    """Common DM checks. Returns (dm_key_str, error_response)."""
    if other_user_id not in db['users']:
        return None, (jsonify({'error': 'User not found'}), 404)
    me = db['users'].get(session['user_id'], {})
    other = db['users'].get(other_user_id, {})
    if other_user_id in me.get('blocked_users', []):
        return None, (jsonify({'error': 'You have blocked this user'}), 403)
    if session['user_id'] in other.get('blocked_users', []):
        return None, (jsonify({'error': 'You cannot interact with this user'}), 403)
    key = tuple(sorted([session['user_id'], other_user_id]))
    return f"dm_{'_'.join(key)}", None


def _channel_poll_message(db, message_id):
    """Returns (msg, server, error_response) for a channel poll message the current user can see."""
    msg = db['all_messages'].get(message_id)
    if not msg or not msg.get('poll'):
        return None, None, (jsonify({'error': 'Poll not found'}), 404)
    channel = db['channels'].get(msg.get('channel_id'))
    server = db['servers'].get(channel['server_id']) if channel else None
    if not server or session['user_id'] not in server.get('members', []):
        return None, None, (jsonify({'error': 'Not a member of this server'}), 403)
    return msg, server, None


# ---------------------------------------------------------------
# Poll routes - channels
# ---------------------------------------------------------------
@app.route('/api/messages/<message_id>/poll/vote', methods=['POST'])
@login_required
def vote_channel_poll(message_id):
    data = request.get_json(silent=True) or {}
    option_ids = data.get('option_ids', [])
    if not isinstance(option_ids, list):
        return jsonify({'error': 'option_ids must be a list'}), 400
    with poll_lock:
        db = load_database()
        msg, server, err = _channel_poll_message(db, message_id)
        if err:
            return err
        problem = apply_poll_vote(msg['poll'], session['user_id'], option_ids)
        if problem:
            return jsonify({'error': problem}), 400
        save_database(db)
        return _poll_json(msg)


@app.route('/api/messages/<message_id>/poll/close', methods=['POST'])
@login_required
def close_channel_poll(message_id):
    with poll_lock:
        db = load_database()
        msg, server, err = _channel_poll_message(db, message_id)
        if err:
            return err
        uid = session['user_id']
        server_id = db['channels'][msg['channel_id']]['server_id']
        allowed = (msg.get('user_id') == uid or server.get('owner_id') == uid
                   or has_permission(db, uid, server_id, 'manage_messages'))
        if not allowed:
            return jsonify({'error': 'Permission denied'}), 403
        msg['poll']['closed'] = True
        msg['poll']['closed_at'] = datetime.now().isoformat()
        save_database(db)
        return _poll_json(msg)


# ---------------------------------------------------------------
# Poll routes - direct messages
# ---------------------------------------------------------------
@app.route('/api/dm/<user_id>/messages/<message_id>/poll/vote', methods=['POST'])
@login_required
def vote_dm_poll(user_id, message_id):
    data = request.get_json(silent=True) or {}
    option_ids = data.get('option_ids', [])
    if not isinstance(option_ids, list):
        return jsonify({'error': 'option_ids must be a list'}), 400
    with poll_lock:
        db = load_database()
        dm_key_str, err = _dm_context(db, user_id)
        if err:
            return err
        msg = find_dm_message_by_id(db, dm_key_str, message_id)
        if not msg or not msg.get('poll'):
            return jsonify({'error': 'Poll not found'}), 404
        problem = apply_poll_vote(msg['poll'], session['user_id'], option_ids)
        if problem:
            return jsonify({'error': problem}), 400
        save_database(db)
        return _poll_json(msg)


@app.route('/api/dm/<user_id>/messages/<message_id>/poll/close', methods=['POST'])
@login_required
def close_dm_poll(user_id, message_id):
    with poll_lock:
        db = load_database()
        dm_key_str, err = _dm_context(db, user_id)
        if err:
            return err
        msg = find_dm_message_by_id(db, dm_key_str, message_id)
        if not msg or not msg.get('poll'):
            return jsonify({'error': 'Poll not found'}), 404
        if msg.get('user_id') != session['user_id']:
            return jsonify({'error': 'Only the creator can close this poll'}), 403
        msg['poll']['closed'] = True
        msg['poll']['closed_at'] = datetime.now().isoformat()
        save_database(db)
        return _poll_json(msg)


# ============================================================
# COSMETICS SHOP  |  CHANNEL INFO + NITRO  |  CHAT BACKGROUNDS
# همه‌ی داده‌ها داخل فایل‌های JSON ذخیره می‌شوند:
#   data/cosmetics.json        -> آیتم‌های فروشگاه (حلقه آواتار / افکت بیو)
#   data/chat_backgrounds.json -> پس‌زمینه چت هر کاربر (کانال / سرور / DM)
#   data/database.json         -> توضیحات و Nitro کانال و سرور + آیتم‌های هر کاربر
# ============================================================
import re as _re

COSMETICS_FILE = os.path.join(DATA_DIR, 'cosmetics.json')
BACKGROUNDS_FILE = os.path.join(DATA_DIR, 'chat_backgrounds.json')
cosmetics_lock = threading.RLock()

RING_STYLES = ('solid', 'gradient', 'spin', 'rainbow', 'pulse', 'glow')
BIO_EFFECTS = ('rainbow', 'neon', 'shimmer', 'glitch', 'fire', 'typewriter', 'sparkle', 'pulse')
BG_TYPES = ('color', 'gradient', 'image')
HEX_RE = _re.compile(r'^#[0-9a-fA-F]{6}$')


def _read_json_file(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                return default
            data = json.loads(content)
            return data if isinstance(data, type(default)) else default
    except (json.JSONDecodeError, OSError):
        return default


def _write_json_file(path, data):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def _seed_cosmetics():
    def mk(name, typ, **kw):
        iid = uuid.uuid4().hex[:8]
        item = {'id': iid, 'name': name, 'type': typ, 'description': kw.pop('description', ''),
                'nitro_only': kw.pop('nitro_only', False), 'colors': kw.pop('colors', []),
                'style': kw.pop('style', ''), 'effect': kw.pop('effect', ''),
                'active': True, 'created_at': datetime.now().isoformat()}
        item.update(kw)
        return iid, item
    items = {}
    for args in [
        ('Gold Ring', 'ring', dict(style='solid', colors=['#f5b301'])),
        ('Ocean Gradient', 'ring', dict(style='gradient', colors=['#00c6ff', '#0072ff'])),
        ('Sunset Spin', 'ring', dict(style='spin', colors=['#ff512f', '#f09819', '#ff512f'])),
        ('Rainbow', 'ring', dict(style='rainbow', colors=['#ff0000'])),
        ('Neon Glow', 'ring', dict(style='glow', colors=['#39ff14'], nitro_only=True)),
        ('Rainbow Bio', 'bio_effect', dict(effect='rainbow', colors=['#ff0080', '#00cfff'])),
        ('Neon Bio', 'bio_effect', dict(effect='neon', colors=['#39ff14', '#00ffd5'])),
        ('Shimmer Bio', 'bio_effect', dict(effect='shimmer', colors=['#aaaaaa', '#ffffff'])),
        ('Fire Bio', 'bio_effect', dict(effect='fire', colors=['#ff4500', '#ffd000'], nitro_only=True)),
    ]:
        iid, item = mk(args[0], args[1], **args[2])
        items[iid] = item
    return {'items': items}


def load_cosmetics():
    with cosmetics_lock:
        data = _read_json_file(COSMETICS_FILE, {})
        if not isinstance(data.get('items'), dict):
            data = _seed_cosmetics()
            _write_json_file(COSMETICS_FILE, data)
        return data


def save_cosmetics(data):
    with cosmetics_lock:
        _write_json_file(COSMETICS_FILE, data)


def _clean_colors(colors, minimum=1, maximum=6):
    if not isinstance(colors, list):
        return None
    out = [c for c in colors if isinstance(c, str) and HEX_RE.match(c)]
    if len(out) < minimum:
        return None
    return out[:maximum]


def _is_admin_user(db, uid):
    return bool(db['users'].get(uid, {}).get('is_admin'))


def _can_use_nitro_items(user):
    return bool(user.get('is_admin') or user.get('is_premium') or user.get('is_nitro'))


def _cosmetic_payload(item):
    """Small dict copied onto the user so every client can render it."""
    if item['type'] == 'ring':
        return {'id': item['id'], 'name': item['name'], 'style': item.get('style', 'solid'),
                'colors': item.get('colors', [])}
    return {'id': item['id'], 'name': item['name'], 'effect': item.get('effect', 'rainbow'),
            'colors': item.get('colors', [])}


def _cos_state(user):
    st = user.setdefault('cosmetics', {})
    st.setdefault('owned', [])
    st.setdefault('ring', None)
    st.setdefault('bio_effect', None)
    return st


def _validate_item(data, existing=None):
    typ = data.get('type', (existing or {}).get('type'))
    if typ not in ('ring', 'bio_effect'):
        return None, 'type must be ring or bio_effect'
    name = str(data.get('name', (existing or {}).get('name', ''))).strip()[:40]
    if not name:
        return None, 'name is required'
    colors = _clean_colors(data.get('colors', (existing or {}).get('colors', [])), 1, 6)
    if colors is None:
        return None, 'at least one valid #RRGGBB color is required'
    item = dict(existing or {})
    item.update({
        'name': name, 'type': typ, 'colors': colors,
        'description': str(data.get('description', item.get('description', '')))[:200],
        'nitro_only': bool(data.get('nitro_only', item.get('nitro_only', False))),
        'active': bool(data.get('active', item.get('active', True))),
    })
    if typ == 'ring':
        style = data.get('style', item.get('style', 'solid'))
        if style not in RING_STYLES:
            return None, 'invalid ring style'
        if style in ('gradient', 'spin') and len(colors) < 2:
            return None, 'this style needs at least 2 colors'
        item['style'] = style
        item['effect'] = ''
    else:
        effect = data.get('effect', item.get('effect', 'rainbow'))
        if effect not in BIO_EFFECTS:
            return None, 'invalid bio effect'
        item['effect'] = effect
        item['style'] = ''
    return item, None


@app.route('/api/cosmetics/items', methods=['GET'])
@login_required
def cosmetics_list():
    db = load_database()
    user = db['users'].get(session['user_id'], {})
    st = _cos_state(user)
    items = []
    for it in load_cosmetics()['items'].values():
        if not it.get('active', True) and not user.get('is_admin'):
            continue
        row = dict(it)
        row['owned'] = it['id'] in st['owned']
        row['equipped'] = st.get(it['type']) == it['id']
        items.append(row)
    items.sort(key=lambda x: x.get('created_at', ''))
    return jsonify({'items': items, 'equipped': {'ring': st['ring'], 'bio_effect': st['bio_effect']},
                    'can_use_nitro': _can_use_nitro_items(user)})


@app.route('/api/cosmetics/items', methods=['POST'])
@admin_required
def cosmetics_create():
    item, err = _validate_item((request.get_json(silent=True) or {}) or {})
    if err:
        return jsonify({'error': err}), 400
    item['id'] = uuid.uuid4().hex[:8]
    item['created_at'] = datetime.now().isoformat()
    data = load_cosmetics()
    data['items'][item['id']] = item
    save_cosmetics(data)
    return jsonify({'success': True, 'item': item})


@app.route('/api/cosmetics/items/<item_id>', methods=['PUT'])
@admin_required
def cosmetics_update(item_id):
    data = load_cosmetics()
    existing = data['items'].get(item_id)
    if not existing:
        return jsonify({'error': 'Item not found'}), 404
    body = (request.get_json(silent=True) or {}) or {}
    body['type'] = existing['type']  # نوع آیتم قابل تغییر نیست
    item, err = _validate_item(body, existing)
    if err:
        return jsonify({'error': err}), 400
    data['items'][item_id] = item
    save_cosmetics(data)
    # آپدیت نسخه‌ی کپی‌شده روی کاربرانی که این آیتم را فعال دارند
    db = load_database()
    changed = False
    for u in db['users'].values():
        st = u.get('cosmetics') or {}
        if st.get(item['type']) == item_id:
            u['avatar_ring' if item['type'] == 'ring' else 'bio_effect'] = _cosmetic_payload(item)
            changed = True
    if changed:
        save_database(db)
    return jsonify({'success': True, 'item': item})


@app.route('/api/cosmetics/items/<item_id>', methods=['DELETE'])
@admin_required
def cosmetics_delete(item_id):
    data = load_cosmetics()
    item = data['items'].pop(item_id, None)
    if not item:
        return jsonify({'error': 'Item not found'}), 404
    save_cosmetics(data)
    db = load_database()
    for u in db['users'].values():
        st = u.get('cosmetics')
        if not st:
            continue
        if item_id in st.get('owned', []):
            st['owned'].remove(item_id)
        if st.get(item['type']) == item_id:
            st[item['type']] = None
            u['avatar_ring' if item['type'] == 'ring' else 'bio_effect'] = None
    save_database(db)
    return jsonify({'success': True})


@app.route('/api/cosmetics/claim/<item_id>', methods=['POST'])
@login_required
def cosmetics_claim(item_id):
    item = load_cosmetics()['items'].get(item_id)
    if not item or not item.get('active', True):
        return jsonify({'error': 'Item not found'}), 404
    db = load_database()
    user = db['users'].get(session['user_id'])
    if item.get('nitro_only') and not _can_use_nitro_items(user):
        return jsonify({'error': 'This item needs Nitro'}), 403
    st = _cos_state(user)
    if item_id not in st['owned']:
        st['owned'].append(item_id)
    save_database(db)
    return jsonify({'success': True})


@app.route('/api/cosmetics/equip', methods=['POST'])
@login_required
def cosmetics_equip():
    body = (request.get_json(silent=True) or {}) or {}
    typ = body.get('type')
    item_id = body.get('item_id')
    if typ not in ('ring', 'bio_effect'):
        return jsonify({'error': 'Invalid type'}), 400
    db = load_database()
    user = db['users'].get(session['user_id'])
    st = _cos_state(user)
    field = 'avatar_ring' if typ == 'ring' else 'bio_effect'
    if not item_id:
        st[typ] = None
        user[field] = None
    else:
        item = load_cosmetics()['items'].get(item_id)
        if not item or item['type'] != typ:
            return jsonify({'error': 'Item not found'}), 404
        if item_id not in st['owned']:
            return jsonify({'error': 'Claim this item first'}), 403
        if item.get('nitro_only') and not _can_use_nitro_items(user):
            return jsonify({'error': 'This item needs Nitro'}), 403
        st[typ] = item_id
        user[field] = _cosmetic_payload(item)
    save_database(db)
    return jsonify({'success': True, 'avatar_ring': user.get('avatar_ring'), 'bio_effect': user.get('bio_effect')})


# ---------------- Channel description + Nitro ----------------
SLOWMODE_CHOICES = (0, 5, 10, 15, 30, 60, 120, 300, 600, 3600)   # seconds; 0 = off


def _can_edit_channel(db, uid, channel):
    server = db['servers'].get(channel.get('server_id'), {})
    return bool(uid and server.get('owner_id') == uid)


@app.route('/api/channels/<channel_id>/settings', methods=['PUT'])
@login_required
def update_channel_settings(channel_id):
    db = load_database()
    channel = db['channels'].get(channel_id)
    if not channel:
        return jsonify({'error': 'Channel not found'}), 404
    uid = session['user_id']
    body = (request.get_json(silent=True) or {}) or {}
    if any(k != 'nitro' for k in body) and not _can_edit_channel(db, uid, channel):
        return owner_only_response('Only the server owner can change channel settings')
    if 'description' in body:
        if not _can_edit_channel(db, uid, channel):
            return jsonify({'error': 'Permission denied'}), 403
        channel['description'] = str(body.get('description') or '').strip()[:500]
    if 'name' in body:
        if not _can_edit_channel(db, uid, channel):
            return jsonify({'error': 'Permission denied'}), 403
        new_name = str(body.get('name') or '').strip()[:50]
        if new_name:
            channel['name'] = new_name
    if 'category_id' in body:
        if not _can_edit_channel(db, uid, channel):
            return jsonify({'error': 'Permission denied'}), 403
        new_cat = body.get('category_id') or None
        if new_cat is not None:
            cat = db['categories'].get(new_cat)
            if not cat or cat.get('server_id') != channel.get('server_id'):
                return jsonify({'error': 'Invalid category'}), 400
        channel['category_id'] = new_cat
    if 'slowmode' in body:
        if not _can_edit_channel(db, uid, channel):
            return jsonify({'error': 'Permission denied'}), 403
        try:
            slow = int(body.get('slowmode') or 0)
        except (TypeError, ValueError):
            return jsonify({'error': 'Invalid slowmode'}), 400
        if slow not in SLOWMODE_CHOICES:
            return jsonify({'error': 'Invalid slowmode'}), 400
        channel['slowmode'] = slow
    if 'nsfw' in body:
        if not _can_edit_channel(db, uid, channel):
            return jsonify({'error': 'Permission denied'}), 403
        channel['nsfw'] = bool(body.get('nsfw'))
    if 'nitro' in body:
        if not (ADMIN_CAN_SET_NITRO and _is_admin_user(db, uid)):
            return jsonify({'error': 'Only an admin can change Nitro'}), 403
        channel['nitro'] = bool(body['nitro'])
    if any(k in body for k in ('private', 'private_members', 'view_only_members', 'read_only', 'password', 'remove_password')):
        if not _can_edit_channel(db, uid, channel):
            return jsonify({'error': 'Permission denied'}), 403
    server = db['servers'].get(channel.get('server_id')) or {}
    if 'private' in body:
        channel['private'] = bool(body.get('private'))
    if 'private_members' in body:
        channel['private_members'] = _clean_member_ids(db, server, body.get('private_members'))
    if 'view_only_members' in body:
        channel['view_only_members'] = _clean_member_ids(db, server, body.get('view_only_members'))
    # a member is either 'chat' or 'view only', never both
    channel['view_only_members'] = [u for u in (channel.get('view_only_members') or [])
                                    if u not in (channel.get('private_members') or [])]
    if 'read_only' in body:
        channel['read_only'] = bool(body.get('read_only'))
    if body.get('remove_password'):
        channel.pop('password_hash', None)
        channel['unlocked_users'] = []
    elif body.get('password'):
        pw = str(body.get('password'))
        if _password_error(pw):
            return jsonify({'error': _password_error(pw)}), 400
        channel['password_hash'] = generate_password_hash(pw)
        channel['unlocked_users'] = []      # everybody must enter the new password
    save_database(db)
    return jsonify({'success': True, 'channel': public_channel(db, channel, uid)})


@app.route('/api/servers/<server_id>/nitro', methods=['PUT'])
@login_required
def set_server_nitro(server_id):
    db = load_database()
    if not (ADMIN_CAN_SET_NITRO and _is_admin_user(db, session['user_id'])):
        return jsonify({'error': 'Only an admin can change Nitro'}), 403
    server = db['servers'].get(server_id)
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    server['nitro'] = bool(((request.get_json(silent=True) or {}) or {}).get('nitro'))
    save_database(db)
    return jsonify({'success': True, 'nitro': server['nitro']})


# ---------------- Chat backgrounds (per user, per context) ----------------
def _bg_context_nitro(db, context):
    kind, _, ident = context.partition(':')
    if kind == 'channel':
        ch = db['channels'].get(ident, {})
        return bool(ch.get('nitro') or db['servers'].get(ch.get('server_id'), {}).get('nitro'))
    if kind == 'server':
        return bool(db['servers'].get(ident, {}).get('nitro'))
    return False


def _clean_background(bg):
    if not isinstance(bg, dict) or bg.get('type') not in BG_TYPES:
        return None, 'invalid background'
    out = {'type': bg['type']}
    try:
        out['dim'] = max(0.0, min(0.85, float(bg.get('dim', 0.0))))
    except (TypeError, ValueError):
        out['dim'] = 0.0
    if bg['type'] == 'color':
        c = bg.get('color')
        if not (isinstance(c, str) and HEX_RE.match(c)):
            return None, 'invalid color'
        out['color'] = c
    elif bg['type'] == 'gradient':
        colors = _clean_colors(bg.get('colors'), 2, 4)
        if not colors:
            return None, 'gradient needs 2-4 colors'
        out['colors'] = colors
        try:
            out['angle'] = int(bg.get('angle', 135)) % 360
        except (TypeError, ValueError):
            out['angle'] = 135
        out['animated'] = bool(bg.get('animated', False))
    else:
        url = bg.get('url')
        if not (isinstance(url, str) and url.startswith('/uploads/') and '..' not in url
                and len(url) < 200 and _re.match(r'^/uploads/[\w.\-]+$', url)):
            return None, 'invalid image'
        out['url'] = url
    return out, None


@app.route('/api/chat-backgrounds', methods=['GET'])
@login_required
def get_chat_backgrounds():
    data = _read_json_file(BACKGROUNDS_FILE, {})
    return jsonify(data.get(session['user_id'], {}))


@app.route('/api/chat-backgrounds', methods=['PUT'])
@login_required
def set_chat_background():
    body = (request.get_json(silent=True) or {}) or {}
    context = str(body.get('context', ''))
    if not _re.match(r'^(global|dm:\*|(channel|server|dm):[\w\-]{1,64})$', context):
        return jsonify({'error': 'Invalid context'}), 400
    db = load_database()
    bg = body.get('background')
    if bg is not None:
        bg, err = _clean_background(bg)
        if err:
            return jsonify({'error': err}), 400
        user = db['users'].get(session['user_id'], {})
        if bg['type'] == 'gradient' and bg.get('animated'):
            if not (_can_use_nitro_items(user) or _bg_context_nitro(db, context)):
                return jsonify({'error': 'Animated backgrounds need Nitro (user or channel/server)'}), 403
    with cosmetics_lock:
        data = _read_json_file(BACKGROUNDS_FILE, {})
        mine = data.setdefault(session['user_id'], {})
        if bg is None:
            mine.pop(context, None)
        else:
            mine[context] = bg
        _write_json_file(BACKGROUNDS_FILE, data)
    return jsonify({'success': True, 'backgrounds': mine})



# ============================================================
# ADMIN CONSOLE v2 + REPORTS SYSTEM
# (added block - nothing above this line was removed or changed)
#   - /api/admin2/...   full admin console (users, badges, servers,
#                       messages, reports, settings, audit, broadcast)
#   - /api/reports...   user-side report submission
#   - /api/custom-badges, /api/announcement  (public read-only helpers)
# ============================================================
import re as _adm_re

ADM2_PROTECTED_USERNAMES = ['admin', 'aminsoft356']
ADM2_BADGE_KEYS = ['vip', 'staff', 'developer', 'verified', 'nitro', 'partner',
                   'early_supporter', 'bug_hunter', 'translator', 'support',
                   'active', 'moderator', 'bot']
ADM2_PREFIX_ONLY_BADGES = ('active', 'moderator', 'bot')   # stored only as is_<name>
ADM2_STATUSES = ('online', 'idle', 'dnd', 'offline')
ADM2_HOUSES = ('bravery', 'brilliance', 'balance')
ADM2_SETTING_DEFAULTS = {
    'registration_enabled': True,
    'store_enabled': True,
    'upload_enabled': True,
    'reports_enabled': True,
    'maintenance_mode': False,
    'maintenance_message': 'The site is under maintenance. Please try again later.',
    'announcement_text': '',
    'announcement_level': 'info',
    'announcement_id': '',
}

REPORT_REASONS = {
    'spam': 'Spam',
    'harassment': 'Harassment or bullying',
    'hate': 'Hate speech',
    'nsfw': 'Inappropriate / NSFW content',
    'violence': 'Violence or threats',
    'scam': 'Scam or phishing',
    'impersonation': 'Impersonation',
    'self_harm': 'Self-harm',
    'illegal': 'Illegal content',
    'other': 'Other',
}
REPORT_TYPES = ('message', 'user', 'channel', 'server', 'dm', 'pack')
REPORT_STATUSES = ('open', 'reviewing', 'resolved', 'dismissed')
REPORT_PRIORITIES = ('low', 'normal', 'high', 'urgent')


# ---------- helpers ----------
def _adm2_now():
    return datetime.now().isoformat()


def _adm2_dt(value):
    try:
        return datetime.fromisoformat(value) if value else None
    except (TypeError, ValueError):
        return None


def _adm2_uname(db, uid):
    if uid == 'system':
        return 'System'
    return db['users'].get(uid, {}).get('username', 'Unknown')


def _adm2_is_protected(user):
    return (user.get('username') or '').lower() in ADM2_PROTECTED_USERNAMES


def _adm2_settings(db):
    s = dict(ADM2_SETTING_DEFAULTS)
    s.update(db.get('settings', {}) or {})
    return s


def _adm2_audit(db, action, target_type=None, target_id=None, details=None):
    log = db.setdefault('admin_audit', [])
    uid = session.get('user_id')
    log.append({
        'id': uuid.uuid4().hex[:10],
        'at': _adm2_now(),
        'admin_id': uid,
        'admin_name': db['users'].get(uid, {}).get('username', 'Unknown'),
        'action': action,
        'target_type': target_type,
        'target_id': target_id,
        'details': details or {},
    })
    if len(log) > 3000:
        del log[:len(log) - 3000]


def _adm2_notify(db, user_id, title, message, ntype='admin_message', extra=None):
    n = {
        'id': uuid.uuid4().hex[:12],
        'user_id': user_id,
        'type': ntype,
        'title': title,
        'message': message,
        'read': False,
        'created_at': _adm2_now(),
    }
    if extra:
        n.update(extra)
    db.setdefault('notifications', []).append(n)
    # also show it in the user's DMs: pinned, read-only system conversation
    try:
        sys_id = 'adminwarn' if ntype in SYSTEM_DM_WARN_TYPES else 'discordsys'
        icon = '⚠️' if sys_id == 'adminwarn' else '📢'
        body = f"{icon} **{title}**\n{message}" if title else str(message)
        post_system_dm(db, user_id, sys_id, body)
    except Exception as e:
        print(f'System DM error: {e}')


def _adm2_get_badge(user, key):
    if key in ADM2_PREFIX_ONLY_BADGES:
        return bool(user.get('is_' + key))
    return bool(user.get(key) or user.get('is_' + key))


def _adm2_set_badge(user, key, value):
    value = bool(value)
    user['is_' + key] = value
    if key not in ADM2_PREFIX_ONLY_BADGES:
        user[key] = value


def _adm2_badges_of(user):
    return {k: _adm2_get_badge(user, k) for k in ADM2_BADGE_KEYS}


def _adm2_slim_user(u):
    return {
        'id': u.get('id'),
        'username': u.get('username'),
        'email': u.get('email'),
        'avatar': u.get('avatar'),
        'avatar_color': u.get('avatar_color', '#7289da'),
        'status': u.get('status', 'offline'),
        'is_admin': bool(u.get('is_admin')),
        'is_premium': bool(u.get('is_premium')),
        'coins': u.get('coins', 0),
        'created_at': u.get('created_at'),
        'last_seen': u.get('last_seen'),
        'badges': _adm2_badges_of(u),
        'custom_badges': u.get('custom_badges', []),
        'suspended': bool(u.get('suspended')),
        'suspended_until': u.get('suspended_until'),
        'reputation': u.get('reputation', 0),
    }


def _adm2_full_user(u):
    d = {k: v for k, v in u.items() if k not in ('password', 'devices')}
    d['badges'] = _adm2_badges_of(u)
    d['custom_badges'] = u.get('custom_badges', [])
    d['device_count'] = len(u.get('devices', []) or [])
    return d


def _adm2_valid_color(c, default=None):
    if isinstance(c, str) and _adm_re.match(r'^#[0-9a-fA-F]{6}$', c):
        return c
    return default


def _adm2_int(value, lo, hi, default=0):
    try:
        v = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))


def _adm2_dm_key(a, b):
    return f"dm_{'_'.join(sorted([a, b]))}"


# ---------- suspension (cached so the request hook stays cheap) ----------
_ADM2_SUSPENDED = {}
_adm2_susp_lock = threading.Lock()
_adm2_susp_loaded = {'v': False}


def _adm2_reload_suspensions(db=None):
    db = db or load_database()
    with _adm2_susp_lock:
        _ADM2_SUSPENDED.clear()
        for uid, u in db['users'].items():
            if u.get('suspended') and not u.get('is_admin'):
                _ADM2_SUSPENDED[uid] = {
                    'until': u.get('suspended_until'),
                    'reason': u.get('suspended_reason', ''),
                    'email': (u.get('email') or '').lower(),
                }
        _adm2_susp_loaded['v'] = True


def _adm2_active_suspension(uid):
    info = _ADM2_SUSPENDED.get(uid)
    if not info:
        return None
    until = _adm2_dt(info.get('until'))
    if until and until < datetime.now():
        return None
    return info


def _adm2_apply_suspension(db, uid, suspend, hours=None, reason=''):
    user = db['users'].get(uid)
    if not user:
        return False, 'User not found'
    if user.get('is_admin'):
        return False, 'Admins cannot be suspended'
    if suspend:
        user['suspended'] = True
        user['suspended_reason'] = (reason or '')[:300]
        user['suspended_at'] = _adm2_now()
        user['suspended_until'] = None
        if hours:
            user['suspended_until'] = (datetime.now() + timedelta(hours=_adm2_int(hours, 1, 24 * 365, 24))).isoformat()
        user['status'] = 'offline'
        _adm2_notify(db, uid, 'Account suspended', user['suspended_reason'] or 'Your account was suspended by an administrator.', 'suspension')
    else:
        user['suspended'] = False
        user['suspended_until'] = None
        user['suspended_reason'] = ''
        _adm2_notify(db, uid, 'Suspension lifted', 'Your account is active again.', 'suspension')
    return True, 'ok'


_adm2_gate_cache = {'mtime': None, 'settings': dict(ADM2_SETTING_DEFAULTS), 'admins': set()}
_adm2_gate_lock = threading.Lock()


def _adm2_gate_info():
    """Cheap per-request lookup: re-reads the database only when the file changed."""
    try:
        mt = os.path.getmtime(DB_FILE)
    except OSError:
        return _adm2_gate_cache
    if _adm2_gate_cache['mtime'] != mt:
        with _adm2_gate_lock:
            try:
                db = load_database()
                _adm2_gate_cache['settings'] = _adm2_settings(db)
                _adm2_gate_cache['admins'] = {uid for uid, u in db['users'].items() if u.get('is_admin')}
                _adm2_gate_cache['mtime'] = mt
            except Exception:
                pass
    return _adm2_gate_cache


@app.before_request
def _adm2_request_gate():
    """Blocks suspended users, applies maintenance mode and the upload switch."""
    path = request.path
    if not path.startswith('/api/'):
        return None
    if not _adm2_susp_loaded['v']:
        try:
            _adm2_reload_suspensions()
        except Exception:
            _adm2_susp_loaded['v'] = True
    uid = session.get('user_id')

    # suspended users: everything blocked except logout
    if uid and uid in _ADM2_SUSPENDED and path != '/api/logout':
        info = _adm2_active_suspension(uid)
        if info:
            return jsonify({'error': 'Account suspended', 'suspended': True,
                            'reason': info.get('reason', ''), 'until': info.get('until')}), 403

    # suspended users also cannot log in again
    if path == '/api/login' and request.method == 'POST' and _ADM2_SUSPENDED:
        body = request.get_json(silent=True) or {}
        em = (body.get('email') or '').strip().lower()
        for suid, info in _ADM2_SUSPENDED.items():
            if info.get('email') == em and _adm2_active_suspension(suid):
                return jsonify({'error': 'Account suspended', 'suspended': True,
                                'reason': info.get('reason', ''), 'until': info.get('until')}), 403

    if path in ('/api/login', '/api/logout') or path.startswith('/api/admin') or not uid:
        return None

    info = _adm2_gate_info()
    if uid in info['admins']:
        return None
    settings = info['settings']
    if settings.get('maintenance_mode'):
        return jsonify({'error': 'maintenance', 'maintenance': True,
                        'message': settings.get('maintenance_message')}), 503
    if path.startswith('/api/upload') and not settings.get('upload_enabled', True):
        if request.form.get('type') not in ('avatar', 'banner'):
            return jsonify({'error': 'Uploads are disabled by the administrator'}), 403
    return None


# ---------- public helpers ----------
@app.route('/api/announcement')
@login_required
def adm2_public_announcement():
    s = _adm2_settings(load_database())
    if not (s.get('announcement_text') or '').strip():
        return jsonify({'active': False})
    return jsonify({'active': True, 'id': s.get('announcement_id'),
                    'text': s.get('announcement_text'), 'level': s.get('announcement_level', 'info')})


@app.route('/api/custom-badges')
@login_required
def adm2_public_custom_badges():
    return jsonify(list((load_database().get('custom_badges') or {}).values()))


@app.route('/api/reports/reasons')
@login_required
def rpt_reasons():
    s = _adm2_settings(load_database())
    return jsonify({'reasons': REPORT_REASONS, 'types': REPORT_TYPES, 'enabled': bool(s.get('reports_enabled', True))})


# ============================================================
# ADMIN: OVERVIEW
# ============================================================
@app.route('/api/admin2/overview')
@admin_required
def adm2_overview():
    db = load_database()
    now = datetime.now()
    users = db['users']
    created = [(_adm2_dt(u.get('created_at')), u) for u in users.values()]
    new24 = sum(1 for d, _ in created if d and now - d < timedelta(hours=24))
    new7 = sum(1 for d, _ in created if d and now - d < timedelta(days=7))
    online = sum(1 for u in users.values() if u.get('status') in ('online', 'idle', 'dnd'))

    # messages per day (last 7 days) - channel messages + DMs
    days = {}
    for i in range(6, -1, -1):
        days[(now - timedelta(days=i)).strftime('%Y-%m-%d')] = 0
    for m in db.get('all_messages', {}).values():
        k = (m.get('created_at') or '')[:10]
        if k in days:
            days[k] += 1
    dm_total = 0
    for lst in db.get('direct_messages', {}).values():
        dm_total += len(lst)
        for m in lst:
            k = (m.get('created_at') or '')[:10]
            if k in days:
                days[k] += 1

    signups = {}
    for i in range(6, -1, -1):
        signups[(now - timedelta(days=i)).strftime('%Y-%m-%d')] = 0
    for d, _ in created:
        if d and d.strftime('%Y-%m-%d') in signups:
            signups[d.strftime('%Y-%m-%d')] += 1

    reports = db.get('reports', {}) or {}
    rc = {s: 0 for s in REPORT_STATUSES}
    for r in reports.values():
        rc[r.get('status', 'open')] = rc.get(r.get('status', 'open'), 0) + 1

    top_servers = sorted(db['servers'].values(), key=lambda s: len(s.get('members', [])), reverse=True)[:6]
    recent_users = sorted(users.values(), key=lambda u: u.get('created_at') or '', reverse=True)[:8]
    recent_reports = sorted(reports.values(), key=lambda r: r.get('created_at') or '', reverse=True)[:6]

    upload_count, upload_bytes = 0, 0
    try:
        for fn in os.listdir(UPLOAD_DIR):
            p = os.path.join(UPLOAD_DIR, fn)
            if os.path.isfile(p):
                upload_count += 1
                upload_bytes += os.path.getsize(p)
    except OSError:
        pass
    try:
        db_bytes = os.path.getsize(DB_FILE)
    except OSError:
        db_bytes = 0

    return jsonify({
        'users': len(users), 'online': online, 'new_24h': new24, 'new_7d': new7,
        'admins': sum(1 for u in users.values() if u.get('is_admin')),
        'premium': sum(1 for u in users.values() if u.get('is_premium')),
        'suspended': sum(1 for u in users.values() if u.get('suspended')),
        'servers': len(db['servers']), 'channels': len(db['channels']),
        'messages': len(db.get('all_messages', {})), 'dm_messages': dm_total,
        'store_items': len(db.get('store_items', {})),
        'custom_badges': len(db.get('custom_badges', {}) or {}),
        'reports': rc, 'reports_total': len(reports),
        'messages_per_day': [{'day': k, 'count': v} for k, v in days.items()],
        'signups_per_day': [{'day': k, 'count': v} for k, v in signups.items()],
        'top_servers': [{'id': s['id'], 'name': s.get('name'), 'members': len(s.get('members', [])),
                         'icon': s.get('icon')} for s in top_servers],
        'recent_users': [_adm2_slim_user(u) for u in recent_users],
        'recent_reports': [{'id': r['id'], 'type': r['type'], 'reason_label': r.get('reason_label'),
                            'status': r.get('status'), 'reporter_name': r.get('reporter_name'),
                            'created_at': r.get('created_at')} for r in recent_reports],
        'upload_count': upload_count, 'upload_mb': round(upload_bytes / 1048576, 2),
        'db_mb': round(db_bytes / 1048576, 2),
    })


# ============================================================
# ADMIN: USERS
# ============================================================
@app.route('/api/admin2/users')
@admin_required
def adm2_users():
    db = load_database()
    q = (request.args.get('q') or '').strip().lower()
    flt = request.args.get('filter', 'all')
    sort = request.args.get('sort', 'newest')
    page = _adm2_int(request.args.get('page', 1), 1, 100000, 1)
    per = _adm2_int(request.args.get('per', 30), 5, 100, 30)

    rows = list(db['users'].values())
    if q:
        rows = [u for u in rows if q in (u.get('username') or '').lower()
                or q in (u.get('email') or '').lower() or q == (u.get('id') or '').lower()]
    flt_map = {
        'admin': lambda u: u.get('is_admin'),
        'premium': lambda u: u.get('is_premium'),
        'suspended': lambda u: u.get('suspended'),
        'online': lambda u: u.get('status') in ('online', 'idle', 'dnd'),
        'bots': lambda u: _adm2_get_badge(u, 'bot'),
        'verified': lambda u: _adm2_get_badge(u, 'verified'),
        'staff': lambda u: _adm2_get_badge(u, 'staff'),
    }
    if flt in flt_map:
        rows = [u for u in rows if flt_map[flt](u)]
    if sort == 'oldest':
        rows.sort(key=lambda u: u.get('created_at') or '')
    elif sort == 'name':
        rows.sort(key=lambda u: (u.get('username') or '').lower())
    elif sort == 'coins':
        rows.sort(key=lambda u: u.get('coins', 0), reverse=True)
    elif sort == 'seen':
        rows.sort(key=lambda u: u.get('last_seen') or '', reverse=True)
    else:
        rows.sort(key=lambda u: u.get('created_at') or '', reverse=True)

    total = len(rows)
    pages = max(1, (total + per - 1) // per)
    page = min(page, pages)
    chunk = rows[(page - 1) * per: page * per]
    return jsonify({'users': [_adm2_slim_user(u) for u in chunk], 'total': total, 'page': page, 'pages': pages})


@app.route('/api/admin2/users/<user_id>')
@admin_required
def adm2_user_detail(user_id):
    db = load_database()
    u = db['users'].get(user_id)
    if not u:
        return jsonify({'error': 'User not found'}), 404
    owned = [{'id': s['id'], 'name': s.get('name')} for s in db['servers'].values() if s.get('owner_id') == user_id]
    member = [{'id': s['id'], 'name': s.get('name')} for s in db['servers'].values()
              if user_id in s.get('members', []) and s.get('owner_id') != user_id]
    msg_count = sum(1 for m in db.get('all_messages', {}).values() if m.get('user_id') == user_id)
    reports = (db.get('reports') or {}).values()
    hist = []
    for h in (db.get('badge_history', {}).get(user_id, []) or [])[-15:]:
        hh = dict(h)
        hh['admin_name'] = _adm2_uname(db, h.get('by'))
        hist.append(hh)
    out = _adm2_full_user(u)
    out.update({
        'servers_owned': owned, 'servers_member': member, 'message_count': msg_count,
        'reports_against': sum(1 for r in reports if r.get('reported_user_id') == user_id),
        'reports_by': sum(1 for r in reports if r.get('reporter_id') == user_id),
        'badge_history': hist, 'protected': _adm2_is_protected(u),
    })
    return jsonify(out)


@app.route('/api/admin2/users/<user_id>', methods=['PUT'])
@admin_required
def adm2_user_update(user_id):
    data = request.get_json(silent=True) or {}
    db = load_database()
    u = db['users'].get(user_id)
    if not u:
        return jsonify({'error': 'User not found'}), 404
    me = session['user_id']
    changes = {}

    def note(field, old, new):
        if old != new:
            changes[field] = {'old': old, 'new': new}

    if 'username' in data:
        name = str(data['username']).strip()
        if not (2 <= len(name) <= 32):
            return jsonify({'error': 'Username must be 2-32 characters'}), 400
        if any(o['id'] != user_id and (o.get('username') or '').lower() == name.lower() for o in db['users'].values()):
            return jsonify({'error': 'Username already taken'}), 409
        note('username', u.get('username'), name)
        u['username'] = name
    if 'email' in data:
        em = str(data['email']).strip()
        if not _adm_re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', em):
            return jsonify({'error': 'Invalid email'}), 400
        if any(o['id'] != user_id and (o.get('email') or '').lower() == em.lower() for o in db['users'].values()):
            return jsonify({'error': 'Email already used'}), 409
        note('email', u.get('email'), em)
        u['email'] = em
    if 'bio' in data:
        bio = str(data['bio'])[:500]
        note('bio', u.get('bio'), bio)
        u['bio'] = bio
    if 'avatar_color' in data:
        col = _adm2_valid_color(data['avatar_color'])
        if col:
            note('avatar_color', u.get('avatar_color'), col)
            u['avatar_color'] = col
    if 'status' in data and data['status'] in ADM2_STATUSES:
        note('status', u.get('status'), data['status'])
        u['status'] = data['status']
    if 'coins' in data:
        v = _adm2_int(data['coins'], 0, 10 ** 9, u.get('coins', 0))
        note('coins', u.get('coins', 0), v)
        u['coins'] = v
    if 'reputation' in data:
        v = _adm2_int(data['reputation'], -100000, 10 ** 7, u.get('reputation', 0))
        note('reputation', u.get('reputation', 0), v)
        u['reputation'] = v
    if 'server_boost_level' in data:
        v = _adm2_int(data['server_boost_level'], 0, 12, u.get('server_boost_level', 0))
        note('server_boost_level', u.get('server_boost_level', 0), v)
        u['server_boost_level'] = v
    if 'hypesquad_house' in data:
        h = data['hypesquad_house'] or None
        if h is not None and h not in ADM2_HOUSES:
            return jsonify({'error': 'Invalid HypeSquad house'}), 400
        note('hypesquad_house', u.get('hypesquad_house'), h)
        u['hypesquad_house'] = h
    if 'is_premium' in data:
        v = bool(data['is_premium'])
        note('is_premium', bool(u.get('is_premium')), v)
        u['is_premium'] = v
        u['premium_since'] = (u.get('premium_since') or _adm2_now()) if v else None
    if 'is_admin' in data:
        v = bool(data['is_admin'])
        if not v and (user_id == me or _adm2_is_protected(u)):
            return jsonify({'error': 'This admin cannot be demoted'}), 403
        note('is_admin', bool(u.get('is_admin')), v)
        u['is_admin'] = v
        if v and u.get('suspended'):
            _adm2_apply_suspension(db, user_id, False)

    # badges (both naming styles are kept in sync so the UI shows them)
    badge_changes = []
    if isinstance(data.get('badges'), dict):
        for key, val in data['badges'].items():
            if key in ADM2_BADGE_KEYS:
                old = _adm2_get_badge(u, key)
                if old != bool(val):
                    _adm2_set_badge(u, key, val)
                    badge_changes.append((key, old, bool(val)))
        for key, old, new in badge_changes:
            changes['badge:' + key] = {'old': old, 'new': new}
    if 'custom_badges' in data and isinstance(data['custom_badges'], list):
        valid = set((db.get('custom_badges') or {}).keys())
        new_list = [b for b in dict.fromkeys(data['custom_badges']) if b in valid]
        note('custom_badges', u.get('custom_badges', []), new_list)
        u['custom_badges'] = new_list

    if badge_changes:
        hist = db.setdefault('badge_history', {}).setdefault(user_id, [])
        for key, old, new in badge_changes:
            hist.append({'action': 'update', 'badge': key, 'old_value': old, 'new_value': new,
                         'by': me, 'at': _adm2_now()})
    if changes:
        _adm2_audit(db, 'user.update', 'user', user_id,
                    {'username': u.get('username'), 'changes': changes})
        save_database(db)
    return jsonify({'success': True, 'changes': changes, 'user': _adm2_full_user(u)})


@app.route('/api/admin2/users/<user_id>/password', methods=['POST'])
@admin_required
def adm2_user_password(user_id):
    data = request.get_json(silent=True) or {}
    pw = str(data.get('password') or '')
    if len(pw) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    db = load_database()
    u = db['users'].get(user_id)
    if not u:
        return jsonify({'error': 'User not found'}), 404
    u['password'] = generate_password_hash(pw)
    _adm2_audit(db, 'user.password_reset', 'user', user_id, {'username': u.get('username')})
    save_database(db)
    return jsonify({'success': True})


@app.route('/api/admin2/users/<user_id>/clear', methods=['POST'])
@admin_required
def adm2_user_clear(user_id):
    data = request.get_json(silent=True) or {}
    db = load_database()
    u = db['users'].get(user_id)
    if not u:
        return jsonify({'error': 'User not found'}), 404
    cleared = []
    for f in data.get('fields', []):
        if f == 'avatar':
            u['avatar'] = None; u['is_animated'] = False; cleared.append(f)
        elif f == 'banner':
            u['banner'] = None; cleared.append(f)
        elif f == 'bio':
            u['bio'] = ''; cleared.append(f)
        elif f == 'current_activity':
            u['current_activity'] = None; cleared.append(f)
        elif f == 'devices':
            u['devices'] = []; cleared.append(f)
    if cleared:
        _adm2_audit(db, 'user.clear', 'user', user_id, {'username': u.get('username'), 'fields': cleared})
        save_database(db)
    return jsonify({'success': True, 'cleared': cleared})


@app.route('/api/admin2/users/<user_id>/suspend', methods=['POST'])
@admin_required
def adm2_user_suspend(user_id):
    data = request.get_json(silent=True) or {}
    if user_id == session['user_id']:
        return jsonify({'error': 'You cannot suspend yourself'}), 400
    db = load_database()
    ok, msg = _adm2_apply_suspension(db, user_id, bool(data.get('suspend', True)),
                                     data.get('hours'), data.get('reason', ''))
    if not ok:
        return jsonify({'error': msg}), 400
    _adm2_audit(db, 'user.suspend' if data.get('suspend', True) else 'user.unsuspend', 'user', user_id,
                {'username': _adm2_uname(db, user_id), 'hours': data.get('hours'), 'reason': data.get('reason', '')})
    save_database(db)
    _adm2_reload_suspensions(db)
    return jsonify({'success': True})


@app.route('/api/admin2/users/<user_id>/notify', methods=['POST'])
@admin_required
def adm2_user_notify(user_id):
    data = request.get_json(silent=True) or {}
    msg = str(data.get('message') or '').strip()[:1000]
    if not msg:
        return jsonify({'error': 'Message is empty'}), 400
    db = load_database()
    if user_id not in db['users']:
        return jsonify({'error': 'User not found'}), 404
    _adm2_notify(db, user_id, str(data.get('title') or 'Message from administrators')[:80], msg)
    _adm2_audit(db, 'user.notify', 'user', user_id, {'username': _adm2_uname(db, user_id), 'message': msg[:120]})
    save_database(db)
    return jsonify({'success': True})


@app.route('/api/admin2/users/<user_id>/messages')
@admin_required
def adm2_user_messages(user_id):
    db = load_database()
    limit = _adm2_int(request.args.get('limit', 40), 1, 200, 40)
    rows = [m for m in db.get('all_messages', {}).values() if m.get('user_id') == user_id]
    rows.sort(key=lambda m: m.get('created_at') or '', reverse=True)
    return jsonify([_adm2_msg_row(db, m) for m in rows[:limit]])


# ============================================================
# ADMIN: CUSTOM BADGES
# ============================================================
def _adm2_clean_badge(data, existing=None):
    name = str(data.get('name', (existing or {}).get('name', ''))).strip()
    if not (1 <= len(name) <= 24):
        return None, 'Badge name must be 1-24 characters'
    emoji = str(data.get('emoji', (existing or {}).get('emoji', '🏅'))).strip()[:8]
    return {
        'name': name, 'emoji': emoji,
        'color': _adm2_valid_color(data.get('color'), (existing or {}).get('color', '#5865f2')),
        'text_color': _adm2_valid_color(data.get('text_color'), (existing or {}).get('text_color', '#ffffff')),
        'description': str(data.get('description', (existing or {}).get('description', '')))[:120],
    }, None


@app.route('/api/admin2/custom-badges', methods=['GET'])
@admin_required
def adm2_cb_list():
    db = load_database()
    out = []
    for b in (db.get('custom_badges') or {}).values():
        bb = dict(b)
        bb['holders'] = sum(1 for u in db['users'].values() if b['id'] in (u.get('custom_badges') or []))
        out.append(bb)
    return jsonify(out)


@app.route('/api/admin2/custom-badges', methods=['POST'])
@admin_required
def adm2_cb_create():
    db = load_database()
    clean, err = _adm2_clean_badge(request.get_json(silent=True) or {})
    if err:
        return jsonify({'error': err}), 400
    bid = 'cb_' + uuid.uuid4().hex[:8]
    clean.update({'id': bid, 'created_at': _adm2_now(), 'created_by': session['user_id']})
    db.setdefault('custom_badges', {})[bid] = clean
    _adm2_audit(db, 'badge.create', 'badge', bid, {'name': clean['name']})
    save_database(db)
    return jsonify({'success': True, 'badge': clean})


@app.route('/api/admin2/custom-badges/<bid>', methods=['PUT'])
@admin_required
def adm2_cb_update(bid):
    db = load_database()
    b = (db.get('custom_badges') or {}).get(bid)
    if not b:
        return jsonify({'error': 'Badge not found'}), 404
    clean, err = _adm2_clean_badge(request.get_json(silent=True) or {}, b)
    if err:
        return jsonify({'error': err}), 400
    b.update(clean)
    _adm2_audit(db, 'badge.update', 'badge', bid, {'name': b['name']})
    save_database(db)
    return jsonify({'success': True, 'badge': b})


@app.route('/api/admin2/custom-badges/<bid>', methods=['DELETE'])
@admin_required
def adm2_cb_delete(bid):
    db = load_database()
    b = (db.get('custom_badges') or {}).pop(bid, None)
    if not b:
        return jsonify({'error': 'Badge not found'}), 404
    for u in db['users'].values():
        if bid in (u.get('custom_badges') or []):
            u['custom_badges'] = [x for x in u['custom_badges'] if x != bid]
    _adm2_audit(db, 'badge.delete', 'badge', bid, {'name': b.get('name')})
    save_database(db)
    return jsonify({'success': True})


@app.route('/api/admin2/custom-badges/<bid>/assign', methods=['POST'])
@admin_required
def adm2_cb_assign(bid):
    data = request.get_json(silent=True) or {}
    db = load_database()
    if bid not in (db.get('custom_badges') or {}):
        return jsonify({'error': 'Badge not found'}), 404
    add = data.get('action', 'add') != 'remove'
    n = 0
    for uid in data.get('user_ids', []):
        u = db['users'].get(uid)
        if not u:
            continue
        cur = list(u.get('custom_badges') or [])
        if add and bid not in cur:
            cur.append(bid); n += 1
        elif not add and bid in cur:
            cur.remove(bid); n += 1
        u['custom_badges'] = cur
    _adm2_audit(db, 'badge.assign' if add else 'badge.unassign', 'badge', bid, {'users': data.get('user_ids', []), 'count': n})
    save_database(db)
    return jsonify({'success': True, 'changed': n})


# ============================================================
# ADMIN: SERVERS / CHANNELS / MESSAGES
# ============================================================
def _adm2_msg_row(db, m):
    ch = db['channels'].get(m.get('channel_id'), {})
    sv = db['servers'].get(ch.get('server_id'), {})
    return {
        'id': m.get('id'), 'content': m.get('content'), 'image_url': m.get('image_url'),
        'user_id': m.get('user_id'), 'author_name': _adm2_uname(db, m.get('user_id')),
        'channel_id': m.get('channel_id'), 'channel_name': ch.get('name', '(deleted)'),
        'server_id': ch.get('server_id'), 'server_name': sv.get('name', '(deleted)'),
        'created_at': m.get('created_at'),
    }


@app.route('/api/admin2/servers')
@admin_required
def adm2_servers():
    db = load_database()
    q = (request.args.get('q') or '').strip().lower()
    msgs_per_channel = {}
    for m in db.get('all_messages', {}).values():
        msgs_per_channel[m.get('channel_id')] = msgs_per_channel.get(m.get('channel_id'), 0) + 1
    rows = []
    for s in db['servers'].values():
        if q and q not in (s.get('name') or '').lower() and q != s['id'].lower():
            continue
        chs = [c for c in db['channels'].values() if c.get('server_id') == s['id']]
        rows.append({
            'id': s['id'], 'name': s.get('name'), 'icon': s.get('icon'),
            'owner_id': s.get('owner_id'), 'owner_name': _adm2_uname(db, s.get('owner_id')),
            'members': len(s.get('members', [])), 'channels': len(chs),
            'messages': sum(msgs_per_channel.get(c['id'], 0) for c in chs),
            'created_at': s.get('created_at'),
            'reports': sum(1 for r in (db.get('reports') or {}).values()
                           if r.get('server_id') == s['id'] and r.get('status') in ('open', 'reviewing')),
        })
    rows.sort(key=lambda r: r['members'], reverse=True)
    return jsonify(rows)


@app.route('/api/admin2/servers/<sid>')
@admin_required
def adm2_server_detail(sid):
    db = load_database()
    s = db['servers'].get(sid)
    if not s:
        return jsonify({'error': 'Server not found'}), 404
    members = []
    for uid in s.get('members', []):
        u = db['users'].get(uid)
        if u:
            members.append({'id': uid, 'username': u.get('username'), 'avatar': u.get('avatar'),
                            'avatar_color': u.get('avatar_color', '#7289da'),
                            'roles': (s.get('user_roles') or {}).get(uid, ['member'])})
    chans = [{'id': c['id'], 'name': c.get('name'), 'type': c.get('type', 'text')}
             for c in db['channels'].values() if c.get('server_id') == sid]
    return jsonify({'id': sid, 'name': s.get('name'), 'description': s.get('description', ''),
                    'owner_id': s.get('owner_id'), 'owner_name': _adm2_uname(db, s.get('owner_id')),
                    'icon': s.get('icon'), 'banner': s.get('banner'), 'created_at': s.get('created_at'),
                    'members': members, 'channels': chans})


@app.route('/api/admin2/servers/<sid>', methods=['PUT'])
@admin_required
def adm2_server_update(sid):
    if not ADMIN_CAN_EDIT_SERVERS:
        return owner_only_response('Servers are controlled only by their owner. Site admins cannot change them.')
    data = request.get_json(silent=True) or {}
    db = load_database()
    s = db['servers'].get(sid)
    if not s:
        return jsonify({'error': 'Server not found'}), 404
    changes = {}
    if 'name' in data:
        n = str(data['name']).strip()
        if not (1 <= len(n) <= 60):
            return jsonify({'error': 'Server name must be 1-60 characters'}), 400
        changes['name'] = {'old': s.get('name'), 'new': n}
        s['name'] = n
    if 'description' in data:
        s['description'] = str(data['description'])[:500]
        changes['description'] = True
    if data.get('clear_icon'):
        s['icon'] = None; changes['icon'] = 'cleared'
    if data.get('clear_banner'):
        s['banner'] = None; changes['banner'] = 'cleared'
    if 'owner_id' in data and data['owner_id'] != s.get('owner_id'):
        new_owner = data['owner_id']
        if new_owner not in db['users']:
            return jsonify({'error': 'New owner does not exist'}), 404
        old_owner = s.get('owner_id')
        if new_owner not in s.setdefault('members', []):
            s['members'].append(new_owner)
        roles = s.setdefault('user_roles', {})
        roles[new_owner] = ['owner']
        if old_owner in roles:
            roles[old_owner] = ['member']
        s['owner_id'] = new_owner
        changes['owner_id'] = {'old': old_owner, 'new': new_owner}
    if changes:
        _adm2_audit(db, 'server.update', 'server', sid, {'name': s.get('name'), 'changes': changes})
        save_database(db)
    return jsonify({'success': True, 'changes': changes})


def _adm2_remove_server(db, sid):
    chans = [cid for cid, c in db['channels'].items() if c.get('server_id') == sid]
    for cid in chans:
        del db['channels'][cid]
    for mid in [mid for mid, m in db['all_messages'].items() if m.get('channel_id') in chans]:
        del db['all_messages'][mid]
    for key in ('bans', 'mutes'):
        db.get(key, {}).pop(sid, None)
    for code in [c for c, i in db.get('invites', {}).items() if i.get('server_id') == sid]:
        del db['invites'][code]
    for cat in [c for c, v in db.get('categories', {}).items() if v.get('server_id') == sid]:
        del db['categories'][cat]
    db['servers'].pop(sid, None)


@app.route('/api/admin2/servers/<sid>', methods=['DELETE'])
@admin_required
def adm2_server_delete(sid):
    if not ADMIN_CAN_DELETE_SERVERS:
        return owner_only_response('Servers can only be deleted by their owner.')
    db = load_database()
    s = db['servers'].get(sid)
    if not s:
        return jsonify({'error': 'Server not found'}), 404
    name = s.get('name')
    _adm2_remove_server(db, sid)
    _adm2_audit(db, 'server.delete', 'server', sid, {'name': name})
    save_database(db)
    return jsonify({'success': True})


@app.route('/api/admin2/servers/<sid>/kick', methods=['POST'])
@admin_required
def adm2_server_kick(sid):
    if not ADMIN_CAN_EDIT_SERVERS:
        return owner_only_response('Only the server owner can remove members from a server.')
    uid = (request.get_json(silent=True) or {}).get('user_id')
    db = load_database()
    s = db['servers'].get(sid)
    if not s:
        return jsonify({'error': 'Server not found'}), 404
    if uid == s.get('owner_id'):
        return jsonify({'error': 'Transfer ownership before removing the owner'}), 400
    if uid in s.get('members', []):
        s['members'].remove(uid)
        _strip_member_from_private_channels(db, sid, uid)
        (s.get('user_roles') or {}).pop(uid, None)
        _adm2_audit(db, 'server.kick', 'server', sid, {'user': _adm2_uname(db, uid), 'server': s.get('name')})
        save_database(db)
    return jsonify({'success': True})


@app.route('/api/admin2/channels/<cid>', methods=['DELETE'])
@admin_required
def adm2_channel_delete(cid):
    if not ADMIN_CAN_EDIT_SERVERS:
        return owner_only_response('Only the server owner can delete channels.')
    db = load_database()
    c = db['channels'].pop(cid, None)
    if not c:
        return jsonify({'error': 'Channel not found'}), 404
    n = 0
    for mid in [mid for mid, m in db['all_messages'].items() if m.get('channel_id') == cid]:
        del db['all_messages'][mid]; n += 1
    _adm2_audit(db, 'channel.delete', 'channel', cid, {'name': c.get('name'), 'messages_removed': n})
    save_database(db)
    return jsonify({'success': True, 'messages_removed': n})


@app.route('/api/admin2/messages')
@admin_required
def adm2_messages():
    db = load_database()
    q = (request.args.get('q') or '').strip().lower()
    uid = request.args.get('user_id')
    cid = request.args.get('channel_id')
    limit = _adm2_int(request.args.get('limit', 60), 1, 200, 60)
    rows = []
    for m in db.get('all_messages', {}).values():
        if uid and m.get('user_id') != uid:
            continue
        if cid and m.get('channel_id') != cid:
            continue
        if q and q not in (m.get('content') or '').lower():
            continue
        rows.append(m)
    rows.sort(key=lambda m: m.get('created_at') or '', reverse=True)
    return jsonify([_adm2_msg_row(db, m) for m in rows[:limit]])


@app.route('/api/admin2/messages/<mid>', methods=['DELETE'])
@admin_required
def adm2_message_delete(mid):
    db = load_database()
    m = db['all_messages'].pop(mid, None)
    if not m:
        return jsonify({'error': 'Message not found'}), 404
    _adm2_audit(db, 'message.delete', 'message', mid,
                {'author': _adm2_uname(db, m.get('user_id')), 'content': (m.get('content') or '')[:120]})
    save_database(db)
    return jsonify({'success': True})


# ============================================================
# ADMIN: SITE SETTINGS, ANNOUNCEMENT, BROADCAST, AUDIT
# ============================================================
@app.route('/api/admin2/settings', methods=['GET'])
@admin_required
def adm2_settings_get():
    return jsonify(_adm2_settings(load_database()))


@app.route('/api/admin2/settings', methods=['PUT'])
@admin_required
def adm2_settings_put():
    data = request.get_json(silent=True) or {}
    db = load_database()
    st = db.setdefault('settings', {})
    changes = {}
    for key in ('registration_enabled', 'store_enabled', 'upload_enabled', 'reports_enabled', 'maintenance_mode'):
        if key in data:
            changes[key] = {'old': st.get(key, ADM2_SETTING_DEFAULTS[key]), 'new': bool(data[key])}
            st[key] = bool(data[key])
    if 'maintenance_message' in data:
        st['maintenance_message'] = str(data['maintenance_message'])[:300]
        changes['maintenance_message'] = True
    if 'announcement_text' in data or 'announcement_level' in data:
        if 'announcement_text' in data:
            st['announcement_text'] = str(data['announcement_text'])[:500]
        if data.get('announcement_level') in ('info', 'warning', 'danger', 'success'):
            st['announcement_level'] = data['announcement_level']
        st['announcement_id'] = uuid.uuid4().hex[:8]
        changes['announcement'] = (st.get('announcement_text') or '')[:80]
    if changes:
        _adm2_audit(db, 'settings.update', 'settings', None, changes)
        save_database(db)
    return jsonify({'success': True, 'settings': _adm2_settings(db)})


@app.route('/api/admin2/broadcast', methods=['POST'])
@admin_required
def adm2_broadcast():
    data = request.get_json(silent=True) or {}
    msg = str(data.get('message') or '').strip()[:1000]
    if not msg:
        return jsonify({'error': 'Message is empty'}), 400
    title = str(data.get('title') or 'Announcement')[:80]
    db = load_database()
    n = 0
    for uid in db['users']:
        _adm2_notify(db, uid, title, msg, 'broadcast')
        n += 1
    _adm2_audit(db, 'broadcast', 'all', None, {'title': title, 'message': msg[:120], 'recipients': n})
    save_database(db)
    return jsonify({'success': True, 'recipients': n})


@app.route('/api/admin2/audit')
@admin_required
def adm2_audit_list():
    db = load_database()
    q = (request.args.get('q') or '').strip().lower()
    limit = _adm2_int(request.args.get('limit', 150), 10, 500, 150)
    rows = list(reversed(db.get('admin_audit', [])))
    if q:
        rows = [r for r in rows if q in json.dumps(r, ensure_ascii=False).lower()]
    return jsonify(rows[:limit])


# ============================================================
# REPORTS - user side
# ============================================================
def _rpt_msg_snapshot(m, db):
    return {
        'id': m.get('id'), 'user_id': m.get('user_id'),
        'author_name': _adm2_uname(db, m.get('user_id')),
        'content': (m.get('content') or '')[:2000],
        'image_url': m.get('image_url'), 'file_url': m.get('file_url'), 'file_name': m.get('file_name'),
        'created_at': m.get('created_at'),
    }


def _rpt_channel_messages(db, cid):
    rows = [m for m in db.get('all_messages', {}).values() if m.get('channel_id') == cid]
    rows.sort(key=lambda m: m.get('created_at') or '')
    return rows


@app.route('/api/reports', methods=['POST'])
@login_required
def rpt_create():
    data = request.get_json(silent=True) or {}
    db = load_database()
    me = session['user_id']
    if not _adm2_settings(db).get('reports_enabled', True):
        return jsonify({'error': 'Reports are currently disabled'}), 403

    rtype = data.get('target_type')
    target_id = str(data.get('target_id') or '')
    reason = data.get('reason')
    desc = str(data.get('description') or '').strip()
    if rtype not in REPORT_TYPES or not target_id:
        return jsonify({'error': 'Invalid report target'}), 400
    if reason not in REPORT_REASONS:
        return jsonify({'error': 'Please choose a reason'}), 400
    if len(desc) < 5:
        return jsonify({'error': 'Please describe the problem (at least 5 characters)'}), 400
    desc = desc[:2000]
    evidence = []
    for url in (data.get('evidence') or [])[:8]:
        if isinstance(url, str) and _adm_re.match(r'^/uploads/[\w.\-]+$', url):
            evidence.append(url)

    reports = db.setdefault('reports', {})
    hour_ago = datetime.now() - timedelta(hours=1)
    recent = [r for r in reports.values() if r.get('reporter_id') == me and (_adm2_dt(r.get('created_at')) or datetime.min) > hour_ago]
    if len(recent) >= 15:
        return jsonify({'error': 'Too many reports. Please try again later.'}), 429
    for r in reports.values():
        if (r.get('reporter_id') == me and r.get('type') == rtype and r.get('target_id') == target_id
                and r.get('status') in ('open', 'reviewing')):
            return jsonify({'error': 'You already have an open report for this'}), 409

    ctx = data.get('context') or {}
    reported_user_id, server_id, channel_id = None, None, None
    snapshot = {}

    if rtype == 'message':
        msg = db['all_messages'].get(target_id)
        kind, thread = 'channel', None
        if msg:
            channel_id = msg.get('channel_id')
            ch = db['channels'].get(channel_id, {})
            server_id = ch.get('server_id')
            srv = db['servers'].get(server_id)
            if not srv or me not in srv.get('members', []):
                return jsonify({'error': 'You cannot report this message'}), 403
            thread = _rpt_channel_messages(db, channel_id)
            snapshot['channel_name'] = ch.get('name')
            snapshot['server_name'] = (srv or {}).get('name')
        else:
            kind = 'dm'
            for key, lst in db.get('direct_messages', {}).items():
                ids = key.replace('dm_', '', 1).split('_')
                if me in ids:
                    for m in lst:
                        if m.get('id') == target_id:
                            msg, thread = m, lst
                            other = [i for i in ids if i != me]
                            snapshot['dm_with'] = other[0] if other else None
                            break
                if msg:
                    break
        if not msg:
            return jsonify({'error': 'Message not found'}), 404
        if msg.get('user_id') == me:
            return jsonify({'error': 'You cannot report your own message'}), 400
        reported_user_id = msg.get('user_id')
        idx = next((i for i, m in enumerate(thread) if m.get('id') == target_id), 0)
        snapshot.update({
            'kind': kind, 'message': _rpt_msg_snapshot(msg, db),
            'context_messages': [_rpt_msg_snapshot(m, db) for m in thread[max(0, idx - 10): idx + 6]],
        })

    elif rtype == 'user':
        u = db['users'].get(target_id)
        if not u:
            return jsonify({'error': 'User not found'}), 404
        if target_id == me:
            return jsonify({'error': 'You cannot report yourself'}), 400
        reported_user_id = target_id
        snapshot = {'username': u.get('username'), 'avatar': u.get('avatar'), 'bio': u.get('bio', ''),
                    'created_at': u.get('created_at'), 'email_hidden': True}

    elif rtype == 'channel':
        ch = db['channels'].get(target_id)
        if not ch:
            return jsonify({'error': 'Channel not found'}), 404
        srv = db['servers'].get(ch.get('server_id'))
        if not srv or me not in srv.get('members', []):
            return jsonify({'error': 'You cannot report this channel'}), 403
        channel_id, server_id = target_id, ch.get('server_id')
        reported_user_id = srv.get('owner_id')
        snapshot = {'channel_name': ch.get('name'), 'server_name': srv.get('name'),
                    'context_messages': [_rpt_msg_snapshot(m, db) for m in _rpt_channel_messages(db, target_id)[-20:]]}

    elif rtype == 'server':
        srv = db['servers'].get(target_id)
        if not srv:
            return jsonify({'error': 'Server not found'}), 404
        if me not in srv.get('members', []):
            return jsonify({'error': 'You cannot report this server'}), 403
        server_id = target_id
        reported_user_id = srv.get('owner_id')
        cids = [c['id'] for c in db['channels'].values() if c.get('server_id') == target_id]
        recent_msgs = [m for m in db.get('all_messages', {}).values() if m.get('channel_id') in cids]
        recent_msgs.sort(key=lambda m: m.get('created_at') or '')
        snapshot = {'server_name': srv.get('name'), 'owner_name': _adm2_uname(db, srv.get('owner_id')),
                    'member_count': len(srv.get('members', [])),
                    'channels': [db['channels'][c].get('name') for c in cids],
                    'context_messages': [_rpt_msg_snapshot(m, db) for m in recent_msgs[-20:]]}

    elif rtype == 'pack':
        packs, _ = _media_packs(db)
        pack = packs.get(target_id)
        if not pack:
            return jsonify({'error': 'Pack not found'}), 404
        if pack.get('owner_id') == me:
            return jsonify({'error': 'You cannot report your own pack'}), 400
        owner = pack.get('owner_id')
        reported_user_id = owner if owner in db['users'] else None
        snapshot = {'pack_id': target_id, 'pack_name': pack['name'], 'pack_type': pack['type'],
                    'description': pack.get('description', ''), 'owner_name': _pack_owner_name(db, pack),
                    'item_count': len(pack.get('items', [])), 'adult': bool(pack.get('adult')),
                    'items': [{'id': i['id'], 'url': i['url'], 'name': i.get('name', '')} for i in pack.get('items', [])[:40]]}

    else:  # dm conversation
        other = db['users'].get(target_id)
        if not other or target_id == me:
            return jsonify({'error': 'User not found'}), 404
        reported_user_id = target_id
        lst = db.get('direct_messages', {}).get(_adm2_dm_key(me, target_id), [])
        snapshot = {'kind': 'dm', 'dm_with': target_id, 'dm_with_name': other.get('username'),
                    'context_messages': [_rpt_msg_snapshot(m, db) for m in lst[-30:]]}

    rid = 'rp_' + uuid.uuid4().hex[:10]
    report = {
        'id': rid, 'type': rtype, 'target_id': target_id,
        'reason': reason, 'reason_label': REPORT_REASONS[reason],
        'description': desc, 'evidence': evidence,
        'reporter_id': me, 'reporter_name': _adm2_uname(db, me),
        'reported_user_id': reported_user_id, 'reported_user_name': _adm2_uname(db, reported_user_id) if reported_user_id else None,
        'server_id': server_id, 'channel_id': channel_id,
        'snapshot': snapshot,
        'status': 'open', 'priority': 'normal',
        'admin_note': '', 'response': '', 'handled_by': None, 'handled_at': None,
        'created_at': _adm2_now(), 'updated_at': _adm2_now(),
        'history': [{'at': _adm2_now(), 'by': me, 'by_name': _adm2_uname(db, me), 'action': 'created', 'detail': ''}],
    }
    reports[rid] = report
    if rtype == 'pack':
        _pack_check_autohide(db, target_id)
    for uid, u in db['users'].items():
        if u.get('is_admin'):
            _adm2_notify(db, uid, 'New report', f"{report['reporter_name']} reported a {rtype}: {REPORT_REASONS[reason]}",
                         'report', {'report_id': rid})
    save_database(db)
    return jsonify({'success': True, 'id': rid})


@app.route('/api/reports/mine')
@login_required
def rpt_mine():
    db = load_database()
    me = session['user_id']
    rows = [r for r in (db.get('reports') or {}).values() if r.get('reporter_id') == me]
    rows.sort(key=lambda r: r.get('created_at') or '', reverse=True)
    return jsonify([{
        'id': r['id'], 'type': r['type'], 'reason_label': r.get('reason_label'),
        'description': r.get('description'), 'status': r.get('status'),
        'response': r.get('response', ''), 'created_at': r.get('created_at'),
        'target_label': _rpt_target_label(db, r),
    } for r in rows])


def _rpt_target_label(db, r):
    s = r.get('snapshot') or {}
    t = r.get('type')
    if t == 'message':
        return ((s.get('message') or {}).get('content') or '(attachment)')[:80]
    if t == 'user':
        return s.get('username') or r.get('reported_user_name') or 'user'
    if t == 'channel':
        return '#' + (s.get('channel_name') or 'channel') + ' in ' + (s.get('server_name') or '')
    if t == 'server':
        return s.get('server_name') or 'server'
    if t == 'pack':
        return 'Pack: ' + (s.get('pack_name') or 'pack')
    return 'DM with ' + (s.get('dm_with_name') or r.get('reported_user_name') or 'user')


# ============================================================
# REPORTS - admin side
# ============================================================
def _rpt_admin_row(db, r):
    return {
        'id': r['id'], 'type': r['type'], 'reason': r.get('reason'), 'reason_label': r.get('reason_label'),
        'description': (r.get('description') or '')[:160], 'status': r.get('status'), 'priority': r.get('priority', 'normal'),
        'reporter_id': r.get('reporter_id'), 'reporter_name': _adm2_uname(db, r.get('reporter_id')),
        'reported_user_id': r.get('reported_user_id'),
        'reported_user_name': _adm2_uname(db, r.get('reported_user_id')) if r.get('reported_user_id') else None,
        'target_label': _rpt_target_label(db, r), 'evidence_count': len(r.get('evidence') or []),
        'created_at': r.get('created_at'), 'updated_at': r.get('updated_at'),
    }


@app.route('/api/admin2/reports')
@admin_required
def rpt_admin_list():
    db = load_database()
    rows = list((db.get('reports') or {}).values())
    counts = {s: 0 for s in REPORT_STATUSES}
    for r in rows:
        counts[r.get('status', 'open')] = counts.get(r.get('status', 'open'), 0) + 1
    status, rtype, reason = request.args.get('status'), request.args.get('type'), request.args.get('reason')
    q = (request.args.get('q') or '').strip().lower()
    if status and status != 'all':
        rows = [r for r in rows if r.get('status') == status]
    if rtype and rtype != 'all':
        rows = [r for r in rows if r.get('type') == rtype]
    if reason and reason != 'all':
        rows = [r for r in rows if r.get('reason') == reason]
    if q:
        rows = [r for r in rows if q in (r.get('description') or '').lower()
                or q in _adm2_uname(db, r.get('reporter_id')).lower()
                or q in (r.get('reported_user_name') or '').lower() or q == r['id'].lower()]
    order = {'urgent': 0, 'high': 1, 'normal': 2, 'low': 3}
    if request.args.get('sort') == 'priority':
        rows.sort(key=lambda r: (order.get(r.get('priority', 'normal'), 2), r.get('created_at') or ''))
    elif request.args.get('sort') == 'oldest':
        rows.sort(key=lambda r: r.get('created_at') or '')
    else:
        rows.sort(key=lambda r: r.get('created_at') or '', reverse=True)
    page = _adm2_int(request.args.get('page', 1), 1, 100000, 1)
    per = 25
    pages = max(1, (len(rows) + per - 1) // per)
    page = min(page, pages)
    return jsonify({'reports': [_rpt_admin_row(db, r) for r in rows[(page - 1) * per: page * per]],
                    'counts': counts, 'total': len(rows), 'page': page, 'pages': pages})


@app.route('/api/admin2/reports/<rid>')
@admin_required
def rpt_admin_detail(rid):
    db = load_database()
    r = (db.get('reports') or {}).get(rid)
    if not r:
        return jsonify({'error': 'Report not found'}), 404
    out = dict(r)
    out['reporter_name'] = _adm2_uname(db, r.get('reporter_id'))
    out['reported_user_name'] = _adm2_uname(db, r.get('reported_user_id')) if r.get('reported_user_id') else None
    out['reported_user_suspended'] = bool(db['users'].get(r.get('reported_user_id'), {}).get('suspended'))
    out['target_label'] = _rpt_target_label(db, r)
    out['message_still_exists'] = None
    if r['type'] == 'message':
        if (r.get('snapshot') or {}).get('kind') == 'dm':
            lst = db.get('direct_messages', {}).get(_adm2_dm_key(r['reporter_id'], r.get('reported_user_id') or ''), [])
            out['message_still_exists'] = any(m.get('id') == r['target_id'] for m in lst)
        else:
            out['message_still_exists'] = r['target_id'] in db.get('all_messages', {})
    other_reports = [x['id'] for x in (db.get('reports') or {}).values()
                     if x['id'] != rid and r.get('reported_user_id') and x.get('reported_user_id') == r.get('reported_user_id')]
    out['other_reports_on_user'] = len(other_reports)
    if r['type'] == 'pack':
        packs, _ = _media_packs(db)
        pk = packs.get(r['target_id'])
        out['pack_exists'] = bool(pk)
        out['pack_hidden'] = bool(pk and pk.get('hidden'))
        out['pack_adult'] = bool(pk and pk.get('adult'))
        out['creator_media_banned'] = bool(db['users'].get(r.get('reported_user_id'), {}).get('media_banned'))
        if pk:   # show the CURRENT content of the pack, not just the snapshot
            out['snapshot'] = dict(out.get('snapshot') or {}, items=[{'id': i['id'], 'url': i['url'], 'name': i.get('name', '')} for i in pk.get('items', [])[:60]],
                                   item_count=len(pk.get('items', [])))
    return jsonify(out)


@app.route('/api/admin2/reports/<rid>', methods=['PUT'])
@admin_required
def rpt_admin_update(rid):
    data = request.get_json(silent=True) or {}
    db = load_database()
    r = (db.get('reports') or {}).get(rid)
    if not r:
        return jsonify({'error': 'Report not found'}), 404
    me = session['user_id']
    notes = []
    old_status = r.get('status')
    if data.get('status') in REPORT_STATUSES and data['status'] != old_status:
        r['status'] = data['status']
        notes.append(f"status {old_status} -> {data['status']}")
        if data['status'] in ('resolved', 'dismissed'):
            r['handled_by'], r['handled_at'] = me, _adm2_now()
    if data.get('priority') in REPORT_PRIORITIES and data['priority'] != r.get('priority'):
        notes.append(f"priority {r.get('priority')} -> {data['priority']}")
        r['priority'] = data['priority']
    if 'admin_note' in data and data['admin_note'] != r.get('admin_note'):
        r['admin_note'] = str(data['admin_note'])[:2000]
        notes.append('note updated')
    reply = None
    if 'response' in data and str(data['response']).strip() and data['response'] != r.get('response'):
        r['response'] = str(data['response']).strip()[:1000]
        reply = r['response']
        notes.append('reply sent to reporter')
    if notes:
        r['updated_at'] = _adm2_now()
        r['history'].append({'at': _adm2_now(), 'by': me, 'by_name': _adm2_uname(db, me),
                             'action': 'update', 'detail': '; '.join(notes)})
        if reply or (r['status'] in ('resolved', 'dismissed') and old_status != r['status']):
            text = reply or ('Your report was ' + r['status'] + '.')
            _adm2_notify(db, r['reporter_id'], f"Report {r['status']}", text, 'report_update', {'report_id': rid})
        _adm2_audit(db, 'report.update', 'report', rid, {'notes': notes})
        save_database(db)
    return jsonify({'success': True, 'report': r})


@app.route('/api/admin2/reports/<rid>', methods=['DELETE'])
@admin_required
def rpt_admin_delete(rid):
    db = load_database()
    if rid not in (db.get('reports') or {}):
        return jsonify({'error': 'Report not found'}), 404
    del db['reports'][rid]
    _adm2_audit(db, 'report.delete', 'report', rid)
    save_database(db)
    return jsonify({'success': True})


@app.route('/api/admin2/reports/bulk', methods=['POST'])
@admin_required
def rpt_admin_bulk():
    data = request.get_json(silent=True) or {}
    db = load_database()
    ids = [i for i in data.get('ids', []) if i in (db.get('reports') or {})]
    action = data.get('action')
    for rid in ids:
        r = db['reports'][rid]
        if action == 'delete':
            del db['reports'][rid]
        elif action in REPORT_STATUSES:
            r['status'] = action
            r['updated_at'] = _adm2_now()
            if action in ('resolved', 'dismissed'):
                r['handled_by'], r['handled_at'] = session['user_id'], _adm2_now()
            r['history'].append({'at': _adm2_now(), 'by': session['user_id'],
                                 'by_name': _adm2_uname(db, session['user_id']),
                                 'action': 'bulk', 'detail': 'status -> ' + action})
    _adm2_audit(db, 'report.bulk', 'report', None, {'action': action, 'count': len(ids)})
    save_database(db)
    return jsonify({'success': True, 'count': len(ids)})


@app.route('/api/admin2/reports/<rid>/action', methods=['POST'])
@admin_required
def rpt_admin_action(rid):
    data = request.get_json(silent=True) or {}
    db = load_database()
    r = (db.get('reports') or {}).get(rid)
    if not r:
        return jsonify({'error': 'Report not found'}), 404
    action = data.get('action')
    me = session['user_id']
    detail = ''
    if action == 'delete_message':
        if r['type'] != 'message':
            return jsonify({'error': 'This report is not about a message'}), 400
        if r['target_id'] in db['all_messages']:
            del db['all_messages'][r['target_id']]
            detail = 'reported message deleted'
        else:
            removed = False
            for key, lst in db.get('direct_messages', {}).items():
                before = len(lst)
                db['direct_messages'][key] = [m for m in lst if m.get('id') != r['target_id']]
                removed = removed or len(db['direct_messages'][key]) != before
            if not removed:
                return jsonify({'error': 'Message no longer exists'}), 404
            detail = 'reported DM message deleted'
    elif action == 'warn_user':
        uid = r.get('reported_user_id')
        text = str(data.get('message') or 'You received a warning because of a report about your behavior.')[:500]
        if not uid or uid not in db['users']:
            return jsonify({'error': 'No user to warn'}), 400
        _adm2_notify(db, uid, 'Warning from administrators', text, 'warning')
        detail = 'warning sent to ' + _adm2_uname(db, uid)
    elif action in ('suspend_user', 'unsuspend_user'):
        uid = r.get('reported_user_id')
        if not uid:
            return jsonify({'error': 'No user to suspend'}), 400
        ok, msg = _adm2_apply_suspension(db, uid, action == 'suspend_user', data.get('hours'), data.get('reason', 'Suspended after a report'))
        if not ok:
            return jsonify({'error': msg}), 400
        detail = f"{action} {_adm2_uname(db, uid)}"
    elif action == 'delete_server':
        if r.get('server_id') not in db['servers']:
            return jsonify({'error': 'Server no longer exists'}), 404
        _adm2_remove_server(db, r['server_id'])
        detail = 'server deleted'
    elif action == 'delete_channel':
        cid = r.get('channel_id')
        if cid not in db['channels']:
            return jsonify({'error': 'Channel no longer exists'}), 404
        db['channels'].pop(cid)
        for mid in [mid for mid, m in db['all_messages'].items() if m.get('channel_id') == cid]:
            del db['all_messages'][mid]
        detail = 'channel deleted'
    elif action in ('delete_pack', 'hide_pack', 'unhide_pack', 'mark_pack_adult', 'unmark_pack_adult'):
        if r['type'] != 'pack':
            return jsonify({'error': 'This report is not about a pack'}), 400
        packs, _ = _media_packs(db)
        pack = packs.get(r['target_id'])
        if not pack:
            return jsonify({'error': 'Pack no longer exists'}), 404
        owner = pack.get('owner_id')
        if action == 'delete_pack':
            _media_remove_pack(db, pack['id'])
            detail = 'pack deleted'
            if owner in db['users']:
                _adm2_notify(db, owner, 'Your pack was removed', f"Your pack \"{pack['name']}\" was removed by the administrators after a report.", 'warning')
        elif action == 'hide_pack':
            pack['hidden'], pack['hidden_reason'] = True, 'admin'
            detail = 'pack hidden'
            if owner in db['users']:
                _adm2_notify(db, owner, 'Your pack was hidden', f"Your pack \"{pack['name']}\" is hidden while it is being reviewed.", 'warning')
        elif action == 'unhide_pack':
            pack['hidden'] = False
            pack.pop('hidden_reason', None)
            detail = 'pack visible again'
        elif action == 'mark_pack_adult':
            pack['adult'] = True
            pack['adult_by_admin'] = True
            detail = 'pack marked as 18+'
        else:
            pack['adult'] = False
            pack.pop('adult_by_admin', None)
            detail = 'pack 18+ mark removed'
    elif action in ('ban_media_user', 'unban_media_user'):
        uid = r.get('reported_user_id')
        if not uid or uid not in db['users']:
            return jsonify({'error': 'No user to restrict'}), 400
        db['users'][uid]['media_banned'] = (action == 'ban_media_user')
        detail = f"{'banned' if action == 'ban_media_user' else 'allowed'} {_adm2_uname(db, uid)} to create/upload sticker packs"
        if action == 'ban_media_user':
            _adm2_notify(db, uid, 'Sticker packs disabled', 'You can no longer create or upload sticker/GIF packs because of rule violations.', 'warning')
    else:
        return jsonify({'error': 'Unknown action'}), 400
    r['updated_at'] = _adm2_now()
    r['history'].append({'at': _adm2_now(), 'by': me, 'by_name': _adm2_uname(db, me), 'action': action, 'detail': detail})
    _adm2_audit(db, 'report.action', 'report', rid, {'action': action, 'detail': detail})
    save_database(db)
    if action in ('suspend_user', 'unsuspend_user'):
        _adm2_reload_suspensions(db)
    return jsonify({'success': True, 'detail': detail})



# ============================================
# CHAT FOLDERS & ARCHIVE  (Home + Direct Messages)
# Stored in data/database.json:
#   db['chat_folders'][user_id] -> [ {id, name, icon, color, items:[{type,id}], created_at} ]
#   db['chat_archive'][user_id] -> [ {type, id, archived_at} ]
# item type: 'dm' (id = other user id) | 'server' (id = server id)
# ============================================
MAX_FOLDERS = 20
MAX_FOLDER_NAME = 32
MAX_PINS = 10
FOLDER_ITEM_TYPES = ('dm', 'server')

def _folder_state(db, uid):
    folders = db.setdefault('chat_folders', {}).setdefault(uid, [])
    archive = db.setdefault('chat_archive', {}).setdefault(uid, [])
    db.setdefault('chat_pins', {}).setdefault(uid, [])   # FIX: KeyError 'chat_pins' in /api/pins
    return folders, archive

def _valid_item(db, uid, item_type, item_id):
    if item_type not in FOLDER_ITEM_TYPES or not isinstance(item_id, str) or not item_id:
        return False
    if item_type == 'dm':
        return item_id in db.get('users', {}) and item_id != uid
    server = db.get('servers', {}).get(item_id)
    return bool(server) and uid in server.get('members', [])

def _clean_folder_name(raw):
    return re.sub(r'\s+', ' ', str(raw or '')).strip()[:MAX_FOLDER_NAME]

def _folders_payload(db, uid):
    folders, archive = _folder_state(db, uid)
    pins = db.setdefault('chat_pins', {}).setdefault(uid, [])
    return {'folders': folders, 'archive': archive, 'pins': pins}

@app.route('/api/folders', methods=['GET'])
@login_required
def folders_list():
    db = load_database()
    return jsonify(_folders_payload(db, session['user_id']))

@app.route('/api/folders', methods=['POST'])
@login_required
def folders_create():
    data = request.get_json(silent=True) or {}
    name = _clean_folder_name(data.get('name'))
    if not name:
        return jsonify({'error': 'Folder name is required'}), 400
    db = load_database()
    uid = session['user_id']
    folders, _ = _folder_state(db, uid)
    if len(folders) >= MAX_FOLDERS:
        return jsonify({'error': f'You can create up to {MAX_FOLDERS} folders'}), 400
    if any(f['name'].lower() == name.lower() for f in folders):
        return jsonify({'error': 'A folder with this name already exists'}), 400
    folder = {
        'id': uuid.uuid4().hex[:10],
        'name': name,
        'icon': str(data.get('icon') or 'fa-folder')[:30],
        'color': str(data.get('color') or '#5865f2')[:9],
        'items': [],
        'created_at': datetime.now().isoformat(),
    }
    folders.append(folder)
    save_database(db)
    return jsonify({'success': True, 'folder': folder, **_folders_payload(db, uid)})

@app.route('/api/folders/<folder_id>', methods=['PUT'])
@login_required
def folders_update(folder_id):
    data = request.get_json(silent=True) or {}
    db = load_database()
    uid = session['user_id']
    folders, _ = _folder_state(db, uid)
    folder = next((f for f in folders if f['id'] == folder_id), None)
    if not folder:
        return jsonify({'error': 'Folder not found'}), 404
    if 'name' in data:
        name = _clean_folder_name(data.get('name'))
        if not name:
            return jsonify({'error': 'Folder name is required'}), 400
        if any(f['id'] != folder_id and f['name'].lower() == name.lower() for f in folders):
            return jsonify({'error': 'A folder with this name already exists'}), 400
        folder['name'] = name
    if 'icon' in data:
        folder['icon'] = str(data.get('icon') or 'fa-folder')[:30]
    if 'color' in data:
        folder['color'] = str(data.get('color') or '#5865f2')[:9]
    if isinstance(data.get('items'), list):
        seen, items = set(), []
        for it in data['items']:
            if not isinstance(it, dict):
                continue
            key = (it.get('type'), it.get('id'))
            if key in seen or not _valid_item(db, uid, *key):
                continue
            seen.add(key)
            items.append({'type': key[0], 'id': key[1]})
        folder['items'] = items
    save_database(db)
    return jsonify({'success': True, 'folder': folder, **_folders_payload(db, uid)})

@app.route('/api/folders/<folder_id>', methods=['DELETE'])
@login_required
def folders_delete(folder_id):
    db = load_database()
    uid = session['user_id']
    folders, _ = _folder_state(db, uid)
    if not any(f['id'] == folder_id for f in folders):
        return jsonify({'error': 'Folder not found'}), 404
    db['chat_folders'][uid] = [f for f in folders if f['id'] != folder_id]
    save_database(db)
    return jsonify({'success': True, **_folders_payload(db, uid)})

@app.route('/api/folders/reorder', methods=['POST'])
@login_required
def folders_reorder():
    ids = (request.get_json(silent=True) or {}).get('ids') or []
    db = load_database()
    uid = session['user_id']
    folders, _ = _folder_state(db, uid)
    by_id = {f['id']: f for f in folders}
    ordered = [by_id[i] for i in ids if i in by_id]
    ordered += [f for f in folders if f['id'] not in set(ids)]
    db['chat_folders'][uid] = ordered
    save_database(db)
    return jsonify({'success': True, **_folders_payload(db, uid)})

@app.route('/api/folders/<folder_id>/items', methods=['POST'])
@login_required
def folders_item(folder_id):
    """body: {type, id, action: 'add' | 'remove'}"""
    data = request.get_json(silent=True) or {}
    item_type, item_id = data.get('type'), data.get('id')
    action = data.get('action', 'add')
    db = load_database()
    uid = session['user_id']
    folders, _ = _folder_state(db, uid)
    folder = next((f for f in folders if f['id'] == folder_id), None)
    if not folder:
        return jsonify({'error': 'Folder not found'}), 404
    exists = any(i['type'] == item_type and i['id'] == item_id for i in folder['items'])
    if action == 'remove':
        folder['items'] = [i for i in folder['items'] if not (i['type'] == item_type and i['id'] == item_id)]
    else:
        if not _valid_item(db, uid, item_type, item_id):
            return jsonify({'error': 'Invalid item'}), 400
        if not exists:
            folder['items'].append({'type': item_type, 'id': item_id})
    save_database(db)
    return jsonify({'success': True, 'folder': folder, **_folders_payload(db, uid)})

@app.route('/api/archive', methods=['GET'])
@login_required
def archive_list():
    db = load_database()
    return jsonify(_folders_payload(db, session['user_id'])['archive'])

@app.route('/api/archive', methods=['POST'])
@login_required
def archive_toggle():
    """body: {type, id, action: 'add' | 'remove'}"""
    data = request.get_json(silent=True) or {}
    item_type, item_id = data.get('type'), data.get('id')
    action = data.get('action', 'add')
    db = load_database()
    uid = session['user_id']
    _, archive = _folder_state(db, uid)
    if action == 'remove':
        db['chat_archive'][uid] = [a for a in archive if not (a['type'] == item_type and a['id'] == item_id)]
    else:
        if not _valid_item(db, uid, item_type, item_id):
            return jsonify({'error': 'Invalid item'}), 400
        if not any(a['type'] == item_type and a['id'] == item_id for a in archive):
            archive.append({'type': item_type, 'id': item_id, 'archived_at': datetime.now().isoformat()})
    save_database(db)
    return jsonify({'success': True, **_folders_payload(db, uid)})



@app.route('/api/pins', methods=['POST'])
@login_required
def pins_toggle():
    """body: {type, id, action: 'add' | 'remove'}  (system chats are always pinned and cannot be changed)"""
    data = request.get_json(silent=True) or {}
    item_type, item_id = data.get('type'), data.get('id')
    action = data.get('action', 'add')
    db = load_database()
    uid = session['user_id']
    _folder_state(db, uid)
    pins = db.setdefault('chat_pins', {}).setdefault(uid, [])
    if action == 'remove':
        db['chat_pins'][uid] = [p for p in pins if not (p['type'] == item_type and p['id'] == item_id)]
    else:
        if not _valid_item(db, uid, item_type, item_id):
            return jsonify({'error': 'Invalid item'}), 400
        if not any(p['type'] == item_type and p['id'] == item_id for p in pins):
            if len(pins) >= MAX_PINS:
                return jsonify({'error': f'You can pin up to {MAX_PINS} chats'}), 400
            pins.append({'type': item_type, 'id': item_id, 'pinned_at': datetime.now().isoformat()})
    save_database(db)
    return jsonify({'success': True, **_folders_payload(db, uid)})



# ============================================
# MEDIA LIBRARY  -  GIFs / Stickers / Emojis (managed by admins, stored in the DB)
#   * GET    /api/media-library                        -> everyone (logged in)
#   * POST   /api/admin/media-library                  -> admin: upload files / add URL / add unicode emoji
#   * PUT    /api/admin/media-library/<cat>/<item_id>  -> admin: rename
#   * DELETE /api/admin/media-library/<cat>/<item_id>  -> admin: remove from library
# Removing an item only removes it from the picker; the uploaded file is kept so
# old messages that already used it keep working.
# ============================================
MEDIA_CATEGORIES = ('gifs', 'stickers', 'emojis')   # gifs/stickers now live in packs; the library is only used for the emoji list
MEDIA_MAX_ITEMS = 500
MEDIA_MAX_BYTES = 8 * 1024 * 1024
MEDIA_EXTS = {'gif', 'png', 'webp', 'jpg', 'jpeg'}
DEFAULT_MEDIA_GIFS = ['Monkey.gif', '16.gif', '20.gif', '31.gif']
DEFAULT_MEDIA_STICKERS = [
    'Screenshot 2026-05-12 165337.png',
    '78075a91-7773-4a15-b4dd-29132bc92cea.webp',
    '01ffea0a-5f62-4db7-bc1d-4d50aa7ba27f.webp',
    'decf85a7-f95f-47d0-bd2a-65e8c667c4e0.jpg',
    '40b559d5-4258-472f-bf3e-88069a40b5d1.webp',
    'e8553b47-fd98-4dcc-bf07-52b0a1111cc8.webp',
    '4a329197-2e44-4cd7-bbb3-bfd76468b60d.webp',
]
DEFAULT_MEDIA_EMOJIS = ['😀', '😂', '❤️', '🔥', '👍', '👎', '🎉', '😎', '😢', '🤔', '🎊', '💯', '👋', '🙏', '💀', '🤡']

def _new_media_item(kind, name, added_by, url=None, char=None):
    item = {
        'id': uuid.uuid4().hex[:12],
        'kind': kind,                      # 'image' | 'unicode'
        'name': (name or '')[:64],
        'added_by': added_by,
        'created_at': datetime.now().isoformat(),
    }
    if kind == 'unicode':
        item['char'] = char
    else:
        item['url'] = url
    return item

def _media_library(db):
    """Returns (library, created). Seeds the old hard-coded files/emojis the first time."""
    lib = db.get('media_library')
    if isinstance(lib, dict):
        for c in MEDIA_CATEGORIES:
            if not isinstance(lib.get(c), list):
                lib[c] = []
        return lib, False
    lib = {'gifs': [], 'stickers': [], 'emojis': []}
    static_root = app.static_folder or 'static'
    for fn in DEFAULT_MEDIA_GIFS:
        if os.path.exists(os.path.join(static_root, 'gif', fn)):
            lib['gifs'].append(_new_media_item('image', os.path.splitext(fn)[0], 'system', url='/static/gif/' + urllib.parse.quote(fn)))
    for fn in DEFAULT_MEDIA_STICKERS:
        if os.path.exists(os.path.join(static_root, 'sticker', fn)):
            lib['stickers'].append(_new_media_item('image', os.path.splitext(fn)[0], 'system', url='/static/sticker/' + urllib.parse.quote(fn)))
    for ch in DEFAULT_MEDIA_EMOJIS:
        lib['emojis'].append(_new_media_item('unicode', '', 'system', char=ch))
    db['media_library'] = lib
    return lib, True

def _is_admin_user(db, uid):
    return bool(db.get('users', {}).get(uid, {}).get('is_admin'))

@app.route('/api/media-library', methods=['GET'])
@login_required
def media_library_get():
    db = load_database()
    lib, created = _media_library(db)
    if created:
        save_database(db)
    return jsonify({**lib, 'can_manage': _is_admin_user(db, session['user_id'])})

@app.route('/api/admin/media-library', methods=['POST'])
@admin_required
def media_library_add():
    db = load_database()
    uid = session['user_id']
    lib, _ = _media_library(db)

    # ----- multipart: one or many uploaded files -----
    if request.files:
        category = request.form.get('category', '')
        if category not in MEDIA_CATEGORIES:
            return jsonify({'error': 'Invalid category'}), 400
        files = request.files.getlist('file') or request.files.getlist('files')
        if not files:
            return jsonify({'error': 'No file part'}), 400
        custom_name = request.form.get('name', '').strip()
        added, errors = [], []
        for f in files:
            if not f or not f.filename:
                continue
            if len(lib[category]) + len(added) >= MEDIA_MAX_ITEMS:
                errors.append(f'{f.filename}: library is full ({MEDIA_MAX_ITEMS} max)')
                break
            ext = f.filename.rsplit('.', 1)[1].lower() if '.' in f.filename else ''
            if ext not in MEDIA_EXTS:
                errors.append(f'{f.filename}: unsupported type (allowed: {", ".join(sorted(MEDIA_EXTS))})')
                continue
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(0)
            if size > MEDIA_MAX_BYTES:
                errors.append(f'{f.filename}: too large (max {MEDIA_MAX_BYTES // (1024 * 1024)} MB)')
                continue
            new_filename = f"media_{uuid.uuid4().hex}.{ext}"
            try:
                f.save(os.path.join(UPLOAD_DIR, new_filename))
            except Exception as e:
                errors.append(f'{f.filename}: {e}')
                continue
            stem = os.path.splitext(os.path.basename(f.filename))[0]
            name = custom_name if (custom_name and len(files) == 1) else stem
            added.append(_new_media_item('image', name, uid, url=f'/uploads/{new_filename}'))
        if not added:
            return jsonify({'error': errors[0] if errors else 'Nothing uploaded', 'errors': errors}), 400
        lib[category].extend(added)
        save_database(db)
        return jsonify({'success': True, 'items': added, 'errors': errors, **lib})

    # ----- JSON: unicode emoji or external image URL -----
    data = request.get_json(silent=True) or {}
    category = data.get('category', '')
    if category not in MEDIA_CATEGORIES:
        return jsonify({'error': 'Invalid category'}), 400
    if len(lib[category]) >= MEDIA_MAX_ITEMS:
        return jsonify({'error': f'Library is full ({MEDIA_MAX_ITEMS} max)'}), 400

    char = (data.get('char') or '').strip()
    url = (data.get('url') or '').strip()
    name = (data.get('name') or '').strip()
    if char:
        if category != 'emojis':
            return jsonify({'error': 'Unicode emojis can only be added to the emojis category'}), 400
        if len(char) > 16:
            return jsonify({'error': 'Emoji is too long'}), 400
        if any(i.get('char') == char for i in lib['emojis']):
            return jsonify({'error': 'This emoji already exists'}), 400
        item = _new_media_item('unicode', name, uid, char=char)
    elif url:
        if not (url.startswith('https://') or url.startswith('http://') or url.startswith('/static/') or url.startswith('/uploads/')):
            return jsonify({'error': 'URL must start with http(s)://'}), 400
        if len(url) > 2000:
            return jsonify({'error': 'URL is too long'}), 400
        if any(i.get('url') == url for i in lib[category]):
            return jsonify({'error': 'This URL already exists'}), 400
        item = _new_media_item('image', name or url.rsplit('/', 1)[-1][:64], uid, url=url)
    else:
        return jsonify({'error': 'Provide a file, a url or an emoji character'}), 400
    lib[category].append(item)
    save_database(db)
    return jsonify({'success': True, 'items': [item], **lib})

@app.route('/api/admin/media-library/<category>/<item_id>', methods=['PUT'])
@admin_required
def media_library_rename(category, item_id):
    if category not in MEDIA_CATEGORIES:
        return jsonify({'error': 'Invalid category'}), 400
    data = request.get_json(silent=True) or {}
    db = load_database()
    lib, _ = _media_library(db)
    for item in lib[category]:
        if item['id'] == item_id:
            item['name'] = str(data.get('name', '')).strip()[:64]
            save_database(db)
            return jsonify({'success': True, 'item': item, **lib})
    return jsonify({'error': 'Item not found'}), 404

@app.route('/api/admin/media-library/<category>/<item_id>', methods=['DELETE'])
@admin_required
def media_library_delete(category, item_id):
    if category not in MEDIA_CATEGORIES:
        return jsonify({'error': 'Invalid category'}), 400
    db = load_database()
    lib, _ = _media_library(db)
    before = len(lib[category])
    lib[category] = [i for i in lib[category] if i['id'] != item_id]
    if len(lib[category]) == before:
        return jsonify({'error': 'Item not found'}), 404
    save_database(db)
    return jsonify({'success': True, **lib})


# ============================================
# STICKER / GIF PACKS + SHOP
#   * Anyone can create packs, upload stickers/GIFs into them, edit and delete their own packs.
#   * Admins can edit/delete any pack.
#   * Nothing is installed by default: users install packs from the shop (or by clicking a
#     sticker/GIF someone sent, which opens its pack).
#   * Public packs appear in the shop; private ones are reachable only through a sent sticker.
# ============================================
PACK_TYPES = ('stickers', 'gifs')
PACK_EXTS = {'stickers': {'png', 'webp', 'gif', 'jpg', 'jpeg'}, 'gifs': {'gif', 'webp'}}
MAX_PACKS_PER_USER = 20
MAX_ITEMS_PER_PACK = 120
MAX_INSTALLED_PACKS = 100
MAX_PACK_PRICE = 10000          # coins; 0 = free pack

def _media_packs(db):
    """Returns (packs_dict, created). Migrates the old admin-managed GIF/sticker library into official packs."""
    packs = db.get('media_packs')
    if isinstance(packs, dict):
        db.setdefault('media_installed', {})
        return packs, False
    lib, _ = _media_library(db)
    packs = {}
    for ptype, title, desc in (('gifs', 'Classic GIFs', 'The original GIF collection'),
                               ('stickers', 'Classic Stickers', 'The original sticker collection')):
        items = [{'id': i['id'], 'url': i.get('url'), 'name': i.get('name', ''), 'created_at': i.get('created_at')}
                 for i in lib.get(ptype, []) if i.get('url')]
        if items:
            pid = 'pack_' + uuid.uuid4().hex[:10]
            packs[pid] = {'id': pid, 'name': title, 'type': ptype, 'description': desc, 'owner_id': 'system',
                          'public': True, 'official': True, 'items': items, 'created_at': datetime.now().isoformat()}
        lib[ptype] = []
    db['media_packs'] = packs
    db.setdefault('media_installed', {})
    save_database(db)   # persist the migration right away so pack ids stay stable
    return packs, True

def _pack_owner_name(db, pack):
    if pack.get('owner_id') == 'system':
        return 'Official'
    return db.get('users', {}).get(pack.get('owner_id'), {}).get('username', 'Unknown')

def _can_edit_pack(db, uid, pack):
    return pack.get('owner_id') == uid or _is_admin_user(db, uid)

def _adult_blocked(db, uid):
    """Is this user's parental control set to block 18+ content?"""
    pc = (db.get('parental_control') or {}).get(uid) or {}
    if pc.get('block_adult_content'):
        return True
    return any(str(t).strip().lower() in ('+18', '18+') for t in (pc.get('blocked_tags') or []))

def _pack_restriction(db, uid, pack):
    """None, or why this user may not see the pack's content: 'adult' | 'hidden'."""
    if pack.get('adult') and _adult_blocked(db, uid):
        return 'adult'
    if pack.get('hidden') and not _can_edit_pack(db, uid, pack):
        return 'hidden'
    return None

def _media_remove_pack(db, pack_id):
    db.get('media_packs', {}).pop(pack_id, None)
    for u, lst in db.get('media_installed', {}).items():
        if pack_id in lst:
            db['media_installed'][u] = [i for i in lst if i != pack_id]

PACK_AUTOHIDE_REPORTS = 3       # distinct reporters with open reports -> pack is hidden until an admin reviews it
MEDIA_UPLOAD_LIMIT = 40         # files per user per 10 minutes (admins exempt)
_media_upload_log = {}

def _media_rate_ok(db, uid, n):
    if _is_admin_user(db, uid):
        return True
    now = _time_rich.time()
    recent = [t for t in _media_upload_log.get(uid, []) if now - t < 600]
    if len(recent) + n > MEDIA_UPLOAD_LIMIT:
        _media_upload_log[uid] = recent
        return False
    _media_upload_log[uid] = recent + [now] * n
    return True

def _looks_like_image(f, ext):
    """Check the real file header so a renamed .exe/.html can't be uploaded as a sticker."""
    head = f.read(16)
    f.seek(0)
    if ext == 'gif':
        return head[:6] in (b'GIF87a', b'GIF89a')
    if ext == 'png':
        return head[:8] == b'\x89PNG\r\n\x1a\n'
    if ext in ('jpg', 'jpeg'):
        return head[:3] == b'\xff\xd8\xff'
    if ext == 'webp':
        return head[:4] == b'RIFF' and head[8:12] == b'WEBP'
    return False

def _pack_check_autohide(db, pack_id):
    packs, _ = _media_packs(db)
    pack = packs.get(pack_id)
    if not pack or pack.get('hidden') or pack.get('official'):
        return
    reporters = {r.get('reporter_id') for r in (db.get('reports') or {}).values()
                 if r.get('type') == 'pack' and r.get('target_id') == pack_id and r.get('status') in ('open', 'reviewing')}
    if len(reporters) >= PACK_AUTOHIDE_REPORTS:
        pack['hidden'], pack['hidden_reason'] = True, 'reports'
        for uid, u in db['users'].items():
            if u.get('is_admin'):
                _adm2_notify(db, uid, 'Pack auto-hidden', f"Pack \"{pack['name']}\" got {len(reporters)} reports and was hidden until reviewed.", 'report', {})
        owner = pack.get('owner_id')
        if owner in db['users']:
            _adm2_notify(db, owner, 'Your pack was hidden', f"Your pack \"{pack['name']}\" was hidden because of reports and will be reviewed by an administrator.", 'warning')

def _parse_pack_price(raw):
    """Whole number of coins from 0 to MAX_PACK_PRICE, or None when invalid."""
    if raw is None or raw == '':
        return 0
    if isinstance(raw, bool):
        return None
    try:
        value = int(float(raw))
    except (TypeError, ValueError, OverflowError):
        return None
    return value if 0 <= value <= MAX_PACK_PRICE else None

def _pack_paid_locked(db, uid, pack):
    """True when this user must buy the pack before installing it (paid pack, not the creator, not bought yet)."""
    if int(pack.get('price') or 0) <= 0 or pack.get('owner_id') == uid:
        return False
    return pack['id'] not in (db.get('media_purchases') or {}).get(uid, [])

def _pack_json(db, pack, uid, full=False):
    installed = pack['id'] in db.get('media_installed', {}).get(uid, [])
    items = pack.get('items', [])
    restricted = _pack_restriction(db, uid, pack)
    out = {
        'id': pack['id'], 'name': pack['name'], 'type': pack['type'],
        'description': pack.get('description', ''), 'public': bool(pack.get('public', True)),
        'official': bool(pack.get('official')), 'adult': bool(pack.get('adult')),
        'hidden': bool(pack.get('hidden')), 'owner_id': pack.get('owner_id'),
        'owner_name': _pack_owner_name(db, pack), 'count': len(items),
        'cover': None if restricted else (items[0]['url'] if items else None),
        'previews': [] if restricted else [i['url'] for i in items[:4]],
        'installed': installed, 'can_edit': _can_edit_pack(db, uid, pack),
        'price': int(pack.get('price') or 0),
        'purchased': pack['id'] in (db.get('media_purchases') or {}).get(uid, []) or pack.get('owner_id') == uid,
        'restricted': restricted, 'created_at': pack.get('created_at'),
    }
    if full:
        out['items'] = [] if restricted else items
    return out

def _clean_pack_text(raw, limit):
    return re.sub(r'\s+', ' ', str(raw or '')).strip()[:limit]

@app.route('/api/media/packs', methods=['GET'])
@login_required
def media_packs_list():
    """scope = shop (public packs) | mine | installed (includes items, used by the picker)"""
    db = load_database()
    uid = session['user_id']
    packs, created = _media_packs(db)
    if created:
        save_database(db)
    scope = request.args.get('scope', 'shop')
    ptype = request.args.get('type', '')
    q = request.args.get('q', '').strip().lower()
    if scope == 'installed':
        ids = db['media_installed'].get(uid, [])
        chosen = [packs[i] for i in ids if i in packs and not _pack_restriction(db, uid, packs[i])]
    elif scope == 'mine':
        chosen = [p for p in packs.values() if p.get('owner_id') == uid]
    else:
        chosen = [p for p in packs.values() if p.get('public', True) and not p.get('hidden') and not _pack_restriction(db, uid, p)]
    if ptype in PACK_TYPES:
        chosen = [p for p in chosen if p['type'] == ptype]
    if q:
        chosen = [p for p in chosen if q in p['name'].lower() or q in p.get('description', '').lower()]
    if scope == 'shop':
        chosen.sort(key=lambda p: (not p.get('official'), -sum(1 for l in db['media_installed'].values() if p['id'] in l)))
    return jsonify({'packs': [_pack_json(db, p, uid, full=(scope == 'installed')) for p in chosen]})

@app.route('/api/media/packs', methods=['POST'])
@login_required
def media_pack_create():
    data = request.get_json(silent=True) or {}
    db = load_database()
    uid = session['user_id']
    packs, _ = _media_packs(db)
    if db['users'].get(uid, {}).get('media_banned'):
        return jsonify({'error': 'You are not allowed to create sticker packs'}), 403
    if not data.get('agree'):
        return jsonify({'error': 'You must confirm that your pack follows the rules'}), 400
    name = _clean_pack_text(data.get('name'), 40)
    ptype = data.get('type')
    if not name:
        return jsonify({'error': 'Pack name is required'}), 400
    if ptype not in PACK_TYPES:
        return jsonify({'error': 'Pack type must be stickers or gifs'}), 400
    if not _is_admin_user(db, uid) and sum(1 for p in packs.values() if p.get('owner_id') == uid) >= MAX_PACKS_PER_USER:
        return jsonify({'error': f'You can create up to {MAX_PACKS_PER_USER} packs'}), 400
    price = _parse_pack_price(data.get('price'))
    if price is None:
        return jsonify({'error': f'Price must be a whole number from 0 to {MAX_PACK_PRICE} coins'}), 400
    pid = 'pack_' + uuid.uuid4().hex[:10]
    pack = {'id': pid, 'name': name, 'type': ptype, 'description': _clean_pack_text(data.get('description'), 200),
            'owner_id': uid, 'price': price, 'public': bool(data.get('public', True)), 'official': False,
            'adult': bool(data.get('adult', False)), 'hidden': False, 'items': [],
            'created_at': datetime.now().isoformat()}
    packs[pid] = pack
    db['media_installed'].setdefault(uid, []).append(pid)   # the creator gets their own pack installed
    save_database(db)
    return jsonify({'success': True, 'pack': _pack_json(db, pack, uid, full=True)})

@app.route('/api/media/packs/<pack_id>', methods=['GET'])
@login_required
def media_pack_get(pack_id):
    db = load_database()
    packs, _ = _media_packs(db)
    pack = packs.get(pack_id)
    if not pack:
        return jsonify({'error': 'Pack not found'}), 404
    return jsonify({'pack': _pack_json(db, pack, session['user_id'], full=True)})

@app.route('/api/media/packs/<pack_id>', methods=['PUT'])
@login_required
def media_pack_update(pack_id):
    data = request.get_json(silent=True) or {}
    db = load_database()
    uid = session['user_id']
    packs, _ = _media_packs(db)
    pack = packs.get(pack_id)
    if not pack:
        return jsonify({'error': 'Pack not found'}), 404
    if not _can_edit_pack(db, uid, pack):
        return jsonify({'error': 'Permission denied'}), 403
    if 'name' in data:
        name = _clean_pack_text(data.get('name'), 40)
        if not name:
            return jsonify({'error': 'Pack name is required'}), 400
        pack['name'] = name
    if 'description' in data:
        pack['description'] = _clean_pack_text(data.get('description'), 200)
    if 'public' in data:
        if db['users'].get(uid, {}).get('media_banned') and data.get('public'):
            return jsonify({'error': 'You are not allowed to publish packs'}), 403
        pack['public'] = bool(data.get('public'))
    if 'price' in data:
        price = _parse_pack_price(data.get('price'))
        if price is None:
            return jsonify({'error': f'Price must be a whole number from 0 to {MAX_PACK_PRICE} coins'}), 400
        if price != int(pack.get('price') or 0) and pack.get('owner_id') != uid:
            return jsonify({'error': 'Only the pack creator can change the price'}), 403
        pack['price'] = price
    if 'adult' in data:
        want = bool(data.get('adult'))
        if not want and pack.get('adult') and not _is_admin_user(db, uid) and pack.get('adult_by_admin'):
            return jsonify({'error': 'An administrator marked this pack as 18+'}), 403
        pack['adult'] = want
    save_database(db)
    return jsonify({'success': True, 'pack': _pack_json(db, pack, uid, full=True)})

@app.route('/api/media/packs/<pack_id>', methods=['DELETE'])
@login_required
def media_pack_delete(pack_id):
    db = load_database()
    uid = session['user_id']
    packs, _ = _media_packs(db)
    pack = packs.get(pack_id)
    if not pack:
        return jsonify({'error': 'Pack not found'}), 404
    if not _can_edit_pack(db, uid, pack):
        return jsonify({'error': 'Permission denied'}), 403
    _media_remove_pack(db, pack_id)
    save_database(db)   # uploaded files stay on disk so old messages keep showing them
    return jsonify({'success': True})

@app.route('/api/media/packs/<pack_id>/items', methods=['POST'])
@login_required
def media_pack_add_items(pack_id):
    db = load_database()
    uid = session['user_id']
    packs, _ = _media_packs(db)
    pack = packs.get(pack_id)
    if not pack:
        return jsonify({'error': 'Pack not found'}), 404
    if not _can_edit_pack(db, uid, pack):
        return jsonify({'error': 'Permission denied'}), 403
    if db['users'].get(uid, {}).get('media_banned'):
        return jsonify({'error': 'You are not allowed to upload to sticker packs'}), 403
    files = request.files.getlist('file')
    if not files:
        return jsonify({'error': 'No file part'}), 400
    if not _media_rate_ok(db, uid, len(files)):
        return jsonify({'error': 'Too many uploads. Please wait a few minutes and try again.'}), 429
    allowed = PACK_EXTS[pack['type']]
    custom_name = request.form.get('name', '').strip()
    added, errors = [], []
    for f in files:
        if not f or not f.filename:
            continue
        if len(pack['items']) + len(added) >= MAX_ITEMS_PER_PACK:
            errors.append(f'Pack is full ({MAX_ITEMS_PER_PACK} max)')
            break
        ext = f.filename.rsplit('.', 1)[1].lower() if '.' in f.filename else ''
        if ext not in allowed:
            errors.append(f'{f.filename}: unsupported type (allowed: {", ".join(sorted(allowed))})')
            continue
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(0)
        if size > MEDIA_MAX_BYTES:
            errors.append(f'{f.filename}: too large (max {MEDIA_MAX_BYTES // (1024 * 1024)} MB)')
            continue
        if not _looks_like_image(f, ext):
            errors.append(f'{f.filename}: not a valid {ext.upper()} image')
            continue
        new_filename = f"media_{uuid.uuid4().hex}.{ext}"
        try:
            f.save(os.path.join(UPLOAD_DIR, new_filename))
        except Exception as e:
            errors.append(f'{f.filename}: {e}')
            continue
        stem = os.path.splitext(os.path.basename(f.filename))[0][:64]
        added.append({'id': uuid.uuid4().hex[:12], 'url': f'/uploads/{new_filename}',
                      'name': custom_name if (custom_name and len(files) == 1) else stem,
                      'created_at': datetime.now().isoformat()})
    if not added:
        return jsonify({'error': errors[0] if errors else 'Nothing uploaded', 'errors': errors}), 400
    pack['items'].extend(added)
    save_database(db)
    return jsonify({'success': True, 'errors': errors, 'pack': _pack_json(db, pack, uid, full=True)})

@app.route('/api/media/packs/<pack_id>/items/<item_id>', methods=['DELETE'])
@login_required
def media_pack_delete_item(pack_id, item_id):
    db = load_database()
    uid = session['user_id']
    packs, _ = _media_packs(db)
    pack = packs.get(pack_id)
    if not pack:
        return jsonify({'error': 'Pack not found'}), 404
    if not _can_edit_pack(db, uid, pack):
        return jsonify({'error': 'Permission denied'}), 403
    before = len(pack['items'])
    pack['items'] = [i for i in pack['items'] if i['id'] != item_id]
    if len(pack['items']) == before:
        return jsonify({'error': 'Item not found'}), 404
    save_database(db)
    return jsonify({'success': True, 'pack': _pack_json(db, pack, uid, full=True)})

@app.route('/api/media/packs/<pack_id>/install', methods=['POST', 'DELETE'])
@login_required
def media_pack_install(pack_id):
    db = load_database()
    uid = session['user_id']
    packs, _ = _media_packs(db)
    pack = packs.get(pack_id)
    if not pack:
        return jsonify({'error': 'Pack not found'}), 404
    lst = db['media_installed'].setdefault(uid, [])
    if request.method == 'POST':
        if _pack_restriction(db, uid, pack):
            return jsonify({'error': 'This pack is not available'}), 403
        if _pack_paid_locked(db, uid, pack):
            return jsonify({'error': f"This pack costs {pack.get('price')} coins. Buy it first."}), 402
        if pack_id not in lst:
            if len(lst) >= MAX_INSTALLED_PACKS:
                return jsonify({'error': f'You can install up to {MAX_INSTALLED_PACKS} packs'}), 400
            lst.append(pack_id)
    else:
        db['media_installed'][uid] = [i for i in lst if i != pack_id]
    save_database(db)
    return jsonify({'success': True, 'pack': _pack_json(db, pack, uid, full=True)})

@app.route('/api/media/packs/<pack_id>/buy', methods=['POST'])
@login_required
def media_pack_buy(pack_id):
    """Buys a paid pack: the coins go from the buyer to the pack creator, then the pack is installed for the buyer."""
    db = load_database()
    uid = session['user_id']
    packs, _ = _media_packs(db)
    pack = packs.get(pack_id)
    if not pack:
        return jsonify({'error': 'Pack not found'}), 404
    if _pack_restriction(db, uid, pack):
        return jsonify({'error': 'This pack is not available'}), 403
    lst = db['media_installed'].setdefault(uid, [])
    purchases = db.setdefault('media_purchases', {}).setdefault(uid, [])
    balance = int(db['users'].get(uid, {}).get('coins', 0) or 0)
    if _pack_paid_locked(db, uid, pack):
        if pack_id not in lst and len(lst) >= MAX_INSTALLED_PACKS:
            return jsonify({'error': f'You can install up to {MAX_INSTALLED_PACKS} packs'}), 400
        status, error, balance = coin_transfer(db, uid, pack['owner_id'], int(pack['price']))
        if error:
            return jsonify({'error': error}), status
        purchases.append(pack_id)
    elif pack_id not in lst and len(lst) >= MAX_INSTALLED_PACKS:
        return jsonify({'error': f'You can install up to {MAX_INSTALLED_PACKS} packs'}), 400
    if pack_id not in lst:
        lst.append(pack_id)
    save_database(db)
    return jsonify({'success': True, 'coins': balance, 'pack': _pack_json(db, pack, uid, full=True)})

@app.route('/api/media/adult-urls', methods=['GET'])
@login_required
def media_adult_urls():
    """Urls of stickers/GIFs the client must NOT show to this user (18+ for parental-blocked users, hidden packs)."""
    db = load_database()
    uid = session['user_id']
    packs, _ = _media_packs(db)
    blocked = _adult_blocked(db, uid)
    is_admin = _is_admin_user(db, uid)
    adult, hidden = [], []
    for p in packs.values():
        if p.get('adult') and blocked:
            adult.extend(i['url'] for i in p.get('items', []))
        elif p.get('hidden') and not is_admin and p.get('owner_id') != uid:
            hidden.extend(i['url'] for i in p.get('items', []))
    return jsonify({'blocked': blocked, 'adult': adult, 'hidden': hidden})

@app.route('/api/admin/media/ban', methods=['POST'])
@admin_required
def media_ban_user():
    data = request.get_json(silent=True) or {}
    db = load_database()
    target = data.get('user_id')
    if target not in db['users']:
        return jsonify({'error': 'User not found'}), 404
    db['users'][target]['media_banned'] = bool(data.get('banned', True))
    save_database(db)
    return jsonify({'success': True, 'media_banned': db['users'][target]['media_banned']})

@app.route('/api/media/lookup', methods=['GET'])
@login_required
def media_lookup():
    """Which pack does this sticker/GIF url belong to? (used when someone clicks a sent sticker)"""
    raw = request.args.get('url', '')
    path = urllib.parse.unquote(urllib.parse.urlparse(raw).path or raw)
    db = load_database()
    packs, _ = _media_packs(db)
    for pack in packs.values():
        for item in pack.get('items', []):
            if urllib.parse.unquote(item.get('url', '')) == path:
                return jsonify({'pack': _pack_json(db, pack, session['user_id'])})
    return jsonify({'error': 'Not found'}), 404

# ============================================
# REPORT LOCK  -  servers / channels / groups with too many active reports
#   * nobody new can join (invite link, join, add-member)
#   * current members are limited (no posting, no invites, no new channels, no adding people)
#   * a red notice is shown inside the server / channel (see /api/report-locks)
# A report counts while its status is 'open' or 'reviewing'. When an admin resolves
# or dismisses reports the count drops and the lock lifts automatically.
# Distinct reporters are counted, so one person cannot lock a server alone.
# ============================================
REPORT_LOCK_THRESHOLD = 10          # lock when MORE than this many people reported it
REPORT_REASON_EN = {
    'spam': 'spam', 'harassment': 'harassment or bullying', 'hate': 'hate speech',
    'nsfw': '18+ / inappropriate content', 'violence': 'violence or threats',
    'scam': 'scam or phishing', 'impersonation': 'impersonation', 'self_harm': 'self-harm content',
    'illegal': 'illegal content', 'other': 'rule violations',
}
REPORT_REASON_FA = {
    'spam': 'اسپم', 'harassment': 'آزار و اذیت', 'hate': 'سخنان نفرت‌آمیز',
    'nsfw': 'محتوای ۱۸+ یا نامناسب', 'violence': 'خشونت', 'scam': 'کلاه‌برداری',
    'impersonation': 'جعل هویت', 'self_harm': 'محتوای آسیب به خود',
    'illegal': 'محتوای غیرقانونی', 'other': 'تخلف از قوانین',
}

def _report_lock_table(db):
    """{(type, target_id): {'reporters': set, 'reasons': {reason: n}}} for active reports."""
    table = {}
    for r in db.get('reports', {}).values():
        if r.get('status') not in ('open', 'reviewing') or r.get('type') not in ('server', 'channel'):
            continue
        e = table.setdefault((r['type'], r.get('target_id')), {'reporters': set(), 'reasons': {}})
        e['reporters'].add(r.get('reporter_id'))
        e['reasons'][r.get('reason', 'other')] = e['reasons'].get(r.get('reason', 'other'), 0) + 1
    return table

def _lock_from_entry(entry, kind):
    if not entry or len(entry['reporters']) <= REPORT_LOCK_THRESHOLD:
        return None
    reason = max(entry['reasons'], key=entry['reasons'].get)
    en, fa = REPORT_REASON_EN.get(reason, 'rule violations'), REPORT_REASON_FA.get(reason, 'تخلف از قوانین')
    fa_kind = 'سرور' if kind == 'server' else 'کانال'
    return {
        'locked': True, 'kind': kind, 'count': len(entry['reporters']), 'reason': reason,
        'text_en': f'This {kind} was reported for {en} and is under review. Joining and posting are restricted.',
        'text_fa': f'این {fa_kind} به دلیل {fa} ریپورت شده و در دست بررسی است. عضویت و ارسال پیام محدود شده است.',
    }

def server_report_lock(db, server_id, table=None):
    table = table if table is not None else _report_lock_table(db)
    return _lock_from_entry(table.get(('server', server_id)), 'server')

def channel_report_lock(db, channel_id, table=None):
    """A channel is locked by its own reports or by its server's reports."""
    table = table if table is not None else _report_lock_table(db)
    own = _lock_from_entry(table.get(('channel', channel_id)), 'channel')
    if own:
        return own
    ch = db.get('channels', {}).get(channel_id)
    return server_report_lock(db, ch.get('server_id'), table) if ch else None

@app.route('/api/report-locks')
@login_required
def report_locks_api():
    db = load_database()
    uid = session['user_id']
    table = _report_lock_table(db)
    out = {'servers': {}, 'channels': {}, 'threshold': REPORT_LOCK_THRESHOLD}
    for sid, srv in db.get('servers', {}).items():
        if uid not in srv.get('members', []):
            continue
        lk = server_report_lock(db, sid, table)
        if lk:
            out['servers'][sid] = lk
    for cid, ch in db.get('channels', {}).items():
        srv = db.get('servers', {}).get(ch.get('server_id'))
        if not srv or uid not in srv.get('members', []):
            continue
        lk = _lock_from_entry(table.get(('channel', cid)), 'channel')
        if lk:
            out['channels'][cid] = lk
    return jsonify(out)

_LOCK_RULES = [
    # (regex, kind-of-target)  — only non-GET requests are checked
    (re.compile(r'^/api/servers/([^/]+)/(?:join|invites|members)$'), 'server'),
    (re.compile(r'^/api/channels/([^/]+)/(?:messages|threads|pins)$'), 'channel'),
    (re.compile(r'^/api/(?:join|invite)/([^/]+?)(?:/join)?$'), 'invite'),
    (re.compile(r'^/join/([^/]+)/join$'), 'invite'),
]

@app.before_request
def report_lock_guard():
    if request.method in ('GET', 'HEAD', 'OPTIONS'):
        return None
    path = request.path
    if not (path.startswith('/api/') or path.startswith('/join/')):
        return None
    hit = None
    for rx, kind in _LOCK_RULES:
        m = rx.match(path)
        if m:
            hit = (kind, m.group(1))
            break
    if not hit and path == '/api/channels':           # creating a channel inside a locked server
        hit = ('server', (request.get_json(silent=True) or {}).get('server_id'))
    if not hit or not hit[1]:
        return None
    db = load_database()
    me = db.get('users', {}).get(session.get('user_id'), {})
    if me.get('is_admin'):
        return None
    kind, ident = hit
    if kind == 'invite':
        inv = db.get('invites', {}).get(ident)
        lock = server_report_lock(db, inv.get('server_id')) if inv else None
    elif kind == 'server':
        lock = server_report_lock(db, ident)
    else:
        lock = channel_report_lock(db, ident)
    if not lock:
        return None
    return jsonify({'error': lock['text_en'], 'error_fa': lock['text_fa'], 'code': 'REPORT_LOCK', 'lock': lock}), 403


# ============================================
# PINNED MESSAGES  (channels, groups and DMs; several pins per chat)
#   db['message_pins'][scope] -> [ {message_id, pinned_by, pinned_at} ]
#   scope = 'ch_<channel_id>' for channels, 'dm_<a>_<b>' for DMs
# ============================================
MAX_MESSAGE_PINS = 50

def _pin_msg_find(db, scope_type, scope_id, message_id, uid=None):
    if scope_type == 'channel':
        m = db.get('all_messages', {}).get(message_id)
        return m if m and m.get('channel_id') == scope_id and not m.get('deleted') else None
    for m in db.get('direct_messages', {}).get(scope_id, []):
        if m.get('id') == message_id and not m.get('deleted'):
            return m
    return None

def _pin_context(db, scope_type, ident, uid):
    """-> (scope_key, scope_id, can_manage, error_response)"""
    if scope_type == 'channel':
        ch = db.get('channels', {}).get(ident)
        srv = db.get('servers', {}).get(ch.get('server_id')) if ch else None
        if not ch or not srv:
            return None, None, False, (jsonify({'error': 'Channel not found'}), 404)
        if uid not in srv.get('members', []):
            return None, None, False, (jsonify({'error': 'Not a member of this server'}), 403)
        can = srv.get('owner_id') == uid or has_permission(db, uid, ch['server_id'], 'manage_messages')
        return 'ch_' + ident, ident, bool(can), None
    other = db.get('users', {}).get(ident)
    if not other or ident == uid:
        return None, None, False, (jsonify({'error': 'User not found'}), 404)
    key = _adm2_dm_key(uid, ident)
    return key, key, True, None

def _pins_payload(db, scope_type, scope_key, scope_id, can_manage):
    pins = db.setdefault('message_pins', {}).get(scope_key, [])
    out = []
    for p in sorted(pins, key=lambda x: x.get('pinned_at', ''), reverse=True):
        m = _pin_msg_find(db, scope_type, scope_id, p['message_id'])
        if not m:
            continue
        au = db['users'].get(m.get('user_id'), {})
        by = db['users'].get(p.get('pinned_by'), {})
        content = (m.get('content') or '').strip()
        media = bool(m.get('image_url') or m.get('attachment') or m.get('location') or m.get('poll'))
        out.append({
            'message_id': p['message_id'], 'content': content[:200], 'has_media': media,
            'author_id': m.get('user_id'), 'author_name': au.get('username', 'Unknown'),
            'pinned_by': by.get('username', 'Unknown'), 'pinned_at': p.get('pinned_at'),
            'created_at': m.get('created_at'),
        })
    return {'pins': out, 'can_manage': can_manage}

def _pins_handler(scope_type, ident, method, message_id=None):
    db = load_database()
    uid = session['user_id']
    key, sid, can, err = _pin_context(db, scope_type, ident, uid)
    if err:
        return err
    if method != 'GET':
        if not can:
            return jsonify({'error': 'You do not have permission to pin messages here'}), 403
        pins = db.setdefault('message_pins', {}).setdefault(key, [])
        if method == 'POST':
            message_id = str((request.get_json(silent=True) or {}).get('message_id') or '')
            if not _pin_msg_find(db, scope_type, sid, message_id):
                return jsonify({'error': 'Message not found'}), 404
            if not any(p['message_id'] == message_id for p in pins):
                if len(pins) >= MAX_MESSAGE_PINS:
                    return jsonify({'error': f'You can pin up to {MAX_MESSAGE_PINS} messages'}), 400
                pins.append({'message_id': message_id, 'pinned_by': uid, 'pinned_at': datetime.now().isoformat()})
        else:
            db['message_pins'][key] = [p for p in pins if p['message_id'] != message_id]
        save_database(db)
    return jsonify({'success': True, **_pins_payload(db, scope_type, key, sid, can)})

@app.route('/api/channels/<channel_id>/pins', methods=['GET', 'POST'])
@login_required
def channel_pins(channel_id):
    return _pins_handler('channel', channel_id, request.method)

@app.route('/api/channels/<channel_id>/pins/<message_id>', methods=['DELETE'])
@login_required
def channel_unpin(channel_id, message_id):
    return _pins_handler('channel', channel_id, 'DELETE', message_id)

@app.route('/api/dm/<user_id>/pins', methods=['GET', 'POST'])
@login_required
def dm_pins(user_id):
    return _pins_handler('dm', user_id, request.method)

@app.route('/api/dm/<user_id>/pins/<message_id>', methods=['DELETE'])
@login_required
def dm_unpin(user_id, message_id):
    return _pins_handler('dm', user_id, 'DELETE', message_id)


# ==========================================================================
# HARDENING / FIXES  (helpers used by the patched routes above)
# ==========================================================================
EMAIL_RE = re.compile(r'^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$')
_PRIVATE_USER_FIELDS = ('email', 'devices', 'blocked_users', 'close_friends', 'password')


def sanitize_user_for_viewer(db, viewer_id, user):
    """A user dict that is safe to show to `viewer_id` (no password / e-mail / devices, privacy applied)."""
    u = dict(user)
    u.pop('password', None)
    return apply_privacy_to_user(db, viewer_id, u)


def _clean_image_url(url):
    if not isinstance(url, str):
        return None
    url = url.strip()
    if url.startswith('/uploads/') and len(url) < 300 and '..' not in url:
        return url
    if url.startswith('https://') and len(url) < 500:
        return url
    return None


def _invite_problem(invite):
    try:
        if invite.get('expires_at') and datetime.now() > datetime.fromisoformat(invite['expires_at']):
            return 'This invite has expired'
    except ValueError:
        pass
    if invite.get('max_uses', 0) > 0 and invite.get('uses', 0) >= invite['max_uses']:
        return 'This invite has reached its maximum uses'
    return None


# ---------------- login brute-force protection ----------------
_login_fails = {}
_login_fail_lock = threading.Lock()
LOGIN_MAX_FAILS = 10
LOGIN_WINDOW = 600


def _login_keys(email):
    return [('ip', request.remote_addr or '-'), ('em', (email or '').lower())]


def _login_rate_check(email):
    now = time.time()
    with _login_fail_lock:
        for k in _login_keys(email):
            lst = [t for t in _login_fails.get(k, []) if now - t < LOGIN_WINDOW]
            _login_fails[k] = lst
            if len(lst) >= LOGIN_MAX_FAILS:
                return jsonify({'error': 'Too many failed attempts. Try again in a few minutes.'}), 429
    return None


def _login_record_fail(email):
    now = time.time()
    with _login_fail_lock:
        for k in _login_keys(email):
            _login_fails.setdefault(k, []).append(now)
        if len(_login_fails) > 20000:
            _login_fails.clear()


def _login_clear(email):
    with _login_fail_lock:
        _login_fails.pop(('em', (email or '').lower()), None)


# ---------------- uploads ----------------
IMAGE_EXTS = ('png', 'jpg', 'gif', 'webp')
SAFE_INLINE_EXTS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'mp4', 'webm', 'mp3', 'ogg', 'wav'}
GENERIC_UPLOAD_EXTS = IMAGE_EXTS + ('mp4', 'webm', 'mp3', 'ogg', 'wav', 'pdf')
IMAGE_ONLY_KINDS = ('avatar', 'banner', 'server_icon', 'server_banner', 'ring_image', 'panel_bg', 'chat_bg', 'image')


def _sniff_ext(head):
    if head[:8] == b'\x89PNG\r\n\x1a\n':
        return 'png'
    if head[:3] == b'\xff\xd8\xff':
        return 'jpg'
    if head[:6] in (b'GIF87a', b'GIF89a'):
        return 'gif'
    if head[:4] == b'RIFF' and head[8:12] == b'WEBP':
        return 'webp'
    if head[:4] == b'RIFF' and head[8:12] == b'WAVE':
        return 'wav'
    if head[4:8] == b'ftyp':
        return 'mp4'
    if head[:4] == b'\x1aE\xdf\xa3':
        return 'webm'
    if head[:4] == b'OggS':
        return 'ogg'
    if head[:3] == b'ID3' or (len(head) > 1 and head[0] == 0xFF and (head[1] & 0xE0) == 0xE0):
        return 'mp3'
    if head[:4] == b'%PDF':
        return 'pdf'
    return None


def _check_upload(file, ext, kind):
    """Only real images / media / PDF are accepted (no .html / .svg / .js ...).
    Returns (error_response_or_None, extension_to_use)."""
    head = file.stream.read(16)
    file.stream.seek(0)
    sniffed = _sniff_ext(head)
    allowed = IMAGE_EXTS if kind in IMAGE_ONLY_KINDS else GENERIC_UPLOAD_EXTS
    if sniffed not in allowed:
        what = 'an image (PNG, JPG, GIF, WEBP)' if kind in IMAGE_ONLY_KINDS else 'an image, video, audio or PDF file'
        return (jsonify({'error': f'This file type is not allowed. Please upload {what}.'}), 400), ext
    return None, sniffed


def _serve_upload(filename):
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    is_story = filename.startswith(STORY_FILE_PREFIX)
    if is_story:                      # story media obeys the story's privacy
        uid = session.get('user_id')
        if not uid:
            return jsonify({'error': 'Not authenticated'}), 401
        url = '/uploads/' + filename
        with stories_lock:
            story = next((s for s in _stories_load()['stories'].values()
                          if s.get('media_url') == url and s.get('expires_at', 0) > time.time()), None)
        if not story:
            return jsonify({'error': 'File not found'}), 404
        if uid != story['user_id'] and not _story_can_view(load_database(), uid, story['user_id']):
            return jsonify({'error': 'File not found'}), 404
    try:
        resp = send_from_directory(UPLOAD_DIR, filename, as_attachment=ext not in SAFE_INLINE_EXTS, conditional=True)
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Content-Security-Policy'] = "default-src 'none'; img-src 'self'; media-src 'self'; style-src 'unsafe-inline'; sandbox"
    resp.headers['Cache-Control'] = 'private, max-age=3600' if is_story else 'public, max-age=86400'
    return resp


# ---------------- stories ----------------
def _valid_story_emoji(e):
    if not isinstance(e, str) or not (1 <= len(e) <= 8):
        return False
    core = [c for c in e if c not in '\u200d\ufe0f\u20e3']
    return bool(core) and all(ord(c) > 0x7f and not c.isalpha() for c in core)


def _story_reply_dm_error(db, me_id, owner_id):
    """A story reply is a DM: it must obey the same rules as a normal DM."""
    owner = db['users'].get(owner_id)
    if not owner or owner.get('is_deleted'):
        return jsonify({'error': 'Story not found'}), 404
    me = db['users'].get(me_id) or {}
    if owner_id in (me.get('blocked_users') or []):
        return jsonify({'error': 'You have blocked this user'}), 403
    if me_id in (owner.get('blocked_users') or []):
        return jsonify({'error': 'Story not found'}), 404
    if not get_privacy(db, owner_id).get('allow_dms_from_strangers', True) and me_id not in (owner.get('friends') or []):
        return jsonify({'error': 'This user is not accepting DMs from non-friends', 'code': 'DMS_DISABLED'}), 403
    return None


def _stories_remove_user(user_id):
    """Delete the stories (and files) of a removed account and its views / reactions on other stories."""
    with stories_lock:
        data = _stories_load()
        changed = False
        for sid, s in list(data['stories'].items()):
            if s.get('user_id') == user_id:
                data['stories'].pop(sid, None)
                _stories_remove_media(s.get('media_url'))
                changed = True
                continue
            if user_id in s.get('views', []):
                s['views'] = [v for v in s['views'] if v != user_id]
                changed = True
            for emo in list((s.get('reactions') or {}).keys()):
                if user_id in s['reactions'][emo]:
                    s['reactions'][emo] = [v for v in s['reactions'][emo] if v != user_id]
                    if not s['reactions'][emo]:
                        del s['reactions'][emo]
                    changed = True
        if changed:
            _stories_save(data)


# ---------------- AntiBot notification (never inside a request) ----------------
def _antibot_post_later(url, json=None, timeout=5):
    def run():
        try:
            import requests
            headers = {'X-Antibot-Token': ANTIBOT_TOKEN} if ANTIBOT_TOKEN else {}
            requests.post(url, json=json, headers=headers, timeout=timeout)
        except Exception:
            pass
    threading.Thread(target=run, daemon=True).start()


# ---------------- admin account manager (was referenced but never defined) ----------------
class AccountManager:
    PROTECTED = ('admin', 'aminsoft356')
    STATUSES = ('active', 'limited', 'suspended', 'banned')
    FEATURES = ('dm_with_strangers', 'friend_requests', 'server_creation', 'uploads')

    @staticmethod
    def _admin_ok(db, admin_id):
        return bool((db['users'].get(admin_id) or {}).get('is_admin'))

    def _prep(self, admin_id, user_id):
        db = load_database()
        if not self._admin_ok(db, admin_id):
            return db, None, 'Admin required'
        user = db['users'].get(user_id)
        if not user:
            return db, None, 'User not found'
        return db, user, None

    def get_all_users(self):
        db = load_database()
        out = []
        for u in db['users'].values():
            c = dict(u)
            c.pop('password', None)
            out.append(c)
        return jsonify(out)

    def delete_user_account(self, admin_id, user_id, reason=''):
        db, user, err = self._prep(admin_id, user_id)
        if err:
            return False, err
        if user_id == admin_id:
            return False, 'Cannot delete yourself'
        if (user.get('username') or '').lower() in self.PROTECTED:
            return False, 'This is a protected system account and cannot be deleted'
        _purge_user_data(db, user_id)
        save_database(db)
        return True, 'Account deleted'

    def set_account_status(self, admin_id, user_id, status, reason=''):
        db, user, err = self._prep(admin_id, user_id)
        if err:
            return False, err
        if status not in self.STATUSES:
            return False, 'Invalid status. Use: ' + ', '.join(self.STATUSES)
        if (user.get('username') or '').lower() in self.PROTECTED and status != 'active':
            return False, 'Protected system account'
        user['account_status'] = {'status': status, 'reason': str(reason or '')[:300],
                                  'by': admin_id, 'at': datetime.now().isoformat()}
        save_database(db)
        return True, f'Account status set to {status}'

    def _pc(self, db, user_id):
        return db.setdefault('parental_control', {}).setdefault(user_id, {
            'daily_limit_minutes': 0, 'allowed_start_hour': 0, 'allowed_end_hour': 23,
            'blocked_tags': [], 'allowed_tags': [], 'block_adult_content': False})

    @staticmethod
    def _hour(v):
        v = int(v)
        if not 0 <= v <= 23:
            raise ValueError
        return v

    def set_parental_control(self, admin_id, user_id, data):
        db, user, err = self._prep(admin_id, user_id)
        if err:
            return False, err
        data = data if isinstance(data, dict) else {}
        pc = self._pc(db, user_id)
        try:
            if 'daily_limit_minutes' in data:
                v = int(data['daily_limit_minutes'] or 0)
                if not 0 <= v <= 1440:
                    return False, 'Invalid time limit'
                pc['daily_limit_minutes'] = v
            if 'allowed_start_hour' in data:
                pc['allowed_start_hour'] = self._hour(data['allowed_start_hour'])
            if 'allowed_end_hour' in data:
                pc['allowed_end_hour'] = self._hour(data['allowed_end_hour'])
        except (TypeError, ValueError):
            return False, 'Invalid value'
        if pc['allowed_start_hour'] > pc['allowed_end_hour']:
            return False, 'Start hour must be before end hour'
        if 'blocked_tags' in data and isinstance(data['blocked_tags'], list):
            pc['blocked_tags'] = [str(t).strip()[:32] for t in data['blocked_tags'] if str(t).strip()][:50]
        if 'block_adult_content' in data:
            pc['block_adult_content'] = bool(data['block_adult_content'])
        pc['updated_at'] = datetime.now().isoformat()
        save_database(db)
        return True, 'Parental control updated'

    def get_parental_control_settings(self, user_id):
        return (load_database().get('parental_control') or {}).get(user_id)

    def set_time_limit(self, admin_id, user_id, minutes, reason=''):
        return self.set_parental_control(admin_id, user_id, {'daily_limit_minutes': minutes})

    def set_allowed_hours(self, admin_id, user_id, start, end, reason=''):
        return self.set_parental_control(admin_id, user_id, {'allowed_start_hour': start, 'allowed_end_hour': end})

    def set_content_filter(self, admin_id, user_id, blocked_tags, allowed_tags):
        db, user, err = self._prep(admin_id, user_id)
        if err:
            return False, err
        pc = self._pc(db, user_id)
        clean = lambda lst: [str(t).strip()[:32] for t in (lst if isinstance(lst, list) else []) if str(t).strip()][:50]
        pc['blocked_tags'] = clean(blocked_tags)
        pc['allowed_tags'] = clean(allowed_tags)
        pc['updated_at'] = datetime.now().isoformat()
        save_database(db)
        return True, 'Content filter updated'

    def toggle_feature(self, admin_id, user_id, feature, enabled):
        db, user, err = self._prep(admin_id, user_id)
        if err:
            return False, err
        if feature not in self.FEATURES:
            return False, 'Unknown feature. Use: ' + ', '.join(self.FEATURES)
        disabled = user.setdefault('disabled_features', [])
        if enabled and feature in disabled:
            disabled.remove(feature)
        elif not enabled and feature not in disabled:
            disabled.append(feature)
        save_database(db)
        return True, f"Feature {feature} {'enabled' if enabled else 'disabled'}"

    def get_user_account_status(self, user_id):
        user = load_database()['users'].get(user_id)
        if not user:
            return None
        return user.get('account_status') or {'status': 'active'}

    def get_user_report(self, admin_id, user_id):
        db = load_database()
        if not self._admin_ok(db, admin_id):
            return 'Admin required'
        u = db['users'].get(user_id)
        if not u:
            return 'User not found'
        st = (u.get('account_status') or {}).get('status', 'active')
        pc = (db.get('parental_control') or {}).get(user_id) or {}
        servers = [s.get('name') for s in db['servers'].values() if user_id in s.get('members', [])]
        return (f"User: {u.get('username')} ({user_id})\nStatus: {st}\nPremium: {bool(u.get('is_premium'))}\n"
                f"Coins: {u.get('coins', 0)}\nFriends: {len(u.get('friends') or [])}\n"
                f"Servers: {', '.join(servers) or '-'}\nDisabled features: {', '.join(u.get('disabled_features') or []) or '-'}\n"
                f"Daily limit (min): {pc.get('daily_limit_minutes', 0)}  Allowed hours: "
                f"{pc.get('allowed_start_hour', 0)}-{pc.get('allowed_end_hour', 23)}")


account_manager = AccountManager()


# ---------------- startup ----------------
def _warn_default_admin():
    try:
        db = load_database()
        for u in db['users'].values():
            if u.get('is_admin') and check_password_hash(u.get('password', ''), 'admin123'):
                print('⚠️  SECURITY: an admin account still uses the default password "admin123" - change it now!')
    except Exception:
        pass


_bg_started = False


def start_background_threads():
    """Also runs under gunicorn / waitress (not only with `python app.py`)."""
    global _bg_started
    if _bg_started:
        return
    _bg_started = True
    threading.Thread(target=_auto_delete_loop, daemon=True, name='auto-delete-sweeper').start()
    threading.Thread(target=_stories_purge_loop, daemon=True, name='stories-purge').start()
    _warn_default_admin()


start_background_threads()



# ============================================
# MENTION NOTIFICATIONS + GLOBAL ACTIVITY POLL
#  - @username / @everyone / @here in a server channel creates a notification (deletable)
#  - /api/activity/poll tells the browser about new messages in OTHER servers / DMs (for the sound)
# ============================================
MENTION_NOTIF_MAX = 300      # notifications kept per user (oldest are dropped)
ACTIVITY_MAX_EVENTS = 30


def _everyone_allowed(db, server, author_id):
    """@everyone / @here only works for the server owner and people who may manage messages."""
    try:
        return author_id == server.get('owner_id') or bool(
            has_permission(db, author_id, server.get('id'), 'manage_messages'))
    except Exception:
        return False


def message_mentions_user(db, content, user, everyone_ok=False):
    text = str(content or '')
    if '@' not in text or not user:
        return False
    low = text.lower()
    if everyone_ok and re.search(r'(?<![\w@])@(everyone|here)(?!\w)', low):
        return True
    name = str(user.get('username') or '').strip().lower()
    if not name:
        return False
    return re.search(r'(?<![\w@])@' + re.escape(name) + r'(?!\w)', low) is not None


def create_mention_notifications(db, message, channel, server):
    """Called by send_message (in memory - the caller saves the db). Returns the user ids that were notified."""
    content = message.get('content') or ''
    if '@' not in content:
        return []
    author_id = message.get('user_id')
    author = db['users'].get(author_id) or {}
    author_name = author.get('username') or 'Someone'
    everyone_ok = _everyone_allowed(db, server, author_id)
    preview = content.strip()
    if len(preview) > 160:
        preview = preview[:160] + '…'
    notified = []
    now = datetime.now().isoformat()
    for uid in (server.get('members') or []):
        if uid == author_id:
            continue
        target = db['users'].get(uid) or {}
        if not target or target.get('is_bot') or target.get('is_deleted'):
            continue
        if author_id in (target.get('blocked_users') or []):
            continue
        if not message_mentions_user(db, content, target, everyone_ok):
            continue
        acc = channel_access(db, channel, uid)
        if not acc['visible'] or acc['locked']:
            continue
        db.setdefault('notifications', []).append({
            'id': uuid.uuid4().hex[:12],
            'user_id': uid,
            'type': 'mention',
            'title': f"{author_name} mentioned you in #{channel.get('name', 'channel')}",
            'message': preview,
            'read': False,
            'created_at': now,
            'server_id': channel.get('server_id'),
            'server_name': server.get('name', ''),
            'channel_id': channel.get('id') or message.get('channel_id'),
            'channel_name': channel.get('name', ''),
            'message_id': message.get('id'),
            'from_user_id': author_id,
            'from_username': author_name,
        })
        notified.append(uid)
    for uid in set(notified):
        _trim_notifications(db, uid)
    return notified


def _trim_notifications(db, uid):
    mine = [n for n in db.get('notifications', []) if n.get('user_id') == uid]
    if len(mine) <= MENTION_NOTIF_MAX:
        return
    mine.sort(key=lambda n: n.get('created_at') or '')
    drop = {n.get('id') for n in mine[:len(mine) - MENTION_NOTIF_MAX]}
    db['notifications'] = [n for n in db['notifications'] if n.get('id') not in drop]


@app.route('/api/notifications/read', methods=['POST'])
@login_required
def mark_notifications_read():
    """body: {"ids": [...]} marks those as read; no body / no ids = mark everything as read."""
    data = request.get_json(silent=True) or {}
    ids = data.get('ids')
    ids = set(map(str, ids)) if isinstance(ids, list) else None
    db = load_database()
    changed = 0
    for n in db.get('notifications', []):
        if n.get('user_id') != session['user_id'] or n.get('read'):
            continue
        if ids is None or str(n.get('id')) in ids:
            n['read'] = True
            changed += 1
    if changed:
        save_database(db)
    return jsonify({'success': True, 'updated': changed})


@app.route('/api/notifications/clear', methods=['POST'])
@login_required
def clear_notifications():
    """Deletes the user's notifications. body: {"type": "mention"} deletes only that type, {} deletes all."""
    data = request.get_json(silent=True) or {}
    only_type = str(data.get('type') or '').strip()
    db = load_database()
    before = len(db.get('notifications', []))
    db['notifications'] = [
        n for n in db.get('notifications', [])
        if n.get('user_id') != session['user_id'] or (only_type and n.get('type') != only_type)
    ]
    removed = before - len(db['notifications'])
    if removed:
        save_database(db)
    return jsonify({'success': True, 'removed': removed})


@app.route('/api/activity/poll')
@login_required
def activity_poll():
    """Light poll used by the browser for sounds / toasts about chats that are NOT open.
    ?since=<cursor from the previous answer>. Without 'since' it only returns the first cursor (nothing is replayed)."""
    uid = session['user_id']
    db = load_database()
    now = datetime.now()
    out = {'cursor': (now - timedelta(seconds=6)).isoformat(), 'events': []}

    mine = [n for n in db.get('notifications', []) if n.get('user_id') == uid]
    unread = sum(1 for n in mine if not n.get('read'))
    out['notif_unread'] = unread
    out['notif_sig'] = f"{len(mine)}:{max((n.get('created_at') or '' for n in mine), default='')}:{unread}"

    since = (request.args.get('since') or '').strip()
    try:
        datetime.fromisoformat(since)
    except ValueError:
        return jsonify(out)

    me = db['users'].get(uid) or {}
    blocked = set(me.get('blocked_users') or [])
    events = []

    # ---- server channels the user can read right now ----
    servers = db.get('servers', {})
    mutes = db.get('mutes', {})
    allowed = {}
    for cid, ch in db.get('channels', {}).items():
        server = servers.get(ch.get('server_id'))
        if not server or uid not in (server.get('members') or []):
            continue
        mi = (mutes.get(ch.get('server_id')) or {}).get(uid)
        if mi:
            try:
                if datetime.fromisoformat(mi['muted_until']) > now:
                    continue
            except Exception:
                pass
        acc = channel_access(db, ch, uid)
        if not acc['visible'] or acc['locked']:
            continue
        allowed[cid] = (server, ch)

    everyone_cache = {}
    older_run = 0
    for msg in reversed(list(db.get('all_messages', {}).values())):
        ca = msg.get('created_at') or ''
        if ca <= since:
            older_run += 1
            if older_run > 300:
                break
            continue
        older_run = 0
        cid = msg.get('channel_id')
        sender = msg.get('user_id')
        if cid not in allowed or sender == uid or sender in blocked:
            continue
        if msg.get('deleted') or msg.get('type') == 'system':
            continue
        server, ch = allowed[cid]
        ck = (server.get('id'), sender)
        if ck not in everyone_cache:
            everyone_cache[ck] = _everyone_allowed(db, server, sender)
        ok = everyone_cache[ck]
        su = db['users'].get(sender) or {}
        events.append({
            'kind': 'channel', 'message_id': msg.get('id'), 'target_id': cid,
            'server_id': ch.get('server_id'), 'server_name': server.get('name', ''),
            'channel_name': ch.get('name', ''), 'from_id': sender,
            'from_username': su.get('username', 'Unknown'),
            'mention': message_mentions_user(db, msg.get('content'), me, ok),
            'preview': (msg.get('content') or '')[:100], 'created_at': ca,
        })

    # ---- direct messages (system conversations have their own toast) ----
    for key, lst in db.get('direct_messages', {}).items():
        if not key.startswith('dm_') or not (key.startswith(f"dm_{uid}_") or key.endswith(f"_{uid}")):
            continue
        for msg in reversed(lst):
            ca = msg.get('created_at') or ''
            if ca <= since:
                break
            sender = msg.get('user_id')
            if sender == uid or sender in blocked or sender in SYSTEM_DM_USERS:
                continue
            if msg.get('deleted') or msg.get('system_dm') or not dm_visible_to(msg, uid):
                continue
            hs = dm_hidden_since(db, uid, sender)
            if hs and ca <= hs:
                continue
            su = db['users'].get(sender) or {}
            events.append({
                'kind': 'dm', 'message_id': msg.get('id'), 'target_id': sender,
                'from_id': sender, 'from_username': su.get('username', 'Unknown'),
                'mention': False, 'preview': (msg.get('content') or '')[:100], 'created_at': ca,
            })

    events.sort(key=lambda e: e['created_at'])
    out['events'] = events[-ACTIVITY_MAX_EVENTS:]
    return jsonify(out)


if __name__ == '__main__':
    init_database()
    st = _bot_runner.status()
    print('BotShop: ' + (f"bot runner ready (Node.js {st['node']})" if st.get('ok') else f"WARNING - bots cannot run: {st.get('error')}"))
    _bs_seed_if_needed()
    app.run(debug=os.getenv('FLASK_DEBUG', '0') == '1', use_reloader=False,
            host=os.getenv('HOST', '0.0.0.0'), port=int(os.getenv('PORT', '4212')))
