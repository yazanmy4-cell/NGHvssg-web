#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FF LIKE - web server for the Free Fire like bot panel.

Standard library only (http.server + urllib). Nothing to install.
The two upstream services (player info / profile card and the like
engine) are contacted ONLY from this file through config.json, never
from the browser. Visitors call only local /api/... routes, so the
upstream URLs and keys stay hidden.

Site flow: a visitor must create an account and log in first. Payments
go through a wallet: the customer sends USDT with Binance Pay, pastes
the Transaction ID, credit is added to his balance, then he buys plans
from his balance. Admin can refund, adjust balances, create coupon
codes (free credit) and promo codes (price discounts) and manage every
autolike run from the dashboard.

Run:  python server.py      (or double click start.bat)
Web:  http://localhost:8080
Admin: at  /admin  (not linked anywhere on the public page)
"""

import base64
import colorsys
import hashlib
import hmac
import io
import json
import mimetypes
import os
import re
import secrets
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_OK = True
except Exception:
    PIL_OK = False

APP = "FF LIKE"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
DATA_DIR = os.path.join(BASE_DIR, "data")
STATE_PATH = os.path.join(DATA_DIR, "state.json")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

UID_RE = re.compile(r"^\d{5,12}$")
USER_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
CODE_RE = re.compile(r"^[A-Za-z0-9\-]{3,24}$")
NAME_KEYS = ("name", "nickname", "username", "nick", "player_name", "ign")
REGION_KEYS = ("region", "server", "area", "country", "region_code")
LEVEL_KEYS = ("level", "lv")

DEFAULT_CONFIG = {
    "site_name": "FF LIKE",
    "tagline": "Free Fire likes delivered automatically",
    "currency": "USD",
    "port": 8080,
    "admin_user": "udp",
    "admin_password": "",
    "admin_password_hash": "",
    "auto_approve_orders": True,
    "auto_approve_deposits": True,
    "binance": {
        "pay_id": "000000000",
        "note": "Open Binance, choose Pay, send USDT to the Pay ID above, "
                "then paste the Transaction ID in your wallet.",
    },
    "autolike_plans": [
        {"days": 30, "price": 1.5},
        {"days": 60, "price": 3.0},
        {"days": 120, "price": 5.0},
    ],
    "credit_rate_days_per_dollar": 10,
    "credit_amounts": [1, 2, 3, 5, 10],
    "likes_per_day": 135,
    "info_api_base": "https://likes.freefire.site",
    "info_api_cookie": "",
    "like_api": {
        "base": "",
        "key": "",
        "key_header": "X-API-Key",
    },
}

STATE_LOCK = threading.RLock()
CONFIG_LOCK = threading.RLock()
PLAYER_CACHE = {}          # uid -> (expires_epoch, info dict)
CARD_CACHE = {}            # uid|theme -> (expires_epoch, ctype, bytes)
CACHE_LOCK = threading.RLock()
SESSIONS = {}              # token -> {"kind": "admin"|"user", "exp": float, "user_no": str|None}
SESSIONS_LOCK = threading.RLock()
LOGIN_FAILS = {}           # scope|ip -> [fails, blocked_until_epoch]
HITS = {}                  # scope|ip -> [timestamps]

MIME = {
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".txt": "text/plain; charset=utf-8",
}


class ApiError(Exception):
    def __init__(self, message, status=400):
        Exception.__init__(self, message)
        self.message = message
        self.status = status


def now_iso():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def today_str():
    return date.today().isoformat()


def log_line(msg):
    print("[%s] %s" % (datetime.now().strftime("%H:%M:%S"), msg), flush=True)


def tr(value, limit=300):
    text = "" if value is None else str(value)
    text = text.replace("\r", " ").replace("\n", " ")
    if len(text) > limit:
        return text[:limit] + "..."
    return text


def money_round(value):
    try:
        return round(float(value), 2)
    except Exception:
        return 0.0


# ------------------------------------------------------------------
# Configuration (config.json - server side only)
# ------------------------------------------------------------------
def load_config():
    merged = json.loads(json.dumps(DEFAULT_CONFIG))
    raw = {}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            if not isinstance(raw, dict):
                raw = {}
        except Exception as exc:
            log_line("config.json is not valid JSON (%s), using defaults" % exc)
            raw = {}
    for key, value in raw.items():
        if key in ("binance", "like_api") and isinstance(value, dict):
            merged.setdefault(key, {}).update(value)
        else:
            merged[key] = value
    return merged


def write_config_file(raw):
    temp = CONFIG_PATH + ".tmp"
    with open(temp, "w", encoding="utf-8") as fh:
        json.dump(raw, fh, ensure_ascii=False, indent=2)
    os.replace(temp, CONFIG_PATH)


def save_config_partial(updates):
    raw = {}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            if not isinstance(raw, dict):
                raw = {}
        except Exception:
            raw = {}
    for key, value in updates.items():
        if key in ("binance", "like_api") and isinstance(value, dict):
            raw.setdefault(key, {}).update(value)
        else:
            raw[key] = value
    write_config_file(raw)


CONFIG = load_config()


# ------------------------------------------------------------------
# Password hashing (PBKDF2) and admin migration
# ------------------------------------------------------------------
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", str(password).encode("utf-8"), bytes.fromhex(salt), 150000
    ).hex()
    return salt, digest


def verify_password(password, salt, expected_hash):
    try:
        _, digest = hash_password(password, salt)
        return hmac.compare_digest(digest, expected_hash)
    except Exception:
        return False


def migrate_admin_password():
    """Turn the plaintext admin password into a PBKDF2 hash on first run."""
    global CONFIG
    if CONFIG.get("admin_password_hash"):
        return
    plain = CONFIG.get("admin_password") or ""
    if not plain:
        plain = "yazan"
        log_line("No admin password found, setting the default one (change it in admin settings).")
    salt, digest = hash_password(plain)
    with CONFIG_LOCK:
        save_config_partial({"admin_password_hash": "%s$%s" % (salt, digest)})
        raw = {}
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            if isinstance(raw, dict) and "admin_password" in raw:
                raw.pop("admin_password", None)
                write_config_file(raw)
        except Exception:
            pass
        CONFIG = load_config()


def admin_password_matches(password):
    stored = str(CONFIG.get("admin_password_hash") or "")
    if "$" in stored:
        salt, digest = stored.split("$", 1)
        return verify_password(password, salt, digest)
    return False


# ------------------------------------------------------------------
# State (data/state.json)
# ------------------------------------------------------------------
def default_state():
    return {
        "project_start": today_str(),
        "next_order": 1,
        "next_account": 1,
        "next_user": 1,
        "next_deposit": 1,
        "users": [],
        "orders": [],
        "accounts": [],
        "deposits": [],
        "coupons": [],
        "promos": [],
        "events": [],
    }


def load_state():
    if os.path.exists(STATE_PATH):
        try:
            with open(STATE_PATH, "r", encoding="utf-8") as fh:
                state = json.load(fh)
            if isinstance(state, dict):
                base = default_state()
                base.update(state)
                for key, value in default_state().items():
                    base.setdefault(key, value)
                return base
        except Exception as exc:
            log_line("state.json is corrupted (%s), starting a fresh file" % exc)
    return default_state()


def save_state(state):
    os.makedirs(DATA_DIR, exist_ok=True)
    temp = STATE_PATH + ".tmp"
    with open(temp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=2)
    os.replace(temp, STATE_PATH)


STATE = load_state()


def add_event(kind, message, detail=""):
    with STATE_LOCK:
        STATE["events"].insert(0, {
            "time": now_iso(),
            "kind": kind,
            "msg": tr(message, 240),
            "detail": tr(detail, 400),
        })
        if len(STATE["events"]) > 500:
            del STATE["events"][500:]
        save_state(STATE)


def next_no(state_key, prefix):
    with STATE_LOCK:
        no = "%s-%04d" % (prefix, STATE[state_key])
        STATE[state_key] += 1
        return no


def public_stats():
    with STATE_LOCK:
        accounts = list(STATE["accounts"])
        orders = list(STATE["orders"])
        users = list(STATE["users"])
        deposits = list(STATE["deposits"])
    today = today_str()
    active = [a for a in accounts
              if a.get("status") == "active" and a.get("expires", "") >= today]
    days_delivered = sum(int(a.get("days", 0)) for a in active)
    est_likes = sum(int(a.get("days", 0)) * int(a.get("likes_per_day", 0)) for a in active)
    pending = [o for o in orders if o.get("status") == "pending"]
    dep_pending = [d for d in deposits if d.get("status") == "pending"]
    wallet = sum(money_round(u.get("balance", 0)) for u in users)
    start = STATE.get("project_start") or today
    try:
        running_days = max(1, (date.today() - date.fromisoformat(start)).days + 1)
    except Exception:
        running_days = 1
    return {
        "project_start": start,
        "running_days": running_days,
        "active_accounts": len(active),
        "total_accounts": len(accounts),
        "autolike_accounts": len([a for a in accounts if a.get("product") == "autolike"]),
        "credit_accounts": len([a for a in accounts if a.get("product") == "like_credit"]),
        "days_delivered": days_delivered,
        "est_likes": est_likes,
        "orders_total": len(orders),
        "orders_pending": len(pending),
        "users_total": len(users),
        "wallet_total": money_round(wallet),
        "deposits_pending": len(dep_pending),
    }


# ------------------------------------------------------------------
# Outbound HTTP
# ------------------------------------------------------------------
def do_http(url, method="GET", params=None, body=None, headers=None, timeout=25):
    if params:
        url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    data = None
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            data = body.encode("utf-8")
        else:
            data = body
    req = urllib.request.Request(url, data=data, method=method.upper())
    req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) FFLikeServer/2.0")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as exc:
        try:
            payload = exc.read()
        except Exception:
            payload = b""
        return exc.code, exc.headers, payload
    except Exception as exc:
        return 0, None, ("network error: %s" % exc).encode("utf-8")


def parse_body(headers, payload):
    ctype = ""
    try:
        ctype = headers.get_content_type() if headers is not None else ""
    except Exception:
        ctype = ""
    text = ""
    try:
        text = payload.decode("utf-8", "replace") if payload else ""
    except Exception:
        text = ""
    parsed = None
    stripped = text.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            parsed = json.loads(stripped)
        except Exception:
            parsed = None
    if parsed is None and ctype == "application/json":
        parsed = stripped or None
    return ctype, parsed, text


def first_string(d, keys):
    for key in keys:
        value = d.get(key)
        if isinstance(value, (str, int)) and str(value).strip():
            return str(value).strip()
    return None


def unwrap_player(payload):
    data = payload if isinstance(payload, dict) else {}
    for key in ("player", "data", "result", "profile"):
        sub = data.get(key)
        if isinstance(sub, dict):
            data = sub
            break
    return data


def player_info(uid):
    now = time.time()
    with CACHE_LOCK:
        cached = PLAYER_CACHE.get(uid)
        if cached and cached[0] > now:
            return cached[1]
    base = str(CONFIG.get("info_api_base") or DEFAULT_CONFIG["info_api_base"]).rstrip("/")
    url = base + "/api/player/" + urllib.parse.quote(uid, safe="")
    status, headers, payload = do_http(url, "GET", timeout=15)
    ctype, parsed, _text = parse_body(headers, payload)
    if status != 200 or not isinstance(parsed, dict):
        raise ApiError("Player info is not available right now. Try again in a moment.", 502)
    data = unwrap_player(parsed)
    name = first_string(data, NAME_KEYS) or "Unknown"
    region = first_string(data, REGION_KEYS) or "-"
    level = first_string(data, LEVEL_KEYS)
    info = {"uid": uid, "name": name, "region": region, "level": level}
    with CACHE_LOCK:
        if len(PLAYER_CACHE) > 400:
            PLAYER_CACHE.clear()
        PLAYER_CACHE[uid] = (now + 90, info)
    return info


# ------------------------------------------------------------------
# Profile card (real image from the info site, generated fallback)
# ------------------------------------------------------------------
def _font_safe(size):
    for path in (r"C:\Windows\Fonts\segoeuib.ttf", r"C:\Windows\Fonts\arialbd.ttf"):
        try:
            return ImageFont.truetype(path, int(size))
        except Exception:
            continue
    try:
        return ImageFont.load_default(size=int(size))
    except Exception:
        return None


def generate_fallback_card(uid, theme, name="Player", region="-"):
    hue = int(hashlib.sha1(str(uid).encode("utf-8")).hexdigest()[:8], 16) % 360
    W, H = 1024, 576
    if theme == "light":
        bg1 = tuple(int(c) for c in colorsys.hls_to_rgb(hue / 360.0, 0.94, 0.55))
        bg2 = (246, 249, 255)
        text = (21, 28, 46)
        muted = (96, 113, 140)
        alpha_bg = 30
    else:
        bg1 = tuple(int(c * 255) for c in colorsys.hls_to_rgb(hue / 360.0, 0.13, 0.45))
        bg2 = (12, 15, 26)
        text = (240, 244, 252)
        muted = (146, 158, 184)
        alpha_bg = 60
    accent = tuple(int(c * 255) for c in
                   colorsys.hls_to_rgb(((hue + 18) % 360) / 360.0, 0.58, 0.78))

    img = Image.new("RGB", (W, H), bg1)
    d = ImageDraw.Draw(img, "RGBA")
    for y in range(H):
        t = y / float(H - 1)
        c = tuple(int(bg1[i] + (bg2[i] - bg1[i]) * t) for i in range(3))
        d.line([(0, y), (W, y)], fill=c)
    for (bx, by, br, ba) in [(W * 0.85, H * 0.15, H * 0.50, alpha_bg),
                             (W * 0.08, H * 0.95, H * 0.40, alpha_bg * 2 // 3)]:
        d.ellipse([bx - br, by - br, bx + br, by + br], fill=accent + (ba,))
    for a in (150, 70):
        rr = H * 0.40 if a == 150 else H * 0.55
        d.ellipse([W * 0.76 - rr, H * 0.42 - rr, W * 0.76 + rr, H * 0.42 + rr],
                  outline=accent + (a,), width=3)
    initial = (name[:1] or "#").upper()
    f_big = _font_safe(H * 0.62)
    if f_big:
        d.text((W * 0.78, H * 0.40), initial, font=f_big, fill=accent + (52,), anchor="mm")
    f_tag = _font_safe(30)
    if f_tag:
        d.text((46, 40), CONFIG.get("site_name") or "FF LIKE", font=f_tag, fill=muted + (230,))
    panel = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    pd = ImageDraw.Draw(panel)
    pd.rounded_rectangle([44, H - 220, W - 44, H - 44], radius=26,
                         fill=(16, 20, 34, 200) if theme == "dark" else (255, 255, 255, 225))
    img = Image.alpha_composite(img.convert("RGBA"), panel)
    d = ImageDraw.Draw(img, "RGBA")
    f_name = _font_safe(64)
    f_meta = _font_safe(34)
    if f_name:
        d.text((80, H - 178), (name or "Player")[:24], font=f_name, fill=text)
    if f_meta:
        d.text((80, H - 96), "UID %s        REGION %s" % (uid, (region or "-")[:12]),
               font=f_meta, fill=muted)
    buf = io.BytesIO()
    img.convert("RGB").save(buf, "PNG")
    return buf.getvalue()


def profile_card_bytes(uid, theme):
    now = time.time()
    cache_key = "%s|%s" % (uid, theme)
    with CACHE_LOCK:
        cached = CARD_CACHE.get(cache_key)
        if cached and cached[0] > now:
            return cached[1], cached[2]

    base = str(CONFIG.get("info_api_base") or DEFAULT_CONFIG["info_api_base"]).rstrip("/")
    url = base + "/api/profile-card/" + urllib.parse.quote(uid, safe="")
    headers = {"Accept": "image/avif,image/webp,image/*,*/*;q=0.8"}
    cookie = str(CONFIG.get("info_api_cookie") or "").strip()
    if cookie:
        headers["Cookie"] = cookie
    status, resp_headers, payload = do_http(url, "GET", timeout=15, headers=headers)
    ctype, parsed, _text = parse_body(resp_headers, payload)
    ctype = (ctype or "").lower()

    data = None
    if status == 200 and ctype.startswith("image/"):
        data = (ctype, payload)
    elif status == 200 and isinstance(parsed, dict):
        link = first_string(parsed, ("url", "image_url", "card_url", "image", "card"))
        if link and link.startswith("http"):
            st2, h2, p2 = do_http(link, "GET", timeout=15, headers=headers)
            ct2, _p2, _t2 = parse_body(h2, p2)
            if st2 == 200 and (ct2 or "").startswith("image/"):
                data = (ct2, p2)
        if data is None:
            b64 = first_string(parsed, ("base64", "b64", "image_base64", "data"))
            if b64 and b64.startswith("data:image"):
                b64 = b64.split(",", 1)[-1]
            if b64:
                try:
                    raw = base64.b64decode(b64, validate=False)
                    data = ("image/png", raw)
                except Exception:
                    data = None

    if data is None:
        info = {}
        with CACHE_LOCK:
            cached_info = PLAYER_CACHE.get(uid)
            if cached_info:
                info = cached_info[1]
        if PIL_OK:
            out = ("image/png",
                   generate_fallback_card(uid, theme, info.get("name", "Player"),
                                          info.get("region", "-")))
            ttl = 900
        else:
            path = os.path.join(STATIC_DIR, "img", "card-fallback-%s.png" % theme)
            with open(path, "rb") as fh:
                out = ("image/png", fh.read())
            ttl = 900
    else:
        out = data
        ttl = 600
    with CACHE_LOCK:
        if len(CARD_CACHE) > 300:
            CARD_CACHE.clear()
        CARD_CACHE[cache_key] = (now + ttl, out[0], out[1])
    return out


# ------------------------------------------------------------------
# Like engine API (like_api in config.json - hidden from visitors)
# ------------------------------------------------------------------
def like_api(path, params=None, method="GET", timeout=30):
    cfg = CONFIG.get("like_api") or {}
    base = str(cfg.get("base") or "").rstrip("/")
    if not base:
        raise ApiError("The like engine is not configured yet (config.json -> like_api.base).", 503)
    url = base + path
    headers = {}
    key = str(cfg.get("key") or "").strip()
    if key:
        headers[str(cfg.get("key_header") or "X-API-Key")] = key
    status, resp_headers, payload = do_http(url, method, params=params,
                                            headers=headers, timeout=timeout)
    ctype, parsed, text = parse_body(resp_headers, payload)
    return status, parsed, text


def is_error_payload(obj):
    if not isinstance(obj, dict):
        return False
    if obj.get("error"):
        return True
    if isinstance(obj.get("detail"), str) and obj.get("detail"):
        return True
    if obj.get("success") is False:
        return True
    if str(obj.get("status", "")).lower() in ("error", "failed"):
        return True
    return False


def summarize_like(obj):
    if not isinstance(obj, dict):
        return tr(obj, 200)
    added = obj.get("Likes Added")
    if added is not None:
        return "Likes Added: %s (before %s, after %s)" % (
            added, obj.get("Like Before", "?"), obj.get("Like After", "?"))
    return tr(json.dumps(obj, ensure_ascii=False), 200)


def summarize_autolike(obj):
    if not isinstance(obj, dict):
        return tr(obj, 240)
    parts = []
    if obj.get("status"):
        parts.append("status: %s" % obj.get("status"))
    if obj.get("accounts_per_day") is not None:
        parts.append("%s likes per day" % obj.get("accounts_per_day"))
    if obj.get("total_likes_expected") is not None:
        parts.append("%s likes expected total" % obj.get("total_likes_expected"))
    if obj.get("schedule"):
        parts.append("schedule: %s" % obj.get("schedule"))
    if parts:
        return "; ".join(str(p) for p in parts)
    return tr(json.dumps(obj, ensure_ascii=False), 240)


def autolike_start(uid, days):
    status, parsed, text = like_api("/autolike", params={"uid": uid, "days": int(days)})
    if status == 0:
        return False, tr(text, 240)
    if status >= 400:
        return False, "HTTP %s: %s" % (status, tr(text or parsed, 200))
    if parsed is None:
        return False, "The like engine returned an empty answer."
    if is_error_payload(parsed):
        return False, tr(json.dumps(parsed, ensure_ascii=False), 240)
    st = str(parsed.get("status", "")).lower() if isinstance(parsed, dict) else ""
    if st and st not in ("scheduled", "active", "success", "ok", "created"):
        return False, "Unexpected status from the like engine: %s" % st
    likes_per_day = parsed.get("accounts_per_day") if isinstance(parsed, dict) else None
    return True, (summarize_autolike(parsed), likes_per_day)


def like_send(uid):
    status, parsed, text = like_api("/like", params={"uid": uid}, timeout=40)
    if status == 0:
        raise ApiError(tr(text, 200), 502)
    if status >= 400:
        raise ApiError("HTTP %s: %s" % (status, tr(text or parsed, 200)), 502)
    if isinstance(parsed, dict) and is_error_payload(parsed):
        raise ApiError("The like engine refused this UID: %s" % tr(parsed, 200), 502)
    return parsed


# ------------------------------------------------------------------
# Pricing, promos, coupons
# ------------------------------------------------------------------
def price_for(product, days):
    try:
        days = int(days)
    except Exception:
        raise ApiError("Days must be a number.")
    if days <= 0:
        raise ApiError("Days must be a positive number.")
    if product == "autolike":
        for plan in CONFIG.get("autolike_plans") or []:
            if int(plan.get("days", -1)) == days:
                return money_round(plan.get("price", 0)), days
        options = ", ".join(str(p.get("days")) for p in (CONFIG.get("autolike_plans") or []))
        raise ApiError("Unknown plan. Available Auto Like plans: %s days." % options)
    if product == "like_credit":
        rate = int(CONFIG.get("credit_rate_days_per_dollar") or 10)
        if days % rate != 0:
            raise ApiError("Like Credit works in blocks of %d days (1 block = 1 USD)." % rate)
        dollars = days // rate
        if dollars < 1 or dollars > 200:
            raise ApiError("Credit amount out of range.")
        return float(dollars), days
    raise ApiError("Unknown product.")


def normalize_code(code):
    return re.sub(r"[^A-Za-z0-9\-]", "", str(code or "")).upper()


def find_promo(code):
    code = normalize_code(code)
    if not code:
        raise ApiError("Enter a promo code.")
    with STATE_LOCK:
        for promo in STATE["promos"]:
            if promo.get("code") == code:
                if promo.get("active", True) is False:
                    raise ApiError("This promo code is not active.")
                max_uses = int(promo.get("max_uses", 0) or 0)
                if max_uses > 0 and int(promo.get("used", 0)) >= max_uses:
                    raise ApiError("This promo code reached its usage limit.")
                return promo
    raise ApiError("Promo code not found.")


def promo_price(product, days, promo):
    base, _days = price_for(product, days)
    percent = int(promo.get("percent", 0))
    final = money_round(base * (100.0 - percent) / 100.0)
    return base, final, percent


def find_coupon(code):
    code = normalize_code(code)
    with STATE_LOCK:
        for coupon in STATE["coupons"]:
            if coupon.get("code") == code:
                return coupon
    return None


# ------------------------------------------------------------------
# Users, sessions, rate limiting
# ------------------------------------------------------------------
def find_user_by_no(user_no):
    user_no = str(user_no or "")
    with STATE_LOCK:
        for user in STATE["users"]:
            if user.get("no") == user_no:
                return user
    return None


def find_user_by_name(username):
    username = str(username or "").strip().lower()
    with STATE_LOCK:
        for user in STATE["users"]:
            if str(user.get("username", "")).lower() == username:
                return user
    return None


def create_user(username, password):
    username = str(username).strip()
    if not USER_RE.match(username):
        raise ApiError("Username: 3 to 20 characters, letters, numbers or underscore.")
    if find_user_by_name(username):
        raise ApiError("This username is already taken.")
    if len(password) < 6:
        raise ApiError("Password must be at least 6 characters.")
    if len(password) > 72:
        raise ApiError("Password too long.")
    salt, digest = hash_password(password)
    user = {
        "no": next_no("next_user", "USR"),
        "created": now_iso(),
        "username": username,
        "salt": salt,
        "hash": digest,
        "balance": 0.0,
    }
    with STATE_LOCK:
        STATE["users"].append(user)
        save_state(STATE)
    return user


def register_login_rate(scope, ip, limit, window):
    return rate_ok(scope, ip, limit, window)


def rate_ok(scope, ip, limit, window):
    now = time.time()
    key = "%s|%s" % (scope, ip)
    with STATE_LOCK:
        bucket = HITS.setdefault(key, [])
        while bucket and bucket[0] < now - window:
            bucket.pop(0)
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True


def check_fails(scope, ip):
    now = time.time()
    key = "%s|%s" % (scope, ip)
    fails, blocked = LOGIN_FAILS.get(key, [0, 0])
    if blocked > now:
        raise ApiError("Too many failed attempts. Try again in a few minutes.", 429)
    return key


def record_fail(key, bad=True):
    now = time.time()
    fails, blocked = LOGIN_FAILS.get(key, [0, 0])
    if bad:
        fails += 1
        if fails >= 8:
            blocked = now + 600
            fails = 0
        LOGIN_FAILS[key] = [fails, blocked]
    else:
        LOGIN_FAILS[key] = [0, 0]


def purge_sessions():
    now = time.time()
    with SESSIONS_LOCK:
        for token in [t for t, s in SESSIONS.items() if s.get("exp", 0) < now]:
            SESSIONS.pop(token, None)


def session_from_cookie(handler, cookie_name):
    cookies = handler.headers.get("Cookie", "") or ""
    for part in cookies.split(";"):
        if "=" in part:
            name, value = part.strip().split("=", 1)
            if name == cookie_name:
                token = value.strip()
                with SESSIONS_LOCK:
                    sess = SESSIONS.get(token)
                if sess and sess.get("exp", 0) > time.time():
                    return token, sess
    return None, None


def start_session(kind, user_no=None):
    token = secrets.token_urlsafe(32)
    with SESSIONS_LOCK:
        SESSIONS[token] = {"kind": kind, "exp": time.time() + (7 * 86400), "user_no": user_no}
    return token


def end_session(token):
    if token:
        with SESSIONS_LOCK:
            SESSIONS.pop(token, None)


def current_user(handler):
    purge_sessions()
    token, sess = session_from_cookie(handler, "fflike_user")
    if not token or sess.get("kind") != "user":
        return None, None
    user = find_user_by_no(sess.get("user_no"))
    if not user:
        end_session(token)
        return None, None
    return token, user


def current_admin(handler):
    purge_sessions()
    token, sess = session_from_cookie(handler, "fflike_admin")
    if not token or sess.get("kind") != "admin":
        return None
    return token


# ------------------------------------------------------------------
# Accounts, orders, deposits
# ------------------------------------------------------------------
def sanitize_txid(value):
    if not value:
        return ""
    return re.sub(r"[^A-Za-z0-9_\-\.]", "", str(value))[:64]


def find_active(uid, product):
    today = today_str()
    with STATE_LOCK:
        for acc in STATE["accounts"]:
            if (str(acc.get("uid")) == str(uid) and acc.get("product") == product
                    and acc.get("status") == "active" and acc.get("expires", "") >= today):
                return acc
    return None


def create_account(uid, name, region, product, days, price, likes_per_day, source,
                   order_no, user_no=None, username=None):
    account = {
        "no": next_no("next_account", "ACC"),
        "created": now_iso(),
        "uid": str(uid),
        "name": name,
        "region": region,
        "product": product,
        "days": int(days),
        "price_usd": money_round(price),
        "likes_per_day": int(likes_per_day or CONFIG.get("likes_per_day") or 135),
        "started": today_str(),
        "expires": (date.today() + timedelta(days=int(days))).isoformat(),
        "status": "active",
        "source": source,
        "order_no": order_no,
        "user_no": user_no,
        "username": username,
    }
    with STATE_LOCK:
        STATE["accounts"].insert(0, account)
    return account


def activate_order(order):
    result = autolike_start(order["uid"], order["days"])
    if not result[0]:
        order["last_error"] = result[1] if isinstance(result[1], str) else tr(result[1], 240)
        add_event("order_failed", "Order %s activation failed" % order["no"], order["last_error"])
        return False
    detail, likes_per_day = result[1]
    account = create_account(order["uid"], order["name"], order["region"], order["product"],
                             order["days"], order.get("price_paid", order.get("price_usd", 0)),
                             likes_per_day, order.get("source", "site"), order["no"],
                             order.get("user_no"), order.get("username"))
    order["status"] = "approved"
    order["decided"] = now_iso()
    order["account_no"] = account["no"]
    order["last_error"] = ""
    add_event("activate", "Order %s activated for %s (%s, %s days)"
              % (order["no"], order["uid"], order["name"], order["days"]), detail)
    return True


def mask_uid(uid):
    text = str(uid)
    if len(text) > 4:
        return "*" * (len(text) - 4) + text[-4:]
    return text


def public_order(order, masked=True, public=False):
    view = {
        "no": order.get("no"),
        "created": order.get("created"),
        "decided": order.get("decided"),
        "product": order.get("product"),
        "days": order.get("days"),
        "price_usd": order.get("price_usd"),
        "price_paid": order.get("price_paid"),
        "currency": order.get("currency"),
        "uid": mask_uid(order["uid"]) if masked else str(order["uid"]),
        "name": order.get("name"),
        "region": order.get("region"),
        "username": order.get("username"),
        "promo": order.get("promo") or "",
        "status": order.get("status"),
        "last_error": order.get("last_error") or "",
        "account_no": order.get("account_no"),
    }
    if not public and "txid" in order:
        view["txid"] = order.get("txid", "")
    return view


def public_account(acc, masked=True):
    return {
        "no": acc.get("no"),
        "created": acc.get("created"),
        "uid": mask_uid(acc["uid"]) if masked else str(acc["uid"]),
        "name": acc.get("name"),
        "region": acc.get("region"),
        "product": acc.get("product"),
        "days": acc.get("days"),
        "price_usd": acc.get("price_usd"),
        "likes_per_day": acc.get("likes_per_day"),
        "started": acc.get("started"),
        "expires": acc.get("expires"),
        "status": acc.get("status"),
        "source": acc.get("source"),
        "order_no": acc.get("order_no"),
        "username": acc.get("username"),
    }


def public_deposit(dep):
    return {
        "no": dep.get("no"),
        "created": dep.get("created"),
        "decided": dep.get("decided"),
        "user_no": dep.get("user_no"),
        "username": dep.get("username"),
        "amount": dep.get("amount"),
        "txid": dep.get("txid", ""),
        "status": dep.get("status"),
        "note": dep.get("note") or "",
    }


def public_user(user):
    return {
        "no": user.get("no"),
        "created": user.get("created"),
        "username": user.get("username"),
        "balance": money_round(user.get("balance", 0)),
    }


def create_order_for_user(user, product, days, uid, promo_code):
    price_base = None
    promo = None
    percent = 0
    if promo_code:
        promo = find_promo(promo_code)
        price_base, price, percent = promo_price(product, days, promo)
    else:
        price, days = price_for(product, days)
        price_base = price
    price = money_round(price)
    existing = find_active(uid, product)
    if existing:
        raise ApiError("This UID already has an active %s until %s."
                       % ("Auto Like" if product == "autolike" else "Like Credit",
                          existing.get("expires")))
    try:
        info = player_info(uid)
    except ApiError:
        info = None
    name = info["name"] if info else "Unknown"
    region = info["region"] if info else "-"

    with STATE_LOCK:
        if money_round(user.get("balance", 0)) + 1e-9 < price:
            raise ApiError("Not enough balance. Add credit in your wallet first.")
        user["balance"] = money_round(user.get("balance", 0) - price)
        if promo is not None:
            promo["used"] = int(promo.get("used", 0)) + 1
        order = {
            "no": next_no("next_order", "ORD"),
            "created": now_iso(),
            "product": product,
            "days": days,
            "price_usd": price_base,
            "price_paid": price,
            "currency": CONFIG.get("currency") or "USD",
            "uid": str(uid),
            "name": name,
            "region": region,
            "txid": "",
            "status": "pending",
            "decided": None,
            "account_no": None,
            "last_error": "",
            "source": "site",
            "user_no": user.get("no"),
            "username": user.get("username"),
            "promo": (promo["code"] if promo is not None else ""),
        }
        STATE["orders"].insert(0, order)
        add_event("order", "Order %s: %s buys %s %s days for %s (%s)"
                  % (order["no"], user.get("username"),
                     "Auto Like" if product == "autolike" else "Credit", days, uid, name),
                  "paid %s USD%s" % (price, " with promo %s (-%s%%)" % (promo["code"], percent)
                                     if promo is not None else ""))
        activated = False
        if CONFIG.get("auto_approve_orders", True):
            try:
                activated = activate_order(order)
            except ApiError as err:
                order["last_error"] = err.message
                add_event("order_failed", "Order %s activation error" % order["no"], err.message)
                activated = False
        save_state(STATE)
    if activated and percent:
        add_event("promo", "Promo %s used in order %s (-%s%%)" % (promo["code"], order["no"], percent))
    return order, activated


# ------------------------------------------------------------------
# Deposits, coupons, promos (mutations)
# ------------------------------------------------------------------
def credit_user(user, amount, reason):
    amount = money_round(amount)
    with STATE_LOCK:
        user["balance"] = money_round(max(0.0, money_round(user.get("balance", 0)) + amount))
        save_state(STATE)
    add_event("wallet", "Balance %s for %s (%s): %+0.2f USD"
              % ("debited" if amount < 0 else "credited",
                 user.get("username"), user.get("no"), amount), reason)


def approve_deposit(dep, auto=False):
    user = find_user_by_no(dep.get("user_no"))
    dep["status"] = "approved"
    dep["decided"] = now_iso()
    if auto:
        dep["note"] = "auto approved (payment flow: credit added instantly)"
    if user is not None:
        with STATE_LOCK:
            user["balance"] = money_round(user.get("balance", 0) + money_round(dep.get("amount", 0)))
            save_state(STATE)
        add_event("deposit", "Deposit %s approved for %s: +%.2f USD%s"
                  % (dep["no"], dep.get("username"), money_round(dep.get("amount", 0)),
                     " (auto)" if auto else ""), "txid: %s" % dep.get("txid", ""))


def redeem_coupon(user, code):
    code = normalize_code(code)
    if not CODE_RE.match(code):
        raise ApiError("Enter a valid coupon code.")
    with STATE_LOCK:
        coupon = None
        for item in STATE["coupons"]:
            if item.get("code") == code:
                coupon = item
                break
        if coupon is None:
            raise ApiError("Coupon code not found.")
        if coupon.get("active", True) is False:
            raise ApiError("This coupon code is not active anymore.")
        max_uses = int(coupon.get("max_uses", 0) or 0)
        if max_uses > 0 and int(coupon.get("used", 0)) >= max_uses:
            raise ApiError("This coupon code reached its usage limit.")
        used_by = coupon.get("used_by") or []
        if user.get("no") in used_by:
            raise ApiError("You already used this coupon code.")
        amount = money_round(coupon.get("amount", 0))
        user["balance"] = money_round(user.get("balance", 0) + amount)
        coupon["used"] = int(coupon.get("used", 0)) + 1
        coupon["used_by"] = used_by + [user.get("no")]
        save_state(STATE)
    add_event("coupon", "Coupon %s redeemed by %s: +%.2f USD" % (code, user.get("username"), amount))
    return amount


def create_coupon(code, amount, max_uses):
    code = normalize_code(code)
    if not CODE_RE.match(code):
        raise ApiError("Coupon code: 3 to 24 characters (letters, numbers, -).")
    amount = money_round(amount)
    if amount <= 0 or amount > 1000:
        raise ApiError("Coupon credit must be between 0.50 and 1000 USD (admin sets it).")
    try:
        max_uses = int(max_uses)
    except Exception:
        max_uses = 0
    if max_uses < 0:
        max_uses = 0
    with STATE_LOCK:
        for item in STATE["coupons"]:
            if item.get("code") == code:
                raise ApiError("This coupon code already exists.")
        coupon = {
            "code": code,
            "amount": amount,
            "max_uses": max_uses,
            "used": 0,
            "used_by": [],
            "created": now_iso(),
            "active": True,
        }
        STATE["coupons"].insert(0, coupon)
        save_state(STATE)
    add_event("coupon", "Coupon %s created: %.2f USD, uses: %s"
              % (code, amount, "unlimited" if max_uses == 0 else max_uses))
    return coupon


def create_promo(code, percent, max_uses):
    code = normalize_code(code)
    if not CODE_RE.match(code):
        raise ApiError("Promo code: 3 to 24 characters (letters, numbers, -).")
    try:
        percent = int(percent)
    except Exception:
        raise ApiError("Discount must be a number.")
    if percent < 1 or percent > 100:
        raise ApiError("Discount must be between 1 and 100 percent.")
    try:
        max_uses = int(max_uses)
    except Exception:
        max_uses = 0
    if max_uses < 0:
        max_uses = 0
    with STATE_LOCK:
        for item in STATE["promos"]:
            if item.get("code") == code:
                raise ApiError("This promo code already exists.")
        promo = {
            "code": code,
            "percent": percent,
            "max_uses": max_uses,
            "used": 0,
            "created": now_iso(),
            "active": True,
        }
        STATE["promos"].insert(0, promo)
        save_state(STATE)
    add_event("promo", "Promo %s created: -%d%%, uses: %s"
              % (code, percent, "unlimited" if max_uses == 0 else max_uses))
    return promo


def manager_rows():
    with STATE_LOCK:
        accounts = list(STATE["accounts"])
    target_map = {}
    upstream_error = None
    try:
        _status, parsed, _text = like_api("/targets", timeout=15)
        if isinstance(parsed, dict):
            for target in parsed.get("targets") or []:
                uid = str(target.get("target_uid", ""))
                target_map[uid] = target
    except ApiError as err:
        upstream_error = err.message
    rows = []
    today = today_str()
    for acc in accounts:
        engine = target_map.pop(str(acc["uid"]), None)
        rows.append({
            "local": public_account(acc, masked=False),
            "expired": acc.get("expires", "") < today,
            "engine": None if engine is None else {
                "days_total": engine.get("days_total"),
                "days_remaining": engine.get("days_remaining"),
                "runs_done": engine.get("runs_done"),
                "total_likes_done": engine.get("total_likes_done"),
                "accounts_per_day": engine.get("accounts_per_day"),
                "end_date": engine.get("end_date"),
            },
        })
    for uid, engine in target_map.items():
        rows.append({
            "local": None,
            "expired": False,
            "uid": uid,
            "engine": {
                "days_total": engine.get("days_total"),
                "days_remaining": engine.get("days_remaining"),
                "runs_done": engine.get("runs_done"),
                "total_likes_done": engine.get("total_likes_done"),
                "accounts_per_day": engine.get("accounts_per_day"),
                "end_date": engine.get("end_date"),
            },
        })
    return rows, upstream_error


# ------------------------------------------------------------------
# HTTP handler
# ------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "FFLike/2.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def client_ip(self):
        fwd = self.headers.get("X-Forwarded-For")
        if fwd:
            return fwd.split(",")[0].strip()
        return self.client_address[0] if self.client_address else "?"

    # ------- plumbing -------
    def _drain_request_body(self):
        """Consume an unread POST body so keep-alive stays in sync."""
        if (self.command or "GET").upper() != "POST":
            return
        if getattr(self, "_body_read", False):
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except Exception:
            length = 0
        if length <= 0:
            return
        if length > 20000:
            # too big to swallow safely: close the connection instead
            self.close_connection = True
            return
        try:
            remaining = length
            while remaining > 0:
                part = self.rfile.read(min(4096, remaining))
                if not part:
                    break
                remaining -= len(part)
        except Exception:
            self.close_connection = True

    def _send(self, code, body, ctype, cache=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")
        if cache:
            self.send_header("Cache-Control", cache)
        else:
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)
        self._status = code
        self._responded = True

    def send_json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8")

    def send_api_error(self, err):
        self.send_json(err.status, {"ok": False, "error": err.message})

    def read_json(self, limit=20000):
        self._body_read = True
        raw_len = int(self.headers.get("Content-Length") or 0)
        if raw_len <= 0:
            return {}
        if raw_len > limit:
            raise ApiError("Request body is too large.", 413)
        raw = self.rfile.read(raw_len)
        if not raw:
            return {}
        try:
            obj = json.loads(raw.decode("utf-8"))
        except Exception:
            raise ApiError("Invalid JSON body.")
        if not isinstance(obj, dict):
            raise ApiError("Invalid JSON body.")
        return obj

    def query(self, key, default=""):
        values = self._qs.get(key, [])
        return values[0] if values else default

    def _need_uid(self):
        uid = str(self.query("uid", "")).strip()
        if not UID_RE.match(uid):
            raise ApiError("Enter a valid Free Fire UID (5 to 12 digits).")
        return uid

    # ------- routing -------
    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method):
        t0 = time.time()
        self._status = 0
        self._responded = False
        self._body_read = False
        parsed = urllib.parse.urlparse(self.path)
        self._path = parsed.path
        self._qs = urllib.parse.parse_qs(parsed.query)
        self._api = self._path.startswith("/api/")
        status = 500
        try:
            if self._api and method == "POST":
                # light CSRF protection: browser forms cannot send this header
                if self.headers.get("X-Requested-With") != "XMLHttpRequest":
                    raise ApiError("Bad request origin.", 403)
            if not self._api:
                if method != "GET":
                    raise ApiError("Method not allowed.", 405)
                self._route_page()
            elif method == "GET":
                self._route_get()
            else:
                self._route_post()
            self._drain_request_body()
            status = self._status or 200
        except ApiError as err:
            if self._responded:
                status = self._status
                log_line("%s %s -> %s (error after response: %s)"
                         % (method, self._path, status, err.message))
                self._drain_request_body()
                return
            if self._api:
                self._drain_request_body()
                self.send_api_error(err)
            else:
                self._drain_request_body()
                self._send(err.status, "<h1>%s</h1><p>%s</p>" % (err.status, err.message),
                           "text/html; charset=utf-8")
            status = err.status
        except Exception:
            status = 500
            self._drain_request_body()
            log_line("EXCEPTION on %s %s" % (method, self._path))
            log_line(traceback.format_exc())
            if not self._responded:
                if self._api:
                    self.send_json(500, {"ok": False, "error": "Internal server error."})
                else:
                    try:
                        self._send(500, "<h1>500</h1><p>Internal server error.</p>",
                                   "text/html; charset=utf-8")
                    except Exception:
                        pass
        dt = int((time.time() - t0) * 1000)
        log_line("%s %s %s (%d ms)" % (method, self._path, status, dt))

    # ------- pages and static files -------
    def _route_page(self):
        path = self._path
        if path in ("/", "/index.html", "/login", "/register"):
            self._serve_file(os.path.join(BASE_DIR, "index.html"), "no-store")
            return
        if path in ("/admin", "/admin.html", "/admin/"):
            self._serve_file(os.path.join(BASE_DIR, "admin.html"), "no-store")
            return
        if path == "/favicon.ico":
            self._serve_file(os.path.join(STATIC_DIR, "img", "logo.png"), "max-age=86400")
            return
        if path.startswith("/static/"):
            rel = path[len("/static/"):]
            full = self._safe_static(rel)
            if full is None:
                raise ApiError("Not found.", 404)
            self._serve_file(full, "max-age=3600")
            return
        raise ApiError("Not found.", 404)

    def _safe_static(self, rel):
        rel = rel.replace("\\", "/").lstrip("/")
        parts = [p for p in rel.split("/") if p not in ("", ".", "..")]
        if not parts:
            return None
        full = os.path.realpath(os.path.join(STATIC_DIR, *parts))
        root = os.path.realpath(STATIC_DIR)
        if full != root and not full.startswith(root + os.sep):
            return None
        if not os.path.isfile(full):
            return None
        return full

    def _serve_file(self, full, cache):
        ext = os.path.splitext(full)[1].lower()
        ctype = MIME.get(ext) or mimetypes.guess_type(full)[0] or "application/octet-stream"
        with open(full, "rb") as fh:
            body = fh.read()
        self._send(200, body, ctype, cache)

    # ------- public GET -------
    def _route_get(self):
        path = self._path
        if path.startswith("/api/admin/"):
            self._admin_get()
            return
        if path == "/api/health":
            self.send_json(200, {"ok": True, "site": CONFIG.get("site_name"), "time": now_iso()})
        elif path == "/api/site-info":
            self.send_json(200, {
                "ok": True,
                "site_name": CONFIG.get("site_name"),
                "tagline": CONFIG.get("tagline"),
                "currency": CONFIG.get("currency"),
                "requires_login": True,
                "autolike_plans": [{"days": int(p["days"]), "price": money_round(p["price"])}
                                   for p in (CONFIG.get("autolike_plans") or [])],
                "credit_rate_days_per_dollar": int(CONFIG.get("credit_rate_days_per_dollar") or 10),
                "credit_amounts": CONFIG.get("credit_amounts") or [1, 2, 3, 5, 10],
                "likes_per_day": CONFIG.get("likes_per_day"),
                "binance": {"pay_id": (CONFIG.get("binance") or {}).get("pay_id", ""),
                            "note": (CONFIG.get("binance") or {}).get("note", "")},
                "auto_approve_orders": bool(CONFIG.get("auto_approve_orders", True)),
                "auto_approve_deposits": bool(CONFIG.get("auto_approve_deposits", True)),
                "stats": public_stats(),
            })
        elif path == "/api/player":
            uid = self._need_uid()
            info = player_info(uid)
            self.send_json(200, {"ok": True, "uid": info["uid"], "name": info["name"],
                                 "region": info["region"], "level": info["level"]})
        elif path == "/api/profile-card":
            uid = self._need_uid()
            theme = self.query("theme", "dark")
            if theme not in ("dark", "light"):
                theme = "dark"
            ctype, payload = profile_card_bytes(uid, theme)
            self._send(200, payload, ctype, "max-age=600")
        elif path == "/api/logs":
            with STATE_LOCK:
                accounts = list(STATE["accounts"])
                orders = list(STATE["orders"])
            today = today_str()
            recent = [public_account(a, masked=True) for a in accounts[:100]]
            self.send_json(200, {
                "ok": True,
                "stats": public_stats(),
                "orders_total": len(orders),
                "accounts": recent,
                "active_today": len([a for a in accounts
                                     if a.get("status") == "active"
                                     and a.get("expires", "") >= today]),
            })
        elif path == "/api/user/me":
            _token, user = current_user(self)
            if user is None:
                raise ApiError("Not logged in.", 401)
            self.send_json(200, self._user_me_payload(user))
        else:
            raise ApiError("Not found.", 404)

    def _user_me_payload(self, user):
        with STATE_LOCK:
            orders = [o for o in STATE["orders"] if o.get("user_no") == user.get("no")]
            accounts = [a for a in STATE["accounts"] if a.get("user_no") == user.get("no")]
            deposits = [d for d in STATE["deposits"] if d.get("user_no") == user.get("no")]
        today = today_str()
        return {
            "ok": True,
            "user": public_user(user),
            "orders": [public_order(o, masked=False, public=True) for o in orders[:60]],
            "accounts": [{
                "no": a.get("no"), "uid": str(a.get("uid")), "name": a.get("name"),
                "region": a.get("region"), "product": a.get("product"), "days": a.get("days"),
                "likes_per_day": a.get("likes_per_day"), "started": a.get("started"),
                "expires": a.get("expires"),
                "status": ("active" if a.get("status") == "active" and a.get("expires", "") >= today
                           else "finished" if a.get("expires", "") < today else a.get("status")),
            } for a in accounts[:60]],
            "deposits": [public_deposit(d) for d in deposits[:60]],
            "stats": public_stats(),
        }

    # ------- POST routing -------
    def _route_post(self):
        path = self._path
        if path.startswith("/api/admin/"):
            self._admin_post()
            return
        if path == "/api/auth/register":
            self._auth_register()
        elif path == "/api/auth/login":
            self._auth_login()
        elif path == "/api/auth/logout":
            token, _sess = session_from_cookie(self, "fflike_user")
            if token:
                end_session(token)
            token2, _sess2 = session_from_cookie(self, "fflike_admin")
            if token2:
                end_session(token2)
            body = json.dumps({"ok": True}).encode("utf-8")
            self._reply_with_cookie(body, [
                ("Set-Cookie", "fflike_user=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"),
                ("Set-Cookie", "fflike_admin=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"),
            ])
        elif path == "/api/user/deposit":
            self._user_deposit()
        elif path == "/api/user/redeem":
            self._user_redeem()
        elif path == "/api/promo/check":
            self._promo_check()
        elif path == "/api/order":
            self._user_order()
        else:
            raise ApiError("Not found.", 404)

    # ---- public POST helpers ----
    def _cookie_session_reply(self, kind, token):
        name = "fflike_admin" if kind == "admin" else "fflike_user"
        self.send_header("Set-Cookie",
                         "%s=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d"
                         % (name, token, 7 * 86400))

    def _auth_register(self):
        ip = self.client_ip()
        if not rate_ok("register", ip, 5, 3600):
            raise ApiError("Too many registrations from this device. Try again later.", 429)
        data = self.read_json()
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        user = create_user(username, password)
        token = start_session("user", user.get("no"))
        body = json.dumps({"ok": True, "user": public_user(user)}, ensure_ascii=False).encode("utf-8")
        self._reply_with_cookie(body, [("Set-Cookie", "fflike_user=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d"
                                        % (token, 7 * 86400))])
        add_event("user", "New account registered: %s (%s)" % (user["username"], user["no"]))

    def _auth_login(self):
        ip = self.client_ip()
        key = check_fails("userlogin", ip)
        if not rate_ok("login", ip, 20, 600):
            raise ApiError("Too many attempts. Try again in a few minutes.", 429)
        data = self.read_json()
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        user = find_user_by_name(username)
        ok = user is not None and verify_password(password, user.get("salt", ""), user.get("hash", ""))
        if not ok:
            time.sleep(0.4)
            record_fail(key, True)
            raise ApiError("Wrong username or password.", 401)
        record_fail(key, False)
        token = start_session("user", user.get("no"))
        body = json.dumps({"ok": True, "user": public_user(user)}, ensure_ascii=False).encode("utf-8")
        self._reply_with_cookie(body, [("Set-Cookie", "fflike_user=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d"
                                        % (token, 7 * 86400))])
        add_event("login", "User logged in: %s (%s)" % (user["username"], ip))

    def _require_user(self):
        _token, user = current_user(self)
        if user is None:
            raise ApiError("Please log in first.", 401)
        return user

    def _reply_with_cookie(self, body, extra_headers):
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        for name, value in extra_headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)
        self._status = 200
        self._responded = True

    def _user_deposit(self):
        user = self._require_user()
        ip = self.client_ip()
        if not rate_ok("deposit", ip, 12, 3600):
            raise ApiError("Too many deposit requests. Try again later.", 429)
        data = self.read_json()
        try:
            amount = money_round(data.get("amount"))
        except Exception:
            raise ApiError("Amount must be a number.")
        if amount < 1 or amount > 500:
            raise ApiError("Deposit amount must be between 1 and 500 USD.")
        txid = sanitize_txid(data.get("txid"))
        if len(txid) < 4:
            raise ApiError("Paste the Binance Transaction ID of your transfer.")
        deposit = {
            "no": next_no("next_deposit", "DEP"),
            "created": now_iso(),
            "user_no": user.get("no"),
            "username": user.get("username"),
            "amount": amount,
            "txid": txid,
            "status": "pending",
            "decided": None,
            "note": "",
        }
        credited = False
        with STATE_LOCK:
            STATE["deposits"].insert(0, deposit)
            if CONFIG.get("auto_approve_deposits", True):
                approve_deposit(deposit, auto=True)
                credited = True
            save_state(STATE)
        add_event("deposit", "Deposit %s: %s sent %0.2f USD (txid %s)"
                  % (deposit["no"], user.get("username"), amount, txid))
        if credited:
            message = ("Credit added to your balance instantly. "
                       "Your transfer is double-checked after.")
            status_txt = "approved"
        else:
            message = ("Deposit received. Your transfer is checked and "
                       "your balance updates.")
            status_txt = "pending"
        self.send_json(200, {"ok": True, "deposit": public_deposit(deposit),
                             "credited": credited, "message": message,
                             "balance": public_user(user)["balance"], "status": status_txt})

    def _user_redeem(self):
        user = self._require_user()
        ip = self.client_ip()
        if not rate_ok("redeem", ip, 15, 3600):
            raise ApiError("Too many attempts. Try again later.", 429)
        data = self.read_json()
        code = str(data.get("code", ""))
        amount = redeem_coupon(user, code)
        self.send_json(200, {"ok": True, "added": amount,
                             "balance": public_user(user)["balance"],
                             "message": "Coupon accepted: +%.2f USD credit." % amount})

    def _promo_check(self):
        if not rate_ok("promo", self.client_ip(), 30, 3600):
            raise ApiError("Too many attempts. Try again later.", 429)
        data = self.read_json()
        promo = find_promo(data.get("code"))
        _base, final, percent = promo_price(data.get("product"), data.get("days"), promo)
        self.send_json(200, {"ok": True, "code": promo["code"], "percent": percent,
                             "price": final})

    def _user_order(self):
        user = self._require_user()
        ip = self.client_ip()
        if not rate_ok("order", ip, 15, 3600):
            raise ApiError("Too many orders from this device. Try again later.", 429)
        data = self.read_json()
        product = str(data.get("product", "")).strip()
        if product not in ("autolike", "like_credit"):
            raise ApiError("Choose Auto Like or Like Credit.")
        uid = str(data.get("uid", "")).strip()
        if not UID_RE.match(uid):
            raise ApiError("Enter a valid Free Fire UID (5 to 12 digits).")
        order, activated = create_order_for_user(user, product, data.get("days"),
                                                 uid, data.get("promo"))
        if activated:
            note = "Paid with your balance and activated on the like engine."
        else:
            note = ("Paid and queued. Activation happens shortly for you or you get refunded.")
        self.send_json(200, {"ok": True, "activated": activated,
                             "order": public_order(order, masked=False, public=True),
                             "balance": public_user(user)["balance"], "note": note})

    # ------- admin GET -------
    def _admin_guard(self):
        if current_admin(self) is None:
            raise ApiError("Admin session expired. Log in again.", 401)

    def _admin_get(self):
        path = self._path
        if path == "/api/admin/check":
            self._admin_guard()
            self.send_json(200, {"ok": True, "user": CONFIG.get("admin_user")})
        elif path == "/api/admin/overview":
            self._admin_guard()
            stats = public_stats()
            upstream = None
            try:
                _status, parsed, _text = like_api("/status", timeout=12)
                if 200 <= _status < 400 and isinstance(parsed, dict):
                    jobs = parsed.get("autolike_jobs") or {}
                    upstream = {
                        "reach": True,
                        "working_accounts": parsed.get("working_accounts"),
                        "jobs": len(jobs),
                        "last_refresh": parsed.get("last_refresh"),
                    }
            except ApiError:
                upstream = {"reach": False}
            with STATE_LOCK:
                events = [dict(e) for e in STATE["events"][:12]]
            self.send_json(200, {"ok": True, "stats": stats, "upstream": upstream,
                                 "events": events})
        elif path == "/api/admin/orders":
            self._admin_guard()
            with STATE_LOCK:
                orders = list(STATE["orders"])
            self.send_json(200, {"ok": True,
                                 "orders": [public_order(o, masked=False) for o in orders[:200]]})
        elif path == "/api/admin/accounts":
            self._admin_guard()
            with STATE_LOCK:
                accounts = list(STATE["accounts"])
            self.send_json(200, {"ok": True,
                                 "accounts": [public_account(a, masked=False) for a in accounts[:300]]})
        elif path == "/api/admin/events":
            self._admin_guard()
            with STATE_LOCK:
                events = [dict(e) for e in STATE["events"][:50]]
            self.send_json(200, {"ok": True, "events": events})
        elif path == "/api/admin/users":
            self._admin_guard()
            with STATE_LOCK:
                users = list(STATE["users"])
                orders = list(STATE["orders"])
            counts = {}
            for o in orders:
                counts[o.get("user_no")] = counts.get(o.get("user_no"), 0) + 1
            rows = []
            for u in users:
                view = public_user(u)
                view["orders"] = counts.get(u.get("no"), 0)
                rows.append(view)
            self.send_json(200, {"ok": True, "users": rows[:300]})
        elif path == "/api/admin/deposits":
            self._admin_guard()
            with STATE_LOCK:
                deposits = list(STATE["deposits"])
            self.send_json(200, {"ok": True,
                                 "deposits": [public_deposit(d) for d in deposits[:200]]})
        elif path == "/api/admin/coupons":
            self._admin_guard()
            with STATE_LOCK:
                coupons = [dict(c) for c in STATE["coupons"]]
            self.send_json(200, {"ok": True, "coupons": coupons[:200]})
        elif path == "/api/admin/promos":
            self._admin_guard()
            with STATE_LOCK:
                promos = [dict(p) for p in STATE["promos"]]
            self.send_json(200, {"ok": True, "promos": promos[:200]})
        elif path == "/api/admin/settings":
            self._admin_guard()
            self.send_json(200, {"ok": True, "settings": {
                "site_name": CONFIG.get("site_name"),
                "tagline": CONFIG.get("tagline"),
                "binance_pay_id": (CONFIG.get("binance") or {}).get("pay_id", ""),
                "binance_note": (CONFIG.get("binance") or {}).get("note", ""),
                "auto_approve_orders": bool(CONFIG.get("auto_approve_orders", True)),
                "auto_approve_deposits": bool(CONFIG.get("auto_approve_deposits", True)),
                "info_api_cookie": CONFIG.get("info_api_cookie") or "",
            }})
        elif path == "/api/admin/manager":
            self._admin_guard()
            rows, upstream_error = manager_rows()
            self.send_json(200, {"ok": True, "rows": rows[:300],
                                 "upstream_error": upstream_error or ""})
        elif path == "/api/admin/upstream/status":
            self._admin_guard()
            self._upstream_passthrough("/status", None, "GET")
        elif path == "/api/admin/upstream/accounts":
            self._admin_guard()
            self._upstream_passthrough("/accounts", None, "GET")
        elif path == "/api/admin/upstream/targets":
            self._admin_guard()
            self._upstream_passthrough("/targets", None, "GET")
        elif path == "/api/admin/upstream/viplog":
            self._admin_guard()
            uid = str(self.query("uid", "")).strip()
            params = {"uid": uid} if uid else None
            self._upstream_passthrough("/viplog", params, "GET")
        else:
            raise ApiError("Not found.", 404)

    def _upstream_passthrough(self, endpoint, params, method):
        try:
            status, parsed, text = like_api(endpoint, params=params, method=method, timeout=30)
        except ApiError as err:
            self.send_json(200, {"ok": False, "error": err.message})
            return
        if status == 0:
            self.send_json(200, {"ok": False, "error": tr(text, 200)})
            return
        if status >= 400:
            self.send_json(200, {"ok": False,
                                 "error": "Upstream HTTP %s: %s" % (status, tr(text, 200))})
            return
        self.send_json(200, {"ok": True, "data": parsed, "text": tr(text, 2000)})

    # ------- admin POST -------
    def _admin_post(self):
        path = self._path
        if path == "/api/admin/login":
            self._admin_login()
        elif path == "/api/admin/logout":
            token, _sess = session_from_cookie(self, "fflike_admin")
            if token:
                end_session(token)
            body = json.dumps({"ok": True}).encode("utf-8")
            self._reply_with_cookie(body, [("Set-Cookie",
                                            "fflike_admin=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")])
        elif path == "/api/admin/settings":
            self._admin_guard()
            self._admin_settings_save()
        elif path == "/api/admin/like":
            self._admin_guard()
            data = self.read_json()
            uid = str(data.get("uid", "")).strip()
            if not UID_RE.match(uid):
                raise ApiError("Enter a valid Free Fire UID (5 to 12 digits).")
            parsed = like_send(uid)
            add_event("like", "Admin sent likes to %s" % uid, summarize_like(parsed))
            self.send_json(200, {"ok": True,
                                 "result": parsed if isinstance(parsed, dict) else {}})
        elif path == "/api/admin/autolike":
            self._admin_guard()
            data = self.read_json()
            uid = str(data.get("uid", "")).strip()
            if not UID_RE.match(uid):
                raise ApiError("Enter a valid Free Fire UID (5 to 12 digits).")
            try:
                days = int(data.get("days"))
            except Exception:
                raise ApiError("Days must be a number.")
            if days < 1 or days > 365:
                raise ApiError("Days must be between 1 and 365.")
            existing = find_active(uid, "autolike")
            if existing:
                raise ApiError("This UID already has an active Auto Like until %s."
                               % existing.get("expires"))
            ok, info = autolike_start(uid, days)
            if not ok:
                raise ApiError("Activation failed: %s" % info)
            detail, likes_per_day = info
            username = ""
            try:
                info_player = player_info(uid)
                pname = info_player["name"]
                region = info_player["region"]
            except ApiError:
                pname, region = "Unknown", "-"
            account = create_account(uid, pname, region, "autolike", days, 0.0,
                                     likes_per_day, "admin", None)
            with STATE_LOCK:
                save_state(STATE)
            add_event("admin", "Admin added Auto Like %s days for %s" % (days, uid), detail)
            self.send_json(200, {"ok": True, "account": public_account(account, masked=False),
                                 "detail": detail})
        elif path == "/api/admin/order/approve":
            self._admin_guard()
            data = self.read_json()
            order = self._find_order(data.get("no"))
            if order.get("status") not in ("pending", "failed"):
                raise ApiError("Only pending orders can be approved.")
            if activate_order(order):
                self.send_json(200, {"ok": True, "order": public_order(order, masked=False)})
            else:
                self.send_json(200, {"ok": False, "order": public_order(order, masked=False),
                                     "message": "Activation failed again. You can reject to refund."})
        elif path == "/api/admin/order/reject":
            self._admin_guard()
            data = self.read_json()
            order = self._find_order(data.get("no"))
            if order.get("status") not in ("pending", "failed"):
                raise ApiError("Only pending orders can be rejected.")
            order["status"] = "rejected"
            order["decided"] = now_iso()
            refunded = ""
            if order.get("price_paid") and order.get("user_no"):
                user = find_user_by_no(order.get("user_no"))
                if user is not None:
                    credit_user(user, order.get("price_paid"),
                                "refund of rejected order %s" % order["no"])
                    refunded = " (balance refunded: %.2f USD)" % money_round(order.get("price_paid"))
            add_event("admin", "Order %s rejected%s" % (order["no"], refunded))
            self.send_json(200, {"ok": True, "order": public_order(order, masked=False)})
        elif path == "/api/admin/order/delete":
            self._admin_guard()
            data = self.read_json()
            order = self._find_order(data.get("no"))
            with STATE_LOCK:
                STATE["orders"] = [o for o in STATE["orders"] if o.get("no") != order["no"]]
                save_state(STATE)
            add_event("admin", "Order %s deleted (no refund)" % order["no"])
            self.send_json(200, {"ok": True})
        elif path == "/api/admin/account/delete":
            self._admin_guard()
            data = self.read_json()
            no = str(data.get("no", "")).strip()
            with STATE_LOCK:
                before = len(STATE["accounts"])
                STATE["accounts"] = [a for a in STATE["accounts"] if a.get("no") != no]
                removed = before != len(STATE["accounts"])
                save_state(STATE)
            if not removed:
                raise ApiError("Account not found.")
            add_event("admin", "Account %s deleted from the site list" % no)
            self.send_json(200, {"ok": True})
        elif path == "/api/admin/user/credit":
            self._admin_guard()
            data = self.read_json()
            user = find_user_by_no(data.get("no")) or find_user_by_name(data.get("username"))
            if user is None:
                raise ApiError("User not found.")
            try:
                amount = money_round(data.get("amount"))
            except Exception:
                raise ApiError("Amount must be a number.")
            if amount == 0:
                raise ApiError("Amount cannot be zero.")
            credit_user(user, amount, "manual admin adjustment")
            self.send_json(200, {"ok": True, "user": public_user(user)})
        elif path == "/api/admin/user/delete":
            self._admin_guard()
            data = self.read_json()
            user = find_user_by_no(data.get("no"))
            if user is None:
                raise ApiError("User not found.")
            with STATE_LOCK:
                STATE["users"] = [u for u in STATE["users"] if u.get("no") != user.get("no")]
                save_state(STATE)
            add_event("admin", "User %s deleted" % user.get("username"))
            self.send_json(200, {"ok": True})
        elif path == "/api/admin/deposit/approve":
            self._admin_guard()
            data = self.read_json()
            dep = self._find_deposit(data.get("no"))
            if dep.get("status") != "pending":
                raise ApiError("Only pending deposits can be approved.")
            approve_deposit(dep, auto=False)
            with STATE_LOCK:
                save_state(STATE)
            self.send_json(200, {"ok": True, "deposit": public_deposit(dep)})
        elif path == "/api/admin/deposit/reject":
            self._admin_guard()
            data = self.read_json()
            dep = self._find_deposit(data.get("no"))
            if dep.get("status") != "pending":
                raise ApiError("Only pending deposits can be rejected.")
            dep["status"] = "rejected"
            dep["decided"] = now_iso()
            with STATE_LOCK:
                save_state(STATE)
            add_event("admin", "Deposit %s rejected (%s)" % (dep["no"], dep.get("username")))
            self.send_json(200, {"ok": True, "deposit": public_deposit(dep)})
        elif path == "/api/admin/deposit/delete":
            self._admin_guard()
            data = self.read_json()
            dep = self._find_deposit(data.get("no"))
            if dep.get("status") == "pending":
                raise ApiError("Pending deposits must be approved or rejected first.")
            with STATE_LOCK:
                STATE["deposits"] = [d for d in STATE["deposits"] if d.get("no") != dep["no"]]
                save_state(STATE)
            add_event("admin", "Deposit %s deleted" % dep["no"])
            self.send_json(200, {"ok": True})
        elif path == "/api/admin/coupon/create":
            self._admin_guard()
            data = self.read_json()
            coupon = create_coupon(data.get("code"), data.get("amount"), data.get("max_uses"))
            self.send_json(200, {"ok": True, "coupon": coupon})
        elif path == "/api/admin/coupon/delete":
            self._admin_guard()
            data = self.read_json()
            code = normalize_code(data.get("code"))
            with STATE_LOCK:
                before = len(STATE["coupons"])
                STATE["coupons"] = [c for c in STATE["coupons"] if c.get("code") != code]
                removed = before != len(STATE["coupons"])
                save_state(STATE)
            if not removed:
                raise ApiError("Coupon not found.")
            add_event("admin", "Coupon %s deleted" % code)
            self.send_json(200, {"ok": True})
        elif path == "/api/admin/promo/create":
            self._admin_guard()
            data = self.read_json()
            promo = create_promo(data.get("code"), data.get("percent"), data.get("max_uses"))
            self.send_json(200, {"ok": True, "promo": promo})
        elif path == "/api/admin/promo/delete":
            self._admin_guard()
            data = self.read_json()
            code = normalize_code(data.get("code"))
            with STATE_LOCK:
                before = len(STATE["promos"])
                STATE["promos"] = [p for p in STATE["promos"] if p.get("code") != code]
                removed = before != len(STATE["promos"])
                save_state(STATE)
            if not removed:
                raise ApiError("Promo not found.")
            add_event("admin", "Promo %s deleted" % code)
            self.send_json(200, {"ok": True})
        elif path == "/api/admin/upstream/refresh":
            self._admin_guard()
            status, parsed, text = like_api("/refresh", method="POST", timeout=90)
            add_event("upstream", "Token refresh done (HTTP %s)" % status, tr(text, 200))
            self.send_json(200, {"ok": 200 <= status < 400, "http_status": status,
                                 "data": parsed, "text": tr(text, 400)})
        elif path == "/api/admin/upstream/viplog/delete":
            self._admin_guard()
            uid = self._need_uid()
            status, parsed, text = like_api("/viplog/delete", params={"uid": uid}, method="POST")
            add_event("upstream", "VIP log deleted for %s (HTTP %s)" % (uid, status))
            self.send_json(200, {"ok": 200 <= status < 400, "http_status": status,
                                 "data": parsed, "text": tr(text, 300)})
        else:
            raise ApiError("Not found.", 404)

    def _find_order(self, no):
        no = str(no or "").strip()
        with STATE_LOCK:
            for order in STATE["orders"]:
                if order.get("no") == no:
                    return order
        raise ApiError("Order not found.")

    def _find_deposit(self, no):
        no = str(no or "").strip()
        with STATE_LOCK:
            for dep in STATE["deposits"]:
                if dep.get("no") == no:
                    return dep
        raise ApiError("Deposit not found.")

    def _admin_login(self):
        ip = self.client_ip()
        key = check_fails("adminlogin", ip)
        data = self.read_json()
        user = str(data.get("username", ""))
        password = str(data.get("password", ""))
        ok_user = hmac.compare_digest(user, str(CONFIG.get("admin_user") or ""))
        ok_pass = admin_password_matches(password)
        if not (ok_user and ok_pass):
            time.sleep(0.4)
            record_fail(key, True)
            raise ApiError("Wrong username or password.", 401)
        record_fail(key, False)
        token = start_session("admin")
        body = json.dumps({"ok": True, "user": CONFIG.get("admin_user")},
                          ensure_ascii=False).encode("utf-8")
        self._reply_with_cookie(body, [("Set-Cookie",
                                        "fflike_admin=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d"
                                        % (token, 86400))])
        add_event("login", "Admin logged in (%s)" % ip)

    def _admin_settings_save(self):
        data = self.read_json()
        updates = {}
        if "site_name" in data:
            updates["site_name"] = tr(data.get("site_name"), 40) or "FF LIKE"
        if "tagline" in data:
            updates["tagline"] = tr(data.get("tagline"), 140) or ""
        if "auto_approve_orders" in data:
            updates["auto_approve_orders"] = bool(data.get("auto_approve_orders"))
        if "auto_approve_deposits" in data:
            updates["auto_approve_deposits"] = bool(data.get("auto_approve_deposits"))
        if "info_api_cookie" in data:
            updates["info_api_cookie"] = tr(data.get("info_api_cookie"), 2000).strip()
        binance_updates = {}
        if "binance_pay_id" in data:
            binance_updates["pay_id"] = tr(data.get("binance_pay_id"), 48) or ""
        if "binance_note" in data:
            binance_updates["note"] = tr(data.get("binance_note"), 400) or ""
        if binance_updates:
            updates["binance"] = binance_updates
        new_password = str(data.get("admin_new_password") or "")
        if new_password:
            if len(new_password) < 6:
                raise ApiError("New admin password must be at least 6 characters.")
            salt, digest = hash_password(new_password)
            updates["admin_password_hash"] = "%s$%s" % (salt, digest)
        if not updates:
            raise ApiError("Nothing to update.")
        with CONFIG_LOCK:
            save_config_partial(updates)
            global CONFIG
            CONFIG = load_config()
        if new_password:
            add_event("admin", "Admin password changed")
        add_event("admin", "Settings updated: %s" % ", ".join(k for k in updates.keys()
                                                              if k != "admin_password_hash"))
        self.send_json(200, {"ok": True})

    def handle_one_request(self):
        try:
            BaseHTTPRequestHandler.handle_one_request(self)
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            self.close_connection = True


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------
def main():
    migrate_admin_password()
    os.makedirs(DATA_DIR, exist_ok=True)
    with STATE_LOCK:
        save_state(STATE)
    port = int(CONFIG.get("port") or 8080)
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.daemon_threads = True
    print("=" * 62)
    print("  FF LIKE  -  Free Fire like bot panel")
    print("=" * 62)
    print("  Web    : http://localhost:%d" % port)
    print("  Admin  : http://localhost:%d/admin  (not linked on the site)" % port)
    print("  User   : %s" % CONFIG.get("admin_user"))
    print("  Dep    : %s" % STATE_PATH)
    print("  Pillow : %s (generated profile card fallback)" % ("yes" if PIL_OK else "no"))
    print("  Card   : real profile-card API cookie %s"
          % ("set" if CONFIG.get("info_api_cookie") else "not set (generated fallback used)"))
    print("  Press Ctrl+C to stop.")
    print("=" * 62)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        try:
            server.server_close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
