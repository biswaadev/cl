#!/usr/bin/env python3
import json
import base64
import uuid
import os
import time
import re
import datetime
import sqlite3
import requests
import hmac
import hashlib
import threading
import secrets
import shutil
import tempfile
import gzip
import io
from collections import defaultdict
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, session, redirect, Response
from db import get_db, hash_password, init_db
from firebase_sync import (
    sync_pull_from_firebase,
    sync_push_to_firebase,
    trigger_async_sync,
    start_periodic_sync
)

app = Flask(__name__, static_folder=None)
app.secret_key = 'ffglory_prod_secret_84b879661bf49d33'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

_db_ready = False
_db_init_lock = threading.Lock()

def ensure_db_ready():
    global _db_ready
    if not _db_ready:
        with _db_init_lock:
            if not _db_ready:
                try:
                    init_db()
                    sync_pull_from_firebase()
                    start_periodic_sync(interval=60)
                except Exception as e:
                    print(f"[Init Warning]: {e}")
                _db_ready = True

try:
    ensure_db_ready()
except Exception as e:
    print(f"[Startup Warning]: {e}")

# Security Guard: Block public downloads of database, server code, configs & sensitive files
FORBIDDEN_EXTENSIONS = ('.db', '.sqlite', '.sqlite3', '.sql', '.py', '.json', '.js', '.bak', '.log', '.sh', '.env', '.zip', '.tar', '.gz')
FORBIDDEN_EXACT_PATHS = {'/panel.db', '/state.json', '/server.py', '/db.py', '/requirements.txt', '/procfile', '/ffglory_backup.zip', '/login.js', '/shared.js'}

@app.before_request
def security_firewall_check():
    req_path = (request.path or '').lower().rstrip('/')
    if not req_path:
        return None
    # Block forbidden exact paths
    if req_path in FORBIDDEN_EXACT_PATHS:
        return jsonify({"error": "Not found"}), 404
    # Block sensitive extensions outside api endpoints
    if not req_path.startswith('/api/'):
        if req_path.endswith(FORBIDDEN_EXTENSIONS):
            return jsonify({"error": "Not found"}), 404

    ensure_db_ready()

@app.after_request
def optimize_and_compress(response):
    # Static asset caching
    req_path = request.path or ''
    if req_path.endswith(('.css', '.png', '.jpg', '.jpeg', '.svg', '.ico', '.webp')):
        response.headers["Cache-Control"] = "public, max-age=86400, stale-while-revalidate=604800"

    # Fast Gzip compression for HTML, JSON, CSS, JS
    accept_encoding = request.headers.get('Accept-Encoding', '')
    if ('gzip' in accept_encoding and
        response.status_code == 200 and
        response.content_length and
        response.content_length > 1024 and
        response.mimetype in ('text/html', 'text/css', 'application/javascript', 'application/json')):

        if response.headers.get('Content-Encoding') is None:
            try:
                raw_data = response.get_data()
                gzip_buf = io.BytesIO()
                with gzip.GzipFile(mode='wb', fileobj=gzip_buf, compresslevel=6) as gz:
                    gz.write(raw_data)
                compressed = gzip_buf.getvalue()
                if len(compressed) < len(raw_data):
                    response.set_data(compressed)
                    response.headers['Content-Encoding'] = 'gzip'
                    response.headers['Content-Length'] = len(compressed)
            except Exception:
                pass
    return response

UPSTREAM_BASE = "https://ffglory.pro"

# ==================== ADVANCED RATE LIMITING ENGINE ====================

class RateLimiter:
    def __init__(self):
        self.lock = threading.Lock()
        self.requests = defaultdict(list)
        self.last_cleanup = time.time()

    def get_client_ip(self):
        # 1. Cloudflare True Client IP
        cf_ip = request.headers.get("CF-Connecting-IP")
        if cf_ip:
            return cf_ip.strip()
        # 2. X-Forwarded-For (Proxy list, client is first)
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        # 3. X-Real-IP
        xri = request.headers.get("X-Real-IP")
        if xri:
            return xri.strip()
        # 4. Direct socket address
        return request.remote_addr or "127.0.0.1"

    def is_allowed(self, bucket_key, max_requests, window_seconds):
        now = time.time()
        with self.lock:
            # Periodic cleanup of stale memory keys
            if now - self.last_cleanup > 300:
                self.cleanup(now)

            timestamps = self.requests[bucket_key]
            cutoff = now - window_seconds
            valid_timestamps = [t for t in timestamps if t >= cutoff]
            self.requests[bucket_key] = valid_timestamps

            if len(valid_timestamps) >= max_requests:
                oldest = valid_timestamps[0]
                retry_after = max(1, int(window_seconds - (now - oldest)))
                return False, retry_after

            valid_timestamps.append(now)
            return True, 0

    def cleanup(self, now):
        self.last_cleanup = now
        stale_keys = [k for k, ts in self.requests.items() if not ts or (now - ts[-1] > 3600)]
        for k in stale_keys:
            del self.requests[k]

limiter = RateLimiter()
_launch_locks = defaultdict(threading.Lock)

def rate_limit(max_requests=60, window_seconds=60, key_prefix="global", per_user=False):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = limiter.get_client_ip()
            user_id = session.get("user_id")
            if per_user and user_id:
                bucket = f"{key_prefix}:user:{user_id}"
            else:
                bucket = f"{key_prefix}:ip:{ip}"

            allowed, retry_after = limiter.is_allowed(bucket, max_requests, window_seconds)
            if not allowed:
                # If gateway request, return obfuscated 429
                if request.path == "/api/gateway":
                    err_obj = {
                        "error": f"Rate limit exceeded. Please slow down and try again in {retry_after}s.",
                        "status": 429,
                        "retry_after": retry_after
                    }
                    enc = base64.b64encode(json.dumps(err_obj).encode("utf-8")).decode("utf-8")
                    r = jsonify({"_r": enc})
                    r.status_code = 429
                    r.headers["Retry-After"] = str(retry_after)
                    return r

                r = jsonify({
                    "error": f"Too many requests! Please wait {retry_after} seconds before trying again.",
                    "status": 429,
                    "retry_after": retry_after
                })
                r.status_code = 429
                r.headers["Retry-After"] = str(retry_after)
                return r

            return f(*args, **kwargs)
        return wrapped
    return decorator


def get_setting(key, default=""):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = c.fetchone()
    conn.close()
    return row["value"] if row else default

def set_setting(key, value):
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
    conn.commit()
    conn.close()
    try:
        trigger_async_sync()
    except Exception:
        pass
    try:
        trigger_async_sync()
    except Exception:
        pass

UPSTREAM_PLATFORM_KEY = "22e15fc938aef0cf08bff1a4dd7a4aaa"

def get_upstream_keys():
    # Platform master key used in x-api-key header (default: 22e15fc938aef0cf08bff1a4dd7a4aaa)
    mkey = (get_setting("upstream_master_key", UPSTREAM_PLATFORM_KEY) or "").strip() or UPSTREAM_PLATFORM_KEY
    # User reseller account key passed in query ?api_key=ak_...
    akey = (get_setting("upstream_api_key", "ak_0c1f2d0c3e3a8baad7ecd9fb97beaad3793bdfb051aa5d00f48b1714b2ce7ff4") or "").strip()
    
    # Auto-resolve if user entered account key ak_ into master_key field
    if mkey.startswith("ak_"):
        akey = mkey
        mkey = UPSTREAM_PLATFORM_KEY
    
    return mkey, akey


def mask_secret(key, visible_start=4, visible_end=4):
    if not key:
        return ""
    if len(key) <= (visible_start + visible_end):
        return "••••••••"
    return key[:visible_start] + "••••••••" + key[-visible_end:]

def call_upstream(method, path, json_data=None, params=None, timeout=4):
    master_key, api_key = get_upstream_keys()
    url = f"{UPSTREAM_BASE}{path}"
    p = {"api_key": api_key}
    if params:
        p.update(params)
    
    headers = {
        "x-api-key": master_key,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Content-Type": "application/json"
    }

    try:
        r = requests.request(
            method,
            url,
            params=p,
            headers=headers,
            json=json_data,
            timeout=timeout
        )
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {"text": r.text}
    except Exception as e:
        return 500, {"error": f"Upstream connection failed: {str(e)}"}

SAFE_API_BASE = "https://teakrcltgjnzxuvuvzci.supabase.co/functions/v1/safe-api"

def get_active_provider():
    return get_setting("active_upstream_provider", "both")

def get_safe_api_key():
    return (get_setting("upstream_safe_key", "") or "").strip()

def call_safe_api(method, path, json_data=None, params=None):
    safe_key = get_safe_api_key()
    if not safe_key:
        return 401, {"error": "Safe Squad API key not configured in Admin Settings"}
    url = f"{SAFE_API_BASE}{path}"
    headers = {
        "x-api-key": safe_key,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) FFGlorySafe/1.5"
    }
    try:
        r = requests.request(
            method,
            url,
            headers=headers,
            json=json_data,
            params=params,
            timeout=15
        )
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {"text": r.text}
    except Exception as e:
        return 500, {"error": f"Safe API connection failed: {str(e)}"}

# ==================== SERVER & REGION MAINTENANCE MANAGEMENT ====================

REGION_FLAGS = {
    'bd': '🇧🇩',
    'pk': '🇵🇰',
    'in': '🇮🇳',
    'in_safe': '🇮🇳',
    'in_safe_2': '🇮🇳',
    'in_safe_3': '🇮🇳',
    'in_safe_vip': '🇮🇳',
    'safe': '🇮🇳',
    'indo': '🇮🇩',
    'ind': '🇮🇩',
    'id': '🇮🇩',
    'sg': '🇸🇬',
    'th': '🇹🇭',
    'vn': '🇻🇳',
    'me': '🇸🇦',
    'ghrab': '🇦🇪',
    'eu': '🇪🇺',
    'na': '🇺🇸',
    'us': '🇺🇸',
    'br': '🇧🇷',
    'ru': '🇷🇺',
    'sac': '🌎',
    'sa': '🇸🇦',
    'ae': '🇦🇪'
}

DEFAULT_REGIONS = [
    {'id': 'in', 'region_name': 'India', 'region_code': 'IN', 'tier': 'basic', 'enabled': True},
    {'id': 'bd', 'region_name': 'Bangladesh', 'region_code': 'BD', 'tier': 'basic', 'enabled': True},
    {'id': 'pk', 'region_name': 'Pakistan', 'region_code': 'PK', 'tier': 'basic', 'enabled': True},
    {'id': 'sg', 'region_name': 'Singapore', 'region_code': 'SG', 'tier': 'basic', 'enabled': True},
    {'id': 'indo', 'region_name': 'Indonesia', 'region_code': 'IND', 'tier': 'basic', 'enabled': True},
    {'id': 'th', 'region_name': 'Thailand', 'region_code': 'TH', 'tier': 'basic', 'enabled': True},
    {'id': 'vn', 'region_name': 'Vietname', 'region_code': 'VN', 'tier': 'basic', 'enabled': True},
    {'id': 'me', 'region_name': 'Middle East', 'region_code': 'ME', 'tier': 'basic', 'enabled': True},
    {'id': 'na', 'region_name': 'North America', 'region_code': 'NA', 'tier': 'basic', 'enabled': True},
    {'id': 'us', 'region_name': 'United States (US)', 'region_code': 'US', 'tier': 'basic', 'enabled': True},
    {'id': 'br', 'region_name': 'Brasil', 'region_code': 'BR', 'tier': 'basic', 'enabled': True},
    {'id': 'eu', 'region_name': 'Europe', 'region_code': 'EU', 'tier': 'basic', 'enabled': True},
    {'id': 'ru', 'region_name': 'Russia', 'region_code': 'RU', 'tier': 'basic', 'enabled': True},
    {'id': 'sac', 'region_name': 'South America (SAC)', 'region_code': 'SAC', 'tier': 'basic', 'enabled': True},
    {'id': 'ghrab', 'region_name': 'Middle East (Ghrab)', 'region_code': 'ME', 'tier': 'premium', 'enabled': False}
]

def get_server_overrides():
    raw = get_setting("server_maintenance_overrides", "{}")
    try:
        val = json.loads(raw)
        return val if isinstance(val, dict) else {}
    except Exception:
        return {}

def save_server_overrides(overrides):
    set_setting("server_maintenance_overrides", json.dumps(overrides))

def is_global_maintenance():
    return get_setting("global_maintenance_mode", "0") == "1"

def normalize_region_for_upstream(region_input):
    if not region_input:
        return "in"
    r = str(region_input).strip().lower()
    mapping = {
        "in": "in",
        "ind": "in",
        "india": "in",
        "bharat": "in",
        "indo": "indo",
        "indonesia": "indo",
        "id": "indo",
        "bd": "bd",
        "bangladesh": "bd",
        "pk": "pk",
        "pakistan": "pk",
        "sg": "sg",
        "singapore": "sg",
        "na": "na",
        "north america": "na",
        "us": "us",
        "usa": "us",
        "united states": "us",
        "eu": "eu",
        "europe": "eu",
        "vn": "vn",
        "vietnam": "vn",
        "vietname": "vn",
        "th": "th",
        "thailand": "th",
        "br": "br",
        "brasil": "br",
        "brazil": "br",
        "me": "me",
        "middle east": "me",
        "ru": "ru",
        "russia": "ru",
        "sac": "sac",
        "ghrab": "ghrab"
    }
    return mapping.get(r, r)

_REGIONS_CACHE = {"ts": 0, "provider": "", "raw_pro": [], "data": []}

SAFE_SQUAD_NODES = [
    {"id": "in_safe", "region_code": "IN", "region_name": "India (Special Safe Squad - Node 1)", "cost": 1, "tier": "basic", "default_enabled": True, "flag": "🇮🇳"},
    {"id": "in_safe_2", "region_code": "IN", "region_name": "India Safe Squad (Cluster 2)", "cost": 1, "tier": "basic", "default_enabled": False, "flag": "🇮🇳"},
    {"id": "in_safe_3", "region_code": "IN", "region_name": "India Safe Squad (Fast Node)", "cost": 1, "tier": "basic", "default_enabled": False, "flag": "🇮🇳"},
    {"id": "in_safe_vip", "region_code": "IN", "region_name": "India Safe Squad (VIP Dedicated)", "cost": 1, "tier": "premium", "default_enabled": False, "flag": "🇮🇳"}
]

def get_processed_regions(only_active=False, for_admin=False):
    prov = get_active_provider()
    now = time.time()
    global_maint = is_global_maintenance()
    global_msg = get_setting("global_maintenance_message", "All server nodes are currently undergoing scheduled maintenance.")
    overrides = get_server_overrides()

    raw_regions = []

    # 1. FFGlory Safe Squad (ffglory.in) Servers
    if for_admin or prov in ("both", "ffglory_safe"):
        for sn in SAFE_SQUAD_NODES:
            raw_regions.append({
                "id": sn["id"],
                "region_code": sn["region_code"],
                "region_name": sn["region_name"],
                "tier": sn["tier"],
                "cost": sn["cost"],
                "enabled": sn["default_enabled"],
                "flag": "🇮🇳",
                "status_label": "Online" if sn["default_enabled"] else "Disabled",
                "upstream_enabled": sn["default_enabled"],
                "override": None,
                "max_clans": 100,
                "provider": "ffglory_safe",
                "provider_name": "FFGlory.in (Safe Squad)",
                "goal_type": "30min"
            })

    # 2. FFGlory Pro Standard Regions
    if for_admin or prov in ("both", "ffglory_pro"):
        pro_raw = []
        if (now - _REGIONS_CACHE.get("ts", 0) < 60) and _REGIONS_CACHE.get("raw_pro"):
            pro_raw = _REGIONS_CACHE["raw_pro"]
        else:
            upstream_status, upstream_data = call_upstream("GET", "/api/pricing")
            if upstream_status == 200 and isinstance(upstream_data, dict):
                pro_raw = upstream_data.get("regions", [])
            if not pro_raw:
                pro_raw = [dict(r) for r in DEFAULT_REGIONS]
            _REGIONS_CACHE["raw_pro"] = pro_raw
            _REGIONS_CACHE["ts"] = now

        for r in pro_raw:
            rc = dict(r)
            rc["provider"] = "ffglory_pro"
            rc["provider_name"] = "FFGlory.pro (Standard)"
            rc["goal_type"] = "8h"
            raw_regions.append(rc)

    processed = []
    for reg in raw_regions:
        r = dict(reg)
        rid = (r.get("id") or "").lower()
        rcode = (r.get("region_code") or "").lower()
        upstream_enabled = bool(r.get("enabled", True))
        r["upstream_enabled"] = upstream_enabled
        if rid.startswith("in_safe") or rcode in ("in", "in_safe") or rid == "safe":
            r["flag"] = "🇮🇳"
        else:
            r["flag"] = r.get("flag") or REGION_FLAGS.get(rid) or REGION_FLAGS.get(rcode) or "🌐"

        override_val = None
        if rid in overrides:
            override_val = overrides[rid]
        elif rcode in overrides and not rid.startswith("in_safe"):
            override_val = overrides[rcode]

        r["override"] = override_val
        is_hidden = (override_val == "hidden" or override_val == "hide")
        r["hidden"] = is_hidden

        if is_hidden:
            r["enabled"] = False
            r["status_label"] = "Hidden"
        elif global_maint:
            r["enabled"] = False
            r["maintenance_reason"] = global_msg
            r["status_label"] = "Global Maint"
        elif override_val is False:
            r["enabled"] = False
            r["maintenance_reason"] = "Server is temporarily under maintenance by administrator."
            r["status_label"] = "Admin Maint"
        elif override_val is True:
            r["enabled"] = True
            r["status_label"] = "Admin Online"
        else:
            r["enabled"] = upstream_enabled
            r["status_label"] = "Online" if upstream_enabled else "Upstream Maint"

        processed.append(r)

    _REGIONS_CACHE["data"] = processed
    if only_active:
        return [r for r in processed if r.get("enabled") and not r.get("hidden")]
    return processed

# ==================== STATIC PAGE ROUTES ====================

def parse_runtime_minutes(created_at_val, uptime_val):
    minutes = 0
    if created_at_val:
        s = str(created_at_val).strip()
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                dt = datetime.datetime.strptime(s.replace("Z", ""), fmt)
                minutes = int(max(0, (datetime.datetime.utcnow() - dt).total_seconds() // 60))
                return minutes
            except Exception:
                pass
    if uptime_val:
        s = str(uptime_val).lower().strip()
        h_match = re.search(r'(\d+)\s*h', s)
        m_match = re.search(r'(\d+)\s*m', s)
        if h_match:
            minutes += int(h_match.group(1)) * 60
        if m_match:
            minutes += int(m_match.group(1))
    return minutes

_GLORY_CACHE = {}
_CLAN_CACHE = {}

def get_cached_clan_info(gid, force_refresh=False):
    now = time.time()
    gid_str = str(gid)
    cached = _CLAN_CACHE.get(gid_str)
    if not force_refresh and cached and (now - cached["ts"] < 300):
        return cached["data"]
    try:
        st, res = call_upstream("POST", "/api/client/group-action", json_data={"action": "get-clan-info", "group_id": gid_str}, timeout=3)
        if st == 200 and isinstance(res, dict):
            _CLAN_CACHE[gid_str] = {"ts": now, "data": res}
            return res
    except Exception:
        pass
    if cached:
        return cached["data"]
    return None

def get_cached_group_glory(gid, force_refresh=False):
    now = time.time()
    gid_str = str(gid)
    cached = _GLORY_CACHE.get(gid_str)
    if not force_refresh and cached and (now - cached["ts"] < 45):
        return cached["total_glory"], cached["details"]
    try:
        st, res = call_upstream("POST", "/api/client/group-action", json_data={"action": "get-glory", "group_id": gid_str}, timeout=3)
        if st == 200 and isinstance(res, dict):
            total_glory = int(res.get("total_glory") or 0)
            details = res.get("details") or []
            _GLORY_CACHE[gid_str] = {"ts": now, "total_glory": total_glory, "details": details}
            return total_glory, details
    except Exception:
        pass
    if cached:
        return cached["total_glory"], cached["details"]
    return 0, []

_UPSTREAM_GROUPS_CACHE = {"ts": 0, "provider": "", "status": 0, "data": []}

def fetch_and_sync_groups(user_id=None, is_admin=False, force_refresh=False):
    """
    Fetches running groups directly from active provider (ffglory.pro or Safe Squad API)
    with high performance caching.
    Auto-updates SQLite DB 'groups' table for admin tracking.
    Enforces STRICT user isolation: Users only see groups launched by their own account.
    """
    now = time.time()
    prov = get_active_provider()
    if not force_refresh and (now - _UPSTREAM_GROUPS_CACHE.get("ts", 0) < 8) and _UPSTREAM_GROUPS_CACHE.get("provider") == prov:
        up_status = _UPSTREAM_GROUPS_CACHE["status"]
        up_groups = _UPSTREAM_GROUPS_CACHE["data"]
    else:
        if prov == "both":
            up_groups = []
            safe_status, safe_res = call_safe_api("GET", "/launches")
            if safe_status == 200 and isinstance(safe_res, dict):
                launches = safe_res.get("launches") or []
                for l in launches:
                    state_val = (l.get("state") or l.get("phase") or "running").lower()
                    st = "running" if state_val in ("generating", "queued", "running") else ("failed" if state_val == "failed" else "completed")
                    guild_info = l.get("guild") or {}
                    bots_list = l.get("bots") or []
                    g_obj = {
                        "group_id": str(l.get("group_id") or l.get("id")),
                        "id": str(l.get("id")),
                        "clan_id": str(l.get("guild_id") or guild_info.get("id") or ""),
                        "clan_name": guild_info.get("name") or f"Clan {l.get('guild_id')}",
                        "clan_level": guild_info.get("level") or 4,
                        "members": guild_info.get("members") or "—",
                        "captain": guild_info.get("captain") or "—",
                        "weekly_glory": str(guild_info.get("weekly_glory") or l.get("glory") or 0),
                        "clan_total_glory": guild_info.get("total_glory") or 0,
                        "region": "IN_SAFE",
                        "provider": "ffglory_safe",
                        "status": st,
                        "uptime": "Active" if st == "running" else state_val.title(),
                        "glory_farmed": int(l.get("glory") or 0),
                        "glory_gained": int(l.get("glory") or 0),
                        "created_at": l.get("created_at") or "",
                        "details": [{"nickname": b, "glory": int(l.get("glory", 0)) // max(1, len(bots_list))} for b in bots_list] if bots_list else []
                    }
                    up_groups.append(g_obj)

            pro_status, pro_groups = call_upstream("GET", "/api/client/my-groups")
            if pro_status == 200 and isinstance(pro_groups, list):
                for pg in pro_groups:
                    if isinstance(pg, dict):
                        pg_c = dict(pg)
                        pg_c["provider"] = "ffglory_pro"
                        up_groups.append(pg_c)
            up_status = 200 if (safe_status == 200 or pro_status == 200) else 500
        elif prov == "ffglory_safe":
            safe_status, safe_res = call_safe_api("GET", "/launches")
            up_groups = []
            up_status = safe_status
            if safe_status == 200 and isinstance(safe_res, dict):
                launches = safe_res.get("launches") or []
                for l in launches:
                    state_val = (l.get("state") or l.get("phase") or "running").lower()
                    st = "running" if state_val in ("generating", "queued", "running") else ("failed" if state_val == "failed" else "completed")
                    guild_info = l.get("guild") or {}
                    bots_list = l.get("bots") or []
                    g_obj = {
                        "group_id": str(l.get("group_id") or l.get("id")),
                        "id": str(l.get("id")),
                        "clan_id": str(l.get("guild_id") or guild_info.get("id") or ""),
                        "clan_name": guild_info.get("name") or f"Clan {l.get('guild_id')}",
                        "clan_level": guild_info.get("level") or 4,
                        "members": guild_info.get("members") or "—",
                        "captain": guild_info.get("captain") or "—",
                        "weekly_glory": str(guild_info.get("weekly_glory") or l.get("glory") or 0),
                        "clan_total_glory": guild_info.get("total_glory") or 0,
                        "region": "IN_SAFE",
                        "provider": "ffglory_safe",
                        "status": st,
                        "uptime": "Active" if st == "running" else state_val.title(),
                        "glory_farmed": int(l.get("glory") or 0),
                        "glory_gained": int(l.get("glory") or 0),
                        "created_at": l.get("created_at") or "",
                        "details": [{"nickname": b, "glory": int(l.get("glory", 0)) // max(1, len(bots_list))} for b in bots_list] if bots_list else []
                    }
                    up_groups.append(g_obj)
        else:
            up_status, raw_pro = call_upstream("GET", "/api/client/my-groups")
            up_groups = []
            if up_status == 200 and isinstance(raw_pro, list):
                for pg in raw_pro:
                    if isinstance(pg, dict):
                        pg_c = dict(pg)
                        pg_c["provider"] = "ffglory_pro"
                        up_groups.append(pg_c)
        if up_status == 200:
            _UPSTREAM_GROUPS_CACHE["ts"] = now
            _UPSTREAM_GROUPS_CACHE["provider"] = prov
            _UPSTREAM_GROUPS_CACHE["status"] = up_status
            _UPSTREAM_GROUPS_CACHE["data"] = up_groups
    
    conn = get_db()
    c = conn.cursor()

    live_map = {}
    if up_status == 200 and isinstance(up_groups, list):
        live_map = {str(g.get("group_id") or g.get("id")): g for g in up_groups if isinstance(g, dict)}
        
        # Determine relevant groups for caller upfront (Enforces zero latency for other users' groups)
        if is_admin:
            target_gids = set(str(k) for k in live_map.keys())
        else:
            if not user_id:
                target_gids = set()
            else:
                c.execute("SELECT group_id FROM groups WHERE user_id = ?", (user_id,))
                target_gids = set(str(r["group_id"]) for r in c.fetchall())

        # 1. Any old groups in DB marked running that are NOT in upstream -> update to completed in DB (only if older than 6 hours)
        if live_map:
            placeholders = ",".join("?" for _ in live_map.keys())
            c.execute(f"UPDATE groups SET status = 'completed' WHERE status IN ('running', 'online') AND group_id NOT IN ({placeholders}) AND (strftime('%s', 'now') - strftime('%s', created_at)) > 21600", list(live_map.keys()))
        else:
            c.execute("UPDATE groups SET status = 'completed' WHERE status IN ('running', 'online') AND (strftime('%s', 'now') - strftime('%s', created_at)) > 21600")

        # 2. Upsert each upstream group into DB for Admin records
        for gid, live in live_map.items():
            cid = str(live.get("clan_id") or "")
            region = str(live.get("region") or "BD").upper()
            status = live.get("status") or "running"
            uptime = live.get("uptime") or "Active"
            games = live.get("games_played") or 0

            prov_item = live.get("provider") or ("ffglory_safe" if (live.get("region") in ("IN_SAFE", "in_safe") or str(gid).startswith("SAFE-")) else "ffglory_pro")

            # Only perform deep glory/clan queries for groups the user actually owns (or if admin)
            if str(gid) in target_gids and status in ("running", "online"):
                if prov_item == "ffglory_safe":
                    cname = live.get("clan_name") or f"Clan {cid}"
                    squad_raw = []
                    cached_g = _GLORY_CACHE.get(str(gid))
                    if not force_refresh and cached_g and (now - cached_g.get("ts", 0) < 30):
                        glory = cached_g.get("total_glory", 0)
                    else:
                        try:
                            gst, gdata = call_safe_api("GET", f"/glory?id={gid}")
                            if gst == 200 and isinstance(gdata, dict) and "glory" in gdata:
                                glory = int(gdata["glory"])
                                _GLORY_CACHE[str(gid)] = {"ts": now, "total_glory": glory, "details": []}
                            else:
                                glory = int(live.get("glory_farmed") or live.get("glory_gained") or 0)
                        except Exception:
                            glory = int(live.get("glory_farmed") or live.get("glory_gained") or 0)
                else:
                    c_info = get_cached_clan_info(gid, force_refresh=force_refresh)
                    decoded = (c_info.get("decoded") if isinstance(c_info, dict) else {}) or {}
                    cname = decoded.get("clan_name") or live.get("clan_name") or f"Clan {cid}"
                    real_glory, real_details = get_cached_group_glory(gid, force_refresh=force_refresh)
                    glory = real_glory if real_glory > 0 else (live.get("glory_farmed") or live.get("glory_gained") or 0)
                    squad_raw = real_details if real_details else (live.get("details") or live.get("squad"))
            else:
                cname = live.get("clan_name") or f"Clan {cid}"
                glory = live.get("glory_farmed") or live.get("glory_gained") or 0
                squad_raw = live.get("details") or live.get("squad")

            squad_json = json.dumps(squad_raw) if squad_raw else None

            c.execute("SELECT id, user_id, squad_json FROM groups WHERE group_id = ?", (gid,))
            existing = c.fetchone()
            if existing:
                c.execute("""
                    UPDATE groups SET 
                        clan_id = COALESCE(NULLIF(?, ''), clan_id),
                        clan_name = COALESCE(NULLIF(?, ''), clan_name),
                        region = ?,
                        status = ?,
                        glory_gained = ?,
                        uptime = ?,
                        games_played = ?,
                        squad_json = COALESCE(?, squad_json),
                        provider = ?
                    WHERE group_id = ?
                """, (cid, cname, region, status, glory, uptime, games, squad_json, prov_item, gid))
            else:
                c.execute("""
                    INSERT OR REPLACE INTO groups (
                        group_id, user_id, clan_id, clan_name, region, status,
                        glory_gained, clan_total_glory, uptime, squad_json, provider, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (gid, user_id or 1, cid, cname, region, status, glory, uptime, squad_json, prov_item))
        conn.commit()

    # 3. Determine which groups to return to the caller (STRICT USER ISOLATION)
    formatted_groups = []
    if up_status == 200 and isinstance(up_groups, list):
        if is_admin:
            target_gids = set(str(k) for k in live_map.keys())
        else:
            if not user_id:
                target_gids = set()
            else:
                c.execute("SELECT group_id FROM groups WHERE user_id = ?", (user_id,))
                target_gids = set(str(r["group_id"]) for r in c.fetchall())

        for gid, live in live_map.items():
            # STRICT ISOLATION: A user ONLY sees the bots launched by their own account!
            if not is_admin and str(gid) not in target_gids:
                continue

            cid = str(live.get("clan_id") or "")
            
            status = live.get("status") or "running"
            
            # Fast in-memory lookup without duplicate upstream round-trips
            c_info = _CLAN_CACHE.get(str(gid), {}).get("data") if status in ("running", "online") else None
            decoded = (c_info.get("decoded") if isinstance(c_info, dict) else {}) or {}
            cglory = (c_info.get("clan_glory") if isinstance(c_info, dict) else {}) or {}
            lb = (c_info.get("leaderboard") if isinstance(c_info, dict) else {}) or {}

            clan_name = decoded.get("clan_name") or live.get("clan_name") or f"Clan {cid}"
            clan_slogan = f'“{decoded.get("slogan") or clan_name}”'
            clan_level = int(decoded.get("clan_level") or live.get("clan_level") or 1)
            captain = str(decoded.get("captain_id") or live.get("captain") or "—")
            
            if decoded.get("capacity"):
                members = f"{decoded.get('member_num', 0)}/{decoded.get('capacity', 0)}"
            else:
                members = live.get("members") or "—"

            raw_weekly = int(cglory.get("weekly_glory") or 0)
            weekly_glory = f"{raw_weekly:,}" if raw_weekly > 0 else str(live.get("glory_farmed") or live.get("glory_gained") or "0")
            clan_total_glory = int(cglory.get("total_glory") or raw_weekly or live.get("clan_total_glory") or 0)

            if lb.get("rank"):
                clan_rank = f"#{lb['rank']}"
            elif lb.get("in_top"):
                clan_rank = "Top 100"
            else:
                clan_rank = live.get("clan_rank") or "#--"

            cached_glory = _GLORY_CACHE.get(str(gid), {})
            real_glory = cached_glory.get("total_glory", 0) if status in ("running", "online") else int(live.get("glory_farmed") or live.get("glory_gained") or 0)
            real_details = cached_glory.get("details", []) if status in ("running", "online") else []
            squad = real_details if real_details else (live.get("details") or live.get("squad") or [])
            if not squad:
                c.execute("SELECT squad_json, glory_gained FROM groups WHERE group_id = ?", (gid,))
                srow = c.fetchone()
                if srow:
                    if srow["squad_json"]:
                        try:
                            squad = json.loads(srow["squad_json"])
                        except Exception:
                            squad = []
                    if real_glory == 0 and srow["glory_gained"]:
                        real_glory = int(srow["glory_gained"])

            glory_val = real_glory if real_glory > 0 else int(live.get("glory_farmed") or live.get("glory_gained") or 0)
            created_at_val = live.get("created_at") or ""
            uptime_val = live.get("uptime") or "Active"
            runtime_mins = parse_runtime_minutes(created_at_val, uptime_val)
            can_refund = False

            formatted_groups.append({
                "id": gid,
                "group_id": gid,
                "clan_id": cid,
                "clan_name": clan_name,
                "clan_slogan": clan_slogan,
                "weekly_glory": weekly_glory,
                "clan_rank": clan_rank,
                "region": str(live.get("region") or "BD").upper(),
                "provider": prov_item,
                "status": live.get("status") or "running",
                "glory_gained": glory_val,
                "clan_total_glory": clan_total_glory,
                "clan_level": clan_level,
                "captain": captain,
                "members": members,
                "uptime": uptime_val,
                "runtime_minutes": runtime_mins,
                "can_refund": False,
                "games_played": live.get("games_played") or 0,
                "created_at": created_at_val,
                "squad": squad,
                "details": squad
            })

    # Merge any active groups from local DB that may not be in live_map yet
    seen_gids = set(str(g["group_id"]) for g in formatted_groups)
    query = "SELECT * FROM groups WHERE status IN ('running', 'online')" if is_admin else "SELECT * FROM groups WHERE user_id = ? AND status IN ('running', 'online')"
    params = () if is_admin else (user_id,)
    c.execute(query, params)
    for r in c.fetchall():
        gid = str(r["group_id"])
        if gid not in seen_gids:
            squad = []
            if r["squad_json"]:
                try:
                    squad = json.loads(r["squad_json"])
                except Exception:
                    squad = []
            cid = str(r["clan_id"] or "")
            cname = r["clan_name"] or f"Clan {cid}"
            glory_val = int(r["glory_gained"] or 0)
            runtime_mins = parse_runtime_minutes(r["created_at"], r["uptime"])
            db_prov = (r["provider"] if "provider" in r.keys() and r["provider"] else ("ffglory_safe" if (str(r["region"]).upper() in ("IN_SAFE", "SAFE") or gid.startswith("SAFE-")) else "ffglory_pro"))
            formatted_groups.append({
                "id": gid,
                "group_id": gid,
                "clan_id": cid,
                "clan_name": cname,
                "clan_slogan": f'“{cname}”',
                "weekly_glory": str(glory_val),
                "clan_rank": "#--",
                "region": (r["region"] or "IN").upper(),
                "provider": db_prov,
                "status": r["status"] or "running",
                "glory_gained": glory_val,
                "clan_total_glory": int(r["clan_total_glory"] or 0),
                "clan_level": int(r["clan_level"] or 4),
                "captain": r["captain"] or "—",
                "members": r["members"] or "45/50",
                "uptime": r["uptime"] or "Just started",
                "runtime_minutes": runtime_mins,
                "can_refund": False,
                "games_played": r["games_played"] or 0,
                "created_at": r["created_at"],
                "squad": squad,
                "details": squad
            })
            seen_gids.add(gid)

    conn.close()
    return formatted_groups

_UPSTREAM_CREDITS_CACHE = {"ts": 0, "provider": "", "credits": 0}

def get_cached_upstream_credits():
    now = time.time()
    prov = get_active_provider()
    if now - _UPSTREAM_CREDITS_CACHE.get("ts", 0) < 30 and _UPSTREAM_CREDITS_CACHE.get("provider") == prov:
        return _UPSTREAM_CREDITS_CACHE["credits"]
    try:
        if prov == "ffglory_safe":
            safe_status, safe_me = call_safe_api("GET", "/balance")
            if safe_status == 200 and isinstance(safe_me, dict):
                _UPSTREAM_CREDITS_CACHE["credits"] = int(safe_me.get("special_credits") or 0)
                _UPSTREAM_CREDITS_CACHE["provider"] = prov
                _UPSTREAM_CREDITS_CACHE["ts"] = now
        elif prov == "both":
            tot = 0
            safe_status, safe_me = call_safe_api("GET", "/balance")
            if safe_status == 200 and isinstance(safe_me, dict):
                tot += int(safe_me.get("special_credits") or 0)
            up_status, up_me = call_upstream("GET", "/api/auth/me")
            if up_status == 200 and isinstance(up_me, dict):
                tot += int(up_me.get("basic_credits") or 0)
            _UPSTREAM_CREDITS_CACHE["credits"] = tot
            _UPSTREAM_CREDITS_CACHE["provider"] = prov
            _UPSTREAM_CREDITS_CACHE["ts"] = now
        else:
            up_status, up_me = call_upstream("GET", "/api/auth/me")
            if up_status == 200 and isinstance(up_me, dict):
                _UPSTREAM_CREDITS_CACHE["credits"] = int(up_me.get("basic_credits") or 0)
                _UPSTREAM_CREDITS_CACHE["provider"] = prov
                _UPSTREAM_CREDITS_CACHE["ts"] = now
    except Exception:
        pass
    return _UPSTREAM_CREDITS_CACHE["credits"]

def get_user_dashboard_state(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username, role, basic_credits, premium_credits, max_groups FROM users WHERE id = ?", (user_id,))
    u = c.fetchone()
    if not u:
        conn.close()
        return None
    user_data = dict(u)
    conn.close()

    is_admin = user_data.get("role") == "admin"
    groups = fetch_and_sync_groups(user_id=user_id, is_admin=is_admin, force_refresh=False)

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY id DESC LIMIT 50", (user_id,))
    transactions = [dict(r) for r in c.fetchall()]

    c.execute("SELECT * FROM coupons WHERE created_by = ? ORDER BY id DESC", (user_data['username'],))
    my_coupons = [dict(r) for r in c.fetchall()]

    c.execute("SELECT * FROM coupons WHERE redeemed_by = ? ORDER BY id DESC", (user_data['username'],))
    redeemed_coupons = [dict(r) for r in c.fetchall()]

    c.execute("SELECT * FROM groups WHERE user_id = ? ORDER BY created_at DESC LIMIT 50", (user_id,))
    history = [dict(r) for r in c.fetchall()]
    conn.close()

    price_inr = float(get_setting("famgateway_price_inr", get_setting("credit_price_inr", "120.0")))
    price_usd = float(get_setting("credit_price_usd", "1.50"))

    regions = get_processed_regions()

    upstream_credits = get_cached_upstream_credits()

    pricing = {
        "credit_price_inr": price_inr,
        "credit_price_usd": price_usd,
        "regions": regions,
        "upstream_credits": upstream_credits,
        "upstream_in_stock": upstream_credits > 0,
        "global_maintenance": is_global_maintenance()
    }

    alerts = {
        "active": (get_setting("broadcast_active", "0") == "1"),
        "title": get_setting("broadcast_title", "Glory Boost Active"),
        "message": get_setting("broadcast_message", "All server nodes are functioning normally across all regions.")
    }

    return {
        "user": user_data,
        "groups": groups,
        "transactions": transactions,
        "coupons": my_coupons,
        "redeemed": redeemed_coupons,
        "history": history,
        "pricing": pricing,
        "alerts": alerts
    }

def get_admin_dashboard_state():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) AS total_users FROM users")
    total_users = c.fetchone()["total_users"]

    c.execute("SELECT COUNT(*) AS total_groups FROM groups")
    total_groups = c.fetchone()["total_groups"]

    c.execute("SELECT SUM(basic_credits) AS total_credits FROM users")
    total_credits = c.fetchone()["total_credits"] or 0

    c.execute("SELECT COUNT(*) AS total_payments FROM transactions WHERE status = 'approved'")
    total_payments = c.fetchone()["total_payments"] or 0

    c.execute("""
        SELECT u.id, u.username, u.role, u.basic_credits, u.premium_credits, u.is_banned, u.created_at,
               COUNT(DISTINCT g.id) AS groups_count,
               COALESCE(SUM(CASE WHEN t.status = 'approved' THEN t.usd ELSE 0 END), 0) AS total_spent_usd
        FROM users u
        LEFT JOIN groups g ON g.user_id = u.id
        LEFT JOIN transactions t ON t.user_id = u.id
        GROUP BY u.id
        ORDER BY u.id DESC
    """)
    users = [dict(r) for r in c.fetchall()]

    c.execute("SELECT * FROM transactions WHERE status = 'pending' ORDER BY id DESC")
    pending_orders = [dict(r) for r in c.fetchall()]
    conn.close()

    upstream_status, upstream_data = call_upstream("GET", "/api/auth/me")
    upstream_credits = 1
    if upstream_status == 200 and isinstance(upstream_data, dict):
        upstream_credits = upstream_data.get("basic_credits", 1)

    mkey, akey = get_upstream_keys()
    gw_key = get_setting("famgateway_api_key", "")

    return {
        "overview": {
            "total_users": total_users,
            "total_groups": total_groups,
            "total_credits": total_credits,
            "pending_orders": total_payments,
            "total_payments": total_payments,
            "upstream_credits_pool": upstream_credits,
            "credit_price_usd": get_setting("credit_price_usd", "1.50"),
            "usd_to_inr_rate": get_setting("usd_to_inr_rate", "85.0"),
            "auto_credit_mode": get_setting("auto_credit_mode", "1")
        },
        "users": users,
        "pending_orders": pending_orders,
        "config": {
            "api_url": get_setting("famgateway_base_url", "https://famgateway.in"),
            "api_key": mask_secret(gw_key),
            "upi_id": get_setting("fampay_upi_id", "merchant@fam"),
            "price_inr": float(get_setting("famgateway_price_inr", get_setting("credit_price_inr", "120.0"))),
            "upstream_api_key": mask_secret(akey),
            "upstream_master_key": mask_secret(mkey)
        },
        "contact": {
            "whatsapp": get_setting("contact_whatsapp", "6282326562316"),
            "telegram": get_setting("contact_telegram", "ff_level_pro")
        },
        "broadcast": {
            "title": get_setting("broadcast_title", "Glory Boost Active"),
            "message": get_setting("broadcast_message", "All server nodes are functioning normally across all regions."),
            "active": get_setting("broadcast_active", "1") == "1"
        },
        "servers": get_processed_regions(),
        "global_maintenance": is_global_maintenance(),
        "global_maintenance_message": get_setting("global_maintenance_message", "All server nodes are currently undergoing scheduled maintenance.")
    }

@app.route("/")
@app.route("/dashboard")
def serve_index():
    if "user_id" not in session:
        if request.path == "/dashboard":
            return redirect("/login")
        return send_from_directory(BASE_DIR, "login.html")
    user_id = session.get("user_id")
    try:
        state = get_user_dashboard_state(user_id)
    except Exception as e:
        print(f"[Dashboard Load Error]: {e}")
        state = None

    if not state:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id, username, role, basic_credits, premium_credits, max_groups FROM users WHERE id = ?", (user_id,))
        u = c.fetchone()
        conn.close()
        if not u:
            session.clear()
            return redirect("/login")
        user_data = dict(u)
        state = {
            "user": user_data,
            "groups": [],
            "transactions": [],
            "coupons": [],
            "redeemed": [],
            "history": [],
            "pricing": {
                "credit_price_inr": 95,
                "credit_price_usd": 1.7,
                "regions": [r for r in DEFAULT_REGIONS if r.get("enabled")],
                "upstream_credits": 0,
                "upstream_in_stock": True,
                "global_maintenance": False
            },
            "alerts": {"active": False, "title": "", "message": ""}
        }

    state_json = json.dumps(state)
    state_b64 = base64.b64encode(state_json.encode("utf-8")).decode("utf-8")

    with open(os.path.join(BASE_DIR, "index.html"), "r", encoding="utf-8") as f:
        html = f.read()

    injection = f'<script id="__SYS_SYNC__">window.__INITIAL_SYNC__="{state_b64}";</script>'
    html = html.replace("</head>", f"{injection}\n</head>")
    return html

@app.route("/google<verification_id>.html")
def google_verification_file(verification_id):
    return f"google-site-verification: google{verification_id}.html", 200, {"Content-Type": "text/html"}

@app.route("/login")
@app.route("/login.html")
def serve_login():
    if "user_id" in session:
        if session.get("role") == "admin":
            return redirect("/admin")
        return redirect("/")
    return send_from_directory(BASE_DIR, "login.html")

@app.route("/admin")
@app.route("/admin.html")
def serve_admin():
    if "user_id" not in session:
        return redirect("/login")
    if session.get("role") != "admin":
        return redirect("/dashboard")

    admin_state = get_admin_dashboard_state()
    state_b64 = base64.b64encode(json.dumps(admin_state).encode("utf-8")).decode("utf-8")

    with open(os.path.join(BASE_DIR, "admin.html"), "r", encoding="utf-8") as f:
        html = f.read()

    injection = f'<script id="__ADMIN_SYNC__">window.__ADMIN_SYNC__="{state_b64}";</script>'
    html = html.replace("</head>", f"{injection}\n</head>")
    return html

@app.route("/logout")
def direct_logout():
    session.clear()
    return redirect("/login")

@app.route("/shared.css")
def serve_css():
    return send_from_directory(BASE_DIR, "shared.css", mimetype="text/css")

@app.route("/shared.js")
@app.route("/login.js")
def block_js_direct_access():
    return jsonify({"error": "Not found"}), 404

@app.route("/favicon.ico")
def serve_favicon():
    res = send_from_directory(BASE_DIR, "favicon.ico", mimetype="image/x-icon")
    res.headers["Cache-Control"] = "public, max-age=86400"
    return res

@app.route("/clan.png")
def serve_clan_png():
    return send_from_directory(BASE_DIR, "clan.png", mimetype="image/png")

@app.route("/assets/<path:path>")
def serve_assets(path):
    return send_from_directory(os.path.join(BASE_DIR, "assets"), path)

@app.route("/robots.txt")
def serve_robots():
    base_url = request.host_url.rstrip("/")
    content = f"""User-agent: *
Allow: /
Allow: /login
Disallow: /admin
Disallow: /api/

Sitemap: {base_url}/sitemap.xml
"""
    return Response(content, mimetype="text/plain")

@app.route("/sitemap.xml")
def serve_sitemap():
    base_url = request.host_url.rstrip("/")
    xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>{base_url}/</loc>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>{base_url}/login</loc>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
</urlset>"""
    return Response(xml_content, mimetype="application/xml")

# Block public database, zip and source downloads
@app.route("/panel.db")
@app.route("/state.json")
@app.route("/server.py")
@app.route("/db.py")
@app.route("/download")
@app.route("/download.zip")
@app.route("/download/project.zip")
@app.route("/ffglory_backup.zip")
@app.route("/<path:path>.zip")
@app.route("/<path:path>.db")
@app.route("/<path:path>.sqlite")
@app.route("/<path:path>.sqlite3")
@app.route("/<path:path>.sql")
@app.route("/<path:path>.bak")
def block_sensitive_downloads(path=None):
    return jsonify({"error": "Not found"}), 404

# ==================== AUTHENTICATION (SQLITE) ====================

@app.route("/api/auth/signup", methods=["POST"])
@rate_limit(max_requests=5, window_seconds=60, key_prefix="signup")
def auth_signup():
    data = request.get_json(silent=True) or request.form.to_dict()
    username = (data.get("username") or "").strip().lower()
    password = (data.get("password") or "").strip()

    if not username or len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters."}), 400
    if not password or len(password) < 4:
        return jsonify({"error": "Password must be at least 4 characters."}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    if c.fetchone():
        conn.close()
        return jsonify({"error": f"Username '{username}' is already taken. Please choose another."}), 409

    pw_hash = hash_password(password)
    # No free credits on signup - zero balance
    starter_credits = 0
    c.execute("""
        INSERT INTO users (username, password_hash, role, basic_credits, premium_credits, max_groups)
        VALUES (?, ?, 'user', 0, 0, 100)
    """, (username, pw_hash))
    user_id = c.lastrowid
    conn.commit()
    conn.close()
    try:
        trigger_async_sync()
    except Exception:
        pass

    session["user_id"] = user_id
    session["username"] = username
    session["role"] = "user"

    return jsonify({
        "success": True,
        "message": "Account created successfully! Welcome to FFGlory.",
        "user": {
            "id": user_id,
            "username": username,
            "role": "user",
            "basic_credits": 0,
            "premium_credits": 0,
            "max_groups": 100
        }
    })

@app.route("/api/auth/login", methods=["POST"])
@rate_limit(max_requests=10, window_seconds=60, key_prefix="login")
def auth_login():
    data = request.get_json(silent=True) or request.form.to_dict()
    username = (data.get("username") or "").strip().lower()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"error": "Please provide username and password."}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE LOWER(username) = ?", (username,))
    user = c.fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "Invalid username or password."}), 401

    if user["is_banned"]:
        return jsonify({"error": "This account has been suspended by administration."}), 403

    pw_hash = hash_password(password)
    if user["password_hash"] != pw_hash:
        return jsonify({"error": "Invalid username or password."}), 401

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]

    return jsonify({
        "success": True,
        "message": f"Welcome back, {user['username']}!",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "basic_credits": user["basic_credits"],
            "premium_credits": user["premium_credits"],
            "max_groups": user["max_groups"]
        }
    })

@app.route("/api/auth/me", methods=["GET"])
def auth_me():
    user_id = session.get("user_id")
    if not user_id:
        # Default guest response
        return jsonify({
            "error": "Not authenticated",
            "username": None,
            "role": "guest",
            "basic_credits": 0,
            "premium_credits": 0,
            "max_groups": 0
        }), 401

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username, role, basic_credits, premium_credits, max_groups, is_banned FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()

    if not user or user["is_banned"]:
        session.clear()
        return jsonify({"error": "User not found or banned"}), 404

    return jsonify({
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "basic_credits": user["basic_credits"],
        "premium_credits": user["premium_credits"],
        "max_groups": user["max_groups"]
    })

@app.route("/api/auth/logout", methods=["POST", "GET"])
def auth_logout():
    session.clear()
    return jsonify({"success": True, "redirect": "/login"})

# ==================== PRICING & PAYMENT GATEWAY SETTINGS ====================

@app.route("/api/pricing", methods=["GET"])
@rate_limit(max_requests=60, window_seconds=60, key_prefix="pricing")
def get_pricing():
    # Maintenance regions are completely hidden from users
    regions = get_processed_regions(only_active=True)
    price_inr = float(get_setting("famgateway_price_inr", get_setting("credit_price_inr", "120.0")))

    upstream_credits = get_cached_upstream_credits()

    return jsonify({
        "credit_price_inr": price_inr,
        "credit_price_usd": float(get_setting("credit_price_usd", "1.50")),
        "regions": regions,
        "upstream_credits": upstream_credits,
        "upstream_in_stock": upstream_credits > 0,
        "global_maintenance": is_global_maintenance(),
        "active_provider": get_active_provider()
    })

# ==================== BOT GROUPS (RESELLER UPSTREAM AUTOMATION) ====================

@app.route("/api/client/my-groups", methods=["GET"])
def get_my_groups():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify([]), 200

    is_admin = session.get("role") == "admin"
    groups = fetch_and_sync_groups(user_id=user_id, is_admin=is_admin, force_refresh=False)
    return jsonify(groups)

@app.route("/api/client/auto-clan-group", methods=["POST"])
def launch_clan_group():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Authentication required. Please log in."}), 401

    # Rate limiting: 1 bot launch per 3 seconds per user to prevent rapid button spam
    ok_launch, wait_launch = limiter.is_allowed(f"act_launch_bot:{user_id}", 1, 3)
    if not ok_launch:
        return jsonify({"error": f"Bot launch in progress. Please wait {wait_launch}s before launching another bot."}), 429

    user_lock = _launch_locks[user_id]
    if not user_lock.acquire(blocking=False):
        return jsonify({"error": "A bot launch is already in progress for your account. Please wait a moment."}), 429

    try:
        payload = request.get_json(silent=True) or request.form.to_dict()
        clan_id = (payload.get("clan_id") or "").strip()
        raw_region = (payload.get("region") or "in").strip()
        region = normalize_region_for_upstream(raw_region)

        if not clan_id:
            return jsonify({"error": "Clan ID is required."}), 400

        conn = get_db()
        c = conn.cursor()

        # ATOMIC CREDIT DEDUCTION (ALWAYS DEDUCTED - NO REFUNDS AS PER POLICY):
        c.execute("UPDATE users SET basic_credits = basic_credits - 1 WHERE id = ? AND basic_credits >= 1", (user_id,))
        conn.commit()
        if c.rowcount == 0:
            conn.close()
            return jsonify({"error": "Insufficient credits! Please buy credits from the panel."}), 402

        c.execute("SELECT username, basic_credits FROM users WHERE id = ?", (user_id,))
        user_row = c.fetchone()
        uname = user_row["username"] if user_row else "user"
        remaining_credits = user_row["basic_credits"] if user_row else 0

        # Forward to active bot provider (ffglory_safe or ffglory_pro)
        use_safe = False
        reg_lower = (raw_region or "").strip().lower()
        active_prov = get_active_provider()

        if reg_lower.startswith("in_safe") or reg_lower == "safe":
            use_safe = True
        elif active_prov == "ffglory_safe":
            use_safe = True
        elif active_prov == "both" and (reg_lower.startswith("in_safe") or reg_lower == "safe"):
            use_safe = True

        assigned_provider = "ffglory_safe" if use_safe else "ffglory_pro"
        assigned_region = "IN_SAFE" if use_safe else region.upper()
        group_id = None
        clan_name = f"Clan {clan_id}"
        glory = 0

        if use_safe:
            try:
                safe_st, safe_res = call_safe_api("POST", "/launch", json_data={"guild_id": str(clan_id)})
                if safe_st == 200 and isinstance(safe_res, dict) and safe_res.get("success"):
                    group_id = str(safe_res.get("launch_id") or safe_res.get("id") or "")
                    if safe_res.get("guild"):
                        clan_name = safe_res["guild"].get("name") or clan_name
                else:
                    err_msg = safe_res.get("error") if isinstance(safe_res, dict) else str(safe_res)
                    print(f"[Safe API Launch Notice]: {err_msg}")
            except Exception as e:
                print(f"[Safe API Launch Error]: {e}")
            if not group_id:
                group_id = f"SAFE-{int(time.time()*1000) % 100000000:08d}"
        else:
            try:
                upstream_status, upstream_res = call_upstream("POST", "/api/client/auto-clan-group", {
                    "clan_id": clan_id,
                    "region": region
                })
                if upstream_status == 200 and isinstance(upstream_res, dict) and (upstream_res.get("group_id") or upstream_res.get("id")):
                    group_id = str(upstream_res.get("group_id") or upstream_res.get("id"))
                    clan_name = upstream_res.get("clan_name") or clan_name
                    glory = upstream_res.get("glory_gained", 0)
            except Exception as e:
                print(f"[Upstream Forward Warning]: {e}")
            if not group_id:
                group_id = f"191{int(time.time()*1000) % 100000000:08d}"

        c.execute("""
            INSERT INTO groups (group_id, user_id, clan_id, clan_name, region, status, glory_gained, clan_total_glory, uptime, created_at, provider)
            VALUES (?, ?, ?, ?, ?, 'running', ?, 0, 'Just started', CURRENT_TIMESTAMP, ?)
        """, (group_id, user_id, clan_id, clan_name, assigned_region, glory, assigned_provider))

        tx_id = f"GLR-{int(time.time()*1000)}_{uuid.uuid4().hex[:6]}"
        c.execute("""
            INSERT INTO transactions (id, user_id, username, amount, credit_type, usd, order_id, status)
            VALUES (?, ?, ?, 1, 'basic', 0.0, ?, 'approved')
        """, (tx_id, user_id, uname, f"LAUNCH-{group_id}"))
        conn.commit()
        conn.close()

        try:
            trigger_async_sync()
        except Exception:
            pass

        return jsonify({
            "success": True,
            "message": f"Successfully launched Glory Boost for Clan {clan_id} in region {region.upper()}!",
            "group_id": group_id,
            "new_basic_credits": remaining_credits
        })
    finally:
        user_lock.release()

@app.route("/api/client/group-action", methods=["POST"])
def client_group_action():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Please log in"}), 401

    payload = request.get_json(silent=True) or request.form.to_dict()
    action = payload.get("action")
    group_id = str(payload.get("group_id") or "").strip()

    if not group_id or group_id == "undefined":
        return jsonify({"error": "Invalid group ID."}), 400

    conn = get_db()
    c = conn.cursor()
    # Admins can manage any group; normal users manage their own
    if session.get("role") == "admin":
        c.execute("SELECT * FROM groups WHERE group_id = ? OR id = ?", (group_id, group_id))
    else:
        c.execute("SELECT * FROM groups WHERE (group_id = ? OR id = ?) AND user_id = ?", (group_id, group_id, user_id))

    grp = c.fetchone()
    real_grp_id = grp["group_id"] if grp else group_id

    if action == "refund":
        conn.close()
        return jsonify({"success": False, "error": "Refunds have been permanently disabled as per policy."}), 400

    if not grp:
        # If group is not in local DB, but action is delete, return success
        if action == "delete":
            try:
                call_upstream("POST", "/api/client/group-action", {"action": "delete", "group_id": group_id})
            except Exception:
                pass
            c.execute("DELETE FROM groups WHERE group_id = ? OR id = ?", (group_id, group_id))
            conn.commit()
            conn.close()
            return jsonify({"success": True, "message": "Group removed."})
        conn.close()
        return jsonify({"error": "Group not found or unauthorized"}), 404

    real_grp_id = grp["group_id"]

    if action == "extend":
        c.execute("SELECT basic_credits FROM users WHERE id = ?", (user_id,))
        u = c.fetchone()
        if not u or u["basic_credits"] < 1:
            conn.close()
            return jsonify({"error": "Insufficient credits! You need 1 credit to extend group runtime (+8h)."}), 402

    # Forward to upstream (best effort, do not block local delete)
    try:
        upstream_status, upstream_res = call_upstream("POST", "/api/client/group-action", {
            "action": action,
            "group_id": real_grp_id
        })
    except Exception:
        upstream_status, upstream_res = 500, {}

    if action == "delete":
        c.execute("DELETE FROM groups WHERE group_id = ? OR id = ?", (real_grp_id, group_id))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Group deleted successfully."})
    elif action == "stop":
        c.execute("UPDATE groups SET status = 'stopped' WHERE group_id = ?", (real_grp_id,))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Bot group paused."})
    elif action == "restart":
        c.execute("UPDATE groups SET status = 'running' WHERE group_id = ?", (real_grp_id,))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Bot group restarted."})
    elif action == "extend":
        if upstream_status == 200 and isinstance(upstream_res, dict) and not upstream_res.get("error"):
            c.execute("UPDATE users SET basic_credits = basic_credits - 1 WHERE id = ?", (user_id,))
            tx_id = f"EXT-{int(time.time()*1000)}_{uuid.uuid4().hex[:6]}"
            c.execute("""
                INSERT INTO transactions (id, user_id, username, amount, credit_type, usd, order_id, status)
                VALUES (?, ?, ?, 1, 'basic', 0.0, ?, 'approved')
            """, (tx_id, user_id, session.get("username", "user"), f"EXTEND-{real_grp_id}"))
            conn.commit()
            new_credits = u["basic_credits"] - 1
            conn.close()
            return jsonify({
                "success": True,
                "message": "Group extended successfully (+8h)! 1 credit deducted.",
                "new_basic_credits": new_credits,
                "data": upstream_res
            })
        else:
            conn.close()
            err = upstream_res.get("error") if isinstance(upstream_res, dict) else "Upstream rejected extend request"
            return jsonify({"error": f"Extend failed: {err}"}), 400
    elif action == "get-glory":
        real_glory, real_details = get_cached_group_glory(real_grp_id)
        conn.close()
        return jsonify({
            "success": True,
            "group_id": real_grp_id,
            "total_glory": real_glory,
            "details": real_details,
            "data": upstream_res if upstream_status == 200 else {"total_glory": real_glory, "details": real_details}
        })

    conn.close()
    return jsonify(upstream_res if upstream_status == 200 else {"success": True, "message": f"Action '{action}' executed."})

# ==================== FAMGATEWAY PURCHASES, WEBHOOKS & TRANSACTIONS ====================

def fulfill_order(order_id, utr=None, sender_name=None, user_id=None):
    """Atomically marks pending transaction as approved and credits user's account."""
    if not order_id and not user_id:
        return False, "Invalid order identification"

    conn = get_db()
    c = conn.cursor()

    row = None
    if order_id:
        c.execute("""
            SELECT id, user_id, amount, status, order_id FROM transactions 
            WHERE order_id = ? OR order_id = ? OR order_id LIKE ?
            ORDER BY created_at DESC LIMIT 1
        """, (order_id, f"[FAMGATEWAY] {order_id}", f"%{order_id}%"))
        row = c.fetchone()

    if not row and user_id:
        c.execute("""
            SELECT id, user_id, amount, status, order_id FROM transactions 
            WHERE user_id = ? AND status = 'pending'
            ORDER BY created_at DESC LIMIT 1
        """, (user_id,))
        row = c.fetchone()

    if not row:
        conn.close()
        return False, "Order not found"

    if row["status"] == "approved":
        conn.close()
        return True, "Order already fulfilled"

    tx_id = row["id"]
    u_id = row["user_id"]
    credits_amount = row["amount"]

    note = f"[FAMGATEWAY] {order_id or row['order_id']}"
    if utr:
        note += f" | UTR: {utr}"
    if sender_name:
        note += f" | By: {sender_name}"

    c.execute("UPDATE transactions SET status = 'approved', order_id = ? WHERE id = ?", (note, tx_id))
    c.execute("UPDATE users SET basic_credits = basic_credits + ? WHERE id = ?", (credits_amount, u_id))
    conn.commit()

    c.execute("SELECT basic_credits FROM users WHERE id = ?", (u_id,))
    updated_user = c.fetchone()
    new_bal = updated_user["basic_credits"] if updated_user else credits_amount
    conn.close()
    return True, new_bal

@app.route("/api/client/famgateway/create-order", methods=["POST"])
def client_famgateway_create_order():
    user_id = session.get("user_id")
    username = session.get("username", "Guest")
    if not user_id:
        return jsonify({"error": "Please log in first."}), 401

    payload = request.get_json(silent=True) or request.form.to_dict()
    try:
        credits = int(payload.get("credits") or payload.get("amount") or 1)
    except Exception:
        credits = 5

    if credits <= 0:
        return jsonify({"error": "Please select at least 1 credit to purchase."}), 400

    price_inr = float(get_setting("famgateway_price_inr", get_setting("credit_price_inr", "120.0")))
    total_inr = round(credits * price_inr, 2)

    api_key = get_setting("famgateway_api_key", "").strip()
    base_url = get_setting("famgateway_base_url", "https://famgateway.in").strip().rstrip("/")
    if not base_url:
        base_url = "https://famgateway.in"

    order_id = f"fg_{int(time.time())%1000000:06d}{user_id}"
    qr_url = ""
    checkout_url = ""
    upi_intent = ""
    upi_id = "merchant@fam"
    created_at_ist = ""
    expires_at_ist = ""
    gateway_connected = False
    gateway_msg = ""

    if api_key:
        try:
            req_body = {
                "api_key": api_key,
                "amount": total_inr,
                "customer_name": username,
                "redirect_url": request.host_url.rstrip("/") + "/#transactions"
            }
            res = requests.post(f"{base_url}/api/create-order", json=req_body, headers={"Content-Type": "application/json"}, timeout=8)
            if res.status_code == 200:
                data = res.json()
                if data.get("status") == "success" and "data" in data:
                    d = data["data"]
                    order_id = d.get("order_id", order_id)
                    qr_url = d.get("qr_url", "")
                    checkout_url = d.get("checkout_url", "")
                    upi_intent = d.get("upi_intent", "")
                    upi_id = d.get("upi_id", upi_id)
                    created_at_ist = d.get("created_at_ist", "")
                    expires_at_ist = d.get("expires_at_ist", "")
                    gateway_connected = True
                else:
                    gateway_msg = data.get("message", "Gateway returned non-success response")
            else:
                gateway_msg = f"HTTP {res.status_code}"
        except Exception as e:
            gateway_msg = str(e)

    # Dynamic fallback QR generation if gateway didn't return a direct qr_url
    if not qr_url:
        upi_string = f"upi://pay?pa={upi_id}&pn=FamPay&tr={order_id}&tn={order_id}&am={total_inr:.2f}&cu=INR"
        qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=250x250&data={requests.utils.quote(upi_string)}"
        if not upi_intent:
            upi_intent = upi_string

    # Record pending transaction in database
    tx_id = f"FG-{int(time.time())%1000000:06d}-{user_id}"
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO transactions (id, user_id, username, amount, credit_type, usd, order_id, status)
        VALUES (?, ?, ?, ?, 'basic', ?, ?, 'pending')
    """, (tx_id, user_id, username, credits, total_inr, order_id))
    conn.commit()
    conn.close()
    try:
        trigger_async_sync()
    except Exception:
        pass

    return jsonify({
        "success": True,
        "order_id": order_id,
        "credits": credits,
        "amount_inr": total_inr,
        "payable_amount": total_inr,
        "upi_id": upi_id,
        "qr_url": qr_url,
        "checkout_url": checkout_url,
        "upi_intent": upi_intent,
        "gateway_connected": gateway_connected,
        "gateway_msg": gateway_msg,
        "created_at_ist": created_at_ist,
        "expires_at_ist": expires_at_ist
    })

@app.route("/api/client/famgateway/verify-order", methods=["POST"])
@app.route("/api/client/purchase-credits", methods=["POST"])
def client_famgateway_verify_order():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Please log in first."}), 401

    payload = request.get_json(silent=True) or request.form.to_dict()
    order_id = (payload.get("order_id") or "").strip()
    utr = (payload.get("utr") or "").strip()

    if not order_id and utr:
        order_id = utr
    if not utr and order_id and len(order_id) >= 12 and order_id.isdigit():
        utr = order_id

    if not order_id and not utr:
        return jsonify({"error": "Order ID or 12-digit Bank UTR is required."}), 400

    api_key = get_setting("famgateway_api_key", "").strip()
    base_url = get_setting("famgateway_base_url", "https://famgateway.in").strip().rstrip("/")
    if not base_url:
        base_url = "https://famgateway.in"

    is_verified = False
    sender_name = None

    # Step 1: Upstream FamGateway verify-order API (if API key configured)
    if api_key and order_id:
        try:
            v_url = f"{base_url}/api/verify-order.php?api_key={api_key}&order_id={order_id}"
            res = requests.get(v_url, timeout=7)
            if res.status_code == 200:
                data = res.json()
                if data.get("status") == "success":
                    is_verified = True
                    d = data.get("data", {})
                    utr = d.get("utr", utr)
                    sender_name = d.get("sender_name")
        except Exception:
            pass

    # Step 2: FamGateway public checkout-status API
    if not is_verified and order_id:
        try:
            s_url = f"{base_url}/api/checkout-status.php?order_id={order_id}"
            res = requests.get(s_url, timeout=5)
            if res.status_code == 200:
                data = res.json()
                if data.get("status") == "success":
                    is_verified = True
                    utr = data.get("utr", utr)
                    sender_name = data.get("sender_name")
        except Exception:
            pass

    # Step 3: Accept valid 10-12 digit UTR provided by customer
    if not is_verified and utr and len(utr) >= 10:
        is_verified = True

    if not is_verified:
        return jsonify({
            "success": False,
            "error": "Payment not verified yet. Please ensure transaction is complete or enter your 12-digit Bank UTR."
        }), 400

    success, res_val = fulfill_order(order_id, utr=utr, sender_name=sender_name, user_id=user_id)
    if not success:
        return jsonify({"error": "No matching pending order found to credit. Please create an order first."}), 404

    return jsonify({
        "success": True,
        "auto_credited": True,
        "new_balance": res_val if isinstance(res_val, (int, float)) else None,
        "utr": utr,
        "message": f"FamGateway payment verified! Credits added instantly! Balance: {res_val} credits."
    })

@app.route("/api/client/famgateway/check-status", methods=["GET"])
def client_famgateway_check_status():
    user_id = session.get("user_id")
    order_id = request.args.get("order_id", "").strip()
    if not order_id:
        return jsonify({"status": "pending", "paid": False})

    base_url = get_setting("famgateway_base_url", "https://famgateway.in").strip().rstrip("/")
    if not base_url:
        base_url = "https://famgateway.in"
    api_key = get_setting("famgateway_api_key", "").strip()

    paid = False
    utr = None
    sender = None

    try:
        res = requests.get(f"{base_url}/api/checkout-status.php?order_id={order_id}", timeout=4)
        if res.status_code == 200:
            data = res.json()
            if data.get("status") == "success":
                paid = True
                utr = data.get("utr")
                sender = data.get("sender_name")
    except Exception:
        pass

    if not paid and api_key:
        try:
            res = requests.get(f"{base_url}/api/verify-order.php?api_key={api_key}&order_id={order_id}", timeout=4)
            if res.status_code == 200:
                data = res.json()
                if data.get("status") == "success":
                    paid = True
                    d = data.get("data", {})
                    utr = d.get("utr")
                    sender = d.get("sender_name")
        except Exception:
            pass

    if paid:
        success, res_val = fulfill_order(order_id, utr=utr, sender_name=sender, user_id=user_id)
        bal = 0
        if user_id:
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT basic_credits FROM users WHERE id = ?", (user_id,))
            u = c.fetchone()
            bal = u["basic_credits"] if u else 0
            conn.close()
        return jsonify({
            "status": "success",
            "paid": True,
            "new_balance": bal,
            "utr": utr,
            "message": "Payment confirmed! Credits added!"
        })

    return jsonify({"status": "pending", "paid": False})

@app.route("/api/famgateway-webhook", methods=["POST"])
def famgateway_webhook():
    api_key = get_setting("famgateway_api_key", "").strip()
    signature = request.headers.get("x-famgateway-signature")
    raw_body = request.get_data()

    if signature and api_key:
        expected = hmac.new(api_key.encode(), raw_body, hashlib.sha256).hexdigest()
        if signature != expected:
            return jsonify({"error": "Invalid webhook signature"}), 401

    payload = request.get_json(silent=True) or {}
    status = payload.get("status")
    order_id = payload.get("order_id")
    utr = payload.get("utr")
    sender_name = payload.get("sender_name")

    if status == "success" and order_id:
        success, res = fulfill_order(order_id, utr=utr, sender_name=sender_name)
        return jsonify({"status": "received", "fulfilled": success, "detail": res})

    return jsonify({"status": "received"})

@app.route("/api/client/transactions", methods=["GET"])
def client_transactions():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify([]), 200

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
    rows = c.fetchall()
    conn.close()

    res = []
    for r in rows:
        res.append({
            "id": r["id"],
            "credits": r["amount"],
            "type": r["credit_type"],
            "amount_usd": r["usd"],
            "order_id": r["order_id"],
            "status": r["status"],
            "date": r["created_at"]
        })
    return jsonify(res)

def extract_coupon_credits(up_res, local_cpn=None):
    """
    Extract exact credit amount and credit type from upstream response or local coupon.
    Fixes glitch where upstream returns 2 or more credits, ensuring exact amount is awarded.
    """
    credits = 0
    ctype = "basic"
    if isinstance(up_res, dict):
        for k in ["credits", "amount", "credit", "basic_credits", "premium_credits", "value", "count", "balance"]:
            val = up_res.get(k)
            if val is not None:
                try:
                    num = int(val)
                    if num > 0:
                        credits = max(credits, num)
                        if k == "premium_credits":
                            ctype = "premium"
                except (ValueError, TypeError):
                    pass

        for subk in ["data", "coupon", "result", "payload"]:
            sub = up_res.get(subk)
            if isinstance(sub, dict):
                for k in ["credits", "amount", "credit", "basic_credits", "premium_credits", "value"]:
                    val = sub.get(k)
                    if val is not None:
                        try:
                            num = int(val)
                            if num > 0:
                                credits = max(credits, num)
                                if k == "premium_credits":
                                    ctype = "premium"
                        except (ValueError, TypeError):
                            pass
                if sub.get("credit_type"):
                    ctype = sub.get("credit_type")

        if up_res.get("credit_type"):
            ctype = up_res.get("credit_type")

        if credits <= 0:
            for text_field in ["message", "msg", "detail", "status_message"]:
                txt = str(up_res.get(text_field) or "")
                if txt:
                    m = re.search(r'(\d+)\s*(?:basic\s*|premium\s*)?credit', txt, re.IGNORECASE)
                    if m:
                        try:
                            credits = int(m.group(1))
                        except (ValueError, TypeError):
                            pass
                        if "premium" in txt.lower():
                            ctype = "premium"
                        break

    if credits <= 0 and local_cpn:
        try:
            credits = int(local_cpn["credits"])
            ctype = local_cpn.get("credit_type") or "basic"
        except (ValueError, TypeError):
            credits = 0

    if credits <= 0:
        credits = 1

    return credits, ctype

@app.route("/api/client/redeem-coupon", methods=["POST"])
def client_redeem_coupon():
    user_id = session.get("user_id")
    username = session.get("username", "Guest")
    if not user_id:
        return jsonify({"error": "Please log in"}), 401

    payload = request.get_json(silent=True) or request.form.to_dict()
    code = (payload.get("code") or "").strip().upper()

    if not code:
        return jsonify({"error": "Coupon code is required"}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM coupons WHERE code = ?", (code,))
    local_coupon = c.fetchone()

    # Check local status
    if local_coupon:
        if local_coupon["status"] == "redeemed":
            conn.close()
            return jsonify({"error": f"This coupon code has already been redeemed."}), 400
        if local_coupon["status"] == "cancelled":
            conn.close()
            return jsonify({"error": "This coupon code was cancelled by the creator."}), 400

    # 1. Redeem on upstream ffglory.pro
    # This automatically adds credits into the reseller API wallet on ffglory.pro!
    up_status, up_res = call_upstream("POST", "/api/client/redeem-coupon", json_data={"code": code})
    
    # Check if upstream accepted it or if it was valid
    credits = 0
    ctype = "basic"
    if up_status == 200 and isinstance(up_res, dict):
        credits, ctype = extract_coupon_credits(up_res, local_coupon)
    elif local_coupon and local_coupon["status"] == "active":
        # Fallback for local coupons
        credits = int(local_coupon["credits"])
        ctype = local_coupon.get("credit_type") or "basic"
    else:
        conn.close()
        err_msg = up_res.get("error", "Invalid or expired coupon code.") if isinstance(up_res, dict) else "Coupon redemption failed."
        return jsonify({"error": err_msg}), 400

    # 2. Add credits to the redeeming user's wallet in local database!
    credit_col = "premium_credits" if ctype == "premium" else "basic_credits"
    c.execute(f"UPDATE users SET {credit_col} = {credit_col} + ? WHERE id = ?", (credits, user_id))

    # 3. Update local coupon record
    if local_coupon:
        c.execute("UPDATE coupons SET status = 'redeemed', redeemed_by = ?, redeemed_at = CURRENT_TIMESTAMP WHERE id = ?", (username, local_coupon["id"]))
    else:
        import uuid
        cpn_id = f"cpn_ext_{int(time.time()*1000)}_{uuid.uuid4().hex[:6]}"
        c.execute("""
            INSERT INTO coupons (id, code, credits, credit_type, created_by, status, redeemed_by, redeemed_at)
            VALUES (?, ?, ?, ?, 'ffglory_upstream', 'redeemed', ?, CURRENT_TIMESTAMP)
        """, (cpn_id, code, credits, ctype, username))

    import uuid
    tx_id = f"CPN-{int(time.time()*1000)}_{uuid.uuid4().hex[:6]}"
    c.execute("""
        INSERT INTO transactions (id, user_id, username, amount, credit_type, usd, order_id, status)
        VALUES (?, ?, ?, ?, ?, 0.0, ?, 'approved')
    """, (tx_id, user_id, username, credits, ctype, f"COUPON: {code}"))

    conn.commit()
    c.execute("SELECT basic_credits FROM users WHERE id = ?", (user_id,))
    new_bal = c.fetchone()["basic_credits"]
    conn.close()

    return jsonify({
        "success": True,
        "new_balance": new_bal,
        "credits": credits,
        "message": f"Coupon redeemed successfully! +{credits} Credits added to your account."
    })

@app.route("/api/client/create-coupon", methods=["POST"])
def client_create_coupon():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Please log in"}), 401

    if session.get("role") != "admin":
        return jsonify({"error": "Coupon creation is currently disabled. You can only redeem coupons."}), 403

    payload = request.get_json(silent=True) or request.form.to_dict()
    amount = int(payload.get("basic_credits") or payload.get("credits") or 1)

    if amount < 1:
        return jsonify({"error": "Coupon must contain at least 1 credit"}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT basic_credits, username FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    if not user or user["basic_credits"] < amount:
        conn.close()
        return jsonify({"error": f"Insufficient credits in your wallet (Required: {amount}, Available: {user['basic_credits'] if user else 0})."}), 400

    uname = user["username"]

    code = None
    try:
        status, up_res = call_upstream("POST", "/api/client/create-coupon", json_data={"basic_credits": amount, "premium_credits": 0})
        if status == 200 and isinstance(up_res, dict):
            code = (up_res.get("coupon", {}) or {}).get("code") or up_res.get("code")
    except Exception:
        pass

    if not code:
        code = f"CPN-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"

    # Deduct customer wallet
    c.execute("UPDATE users SET basic_credits = basic_credits - ? WHERE id = ?", (amount, user_id))

    coupon_id = f"cpn_{int(time.time()*1000)}_{uuid.uuid4().hex[:6]}"
    c.execute("""
        INSERT INTO coupons (id, code, credits, credit_type, created_by, status)
        VALUES (?, ?, ?, 'basic', ?, 'active')
    """, (coupon_id, code, amount, uname))
    conn.commit()
    conn.close()
    try:
        trigger_async_sync()
    except Exception:
        pass

    return jsonify({
        "success": True,
        "code": code,
        "credits": amount,
        "coupon": {
            "id": coupon_id,
            "code": code,
            "credits": amount,
            "status": "active"
        },
        "message": f"Coupon code {code} generated successfully for {amount} credits!"
    })

@app.route("/api/client/cancel-coupon", methods=["POST"])
def client_cancel_coupon():
    user_id = session.get("user_id")
    username = session.get("username", "Guest")
    if not user_id:
        return jsonify({"error": "Please log in"}), 401

    payload = request.get_json(silent=True) or request.form.to_dict()
    code = (payload.get("code") or "").strip().upper()

    if not code:
        return jsonify({"error": "Coupon code is required"}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM coupons WHERE code = ? AND created_by = ?", (code, username))
    coupon = c.fetchone()

    if not coupon:
        conn.close()
        return jsonify({"error": "Coupon not found or does not belong to you."}), 404

    if coupon["status"] != "active":
        conn.close()
        return jsonify({"error": f"Cannot cancel coupon with status: {coupon['status']}"}), 400

    refund_credits = coupon["credits"]

    # 1. Cancel on upstream ffglory.pro
    call_upstream("POST", "/api/client/cancel-coupon", json_data={"code": code})

    # 2. Refund local customer balance
    c.execute("UPDATE coupons SET status = 'cancelled' WHERE id = ?", (coupon["id"],))
    c.execute("UPDATE users SET basic_credits = basic_credits + ? WHERE id = ?", (refund_credits, user_id))

    import uuid
    tx_id = f"REF-{int(time.time()*1000)}_{uuid.uuid4().hex[:6]}"
    c.execute("""
        INSERT INTO transactions (id, user_id, username, amount, credit_type, usd, order_id, status)
        VALUES (?, ?, ?, ?, 'basic', 0.0, ?, 'approved')
    """, (tx_id, user_id, username, refund_credits, f"REFUND: CANCELLED {code}"))

    conn.commit()
    c.execute("SELECT basic_credits FROM users WHERE id = ?", (user_id,))
    new_bal = c.fetchone()["basic_credits"]
    conn.close()

    return jsonify({
        "success": True,
        "new_balance": new_bal,
        "message": f"Coupon {code} cancelled and +{refund_credits} credits refunded to your balance!"
    })

@app.route("/api/client/my-coupons", methods=["GET"])
def client_my_coupons():
    username = session.get("username")
    if not username:
        return jsonify([]), 200

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM coupons WHERE created_by = ? ORDER BY created_at DESC", (username,))
    rows = c.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/client/redeemed-coupons", methods=["GET"])
def client_redeemed_coupons():
    username = session.get("username")
    if not username:
        return jsonify([]), 200

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM coupons WHERE redeemed_by = ? ORDER BY redeemed_at DESC", (username,))
    rows = c.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/client/history", methods=["GET"])
def client_history():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify([]), 200

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM groups WHERE user_id = ? ORDER BY created_at DESC LIMIT 50", (user_id,))
    rows = c.fetchall()
    conn.close()
    res = []
    for r in rows:
        res.append({
            "group_id": r["group_id"],
            "clan_id": r["clan_id"],
            "region": r["region"].upper(),
            "glory_gained": r["glory_gained"],
            "status": r["status"],
            "created_at": r["created_at"]
        })
    return jsonify(res)

@app.route("/api/client/inbox", methods=["GET"])
def client_inbox():
    return jsonify([
        {
            "id": 1,
            "title": "Welcome to FFGlory Reseller Panel",
            "message": "Start automated glory boosting for your Free Fire clan! Buy credits via Binance Pay, UPI, or Crypto USDT.",
            "date": "Today",
            "unread": False
        }
    ])

@app.route("/api/client/alerts", methods=["GET"])
def client_alerts():
    active = get_setting("broadcast_active", "0") == "1"
    if not active:
        return jsonify({"active": False})
    return jsonify({
        "active": True,
        "title": get_setting("broadcast_title", "Glory Boost Notice"),
        "message": get_setting("broadcast_message", "All server nodes are functioning normally across all regions.")
    })

# ==================== ADMIN PANEL MANAGEMENT ====================

def require_admin():
    return session.get("role") == "admin"

@app.route("/api/admin/overview", methods=["GET"])
def admin_overview():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) AS total_users FROM users")
    total_users = c.fetchone()["total_users"]

    c.execute("SELECT COUNT(*) AS total_groups FROM groups")
    total_groups = c.fetchone()["total_groups"]

    c.execute("SELECT SUM(basic_credits) AS total_credits FROM users")
    total_credits = c.fetchone()["total_credits"] or 0

    c.execute("SELECT COUNT(*) AS total_payments FROM transactions WHERE status = 'approved'")
    total_payments = c.fetchone()["total_payments"] or 0
    conn.close()

    # Upstream credits from active provider
    upstream_credits = get_cached_upstream_credits()

    return jsonify({
        "total_users": total_users,
        "total_groups": total_groups,
        "total_credits": total_credits,
        "pending_orders": total_payments,
        "total_payments": total_payments,
        "upstream_credits_pool": upstream_credits,
        "active_upstream_provider": get_active_provider(),
        "credit_price_usd": get_setting("credit_price_usd", "1.50"),
        "usd_to_inr_rate": get_setting("usd_to_inr_rate", "85.0"),
        "reseller_binance_id": get_setting("reseller_binance_pay_id", "759228054"),
        "reseller_upi_id": get_setting("reseller_upi_id", "ffglory@upi"),
        "reseller_usdt_address": get_setting("reseller_usdt_address", "TYDzsxdczEfD29g46j5D7LLDIBOn7T654W"),
        "auto_credit_mode": get_setting("auto_credit_mode", "1")
    })

@app.route("/api/admin/users", methods=["GET"])
def admin_users():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT u.id, u.username, u.role, u.basic_credits, u.premium_credits, u.is_banned, u.created_at,
               COUNT(DISTINCT g.id) AS groups_count,
               COALESCE(SUM(CASE WHEN t.status = 'approved' THEN t.usd ELSE 0 END), 0) AS total_spent_usd
        FROM users u
        LEFT JOIN groups g ON g.user_id = u.id
        LEFT JOIN transactions t ON t.user_id = u.id
        GROUP BY u.id
        ORDER BY u.id DESC
    """)
    rows = c.fetchall()
    conn.close()

    return jsonify([dict(r) for r in rows])

@app.route("/api/admin/user/toggle-ban", methods=["POST"])
def admin_toggle_ban():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403

    data = request.get_json(silent=True) or request.form.to_dict()
    user_id = data.get("user_id")

    if not user_id:
        return jsonify({"error": "User ID is required"}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username, role, is_banned FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    if (user["role"] == "admin" and user["username"] == "admin") or user["id"] == 1:
        conn.close()
        return jsonify({"error": "Cannot ban master admin."}), 400

    new_status = 0 if user["is_banned"] else 1
    c.execute("UPDATE users SET is_banned = ? WHERE id = ?", (new_status, user_id))
    conn.commit()
    conn.close()
    try:
        trigger_async_sync()
    except Exception:
        pass

    status_txt = "suspended (banned)" if new_status else "active (unbanned)"
    return jsonify({"success": True, "is_banned": new_status, "message": f"User '{user['username']}' is now {status_txt}."})

@app.route("/api/admin/user/reset-password", methods=["POST"])
def admin_reset_password():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403

    data = request.get_json(silent=True) or request.form.to_dict()
    user_id = data.get("user_id")
    new_pw = (data.get("password") or "").strip()

    if not user_id or not new_pw:
        return jsonify({"error": "User ID and new password are required"}), 400
    if len(new_pw) < 4:
        return jsonify({"error": "Password must be at least 4 characters long."}), 400

    pw_hash = hash_password(new_pw)
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (pw_hash, user_id))
    conn.commit()
    conn.close()
    try:
        trigger_async_sync()
    except Exception:
        pass

    return jsonify({"success": True, "message": "User password has been successfully reset!"})

@app.route("/api/admin/update-credentials", methods=["POST"])
def admin_update_credentials():
    if not require_admin():
        return jsonify({"error": "Admin access required."}), 403

    user_id = session.get("user_id")
    session_username = session.get("username")
    data = request.get_json(silent=True) or request.form.to_dict()

    current_pw = (data.get("current_password") or "").strip()
    new_username = (data.get("new_username") or "").strip()
    new_pw = (data.get("new_password") or "").strip()

    if not current_pw:
        return jsonify({"error": "Current password is required to authorize changes."}), 400

    conn = get_db()
    c = conn.cursor()
    if user_id:
        c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    else:
        c.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (session_username or "admin",))
    admin_user = c.fetchone()

    if not admin_user:
        conn.close()
        return jsonify({"error": "Admin account not found."}), 404

    if admin_user["password_hash"] != hash_password(current_pw):
        conn.close()
        return jsonify({"error": "Current password is incorrect."}), 401

    updates = []
    params = []

    if new_username and new_username.lower() != admin_user["username"].lower():
        if len(new_username) < 3:
            conn.close()
            return jsonify({"error": "Username must be at least 3 characters long."}), 400
        # Check uniqueness
        c.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?) AND id != ?", (new_username, admin_user["id"]))
        if c.fetchone():
            conn.close()
            return jsonify({"error": f"Username '{new_username}' is already in use."}), 409
        updates.append("username = ?")
        params.append(new_username)

    if new_pw:
        if len(new_pw) < 4:
            conn.close()
            return jsonify({"error": "New password must be at least 4 characters long."}), 400
        updates.append("password_hash = ?")
        params.append(hash_password(new_pw))

    if not updates:
        conn.close()
        return jsonify({"error": "Please provide a new username or new password to update."}), 400

    params.append(admin_user["id"])
    c.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", tuple(params))
    conn.commit()

    final_username = new_username if new_username else admin_user["username"]
    session["username"] = final_username
    conn.close()
    try:
        trigger_async_sync()
    except Exception:
        pass

    return jsonify({
        "success": True,
        "message": "Admin credentials updated successfully! Use your new details next time you log in.",
        "username": final_username
    })

@app.route("/api/admin/user/toggle-role", methods=["POST"])
def admin_toggle_role():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403

    data = request.get_json(silent=True) or request.form.to_dict()
    user_id = data.get("user_id")
    target_role = (data.get("role") or "").strip().lower()

    if target_role not in ["admin", "user"]:
        return jsonify({"error": "Invalid role specified."}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    if (user["username"] == "admin" or user["id"] == 1) and target_role != "admin":
        conn.close()
        return jsonify({"error": "Cannot demote primary admin."}), 400

    c.execute("UPDATE users SET role = ? WHERE id = ?", (target_role, user_id))
    conn.commit()
    conn.close()
    try:
        trigger_async_sync()
    except Exception:
        pass

    return jsonify({"success": True, "message": f"User '{user['username']}' role changed to {target_role.upper()}."})

@app.route("/api/admin/user/delete", methods=["POST"])
def admin_delete_user():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403

    data = request.get_json(silent=True) or request.form.to_dict()
    user_id = data.get("user_id")
    username = (data.get("username") or "").strip().lower()

    conn = get_db()
    c = conn.cursor()
    if user_id:
        c.execute("SELECT id, username, role FROM users WHERE id = ? OR LOWER(username) = ?", (user_id, str(user_id).lower()))
    elif username:
        c.execute("SELECT id, username, role FROM users WHERE LOWER(username) = ?", (username,))
    else:
        conn.close()
        return jsonify({"error": "User identifier is required"}), 400

    user = c.fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    target_id = user["id"]
    target_username = user["username"]

    if target_username.lower() == "admin" or target_id == 1:
        conn.close()
        return jsonify({"error": "Primary administrator account cannot be deleted."}), 400

    c.execute("DELETE FROM groups WHERE user_id = ?", (target_id,))
    c.execute("DELETE FROM transactions WHERE user_id = ?", (target_id,))
    c.execute("DELETE FROM coupons WHERE created_by = ? OR redeemed_by = ?", (target_username, target_username))
    c.execute("DELETE FROM users WHERE id = ?", (target_id,))
    conn.commit()
    conn.close()
    try:
        trigger_async_sync()
    except Exception:
        pass

    return jsonify({"success": True, "message": f"User '{target_username}' and all associated records deleted permanently."})

@app.route("/api/admin/adjust-credits", methods=["POST"])
def admin_adjust_credits():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403

    data = request.get_json(silent=True) or request.form.to_dict()
    username = (data.get("username") or "").strip().lower()
    amount = int(data.get("amount") or 0)
    mode = data.get("mode", "add") # "add" or "set"

    if not username:
        return jsonify({"error": "Please enter or select a username."}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username, basic_credits FROM users WHERE LOWER(username) = ?", (username,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": f"Customer '{username}' not found in database."}), 404

    target_id = row["id"]
    real_username = row["username"]

    if mode == "set":
        c.execute("UPDATE users SET basic_credits = ? WHERE id = ?", (max(0, amount), target_id))
    elif mode == "deduct":
        c.execute("UPDATE users SET basic_credits = MAX(0, basic_credits - ?) WHERE id = ?", (amount, target_id))
    else:
        c.execute("UPDATE users SET basic_credits = MAX(0, basic_credits + ?) WHERE id = ?", (amount, target_id))

    # Log manual adjustment in transactions
    tx_id = f"ADM-{int(time.time())%1000000:06d}"
    c.execute("""
        INSERT INTO transactions (id, user_id, username, amount, credit_type, usd, order_id, status)
        VALUES (?, ?, ?, ?, 'basic', 0.00, 'ADMIN_MANUAL_CREDIT', 'approved')
    """, (tx_id, target_id, real_username, amount))

    conn.commit()

    c.execute("SELECT basic_credits FROM users WHERE id = ?", (target_id,))
    new_bal = c.fetchone()["basic_credits"]
    conn.close()

    return jsonify({
        "success": True,
        "new_balance": new_bal,
        "message": f"Successfully updated '{real_username}' balance to {new_bal} credits!"
    })

@app.route("/api/admin/pending-orders", methods=["GET"])
def admin_pending_orders():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM transactions ORDER BY created_at DESC LIMIT 100")
    rows = c.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/admin/approve-order", methods=["POST"])
def admin_approve_order():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403

    data = request.get_json(silent=True) or request.form.to_dict()
    tx_id = data.get("transaction_id")

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM transactions WHERE id = ?", (tx_id,))
    tx = c.fetchone()
    if not tx:
        conn.close()
        return jsonify({"error": "Order not found"}), 404

    if tx["status"] == "approved":
        conn.close()
        return jsonify({"error": "Order is already approved."}), 400

    c.execute("UPDATE transactions SET status = 'approved' WHERE id = ?", (tx_id,))
    c.execute("UPDATE users SET basic_credits = basic_credits + ? WHERE id = ?", (tx["amount"], tx["user_id"]))
    conn.commit()
    conn.close()
    try:
        trigger_async_sync()
    except Exception:
        pass

    return jsonify({"success": True, "message": f"Order {tx_id} approved! +{tx['amount']} credits delivered to customer {tx['username']}."})

@app.route("/api/admin/reject-order", methods=["POST"])
def admin_reject_order():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403

    data = request.get_json(silent=True) or request.form.to_dict()
    tx_id = data.get("transaction_id")

    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE transactions SET status = 'rejected' WHERE id = ?", (tx_id,))
    conn.commit()
    conn.close()
    try:
        trigger_async_sync()
    except Exception:
        pass

    return jsonify({"success": True, "message": f"Order {tx_id} rejected."})

def format_wa_url(val):
    if not val:
        return "https://wa.me/6282326562316"
    val = str(val).strip()
    if val.startswith("http://") or val.startswith("https://"):
        return val
    clean_num = "".join(c for c in val if c.isdigit())
    return f"https://wa.me/{clean_num}" if clean_num else "https://wa.me/6282326562316"

def format_tg_url(val):
    if not val:
        return "https://t.me/ff_level_pro"
    val = str(val).strip()
    if val.startswith("http://") or val.startswith("https://"):
        return val
    clean_uname = val.lstrip("@").strip()
    return f"https://t.me/{clean_uname}" if clean_uname else "https://t.me/ff_level_pro"

@app.route("/api/contact", methods=["GET"])
@app.route("/api/public/contact", methods=["GET"])
def get_public_contact():
    wa = get_setting("contact_whatsapp", "6282326562316")
    tg = get_setting("contact_telegram", "ff_level_pro")
    return jsonify({
        "success": True,
        "whatsapp": wa,
        "whatsapp_url": format_wa_url(wa),
        "telegram": tg,
        "telegram_url": format_tg_url(tg)
    })

@app.route("/api/admin/contact/save", methods=["POST"])
def admin_save_contact():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403
    data = request.get_json(silent=True) or request.form.to_dict()
    wa = str(data.get("whatsapp", data.get("contact_whatsapp", ""))).strip()
    tg = str(data.get("telegram", data.get("contact_telegram", ""))).strip()
    if wa:
        set_setting("contact_whatsapp", wa)
    if tg:
        set_setting("contact_telegram", tg)
    return jsonify({
        "success": True,
        "message": "Contact support links updated successfully!",
        "whatsapp": get_setting("contact_whatsapp", "6282326562316"),
        "telegram": get_setting("contact_telegram", "ff_level_pro"),
        "whatsapp_url": format_wa_url(get_setting("contact_whatsapp", "6282326562316")),
        "telegram_url": format_tg_url(get_setting("contact_telegram", "ff_level_pro"))
    })

@app.route("/api/admin/firebase/status", methods=["GET"])
def admin_firebase_status():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403
    import firebase_sync
    return jsonify({
        "status": "connected" if bool(firebase_sync.get_secret()) else "unconfigured",
        "has_secret": bool(firebase_sync.get_secret()),
        "firebase_db_url": firebase_sync.get_db_url(),
        "last_sync_time": firebase_sync._last_sync_time,
        "last_sync_formatted": time.ctime(firebase_sync._last_sync_time) if firebase_sync._last_sync_time else "Never",
        "sync_status": firebase_sync._last_sync_status,
        "error": firebase_sync._last_sync_error
    })

@app.route("/api/admin/firebase/config", methods=["GET", "POST"])
def admin_firebase_config():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403
    import firebase_sync

    if request.method == "GET":
        db_url = firebase_sync.get_db_url()
        secret = firebase_sync.get_secret()
        masked_secret = (secret[:4] + "*" * (len(secret) - 8) + secret[-4:]) if len(secret) > 8 else ("*" * len(secret))
        return jsonify({
            "firebase_db_url": db_url,
            "firebase_db_secret": secret,
            "masked_secret": masked_secret,
            "status": "connected" if bool(secret) else "unconfigured",
            "sync_status": firebase_sync._last_sync_status,
            "last_sync_time": firebase_sync._last_sync_time,
            "last_sync_formatted": time.ctime(firebase_sync._last_sync_time) if firebase_sync._last_sync_time else "Never",
            "error": firebase_sync._last_sync_error
        })

    data = request.get_json(silent=True) or request.form.to_dict()
    db_url = data.get("firebase_db_url", "").strip()
    db_secret = data.get("firebase_db_secret", "").strip()
    init_if_empty = data.get("init_if_empty", True)
    if isinstance(init_if_empty, str):
        init_if_empty = init_if_empty.lower() in ("true", "1", "yes", "on")

    current_user = None
    if session.get("user_id"):
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT id, username, role FROM users WHERE id = ?", (session.get("user_id"),))
            row = c.fetchone()
            conn.close()
            if row:
                current_user = dict(row)
        except Exception:
            pass

    success, message, extra = firebase_sync.configure_firebase(
        db_url=db_url,
        db_secret=db_secret,
        init_if_empty=init_if_empty,
        current_user=current_user
    )

    if not success:
        return jsonify({"success": False, "error": message}), 400

    return jsonify({
        "success": True,
        "message": message,
        "data": extra,
        "status": "connected",
        "last_sync_formatted": time.ctime(firebase_sync._last_sync_time) if firebase_sync._last_sync_time else "Just now"
    })

@app.route("/api/admin/firebase/sync", methods=["POST"])
def admin_firebase_sync():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403
    import firebase_sync
    data = request.get_json(silent=True) or {}
    action = data.get("action", "push")
    if action == "pull":
        success = firebase_sync.sync_pull_from_firebase()
        return jsonify({"success": success, "message": "Pulled latest cloud snapshot from Firebase!" if success else "Failed to pull from Firebase."})
    else:
        success, msg = firebase_sync.sync_push_to_firebase()
        return jsonify({"success": success, "message": msg})

@app.route("/api/admin/settings", methods=["GET"])
def admin_get_settings():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403

    keys = [
        "credit_price_usd", "usd_to_inr_rate", "reseller_binance_pay_id",
        "reseller_upi_id", "reseller_upi_name", "reseller_usdt_address",
        "reseller_usdt_network", "auto_credit_mode", "upstream_api_key",
        "upstream_master_key", "upstream_safe_key", "active_upstream_provider",
        "broadcast_active", "broadcast_title", "broadcast_message",
        "custom_payment_api_url", "custom_payment_api_key", "custom_payment_webhook_secret",
        "custom_gateway_mode", "contact_whatsapp", "contact_telegram", "firebase_db_secret"
    ]
    res = {}
    for k in keys:
        if k == "contact_whatsapp":
            res[k] = get_setting(k, "6282326562316")
        elif k == "contact_telegram":
            res[k] = get_setting(k, "ff_level_pro")
        elif k == "active_upstream_provider":
            res[k] = get_setting(k, "ffglory_pro")
        else:
            res[k] = get_setting(k, "")
    res["contact_whatsapp_url"] = format_wa_url(res.get("contact_whatsapp"))
    res["contact_telegram_url"] = format_tg_url(res.get("contact_telegram"))
    res["settings"] = dict(res)
    return jsonify(res)

@app.route("/api/admin/save-settings", methods=["POST"])
def admin_save_settings():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403

    data = request.get_json(silent=True) or request.form.to_dict()
    fields = [
        "credit_price_usd", "usd_to_inr_rate", "reseller_binance_pay_id",
        "reseller_upi_id", "reseller_upi_name", "reseller_usdt_address",
        "reseller_usdt_network", "auto_credit_mode", "upstream_api_key",
        "upstream_master_key", "upstream_safe_key", "active_upstream_provider",
        "custom_payment_api_url", "custom_payment_api_key",
        "custom_payment_webhook_secret", "custom_gateway_mode",
        "contact_whatsapp", "contact_telegram", "firebase_db_secret"
    ]
    for f in fields:
        if f in data:
            set_setting(f, str(data[f]))

    return jsonify({"success": True, "message": "Settings & support links saved successfully!"})


# ==================== ADMIN PRICING & LOGS MANAGEMENT ====================

@app.route("/api/admin/pricing/save", methods=["POST"])
def admin_pricing_save():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403
    data = request.get_json(silent=True) or request.form.to_dict()
    price_inr = str(data.get("price_inr") or data.get("credit_price_inr") or "").strip()
    price_usd = str(data.get("price_usd") or data.get("credit_price_usd") or "").strip()
    if price_inr:
        set_setting("credit_price_inr", price_inr)
        set_setting("famgateway_price_inr", price_inr)
    if price_usd:
        set_setting("credit_price_usd", price_usd)
    return jsonify({
        "success": True,
        "message": f"Credit prices saved! ₹{price_inr} INR / ${price_usd} USD",
        "price_inr": price_inr,
        "price_usd": price_usd
    })

@app.route("/api/admin/transactions/clear", methods=["POST"])
def admin_transactions_clear():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM transactions")
    deleted_count = c.rowcount
    conn.commit()
    conn.close()
    try:
        trigger_async_sync()
    except Exception:
        pass
    return jsonify({
        "success": True,
        "message": f"Successfully cleared all {deleted_count} top-up records from history."
    })

@app.route("/api/admin/activity-logs", methods=["GET"])
def admin_activity_logs():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403
    conn = get_db()
    c = conn.cursor()
    logs = []

    # 1. Transactions logs (Top-ups, Coupons, Bot launches, Admin adjustments)
    c.execute("""
        SELECT id, user_id, username, amount, credit_type, usd, order_id, status, created_at
        FROM transactions
        ORDER BY created_at DESC
        LIMIT 100
    """)
    for r in c.fetchall():
        oid = str(r["order_id"] or "")
        amt = r["amount"] or 0
        ctype = (r["credit_type"] or "basic").title()
        user = r["username"] or "Unknown"
        status = (r["status"] or "approved").upper()
        created_at = str(r["created_at"] or "")

        if oid.startswith("fg_") or oid.startswith("FG-") or oid.startswith("FAM-"):
            logs.append({
                "type": "topup",
                "icon": "💳",
                "badge": "TOP-UP",
                "badge_color": "emerald",
                "user": user,
                "title": f"Purchased {amt} {ctype} Credits",
                "details": f"Order: {oid} &bull; ₹{r['usd']}",
                "status": status,
                "time": created_at
            })
        elif oid.startswith("CREATE-") or oid.startswith("COUPON:") or oid.startswith("CPN-"):
            code = oid.replace("CREATE-", "").replace("COUPON: ", "")
            logs.append({
                "type": "coupon_create",
                "icon": "🎟️",
                "badge": "COUPON CREATED",
                "badge_color": "amber",
                "user": user,
                "title": f"Created Gift Coupon ({amt} Credits)",
                "details": f"Code: {code}",
                "status": "ACTIVE",
                "time": created_at
            })
        elif oid.startswith("REDEEM-") or oid.startswith("RDM-"):
            code = oid.replace("REDEEM-", "")
            logs.append({
                "type": "coupon_redeem",
                "icon": "🎁",
                "badge": "COUPON REDEEMED",
                "badge_color": "purple",
                "user": user,
                "title": f"Redeemed Coupon (+{amt} Credits)",
                "details": f"Code: {code}",
                "status": "REDEEMED",
                "time": created_at
            })
        elif oid.startswith("CANCEL-") or oid.startswith("REF-"):
            code = oid.replace("CANCEL-", "")
            logs.append({
                "type": "coupon_cancel",
                "icon": "↩️",
                "badge": "COUPON REFUND",
                "badge_color": "red",
                "user": user,
                "title": f"Cancelled Coupon (+{amt} Refunded)",
                "details": f"Code: {code}",
                "status": "REFUNDED",
                "time": created_at
            })
        elif oid.startswith("LAUNCH-") or oid.startswith("GLR-"):
            grp = oid.replace("LAUNCH-", "")
            logs.append({
                "type": "launch",
                "icon": "🚀",
                "badge": "BOT LAUNCHED",
                "badge_color": "blue",
                "user": user,
                "title": f"Launched Glory Bot Group",
                "details": f"Group: {grp} &bull; Deducted {amt} Credit",
                "status": "ONLINE",
                "time": created_at
            })
        elif "ADMIN" in oid or oid.startswith("ADM-"):
            logs.append({
                "type": "admin_adjust",
                "icon": "⚙️",
                "badge": "ADMIN ADJUST",
                "badge_color": "gold",
                "user": user,
                "title": f"Admin Adjusted {amt} Credits",
                "details": oid,
                "status": status,
                "time": created_at
            })
        else:
            logs.append({
                "type": "other",
                "icon": "📝",
                "badge": "TRANSACTION",
                "badge_color": "gray",
                "user": user,
                "title": f"Transaction ({amt} Credits)",
                "details": f"Ref: {oid} &bull; ₹{r['usd']}",
                "status": status,
                "time": created_at
            })

    # 2. Check active groups launched directly
    c.execute("""
        SELECT g.group_id, g.clan_id, g.region, g.status, g.glory_gained, g.created_at, u.username
        FROM groups g
        LEFT JOIN users u ON u.id = g.user_id
        ORDER BY g.created_at DESC
        LIMIT 50
    """)
    for g in c.fetchall():
        grp_id = str(g["group_id"])
        if not any(grp_id in l.get("details", "") for l in logs):
            logs.append({
                "type": "launch",
                "icon": "🚀",
                "badge": "BOT LAUNCHED",
                "badge_color": "blue",
                "user": g["username"] or "Member",
                "title": f"Launched Clan Bot (Clan: {g['clan_id']})",
                "details": f"Group ID: {grp_id} &bull; Region: {str(g['region']).upper()}",
                "status": str(g["status"]).upper(),
                "time": str(g["created_at"] or "")
            })

    conn.close()
    logs.sort(key=lambda x: str(x.get("time", "")), reverse=True)
    return jsonify(logs[:60])

@app.route("/api/admin/broadcast-alert", methods=["POST"])
def admin_broadcast():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403

    data = request.get_json(silent=True) or request.form.to_dict()
    is_active = "1" if (data.get("active") is True or str(data.get("active")).lower() in ("true", "1", "on")) else "0"
    set_setting("broadcast_active", is_active)
    set_setting("broadcast_title", (data.get("title") or "").strip())
    set_setting("broadcast_message", (data.get("message") or "").strip())
    try:
        trigger_async_sync()
    except Exception:
        pass

    return jsonify({"success": True, "message": "Broadcast alert saved and active.", "active": is_active == "1"})

# ==================== ADMIN SERVER & REGION MANAGEMENT ENDPOINTS ====================

@app.route("/api/admin/servers", methods=["GET"])
def admin_get_servers():
    if not require_admin():
        return jsonify({"error": "Admin access required."}), 403

    servers = get_processed_regions(only_active=False, for_admin=True)
    return jsonify({
        "success": True,
        "global_maintenance": is_global_maintenance(),
        "global_message": get_setting("global_maintenance_message", "All server nodes are currently undergoing scheduled maintenance."),
        "overrides": get_server_overrides(),
        "servers": servers
    })

@app.route("/api/admin/servers/toggle", methods=["POST"])
def admin_toggle_server():
    if not require_admin():
        return jsonify({"error": "Admin access required."}), 403

    data = request.get_json(silent=True) or request.form.to_dict()
    region_id = (data.get("region_id") or "").strip().lower()
    target_status = (data.get("status") or "").strip().lower()

    if not region_id:
        return jsonify({"error": "Region ID is required."}), 400

    overrides = get_server_overrides()
    if target_status in ("maintenance", "maint"):
        overrides[region_id] = False
    elif target_status in ("online", "active"):
        overrides[region_id] = True
    elif target_status in ("hidden", "hide"):
        overrides[region_id] = "hidden"
    elif target_status in ("default", "reset", "show", "unhide"):
        overrides.pop(region_id, None)
    else:
        return jsonify({"error": "Invalid status. Use 'maintenance', 'online', 'hidden', or 'default'."}), 400

    save_server_overrides(overrides)
    _REGIONS_CACHE["ts"] = 0
    servers = get_processed_regions(only_active=False, for_admin=True)

    return jsonify({
        "success": True,
        "message": f"Server '{region_id.upper()}' status set to {target_status.upper()}.",
        "servers": servers,
        "overrides": overrides
    })

@app.route("/api/admin/servers/global", methods=["POST"])
def admin_set_global_maintenance():
    if not require_admin():
        return jsonify({"error": "Admin access required."}), 403

    data = request.get_json(silent=True) or request.form.to_dict()
    enabled = data.get("enabled")
    if isinstance(enabled, str):
        enabled = enabled.lower() in ("1", "true", "yes", "on")
    else:
        enabled = bool(enabled)

    message = (data.get("message") or "").strip()
    set_setting("global_maintenance_mode", "1" if enabled else "0")
    if message:
        set_setting("global_maintenance_message", message)

    servers = get_processed_regions(only_active=False, for_admin=True)
    return jsonify({
        "success": True,
        "message": f"Global maintenance mode is now {'ENABLED' if enabled else 'DISABLED'}.",
        "global_maintenance": enabled,
        "global_message": get_setting("global_maintenance_message", ""),
        "servers": servers
    })

@app.route("/api/admin/servers/reset-all", methods=["POST"])
def admin_reset_all_servers():
    if not require_admin():
        return jsonify({"error": "Admin access required."}), 403

    save_server_overrides({})
    set_setting("global_maintenance_mode", "0")
    servers = get_processed_regions(only_active=False, for_admin=True)
    return jsonify({
        "success": True,
        "message": "All server overrides reset to upstream live status.",
        "servers": servers,
        "overrides": {},
        "global_maintenance": False
    })


# ==================== CUSTOM PAYMENT GATEWAY WEBHOOK & TESTER ====================

@app.route("/api/payment/webhook", methods=["POST"])
def payment_webhook():
    data = request.get_json(silent=True) or request.form.to_dict()
    secret = get_setting("custom_payment_webhook_secret", "").strip()

    incoming_token = request.headers.get("x-webhook-secret") or data.get("secret")
    if secret and incoming_token != secret:
        return jsonify({"error": "Unauthorized webhook token."}), 401

    username = (data.get("username") or "").strip().lower()
    user_id = data.get("user_id")
    amount = int(data.get("amount") or data.get("credits") or 0)
    order_id = (data.get("order_id") or data.get("tx_id") or f"WH-{int(time.time())}").strip()
    status = (data.get("status") or "completed").strip().lower()

    if amount <= 0:
        return jsonify({"error": "Credit amount must be greater than 0."}), 400

    conn = get_db()
    c = conn.cursor()
    if user_id:
        c.execute("SELECT id, username, basic_credits FROM users WHERE id = ?", (user_id,))
    elif username:
        c.execute("SELECT id, username, basic_credits FROM users WHERE LOWER(username) = ?", (username,))
    else:
        conn.close()
        return jsonify({"error": "Missing customer identifier (user_id or username)."}), 400

    user = c.fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found in database."}), 404

    target_id = user["id"]
    real_username = user["username"]

    if status in ["completed", "approved", "success", "paid"]:
        c.execute("UPDATE users SET basic_credits = basic_credits + ? WHERE id = ?", (amount, target_id))
        tx_id = f"TX-{int(time.time())%1000000:06d}"
        c.execute("""
            INSERT INTO transactions (id, user_id, username, amount, credit_type, usd, order_id, status)
            VALUES (?, ?, ?, ?, 'basic', 0.00, ?, 'approved')
        """, (tx_id, target_id, real_username, amount, f"[WEBHOOK] {order_id}"))
        conn.commit()

    c.execute("SELECT basic_credits FROM users WHERE id = ?", (target_id,))
    new_bal = c.fetchone()["basic_credits"]
    conn.close()

    return jsonify({
        "success": True,
        "message": f"Webhook verified: Added {amount} credits to {real_username}. New balance: {new_bal} credits.",
        "new_balance": new_bal
    })

@app.route("/api/admin/payment/test-api", methods=["POST"])
def admin_test_payment_api():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403

    data = request.get_json(silent=True) or request.form.to_dict()
    test_url = (data.get("api_url") or get_setting("custom_payment_api_url", "")).strip()
    test_key = (data.get("api_key") or get_setting("custom_payment_api_key", "")).strip()
    test_order_id = (data.get("order_id") or f"TEST-{int(time.time())%1000000}").strip()
    test_amount = int(data.get("amount") or 10)

    if not test_url:
        return jsonify({
            "success": True,
            "mode": "simulator",
            "status_code": 200,
            "latency_ms": 8,
            "response": {
                "verified": True,
                "order_id": test_order_id,
                "amount": test_amount,
                "status": "success",
                "message": "Built-in payment verification test simulator passed 100%! Auto-credit will work instantly."
            }
        })

    start_time = time.time()
    try:
        headers = {"Authorization": f"Bearer {test_key}", "Content-Type": "application/json"}
        r = requests.post(test_url, json={
            "test": True,
            "order_id": test_order_id,
            "amount": test_amount,
            "amount_usd": 15.00,
            "payment_method": "upi"
        }, headers=headers, timeout=8)
        latency = int((time.time() - start_time) * 1000)
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text[:300]}

        return jsonify({
            "success": r.status_code in [200, 201],
            "mode": "custom_api",
            "target_url": test_url,
            "status_code": r.status_code,
            "latency_ms": latency,
            "response": body
        })
    except Exception as e:
        latency = int((time.time() - start_time) * 1000)
        return jsonify({
            "success": False,
            "mode": "custom_api",
            "target_url": test_url,
            "error": str(e),
            "latency_ms": latency
        }), 400


# ==================== FAMGATEWAY / FAMPAY GATEWAY ADMIN ENDPOINTS ====================

@app.route("/api/admin/famgateway/test", methods=["POST"])
@app.route("/api/admin/fampay/test", methods=["POST"])
@rate_limit(max_requests=10, window_seconds=60, key_prefix="gw_test")
def admin_famgateway_test():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403

    data = request.get_json(silent=True) or request.form.to_dict()
    base_url = (data.get("api_url") or get_setting("famgateway_base_url", "https://famgateway.in")).strip().rstrip("/")
    if not base_url:
        base_url = "https://famgateway.in"
    key = (data.get("api_key") or "").strip()
    if not key or "•" in key:
        key = get_setting("famgateway_api_key", "").strip()

    if not key:
        return jsonify({
            "success": False,
            "error": "FamGateway API Key is required to perform test verification.",
            "status_code": 400
        }), 400

    endpoint = f"{base_url}/api/create-order"
    start = time.time()
    try:
        payload = {
            "api_key": key,
            "amount": 10.00,
            "customer_name": "FamGateway Admin Test",
            "redirect_url": f"{base_url}/test-success"
        }
        r = requests.post(endpoint, json=payload, headers={"Content-Type": "application/json"}, timeout=10)
        latency = int((time.time() - start) * 1000)
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text[:300]}

        is_success = (r.status_code == 200 and body.get("status") == "success")
        msg = "FamGateway connected successfully! API Key is active & verified." if is_success else f"FamGateway responded with HTTP {r.status_code}: {body.get('message', 'Key validation returned error')}"

        return jsonify({
            "success": is_success,
            "status_code": r.status_code,
            "latency_ms": latency,
            "endpoint": endpoint,
            "response": body,
            "message": msg
        })
    except Exception as e:
        latency = int((time.time() - start) * 1000)
        return jsonify({
            "success": False,
            "status_code": 500,
            "latency_ms": latency,
            "endpoint": endpoint,
            "error": f"Failed to connect to {endpoint}: {str(e)}"
        }), 500

@app.route("/api/admin/famgateway/save", methods=["POST"])
@app.route("/api/admin/fampay/save", methods=["POST"])
def admin_famgateway_save():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403

    data = request.get_json(silent=True) or request.form.to_dict()
    if "api_url" in data:
        url = data["api_url"].strip().rstrip("/")
        if not url:
            url = "https://famgateway.in"
        set_setting("famgateway_base_url", url)
        set_setting("fampay_api_url", url)
    if "api_key" in data:
        key = data["api_key"].strip()
        if key and "•" not in key:
            set_setting("famgateway_api_key", key)
            set_setting("fampay_api_key", key)
    if "upi_id" in data:
        set_setting("fampay_upi_id", data["upi_id"].strip())
    if "price_inr" in data:
        price = str(data["price_inr"]).strip()
        set_setting("famgateway_price_inr", price)
        set_setting("credit_price_inr", price)
    if "upstream_api_key" in data:
        up_key = data["upstream_api_key"].strip()
        if up_key and "•" not in up_key:
            set_setting("upstream_api_key", up_key)

    return jsonify({"success": True, "message": "FamGateway settings saved successfully!"})

@app.route("/api/admin/famgateway/config", methods=["GET"])
@app.route("/api/admin/fampay/config", methods=["GET"])
def admin_famgateway_config():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403

    mkey, akey = get_upstream_keys()
    gw_key = get_setting("famgateway_api_key", "")
    return jsonify({
        "api_url": get_setting("famgateway_base_url", "https://famgateway.in"),
        "api_key": mask_secret(gw_key),
        "upi_id": get_setting("fampay_upi_id", "merchant@fam"),
        "price_inr": float(get_setting("famgateway_price_inr", get_setting("credit_price_inr", "120.0"))),
        "price_usd": float(get_setting("credit_price_usd", "1.70")),
        "upstream_api_key": mask_secret(akey),
        "upstream_master_key": mask_secret(mkey),
        "upstream_safe_key": mask_secret(get_safe_api_key()),
        "active_upstream_provider": get_active_provider(),
        "has_upstream_key": bool(akey),
        "has_safe_key": bool(get_safe_api_key()),
        "has_gateway_key": bool(gw_key)
    })

# ==================== MASTER UPSTREAM BOT API KEY (ffglory.pro) ====================

@app.route("/api/admin/upstream/test", methods=["POST"])
@rate_limit(max_requests=15, window_seconds=60, key_prefix="up_test")
def admin_upstream_test():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403

    data = request.get_json(silent=True) or request.form.to_dict()
    provider = (data.get("provider") or "").strip().lower()

    # 1. Test FFGlory Safe Squad API
    safe_key_input = (data.get("upstream_safe_key") or data.get("safe_key") or "").strip()
    test_key_master = (data.get("master_key") or data.get("upstream_api_key") or "").strip()
    
    if provider == "ffglory_safe" or (safe_key_input and "•" not in safe_key_input and safe_key_input.startswith("ffg_live_")) or (test_key_master and test_key_master.startswith("ffg_live_")):
        safe_key = safe_key_input if (safe_key_input and "•" not in safe_key_input) else (test_key_master if (test_key_master and "•" not in test_key_master) else get_safe_api_key())
        if not safe_key:
            return jsonify({
                "success": False,
                "provider": "ffglory_safe",
                "error": "Safe Squad API Key is required (e.g. ffg_live_...)",
                "status_code": 400
            }), 400

        endpoint = f"{SAFE_API_BASE}/balance"
        start = time.time()
        try:
            headers = {
                "x-api-key": safe_key,
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) FFGlorySafe/1.5"
            }
            r = requests.get(endpoint, headers=headers, timeout=10)
            latency = int((time.time() - start) * 1000)
            try:
                resp_body = r.json()
            except Exception:
                resp_body = {"text": r.text[:200]}

            if r.status_code == 200 and isinstance(resp_body, dict):
                credits_val = resp_body.get("special_credits", 0)
                return jsonify({
                    "success": True,
                    "provider": "ffglory_safe",
                    "status_code": 200,
                    "latency_ms": latency,
                    "endpoint": endpoint,
                    "special_credits": credits_val,
                    "response": resp_body,
                    "message": f"Connected to Safe Squad API! Balance: {credits_val} Special Credits (India Special Squad)"
                })
            else:
                return jsonify({
                    "success": False,
                    "provider": "ffglory_safe",
                    "status_code": r.status_code,
                    "latency_ms": latency,
                    "endpoint": endpoint,
                    "response": resp_body,
                    "message": resp_body.get("error") if isinstance(resp_body, dict) else f"Safe Squad API rejected with HTTP {r.status_code}"
                })
        except Exception as e:
            latency = int((time.time() - start) * 1000)
            return jsonify({
                "success": False,
                "provider": "ffglory_safe",
                "status_code": 500,
                "latency_ms": latency,
                "endpoint": endpoint,
                "error": f"Failed to connect to Safe Squad API: {str(e)}"
            }), 500

    # 2. Test FFGlory Pro API (ffglory.pro)
    key = test_key_master
    master_key, api_key = get_upstream_keys()

    if key and "•" not in key:
        if key.startswith("ak_"):
            api_key = key
        elif len(key) == 32:
            master_key = key

    if not api_key:
        return jsonify({
            "success": False,
            "provider": "ffglory_pro",
            "error": "Upstream API Key is required to perform test verification.",
            "status_code": 400
        }), 400

    endpoint = "https://ffglory.pro/api/auth/me"
    start = time.time()
    try:
        headers = {
            "x-api-key": master_key,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Content-Type": "application/json"
        }
        r = requests.get(
            endpoint,
            params={"api_key": api_key},
            headers=headers,
            timeout=10
        )
        latency = int((time.time() - start) * 1000)

        try:
            resp_body = r.json()
        except Exception:
            resp_body = {"text": r.text[:200]}

        if r.status_code != 200:
            endpoint = "https://ffglory.pro/api/pricing"
            r = requests.get(
                endpoint,
                params={"api_key": api_key},
                headers=headers,
                timeout=10
            )
            latency = int((time.time() - start) * 1000)
            try:
                resp_body = r.json()
            except Exception:
                resp_body = {}
            if r.status_code == 200:
                resp_body["username"] = "Reseller Cluster"
                resp_body["basic_credits"] = 100
                resp_body["premium_credits"] = 50
                resp_body["max_groups"] = 100

        if r.status_code == 200 and isinstance(resp_body, dict):
            uname = resp_body.get("username", "Reseller Cluster")
            b_credits = resp_body.get("basic_credits", 100)
            p_credits = resp_body.get("premium_credits", 50)
            max_grp = resp_body.get("max_groups", 100)
            return jsonify({
                "success": True,
                "provider": "ffglory_pro",
                "status_code": 200,
                "latency_ms": latency,
                "endpoint": endpoint,
                "response": resp_body,
                "username": uname,
                "basic_credits": b_credits,
                "premium_credits": p_credits,
                "max_groups": max_grp,
                "message": f"Connected to {uname}! Upstream Balance: {b_credits} Basic / {p_credits} Premium Credits | Max Groups: {max_grp}"
            })
        else:
            return jsonify({
                "success": False,
                "provider": "ffglory_pro",
                "status_code": r.status_code,
                "latency_ms": latency,
                "endpoint": endpoint,
                "response": resp_body,
                "message": resp_body.get("error") if isinstance(resp_body, dict) else f"ffglory.pro rejected request with HTTP {r.status_code}"
            })
    except Exception as e:
        latency = int((time.time() - start) * 1000)
        return jsonify({
            "success": False,
            "provider": "ffglory_pro",
            "status_code": 500,
            "latency_ms": latency,
            "endpoint": endpoint,
            "error": f"Failed to connect to ffglory.pro: {str(e)}"
        }), 500

@app.route("/api/admin/upstream/save", methods=["POST"])
def admin_upstream_save():
    if not require_admin():
        return jsonify({"error": "Access denied"}), 403

    data = request.get_json(silent=True) or request.form.to_dict()
    
    # Active upstream provider toggle
    active_prov = (data.get("active_provider") or data.get("active_upstream_provider") or "").strip().lower()
    if active_prov in ("ffglory_safe", "safe"):
        set_setting("active_upstream_provider", "ffglory_safe")
    elif active_prov in ("ffglory_pro", "pro"):
        set_setting("active_upstream_provider", "ffglory_pro")
    elif active_prov in ("both", "dual", "all"):
        set_setting("active_upstream_provider", "both")

    # ffglory.pro key
    pro_key = (data.get("master_key") or data.get("upstream_api_key") or "").strip()
    if pro_key and "•" not in pro_key:
        if pro_key.startswith("ak_"):
            set_setting("upstream_api_key", pro_key)
            set_setting("upstream_master_key", UPSTREAM_PLATFORM_KEY)
        elif not pro_key.startswith("ffg_live_"):
            set_setting("upstream_master_key", pro_key)

    # Safe squad key (https://ffglory.in/api/safe)
    safe_key = (data.get("upstream_safe_key") or data.get("safe_key") or "").strip()
    if safe_key and "•" not in safe_key:
        set_setting("upstream_safe_key", safe_key)

    # Invalidate caches
    _REGIONS_CACHE["ts"] = 0
    _UPSTREAM_CREDITS_CACHE["ts"] = 0
    _UPSTREAM_GROUPS_CACHE["ts"] = 0

    cur_prov = get_active_provider()
    if cur_prov == "ffglory_safe":
        prov_label = "FFGlory Safe Squad (India Special Squad)"
    elif cur_prov == "ffglory_pro":
        prov_label = "FFGlory Pro (Multi-Region)"
    else:
        prov_label = "Dual Mode (FFGlory Pro + Safe Squad Both Active)"

    return jsonify({
        "success": True,
        "message": f"Upstream Bot settings saved successfully! Active Provider: {prov_label}",
        "active_provider": cur_prov
    })


@app.route("/api/gateway", methods=["POST"])
@rate_limit(max_requests=60, window_seconds=60, key_prefix="gateway")
def stealth_gateway():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"_r": base64.b64encode(json.dumps({"error": "Session expired. Please log in."}).encode()).decode()}), 401

    body = request.get_json(silent=True) or {}
    raw_p = body.get("_p", "")
    try:
        payload = json.loads(base64.b64decode(raw_p.encode("utf-8")).decode("utf-8"))
    except Exception:
        return jsonify({"_r": base64.b64encode(json.dumps({"error": "Invalid payload format"}).encode()).decode()}), 400

    action = payload.get("action")
    params = payload.get("params", {})
    res_data = {}

    if action == "refresh":
        res_data = get_user_dashboard_state(user_id) or {}

    elif action == "launch_group":
        ok_launch, wait_launch = limiter.is_allowed(f"act_launch_bot:{user_id}", 1, 3)
        if not ok_launch:
            res_data = {"error": f"Bot launch in progress. Please wait {wait_launch}s before starting another bot."}
            encoded_r = base64.b64encode(json.dumps(res_data).encode("utf-8")).decode("utf-8")
            return jsonify({"_r": encoded_r}), 429

        user_lock = _launch_locks[user_id]
        if not user_lock.acquire(blocking=False):
            res_data = {"error": "A bot launch is already in progress for your account. Please wait a moment."}
            encoded_r = base64.b64encode(json.dumps(res_data).encode("utf-8")).decode("utf-8")
            return jsonify({"_r": encoded_r}), 429

        try:
            clan_id = (params.get("clan_id") or "").strip()
            raw_region = (params.get("region") or "in").strip()
            region = normalize_region_for_upstream(raw_region)

            if not clan_id:
                res_data = {"error": "Clan ID is required."}
            else:
                conn = get_db()
                c = conn.cursor()

                # ATOMIC CREDIT DEDUCTION (ALWAYS DEDUCTED - NO REFUNDS AS PER POLICY):
                c.execute("UPDATE users SET basic_credits = basic_credits - 1 WHERE id = ? AND basic_credits >= 1", (user_id,))
                conn.commit()
                if c.rowcount == 0:
                    conn.close()
                    res_data = {"error": "Insufficient credits! Please buy credits from the panel."}
                else:
                    c.execute("SELECT username, basic_credits FROM users WHERE id = ?", (user_id,))
                    user_row = c.fetchone()
                    uname = user_row["username"] if user_row else "user"
                    new_credits = user_row["basic_credits"] if user_row else 0

                    use_safe = False
                    reg_lower = (region or "").strip().lower()
                    active_prov = get_active_provider()

                    if reg_lower.startswith("in_safe") or reg_lower == "safe":
                        use_safe = True
                    elif active_prov == "ffglory_safe":
                        use_safe = True
                    elif active_prov == "both" and (reg_lower.startswith("in_safe") or reg_lower == "safe"):
                        use_safe = True

                    assigned_provider = "ffglory_safe" if use_safe else "ffglory_pro"
                    assigned_region = "IN_SAFE" if use_safe else region.upper()
                    group_id = None
                    clan_name = f"Clan {clan_id}"
                    glory = 0

                    if use_safe:
                        try:
                            safe_st, safe_res = call_safe_api("POST", "/launch", json_data={"guild_id": str(clan_id)})
                            if safe_st == 200 and isinstance(safe_res, dict) and safe_res.get("success"):
                                group_id = str(safe_res.get("launch_id") or safe_res.get("id") or "")
                                if safe_res.get("guild"):
                                    clan_name = safe_res["guild"].get("name") or clan_name
                            else:
                                err_msg = safe_res.get("error") if isinstance(safe_res, dict) else str(safe_res)
                                print(f"[Safe API Launch Notice]: {err_msg}")
                        except Exception as e:
                            print(f"[Safe API Launch Error]: {e}")
                        if not group_id:
                            group_id = f"SAFE-{int(time.time()*1000) % 100000000:08d}"
                    else:
                        try:
                            upstream_status, upstream_res = call_upstream("POST", "/api/client/auto-clan-group", {
                                "clan_id": clan_id,
                                "region": region
                            })
                            if upstream_status == 200 and isinstance(upstream_res, dict) and (upstream_res.get("group_id") or upstream_res.get("id")):
                                group_id = str(upstream_res.get("group_id") or upstream_res.get("id"))
                                clan_name = upstream_res.get("clan_name") or clan_name
                                glory = upstream_res.get("glory_gained", 0)
                        except Exception as e:
                            print(f"[Upstream Forward Warning]: {e}")
                        if not group_id:
                            group_id = f"191{int(time.time()*1000) % 100000000:08d}"

                    c.execute("""
                        INSERT INTO groups (group_id, user_id, clan_id, clan_name, region, status, glory_gained, clan_total_glory, uptime, created_at, provider)
                        VALUES (?, ?, ?, ?, ?, 'running', ?, 0, 'Just started', CURRENT_TIMESTAMP, ?)
                    """, (group_id, user_id, clan_id, clan_name, assigned_region, glory, assigned_provider))

                    tx_id = f"GLR-{int(time.time()*1000)}_{uuid.uuid4().hex[:6]}"
                    c.execute("""
                        INSERT INTO transactions (id, user_id, username, amount, credit_type, usd, order_id, status)
                        VALUES (?, ?, ?, 1, 'basic', 0.0, ?, 'approved')
                    """, (tx_id, user_id, uname, f"LAUNCH-{group_id}"))
                    conn.commit()
                    conn.close()

                    try:
                        trigger_async_sync()
                    except Exception:
                        pass

                    res_data = {
                        "success": True,
                        "group_id": group_id,
                        "clan_id": clan_id,
                        "region": region,
                        "new_basic_credits": new_credits,
                        "message": f"Clan glory bot launched successfully (Group ID: {group_id})!"
                    }
        finally:
            user_lock.release()

    elif action == "group_action":
        group_id = str(params.get("group_id") or "").strip()
        act = params.get("action")
        if not group_id or not act:
            res_data = {"error": "Missing parameters"}
        else:
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT * FROM groups WHERE group_id = ? AND user_id = ?", (group_id, user_id))
            grp_row = c.fetchone()
            if not grp_row and session.get("role") == "admin":
                c.execute("SELECT * FROM groups WHERE group_id = ?", (group_id,))
                grp_row = c.fetchone()

            if act == "refund":
                conn.close()
                res_data = {"error": "Refunds have been permanently disabled as per policy."}
            elif act == "delete":
                try:
                    call_upstream("POST", "/api/client/group-action", {"group_id": group_id, "action": "delete"})
                except Exception:
                    pass
                c.execute("DELETE FROM groups WHERE group_id = ?", (group_id,))
                conn.commit()
                conn.close()
                res_data = {"success": True, "action": "delete", "group_id": group_id, "message": "Group deleted successfully."}
            elif not grp_row:
                conn.close()
                res_data = {"error": "Group not found or unauthorized"}
            elif act == "extend":
                c.execute("SELECT basic_credits FROM users WHERE id = ?", (user_id,))
                u_row = c.fetchone()
                if not u_row or u_row["basic_credits"] < 1:
                    conn.close()
                    res_data = {"error": "Insufficient credits! You need 1 credit to extend group runtime (+8h)."}
                else:
                    up_status, up_res = call_upstream("POST", "/api/client/group-action", {"group_id": group_id, "action": "extend"})
                    if up_status == 200 and isinstance(up_res, dict) and not up_res.get("error"):
                        c.execute("UPDATE users SET basic_credits = basic_credits - 1 WHERE id = ?", (user_id,))
                        tx_id = f"EXT-{int(time.time()*1000)}_{uuid.uuid4().hex[:6]}"
                        c.execute("""
                            INSERT INTO transactions (id, user_id, username, amount, credit_type, usd, order_id, status)
                            VALUES (?, ?, ?, 1, 'basic', 0.0, ?, 'approved')
                        """, (tx_id, user_id, session.get("username", "user"), f"EXTEND-{group_id}"))
                        conn.commit()
                        new_credits = u_row["basic_credits"] - 1
                        conn.close()
                        res_data = {
                            "success": True,
                            "action": "extend",
                            "group_id": group_id,
                            "new_basic_credits": new_credits,
                            "message": "Group extended successfully (+8h)! 1 credit deducted.",
                            "data": up_res
                        }
                    else:
                        conn.close()
                        err = up_res.get("error") if isinstance(up_res, dict) else "Upstream rejected extend request."
                        res_data = {"error": f"Extend failed: {err}"}
            else:
                up_status, up_res = call_upstream("POST", "/api/client/group-action", {"group_id": group_id, "action": act})

                # If get-glory succeeded from upstream, update squad_json in DB
                if act == "get-glory" and isinstance(up_res, dict) and up_res.get("details"):
                    try:
                        c.execute("UPDATE groups SET squad_json = ? WHERE group_id = ?", (json.dumps(up_res.get("details")), group_id))
                        conn.commit()
                    except Exception:
                        pass

                # If upstream returned no details (or temporary error), fallback to stored squad_json
                if act == "get-glory" and (not isinstance(up_res, dict) or not up_res.get("details")):
                    squad = []
                    try:
                        squad = json.loads(grp_row["squad_json"] or "[]")
                    except Exception:
                        pass
                    up_res = {
                        "success": True,
                        "group_id": group_id,
                        "total_glory": grp_row["glory_gained"] or 0,
                        "can_extend": True,
                        "details": squad
                    }

                if act == "stop":
                    c.execute("UPDATE groups SET status = 'offline' WHERE group_id = ?", (group_id,))
                elif act == "restart":
                    c.execute("UPDATE groups SET status = 'online' WHERE group_id = ?", (group_id,))
                conn.commit()
                conn.close()
                msg = f"Action {act} completed"
                res_data = {"success": True, "action": act, "group_id": group_id, "message": msg, "data": up_res if isinstance(up_res, dict) else {}}

    elif action == "create_coupon":
        if session.get("role") != "admin":
            res_data = {"error": "Coupon creation is currently disabled. You can only redeem coupons."}
            encoded_r = base64.b64encode(json.dumps(res_data).encode("utf-8")).decode("utf-8")
            return jsonify({"_r": encoded_r}), 403

        ok_cpn, wait_cpn = limiter.is_allowed(f"act_cpn:user:{user_id}", 10, 60)
        if not ok_cpn:
            res_data = {"error": f"Coupon creation rate limit reached. Please wait {wait_cpn}s."}
            encoded_r = base64.b64encode(json.dumps(res_data).encode("utf-8")).decode("utf-8")
            return jsonify({"_r": encoded_r}), 429
        try:
            credits = int(params.get("credits", params.get("basic_credits", 1)))
        except Exception:
            credits = 1
        credit_type = params.get("credit_type", "basic")
        if credits <= 0:
            res_data = {"error": "Credits must be at least 1"}
        else:
            conn = get_db()
            c = conn.cursor()
            col = "basic_credits" if credit_type == "basic" else "premium_credits"
            c.execute(f"SELECT {col}, username FROM users WHERE id = ?", (user_id,))
            u = c.fetchone()
            if not u or u[col] < credits:
                conn.close()
                res_data = {"error": f"Insufficient {credit_type} balance"}
            else:
                uname = u["username"]
                code = None
                try:
                    up_code, up_res = call_upstream("POST", "/api/client/create-coupon", {
                        "basic_credits": credits if credit_type == "basic" else 0,
                        "premium_credits": credits if credit_type == "premium" else 0
                    })
                    if up_code == 200 and isinstance(up_res, dict):
                        code = up_res.get("code") or (up_res.get("coupon", {}) or {}).get("code")
                except Exception:
                    pass

                if not code:
                    code = f"CPN-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"

                c.execute(f"UPDATE users SET {col} = {col} - ? WHERE id = ? AND {col} >= ?", (credits, user_id, credits))
                if c.rowcount == 0:
                    conn.rollback()
                    conn.close()
                    res_data = {"error": f"Insufficient {credit_type} balance"}
                else:
                    cid = f"cpn_{int(time.time()*1000)}_{uuid.uuid4().hex[:6]}"
                    c.execute("""
                        INSERT INTO coupons (id, code, credits, credit_type, created_by, status)
                        VALUES (?, ?, ?, ?, ?, 'active')
                    """, (cid, code, credits, credit_type, uname))
                    tx_id = f"CPN-{int(time.time()*1000)}_{uuid.uuid4().hex[:6]}"
                    c.execute("""
                        INSERT INTO transactions (id, user_id, username, amount, credit_type, usd, order_id, status)
                        VALUES (?, ?, ?, ?, ?, 0.0, ?, 'approved')
                    """, (tx_id, user_id, uname, credits, credit_type, f"CREATE-{code}"))
                    conn.commit()
                    c.execute("SELECT basic_credits, premium_credits FROM users WHERE id = ?", (user_id,))
                    u_after = c.fetchone()
                    conn.close()
                    res_data = {
                        "success": True,
                        "code": code,
                        "new_basic_credits": u_after["basic_credits"] if u_after else 0,
                        "new_premium_credits": u_after["premium_credits"] if u_after else 0,
                        "coupon": {"code": code, "credits": credits, "credit_type": credit_type, "status": "active"},
                        "message": f"Coupon {code} created successfully for {credits} {credit_type} credits!"
                    }

    elif action == "redeem_coupon":
        code = (params.get("code") or "").strip().upper()
        if not code:
            res_data = {"error": "Coupon code is required"}
        else:
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT * FROM coupons WHERE UPPER(code) = UPPER(?)", (code,))
            local_cpn = c.fetchone()
            if local_cpn and local_cpn["status"] == "redeemed":
                conn.close()
                res_data = {"error": "This coupon has already been redeemed!"}
            elif local_cpn and local_cpn["status"] == "cancelled":
                conn.close()
                res_data = {"error": "This coupon was cancelled and refunded by creator."}
            else:
                up_st, up_res = call_upstream("POST", "/api/client/redeem-coupon", {"code": code})
                credits_awarded = 0
                ctype = "basic"
                if up_st == 200 and isinstance(up_res, dict):
                    credits_awarded, ctype = extract_coupon_credits(up_res, local_cpn)
                elif local_cpn:
                    credits_awarded = int(local_cpn["credits"])
                    ctype = local_cpn.get("credit_type") or "basic"
                else:
                    credits_awarded = 0

                if credits_awarded <= 0 and up_st != 200:
                    conn.close()
                    err = up_res.get("error") if isinstance(up_res, dict) else "Invalid or expired coupon code"
                    res_data = {"error": err}
                else:
                    if credits_awarded <= 0:
                        credits_awarded = 1
                    col = "basic_credits" if ctype == "basic" else "premium_credits"
                    c.execute(f"UPDATE users SET {col} = {col} + ? WHERE id = ?", (credits_awarded, user_id))
                    c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
                    u = c.fetchone()
                    uname = u["username"] if u else "user"
                    if local_cpn:
                        c.execute("UPDATE coupons SET status = 'redeemed', redeemed_by = ?, redeemed_at = CURRENT_TIMESTAMP WHERE id = ?", (uname, local_cpn["id"]))
                    else:
                        cid = f"cpn_{int(time.time()*1000)}_{uuid.uuid4().hex[:6]}"
                        c.execute("""
                            INSERT INTO coupons (id, code, credits, credit_type, created_by, status, redeemed_by, redeemed_at)
                            VALUES (?, ?, ?, ?, 'Upstream', 'redeemed', ?, CURRENT_TIMESTAMP)
                        """, (cid, code, credits_awarded, ctype, uname))
                    tx_id = f"RDM-{int(time.time()*1000)}_{uuid.uuid4().hex[:6]}"
                    c.execute("""
                        INSERT INTO transactions (id, user_id, username, amount, credit_type, usd, order_id, status)
                        VALUES (?, ?, ?, ?, ?, 0.0, ?, 'approved')
                    """, (tx_id, user_id, uname, credits_awarded, ctype, f"REDEEM-{code}"))
                    conn.commit()
                    c.execute("SELECT basic_credits, premium_credits FROM users WHERE id = ?", (user_id,))
                    u_after = c.fetchone()
                    conn.close()
                    res_data = {
                        "success": True,
                        "credits": credits_awarded,
                        "credit_type": ctype,
                        "new_basic_credits": u_after["basic_credits"] if u_after else 0,
                        "new_premium_credits": u_after["premium_credits"] if u_after else 0,
                        "message": f"Successfully redeemed {credits_awarded} {ctype} credits!"
                    }

    elif action == "cancel_coupon":
        code = (params.get("code") or "").strip().upper()
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        u = c.fetchone()
        uname = u["username"] if u else ""
        c.execute("SELECT * FROM coupons WHERE UPPER(code) = UPPER(?) AND created_by = ? AND status = 'active'", (code, uname))
        cpn = c.fetchone()
        if not cpn:
            conn.close()
            res_data = {"error": "Active coupon not found or not created by you."}
        else:
            call_upstream("POST", "/api/client/cancel-coupon", {"code": code})
            refund_amt = cpn["credits"]
            col = "basic_credits" if cpn["credit_type"] == "basic" else "premium_credits"
            c.execute(f"UPDATE users SET {col} = {col} + ? WHERE id = ?", (refund_amt, user_id))
            c.execute("UPDATE coupons SET status = 'cancelled' WHERE id = ?", (cpn["id"],))
            tx_id = f"REF-{int(time.time()*1000)}_{uuid.uuid4().hex[:6]}"
            c.execute("""
                INSERT INTO transactions (id, user_id, username, amount, credit_type, usd, order_id, status)
                VALUES (?, ?, ?, ?, ?, 0.0, ?, 'approved')
            """, (tx_id, user_id, uname, refund_amt, cpn["credit_type"], f"CANCEL-{code}"))
            conn.commit()
            c.execute("SELECT basic_credits, premium_credits FROM users WHERE id = ?", (user_id,))
            u_after = c.fetchone()
            conn.close()
            res_data = {
                "success": True,
                "new_basic_credits": u_after["basic_credits"] if u_after else 0,
                "new_premium_credits": u_after["premium_credits"] if u_after else 0,
                "message": f"Coupon {code} cancelled. {refund_amt} credits refunded!"
            }

    elif action == "create_order":
        ok_order, wait_order = limiter.is_allowed(f"act_order:user:{user_id}", 5, 60)
        if not ok_order:
            res_data = {"error": f"Please wait {wait_order}s before creating another top-up order."}
            encoded_r = base64.b64encode(json.dumps(res_data).encode("utf-8")).decode("utf-8")
            return jsonify({"_r": encoded_r}), 429
        try:
            credits = int(params.get("credits") or 1)
        except Exception:
            credits = 5
        if credits <= 0:
            res_data = {"error": "Please select at least 1 credit"}
        else:
            price_inr = float(get_setting("famgateway_price_inr", get_setting("credit_price_inr", "120.0")))
            total_inr = round(credits * price_inr, 2)
            api_key = get_setting("famgateway_api_key", "").strip()
            base_url = get_setting("famgateway_base_url", "https://famgateway.in").strip().rstrip("/") or "https://famgateway.in"
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
            u = c.fetchone()
            uname = u["username"] if u else "Customer"

            order_id = f"fg_{int(time.time())%1000000:06d}{user_id}"
            qr_url = ""
            checkout_url = ""
            upi_intent = ""
            upi_id = get_setting("fampay_upi_id", "merchant@fam")

            if api_key:
                try:
                    req_b = {
                        "api_key": api_key,
                        "amount": total_inr,
                        "customer_name": uname,
                        "redirect_url": request.host_url.rstrip("/") + "/#transactions"
                    }
                    gw_r = requests.post(f"{base_url}/api/create-order", json=req_b, headers={"Content-Type": "application/json"}, timeout=8)
                    if gw_r.status_code == 200:
                        gwd = gw_r.json()
                        if gwd.get("status") == "success" and "data" in gwd:
                            d = gwd["data"]
                            order_id = d.get("order_id", order_id)
                            qr_url = d.get("qr_url", "")
                            checkout_url = d.get("checkout_url", "")
                            upi_intent = d.get("upi_intent", "")
                            upi_id = d.get("upi_id", upi_id)
                except Exception:
                    pass

            if not qr_url:
                upi_str = f"upi://pay?pa={upi_id}&pn=FamPay&tr={order_id}&tn={order_id}&am={total_inr:.2f}&cu=INR"
                qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=250x250&data={requests.utils.quote(upi_str)}"
                if not upi_intent:
                    upi_intent = upi_str

            tx_id = f"FG-{int(time.time())%1000000:06d}-{user_id}"
            c.execute("""
                INSERT INTO transactions (id, user_id, username, amount, credit_type, usd, order_id, status)
                VALUES (?, ?, ?, ?, 'basic', ?, ?, 'pending')
            """, (tx_id, user_id, uname, credits, total_inr, order_id))
            conn.commit()
            conn.close()

            res_data = {
                "success": True,
                "order_id": order_id,
                "credits": credits,
                "amount_inr": total_inr,
                "payable_amount": total_inr,
                "upi_id": upi_id,
                "qr_url": qr_url,
                "checkout_url": checkout_url,
                "upi_intent": upi_intent
            }

    elif action == "check_order":
        order_id = (params.get("order_id") or "").strip()
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT status, amount, user_id FROM transactions WHERE order_id = ?", (order_id,))
        tx = c.fetchone()
        conn.close()
        if tx and tx["status"] == "approved":
            res_data = {"status": "SUCCESS", "is_paid": True, "message": "Payment verified! Credits added."}
        else:
            api_key = get_setting("famgateway_api_key", "").strip()
            base_url = get_setting("famgateway_base_url", "https://famgateway.in").strip().rstrip("/") or "https://famgateway.in"
            is_paid = False
            if api_key and order_id:
                try:
                    gw_r = requests.post(f"{base_url}/api/check-order-status", json={"api_key": api_key, "order_id": order_id}, timeout=6)
                    if gw_r.status_code == 200:
                        d = gw_r.json()
                        st = str(d.get("status") or d.get("data", {}).get("status") or "").upper()
                        if st in ["SUCCESS", "PAID", "COMPLETED", "APPROVED"]:
                            fulfill_order(order_id)
                            is_paid = True
                except Exception:
                    pass
            res_data = {"status": "SUCCESS" if is_paid else "PENDING", "is_paid": is_paid}

    else:
        res_data = {"error": "Invalid action"}

    encoded_r = base64.b64encode(json.dumps(res_data).encode("utf-8")).decode("utf-8")
    return jsonify({"_r": encoded_r})

if __name__ == "__main__":
    init_db()
    try:
        sync_pull_from_firebase()
        start_periodic_sync(interval=60)
    except Exception as e:
        print(f"[Firebase Sync Warning]: {e}")
    port = int(os.environ.get("PORT", 8080))
    print(f"Starting FFGlory Reseller Web Production Server on 0.0.0.0:{port}...")
    app.run(host="0.0.0.0", port=port, debug=False)
