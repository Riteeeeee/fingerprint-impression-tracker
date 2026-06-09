"""
================================================================
  app.py  —  NitroCommerce Cross-Site Identity Registry
  Version : 5.0.0  (Same-Hardware User Separation Fix)
================================================================

  THE BUG (v4 and earlier):
  ─────────────────────────────────────────────────────────────
  Two users on IDENTICAL M4 MacBook Air hardware received the
  SAME ntrx_ ID. Root cause was a cascade of three failures:

  FAILURE 1 — canvas + audio in make_stable_key():
    canvas hash    = SHA-256 of GPU rendering pipeline output
    audio PCM sum  = sum of DAC chip output samples
    Both are HARDWARE signals. Same GPU → same canvas hash.
    Same DAC chip → same audio PCM sum. Two people on the same
    MacBook Air model produce byte-for-byte identical values.
    Including them in the stable_key meant both users hashed
    to the same stable_key. Person A arrived first and owned it.
    Person B arrived second and was handed Person A's ID by the
    stable_key hit in Step 2.

  FAILURE 2 — gpu_renderer is hardware-level, not user-level:
    "Apple M4 GPU" is the same string for every single M4 Air.
    It differentiates hardware GENERATIONS (M1 vs M2 vs M4)
    but not USERS within the same generation.

  FAILURE 3 — screen_detail identical on same model + default scaling:
    Default macOS display scaling → same DPR (2) → same string.
    Two users who haven't touched Display Preferences produce
    the same "2560x1664x30x2" value.

  CORE INSIGHT:
  ─────────────────────────────────────────────────────────────
  No pure hardware signal can distinguish two users on the same
  hardware model. Hardware signals are per-DEVICE, not per-USER.

  The stable_key must contain at least one USER-LEVEL signal:
  one that reflects individual behavior/choices, is constant for
  the same user over time, but differs between different users.

  THE FIX (v5.0.0):
  ─────────────────────────────────────────────────────────────
  1. font_hash added to stable_key:
     Installed font enumeration is the only standard browser API
     that reflects user-level software installation history.
     Every application a user installs can add fonts to their
     system (Adobe CC, MS Office, Xcode, Final Cut Pro, design
     tools, dev environments, etc.). Two M4 MacBook Airs with
     different software installed will have different font sets →
     different font_hash → different stable_key → different IDs.

     font_hash properties:
       NOT noised by Safari (would break web font rendering)
       NOT affected by network switches
       NOT cleared by Safari cache clear
       NOT changed by OS updates (system fonts stay; only
         user-installed fonts change, and only when user acts)
       IS user-level (reflects individual software history)

  2. canvas + audio REMOVED from make_stable_key():
     They were causing the collision AND are Safari-noised on
     cache clear. They remain in the payload for fuzzy scoring
     (where their low weight is appropriate) but are NO LONGER
     part of any key hash.

  3. _context_matches() restored to hard AND:
     In v4 we weakened it to OR to fix the network-switch issue.
     That was the wrong fix for the wrong problem. Now that the
     stable_key includes font_hash (a user-level signal), two
     users on identical hardware produce different stable_keys,
     so the gatekeeper is no longer the primary collision barrier.
     We can safely restore AND because:
       - The stable_key itself won't collide between users anymore
       - The gatekeeper is a last-resort catch for the residual
         risk of two users with truly identical font sets AND
         identical hardware
       - The tz+lang AND check is correct behavior: a real user
         switching networks keeps the same tz+lang; a different
         user has a different language or (in multi-user scenarios)
         different timezone

  SIGNAL ROLES (v5):
  ─────────────────────────────────────────────────────────────
  Signal          stable_key?  fuzzy?  Notes
  ──────────────  ───────────  ──────  ────────────────────────
  font_hash       YES          YES     USER-level primary key
  gpu_renderer    YES          YES     hardware (generational)
  screen_detail   YES          YES     hardware + OS scaling
  platform        YES          YES     CPU arch
  canvas          NO           YES     Safari-noised, hw-identical
  audio           NO           YES     Safari-noised, hw-identical
  screen          NO           YES     legacy fuzzy coverage
  visitorId       NO           YES     changes on OS/cache update
  ua              NO           YES     changes on OS update
  tz              NO           gatekeeper  hard AND (restored)
  lang            NO           gatekeeper  hard AND (restored)
  cores/ram       NO           YES     hardware hint

  RESOLUTION PIPELINE (v5):
  ─────────────────────────────────────────────────────────────
  1. full_key  DB hit  → fast path (identical device + state)
  2. stable_key DB hit
       a. tz AND lang BOTH match → same user (cache/OS/network)
          → re-alias + return existing ID
       b. tz OR lang mismatch → collision guard → fall through
  3. Fuzzy match (score ≥ FUZZY_THRESHOLD=0.55)
       a. tz AND lang match → same user → re-alias + return
       b. mismatch → fall through
  4. Mint new identity

  SETUP:
  ─────────────────────────────────────────────────────────────
    pip3 install flask flask-cors
    python3 app.py
================================================================
"""

import uuid
import hashlib
import logging
import sqlite3
import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any

from flask import Flask, request, jsonify, render_template_string, Response
from flask_cors import CORS

# ── App init ──────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────

# 0.55 retained. Fuzzy is a last resort; the stable_key now handles
# same-user matching far more precisely with font_hash included.
FUZZY_THRESHOLD = 0.55

# v5 weights — font_hash is the new top-weight signal because it is
# the only USER-LEVEL discriminator. gpu_renderer and screen_detail
# retained for hardware-generation separation. canvas/audio demoted
# further (they are identical across same-hardware, Safari-noised).
WEIGHTS = {
    "font_hash"    : 0.35,   # USER-level — primary same-hardware differentiator
    "gpu_renderer" : 0.15,   # hardware generation discriminator
    "screen_detail": 0.15,   # OS scaling + geometry
    "platform"     : 0.10,   # CPU arch
    "screen"       : 0.05,   # legacy
    "canvas"       : 0.05,   # hw-identical, Safari-noised
    "audio"        : 0.05,   # hw-identical, Safari-noised
    "visitorId"    : 0.03,   # low — changes on OS/cache update
    "ua"           : 0.02,   # very low — changes on OS update
    "cores_ram"    : 0.05,   # hardware hint
}

# ── SQLite setup ──────────────────────────────────────────────

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nitro_registry.db")


def init_db() -> None:
    """
    Create the identities table and indexes. Migrates v3/v4 databases
    non-destructively by adding new columns when they don't exist.

    Columns
    ───────
    id            TEXT  — ntrx_... canonical identifier
    stable_key    TEXT  — SHA-256[:16] of font_hash+gpu_renderer+screen_detail+platform
    full_key      TEXT  — SHA-256[:16] of stable signals + visitorId + ua
    fingerprint   TEXT  — JSON blob of full incoming signal map
    font_hash     TEXT  — installed font presence bitmap hash (user-level)
    gpu_renderer  TEXT  — WebGL unmasked renderer string
    screen_detail TEXT  — w×h×depth×dpr composite
    tz            TEXT  — timezone (hard AND gatekeeper)
    lang          TEXT  — language (hard AND gatekeeper)
    created_at    TEXT  — ISO-8601 UTC
    last_seen     TEXT  — ISO-8601 UTC
    hit_count     INT
    sites_seen    TEXT  — JSON array
    """
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS identities (
                id            TEXT NOT NULL,
                stable_key    TEXT NOT NULL,
                full_key      TEXT NOT NULL,
                fingerprint   TEXT NOT NULL DEFAULT '{}',
                font_hash     TEXT NOT NULL DEFAULT '',
                gpu_renderer  TEXT NOT NULL DEFAULT '',
                screen_detail TEXT NOT NULL DEFAULT '',
                tz            TEXT NOT NULL DEFAULT '',
                lang          TEXT NOT NULL DEFAULT '',
                created_at    TEXT NOT NULL,
                last_seen     TEXT NOT NULL,
                hit_count     INTEGER NOT NULL DEFAULT 1,
                sites_seen    TEXT NOT NULL DEFAULT '[]'
            )
        """)
        # Non-destructive migration for v3/v4 databases
        for col, default in [
            ("font_hash",     "''"),
            ("gpu_renderer",  "''"),
            ("screen_detail", "''"),
        ]:
            try:
                conn.execute(
                    f"ALTER TABLE identities ADD COLUMN {col} TEXT NOT NULL DEFAULT {default}"
                )
                log.info("DB migration: added column '%s'", col)
            except sqlite3.OperationalError:
                pass  # Column already exists — no-op

        conn.execute("CREATE INDEX IF NOT EXISTS idx_full_key   ON identities(full_key)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_stable_key ON identities(stable_key)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_id         ON identities(id)")
        conn.commit()
    log.info("SQLite DB ready: %s", DB_PATH)


@contextmanager
def get_conn():
    """Thread-safe SQLite connection with WAL mode for concurrent reads."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
    finally:
        conn.close()


# ── Helpers ───────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    d["fingerprint"] = json.loads(d.get("fingerprint", "{}"))
    d["sites_seen"]  = json.loads(d.get("sites_seen",  "[]"))
    return d


# ── Key builders ─────────────────────────────────────────────

def make_stable_key(fp: dict) -> str:
    """
    Permanent identity anchor. v5 signals (4 total):

      font_hash     — SHA-256 of installed font presence bitmap
                      This is the USER-LEVEL signal. Different users
                      install different software → different fonts →
                      different hash. Invariant for the same user
                      across network switches, OS updates, cache clears.

      gpu_renderer  — WebGL unmasked renderer string
                      Differentiates hardware generations but NOT users
                      on the same model. Included for cross-generation
                      separation.

      screen_detail — w×h×colorDepth×devicePixelRatio
                      Reflects OS display scaling. Same model + same
                      scaling = same value, but included for coverage.

      platform      — CPU architecture string (e.g. "MacIntel", "arm")

    canvas + audio intentionally EXCLUDED:
      Both are pure hardware signals identical on same-model devices
      AND are Safari-noised on cache clear. They belong only in fuzzy
      scoring, never in key material.

    tz + lang intentionally EXCLUDED:
      They are contextual gatekeeper fields. Including them in the key
      would cause stable_key misses on network switches (tz can shift).

    visitorId + ua intentionally EXCLUDED:
      They change on OS/browser updates (OS update problem from v1).
    """
    raw = "|".join([
        fp.get("font_hash",     ""),   # USER-LEVEL primary discriminator
        fp.get("gpu_renderer",  ""),   # hardware generation
        fp.get("screen_detail", ""),   # OS scaling + geometry
        fp.get("platform",      ""),   # CPU arch
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def make_full_key(fp: dict) -> str:
    """
    Fast-path key: all stable signals + visitorId + ua.
    Exact-matches within the same OS lifecycle.
    Misses after cache clear / OS update → stable_key catches those.
    Network switch does NOT affect this key (tz/lang excluded).
    """
    raw = "|".join([
        fp.get("font_hash",     ""),
        fp.get("gpu_renderer",  ""),
        fp.get("screen_detail", ""),
        fp.get("platform",      ""),
        fp.get("visitorId",     ""),
        fp.get("ua",            ""),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


# ── Contextual gatekeeper (v5 — hard AND, restored from v3) ──

def _context_matches(incoming: dict, stored_tz: str, stored_lang: str) -> bool:
    """
    Hard AND gate: BOTH tz AND lang must match.

    Rationale for restoring hard AND (vs the soft OR in v4):
      In v4 we weakened this to OR to fix the network-switch issue,
      but that was treating a symptom rather than the root cause.
      The real problem was that the stable_key could collide between
      two users on the same hardware, making the gatekeeper do too
      much work.

      Now that font_hash is in the stable_key, two different users
      on the same hardware produce different stable_keys (unless they
      have identical font installations — rare). The gatekeeper is
      therefore a last-resort catch for that residual edge case, not
      the primary collision barrier.

      Hard AND is correct here because:
        • A real user switching networks keeps the same tz and lang
        • A different user (same hardware) is overwhelmingly likely
          to differ in at least one of tz or lang
        • The v4 network-switch false-positive was caused by the
          stable_key collision, not by the gatekeeper being too strict

    Empty stored values → wildcard (legacy rows from v3/v4 that lack
    context data; they re-alias and gain the new fields on first contact).
    """
    incoming_tz   = incoming.get("tz",   "").strip()
    incoming_lang = incoming.get("lang", "").strip()

    # Wildcard: legacy row with no context stored
    if not stored_tz and not stored_lang:
        return True

    tz_ok   = (not stored_tz)   or (incoming_tz   == stored_tz)
    lang_ok = (not stored_lang) or (incoming_lang == stored_lang)

    # Both must match (hard AND)
    return tz_ok and lang_ok


# ── Signal comparison for fuzzy fallback ─────────────────────

def _cmp(a: str, b: str) -> float:
    """
    1.0 for exact match. Float tolerance for audio PCM sums.
    0.0 otherwise.
    """
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    try:
        fa, fb = float(a), float(b)
        diff = abs(fa - fb) / max(abs(fb), 1e-9)
        if diff <= 0.005: return 1.0
        if diff <= 0.020: return 0.5
    except ValueError:
        pass
    return 0.0


def fuzzy_match(incoming: dict) -> Tuple[Optional[Dict], float]:
    """
    O(n) scan over unique stable_key anchors.
    v5 formula weights font_hash highest (0.35) as the USER-level signal.
    """
    inc_cr = "{}_{}".format(incoming.get("cores", "?"), incoming.get("ram", "?"))

    with get_conn() as conn:
        stable_keys = conn.execute(
            "SELECT DISTINCT stable_key FROM identities"
        ).fetchall()

        if not stable_keys:
            return None, 0.0

        best_rec, best_score = None, 0.0

        for sk_row in stable_keys:
            row = conn.execute(
                "SELECT * FROM identities WHERE stable_key = ? ORDER BY created_at ASC LIMIT 1",
                (sk_row["stable_key"],)
            ).fetchone()
            if not row:
                continue

            rec  = _row_to_dict(row)
            s    = rec["fingerprint"]
            s_cr = "{}_{}".format(s.get("cores", "?"), s.get("ram", "?"))

            score = (
                WEIGHTS["font_hash"]    * _cmp(incoming.get("font_hash",    ""), s.get("font_hash",    ""))
              + WEIGHTS["gpu_renderer"] * _cmp(incoming.get("gpu_renderer", ""), s.get("gpu_renderer", ""))
              + WEIGHTS["screen_detail"]* _cmp(incoming.get("screen_detail",""), s.get("screen_detail",""))
              + WEIGHTS["platform"]     * _cmp(incoming.get("platform",     ""), s.get("platform",     ""))
              + WEIGHTS["screen"]       * _cmp(incoming.get("screen",       ""), s.get("screen",       ""))
              + WEIGHTS["canvas"]       * _cmp(incoming.get("canvas",       ""), s.get("canvas",       ""))
              + WEIGHTS["audio"]        * _cmp(incoming.get("audio",        ""), s.get("audio",        ""))
              + WEIGHTS["visitorId"]    * _cmp(incoming.get("visitorId",    ""), s.get("visitorId",    ""))
              + WEIGHTS["ua"]           * _cmp(incoming.get("ua",           ""), s.get("ua",           ""))
              + WEIGHTS["cores_ram"]    * _cmp(inc_cr,                           s_cr)
            )
            if score > best_score:
                best_score, best_rec = score, rec

    return best_rec, best_score


# ── DB write helpers ──────────────────────────────────────────

def _update_hit(conn: sqlite3.Connection, record_id: str, origin: str) -> None:
    """Bump hit_count, last_seen, sites_seen on ALL alias rows for this id."""
    now  = _now()
    rows = conn.execute(
        "SELECT rowid, sites_seen FROM identities WHERE id = ?", (record_id,)
    ).fetchall()
    for row in rows:
        sites = json.loads(row["sites_seen"])
        if origin not in sites:
            sites.append(origin)
        conn.execute(
            "UPDATE identities SET hit_count = hit_count + 1, last_seen = ?, sites_seen = ? "
            "WHERE rowid = ?",
            (now, json.dumps(sites), row["rowid"])
        )
    conn.commit()


def _insert_alias(
    conn: sqlite3.Connection,
    canonical_id: str,
    new_stable_key: str,
    new_full_key: str,
    fp: dict,
    origin: str,
) -> None:
    """
    Insert a new alias row pointing to an existing canonical ID.
    Future requests with these keys hit Step 1 (O(1)).
    """
    now = _now()
    conn.execute("""
        INSERT INTO identities
            (id, stable_key, full_key, fingerprint,
             font_hash, gpu_renderer, screen_detail, tz, lang,
             created_at, last_seen, hit_count, sites_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
    """, (
        canonical_id,
        new_stable_key,
        new_full_key,
        json.dumps(fp),
        fp.get("font_hash",     ""),
        fp.get("gpu_renderer",  ""),
        fp.get("screen_detail", ""),
        fp.get("tz",   ""),
        fp.get("lang", ""),
        now, now,
        json.dumps([origin]),
    ))
    conn.commit()


# ── Main endpoint ─────────────────────────────────────────────

@app.route("/api/get-id", methods=["POST", "OPTIONS"])
def get_or_create():
    """
    Resolution order:

      1. full_key  DB hit
         → return ID immediately (same device, same OS state)

      2. stable_key DB hit
         a. tz AND lang BOTH match (hard AND) → same user
            (cache cleared / OS updated / network switched)
            → re-alias new full_key → return existing ID
         b. tz OR lang mismatch → collision guard → fall through

      3. Fuzzy match (score ≥ FUZZY_THRESHOLD = 0.55)
         a. tz AND lang match → same user → re-alias → return
         b. mismatch → collision guard → fall through

      4. Mint new identity
    """
    if request.method == "OPTIONS":
        return jsonify({}), 200

    if not request.is_json:
        return jsonify({"error": "application/json required"}), 400

    data   = request.get_json(force=True, silent=True) or {}
    origin = request.headers.get("Origin", "unknown")

    full_key   = make_full_key(data)
    stable_key = make_stable_key(data)

    with get_conn() as conn:

        # ── Step 1: full_key exact hit (fast path) ────────────
        row = conn.execute(
            "SELECT * FROM identities WHERE full_key = ? LIMIT 1", (full_key,)
        ).fetchone()

        if row:
            rec = _row_to_dict(row)
            _update_hit(conn, rec["id"], origin)
            log.info("FULL HIT   | %s", rec["id"])
            return jsonify({"id": rec["id"]})

        # ── Step 2: stable_key exact hit ─────────────────────
        row = conn.execute(
            "SELECT * FROM identities WHERE stable_key = ? ORDER BY created_at ASC LIMIT 1",
            (stable_key,)
        ).fetchone()

        if row:
            rec = _row_to_dict(row)

            if _context_matches(data, rec["tz"], rec["lang"]):
                _update_hit(conn, rec["id"], origin)
                _insert_alias(conn, rec["id"], stable_key, full_key, data, origin)
                log.info("STABLE HIT | %s | re-aliased (cache/OS/network change)", rec["id"])
                return jsonify({"id": rec["id"]})
            else:
                log.info(
                    "COLLISION GUARD (stable) | tz/lang mismatch | "
                    "stored=(%s,%s) incoming=(%s,%s)",
                    rec["tz"], rec["lang"],
                    data.get("tz", ""), data.get("lang", ""),
                )
                # Fall through to mint new ID

        # ── Step 3: Fuzzy match ───────────────────────────────
        fuzzy_rec, score = fuzzy_match(data)

        if fuzzy_rec and score >= FUZZY_THRESHOLD:
            if _context_matches(data, fuzzy_rec["tz"], fuzzy_rec["lang"]):
                _update_hit(conn, fuzzy_rec["id"], origin)
                _insert_alias(conn, fuzzy_rec["id"], stable_key, full_key, data, origin)
                log.info("FUZZY HIT  | score=%.2f | %s | re-aliased", score, fuzzy_rec["id"])
                return jsonify({"id": fuzzy_rec["id"]})
            else:
                log.info(
                    "COLLISION GUARD (fuzzy) | score=%.2f | tz/lang mismatch | "
                    "stored=(%s,%s) incoming=(%s,%s)",
                    score,
                    fuzzy_rec["tz"], fuzzy_rec["lang"],
                    data.get("tz", ""), data.get("lang", ""),
                )
                # Fall through to mint new ID

        # ── Step 4: Genuinely new device / user ───────────────
        new_id = "ntrx_{}_{}".format(str(uuid.uuid4()), stable_key)
        # Format: ntrx_ (5) + UUID (36) + _ (1) + stable_key (16) = 58 chars ✓

        now = _now()
        conn.execute("""
            INSERT INTO identities
                (id, stable_key, full_key, fingerprint,
                 font_hash, gpu_renderer, screen_detail, tz, lang,
                 created_at, last_seen, hit_count, sites_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        """, (
            new_id,
            stable_key,
            full_key,
            json.dumps(data),
            data.get("font_hash",     ""),
            data.get("gpu_renderer",  ""),
            data.get("screen_detail", ""),
            data.get("tz",   ""),
            data.get("lang", ""),
            now, now,
            json.dumps([origin]),
        ))
        conn.commit()

        log.info("NEW DEVICE | %s | origin=%s", new_id, origin)
        return jsonify({"id": new_id}), 201


# ── Debug endpoints ───────────────────────────────────────────

@app.route("/api/registry", methods=["GET"])
def dev_registry():
    """Dev-only: all identities deduplicated by canonical ID."""
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT id,
                   MIN(created_at)                      AS created_at,
                   MAX(last_seen)                       AS last_seen,
                   SUM(hit_count)                       AS hits,
                   GROUP_CONCAT(DISTINCT stable_key)    AS stable_keys,
                   GROUP_CONCAT(DISTINCT tz)            AS tzs,
                   GROUP_CONCAT(DISTINCT lang)          AS langs,
                   GROUP_CONCAT(DISTINCT font_hash)     AS font_hashes,
                   GROUP_CONCAT(DISTINCT gpu_renderer)  AS gpu_renderers,
                   GROUP_CONCAT(DISTINCT screen_detail) AS screen_details
            FROM identities
            GROUP BY id
            ORDER BY created_at DESC
        """).fetchall()

    records = []
    for row in rows:
        with get_conn() as conn2:
            site_rows = conn2.execute(
                "SELECT sites_seen FROM identities WHERE id = ?", (row["id"],)
            ).fetchall()
        sites: list = []
        for sr in site_rows:
            for s in json.loads(sr["sites_seen"]):
                if s not in sites:
                    sites.append(s)

        def _split(v):
            return list(set(v.split(","))) if v else []

        records.append({
            "id"            : row["id"],
            "stable_keys"   : _split(row["stable_keys"]),
            "tzs"           : _split(row["tzs"]),
            "langs"         : _split(row["langs"]),
            "font_hashes"   : _split(row["font_hashes"]),
            "gpu_renderers" : _split(row["gpu_renderers"]),
            "screen_details": _split(row["screen_details"]),
            "hits"          : row["hits"],
            "created_at"    : row["created_at"],
            "last_seen"     : row["last_seen"],
            "sites_seen"    : sites,
        })

    return jsonify({"total": len(records), "records": records})


@app.route("/api/registry/raw", methods=["GET"])
def dev_registry_raw():
    """Dev-only: all raw rows including aliases."""
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM identities ORDER BY created_at DESC").fetchall()
    return jsonify({"total": len(rows), "rows": [dict(r) for r in rows]})


@app.route("/api/clear", methods=["POST"])
def dev_clear():
    with get_conn() as conn:
        conn.execute("DELETE FROM identities")
        conn.commit()
    log.warning("Registry CLEARED")
    return jsonify({"status": "cleared"})


# ── Serve id-generator.js ─────────────────────────────────────

@app.route("/id-generator.js")
def serve_sdk():
    possible_paths = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "id-generator.js"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "id-generator.js"),
    ]
    path = None
    for p in possible_paths:
        if os.path.exists(p):
            path = p
            break
    if not path:
        log.error("CRITICAL: id-generator.js not found!")
        return "id-generator.js not found", 404
    with open(path, "r") as f:
        content = f.read()
    current_origin = request.host_url.rstrip("/")
    content = content.replace("http://localhost:8080", current_origin)
    content = content.replace("http://YOUR-SERVER-IP:8080", current_origin)
    return Response(content, mimetype="application/javascript")


@app.route("/testcase.html")
def serve_testcase():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testcase.html")
    if not os.path.exists(path):
        return "testcase.html not found", 404
    with open(path, "r") as f:
        return Response(f.read(), mimetype="text/html")


# ── Smoke-test page ───────────────────────────────────────────

_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>NitroCommerce — {{ site }}</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:#0d0d0d;color:#e0e0e0;font-family:-apple-system,Arial,sans-serif;
         display:flex;flex-direction:column;align-items:center;justify-content:center;
         min-height:100vh;gap:16px;padding:20px}
    .card{background:#1a1a2e;border:1px solid #7b61ff55;border-radius:14px;
          padding:28px 36px;max-width:660px;width:100%;text-align:center}
    h1{color:#7b61ff;font-size:1.4rem;margin-bottom:12px}
    .badge{display:inline-block;background:#7b61ff22;color:#a89fff;
           border:1px solid #7b61ff44;border-radius:6px;padding:3px 12px;
           font-size:.82rem;margin-bottom:14px}
    #identifier{font-size:.88rem;color:#a0ffa0;word-break:break-all;
                margin-top:14px;background:#111;padding:14px;border-radius:8px;
                font-family:monospace;min-height:3rem}
    .links{display:flex;gap:8px;justify-content:center;flex-wrap:wrap;margin-top:18px}
    a{background:#1a1a2e;border:1px solid #7b61ff44;color:#a89fff;padding:7px 14px;
      border-radius:8px;text-decoration:none;font-size:.82rem}
    a:hover{border-color:#7b61ff;color:#fff}
  </style>
  <script type="text/javascript" src="/id-generator.js"></script>
  <script>
    iDx.config = { serverUrl: window.location.origin, debug: true }
    iDx.onIdAquired = function(ident) {
      document.getElementById("identifier").innerHTML =
        "Id from id-generator = " + ident.toString();
    }
    window.addEventListener("DOMContentLoaded", function() {
      console.log("DOM is fully loaded! Going to acquire ID.");
    });
  </script>
</head>
<body>
  <div class="card">
    <h1>🚀 NitroCommerce Tracker</h1>
    <div class="badge">Simulating: {{ site }}</div>
    <p style="color:#888;font-size:.88rem;margin-bottom:8px">Check console for ID.</p>
    <h1 id="identifier">Acquiring ID…</h1>
    <div class="links">
      <a href="/?site=shop.com">shop.com</a>
      <a href="/?site=crow.com">crow.com</a>
      <a href="/?site=pewpie.com">pewpie.com</a>
      <a href="/api/registry" target="_blank">Registry</a>
      <a href="/api/registry/raw" target="_blank">Raw Rows</a>
      <a href="#" onclick="fetch('/api/clear',{method:'POST'}).then(()=>location.reload());return false">Clear</a>
    </div>
  </div>
</body>
</html>"""


@app.route("/")
def home():
    site = request.args.get("site", "localhost")
    return render_template_string(_HTML, site=site)


# ── Entry point ───────────────────────────────────────────────
if __name__ == "__main__":
    init_db()   # Idempotent — creates/migrates nitro_registry.db
    log.info("=" * 58)
    log.info("  NitroCommerce Identity Registry  v5.0.0")
    log.info("  http://0.0.0.0:8080")
    log.info("  Cross-site test:")
    log.info("    http://localhost:8080/?site=shop.com")
    log.info("    http://localhost:8080/?site=crow.com")
    log.info("    http://localhost:8080/?site=pewpie.com")
    log.info("  Registry:     http://localhost:8080/api/registry")
    log.info("  Raw rows:     http://localhost:8080/api/registry/raw")
    log.info("=" * 58)
    app.run(host="0.0.0.0", port=8080, debug=True)
