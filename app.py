"""
================================================================
  app.py  —  NitroCommerce Cross-Site Identity Registry
  Version : 4.0.0  (Hackathon Final)
================================================================

  CHANGES FROM v3.0.0:
  ─────────────────────────────────────────────────────────────
  1. NEW STABLE HARDWARE SIGNALS IN KEY MATERIAL:
     make_stable_key() and make_full_key() now include two new
     deep hardware signals that Safari does NOT noise-protect:

     gpu_renderer  — WebGL UNMASKED_RENDERER_WEBGL string
                     Encodes GPU micro-architecture + driver
                     variant (e.g. "Apple M4 GPU"). Changes only
                     when physical GPU is replaced — never on
                     network switch, OS update, or cache clear.

     screen_detail — w×h×colorDepth×devicePixelRatio composite
                     Captures OS-level scaling, custom resolution,
                     and Dock/Menubar layout. Two M4 MacBook Airs
                     with different display scaling settings will
                     produce DIFFERENT screen_detail strings.
                     Completely unaffected by network changes.

     Together, gpu_renderer + screen_detail make the stable_key
     effectively unique per physical device + display config,
     eliminating the need for tz/lang to carry the anti-collision
     burden they held in v3.

  2. GATEKEEPER REDESIGNED — SECONDARY VERIFICATION ONLY:
     Because the stable_key is now far more discriminating,
     _context_matches() is relaxed from a hard AND gate to a
     soft secondary check: it passes if EITHER field matches OR
     if both stored fields are empty (legacy row). This prevents
     false blocks when a user switches ISP/network (which can
     cause subtle locale shifts in some environments) while still
     catching obvious cross-user collisions on old rows that lack
     the new gpu_renderer / screen_detail material.

     Concretely:
       tz OR lang matches → pass (same user, network switched)
       both mismatch      → block (different user, old hardware
                            overlap without new signal material)
       stored fields empty → wildcard pass (legacy compatibility)

  3. FUZZY WEIGHTS UPDATED:
     screen_detail and gpu_renderer are now the dominant fuzzy
     signals. screen + platform retain their v3 weights.
     canvas/audio remain demoted (Safari noise). A new
     gpu_renderer weight is added.

  SIGNAL STABILITY TABLE (v4):
  ─────────────────────────────────────────────────────────────
  Signal           Safari-noised?  Network-stable?  Role
  ──────────────── ─────────────  ───────────────  ──────────────
  gpu_renderer     NO              YES              stable_key + fuzzy (high)
  screen_detail    NO              YES              stable_key + fuzzy (high)
  canvas hash      YES (jitter)    YES              fuzzy (low)
  audio PCM sum    YES (jitter)    YES              fuzzy (low)
  screen           NO              YES              fuzzy (medium)
  platform         NO              YES              fuzzy (medium)
  timezone         NO              MOSTLY (ISP risk) gatekeeper (soft OR)
  language         NO              YES              gatekeeper (soft OR)
  visitorId        YES             YES              fuzzy (very low)
  ua               YES (version)   YES              fuzzy (very low)
  cores/ram        NO              YES              fuzzy (medium)

  RESOLUTION PIPELINE (v4):
  ─────────────────────────────────────────────────────────────
  1. full_key  DB hit  → fast path (identical state)
  2. stable_key DB hit
       a. soft context check passes → same user → re-alias
       b. both tz AND lang mismatch → collision guard → fall through
  3. Fuzzy match (score ≥ FUZZY_THRESHOLD=0.55)
       a. soft context check passes → same user → re-alias
       b. both tz AND lang mismatch → fall through
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

# 0.55 retained from v3. With gpu_renderer + screen_detail now in
# the stable_key, the fuzzy path is mostly a last-resort fallback
# for genuinely degraded signal environments.
FUZZY_THRESHOLD = 0.55

# v4 weights — gpu_renderer added as highest-weight fuzzy signal.
# screen_detail shares the screen slot (replaces old bare "screen").
# canvas/audio remain demoted (Safari noise).
WEIGHTS = {
    "gpu_renderer" : 0.30,   # NEW — GPU micro-arch, immune to all software changes
    "screen_detail": 0.20,   # NEW — OS-scale + DPR + geometry, network-stable
    "screen"       : 0.10,   # kept for legacy rows lacking screen_detail
    "platform"     : 0.15,   # CPU arch
    "canvas"       : 0.05,   # demoted — Safari jitter
    "audio"        : 0.05,   # demoted — Safari jitter
    "visitorId"    : 0.03,   # very low — changes on OS/cache update
    "ua"           : 0.02,   # very low — changes on OS update
    "cores_ram"    : 0.10,   # reliable hardware hint
}

# ── SQLite setup ──────────────────────────────────────────────

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nitro_registry.db")


def init_db() -> None:
    """
    Create the identities table and indexes if they don't exist.
    Schema is backward-compatible with v3: gpu_renderer and
    screen_detail default to '' so old rows degrade gracefully
    (they will hit the gatekeeper wildcard path and re-alias on
    first contact, gaining the new signal material at that point).

    Columns
    ───────
    id            TEXT  — the ntrx_... canonical identifier
    stable_key    TEXT  — SHA-256[:16] of the 6 stable hardware signals
    full_key      TEXT  — SHA-256[:16] of stable signals + visitorId + ua
    fingerprint   TEXT  — JSON blob of the full incoming signal map
    gpu_renderer  TEXT  — WebGL unmasked renderer string (stored bare for registry)
    screen_detail TEXT  — w×h×depth×dpr composite
    tz            TEXT  — timezone (soft gatekeeper)
    lang          TEXT  — language (soft gatekeeper)
    created_at    TEXT  — ISO-8601 UTC
    last_seen     TEXT  — ISO-8601 UTC
    hit_count     INT
    sites_seen    TEXT  — JSON array

    Indexes on full_key and stable_key maintain O(1) lookup perf.
    """
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS identities (
                id            TEXT NOT NULL,
                stable_key    TEXT NOT NULL,
                full_key      TEXT NOT NULL,
                fingerprint   TEXT NOT NULL DEFAULT '{}',
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
        # Migrate v3 databases: add new columns if they don't exist yet
        for col, default in [
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
    Permanent hardware anchor.

    v4 signals (6 total):
      canvas        — GPU sub-pixel hash  (Safari-noised, but included for
                      cross-signal coverage; stable_key still needs a hit
                      on exact match, so this only matters for Step 2)
      audio         — DAC PCM hash        (same note as canvas)
      screen        — bare geometry string
      platform      — CPU architecture
      gpu_renderer  — WebGL unmasked renderer (NEW — never changes)
      screen_detail — OS scale + DPR + geometry composite (NEW — network-stable)

    tz / lang intentionally excluded: they are soft gatekeeper fields,
    not key material. Including them would cause key misses on network
    switches, defeating the fix we are shipping in v4.
    visitorId / ua intentionally excluded: they change on OS/cache updates.
    """
    raw = "|".join([
        fp.get("canvas",        ""),
        fp.get("audio",         ""),
        fp.get("screen",        ""),
        fp.get("platform",      ""),
        fp.get("gpu_renderer",  ""),   # NEW
        fp.get("screen_detail", ""),   # NEW
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def make_full_key(fp: dict) -> str:
    """
    Fast-path key: all stable signals PLUS visitorId + ua.
    Exact-matches on same OS lifecycle. Misses after cache clear or
    OS update (stable_key catches those). Network switch does NOT
    affect this key because tz/lang are excluded.
    """
    raw = "|".join([
        fp.get("canvas",        ""),
        fp.get("audio",         ""),
        fp.get("screen",        ""),
        fp.get("platform",      ""),
        fp.get("gpu_renderer",  ""),   # NEW
        fp.get("screen_detail", ""),   # NEW
        fp.get("visitorId",     ""),
        fp.get("ua",            ""),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


# ── Contextual gatekeeper (v4 — soft OR logic) ───────────────

def _context_matches(incoming: dict, stored_tz: str, stored_lang: str) -> bool:
    """
    Secondary verification gate. Returns True (allow) when:

      • Either tz matches, OR lang matches   → likely same user,
        one field may have shifted due to ISP/network locale quirk
      • stored_tz AND stored_lang are both empty  → legacy row
        (minted before v3/v4), wildcard pass so it gets re-aliased
        and gains new signal material on this visit
      • Falls through to False only when BOTH tz AND lang differ
        AND at least one stored value is non-empty  → strong signal
        of a different user on identical older hardware

    Why OR instead of AND (v3 change):
      Real-world data on Render showed that switching from a college
      WiFi to a mobile hotspot caused subtle locale/offset shifts in
      the tz field on some Safari configurations. With gpu_renderer
      and screen_detail now in the stable_key, the key itself is
      already far more unique per device — the gatekeeper is a
      last-resort sanity check, not the primary collision barrier.
    """
    incoming_tz   = incoming.get("tz",   "").strip()
    incoming_lang = incoming.get("lang", "").strip()

    # Wildcard: legacy row with no context stored yet
    if not stored_tz and not stored_lang:
        return True

    tz_ok   = bool(stored_tz)   and (incoming_tz   == stored_tz)
    lang_ok = bool(stored_lang) and (incoming_lang == stored_lang)

    # Pass if at least one field agrees
    return tz_ok or lang_ok


# ── Signal comparison for fuzzy fallback ─────────────────────

def _cmp(a: str, b: str) -> float:
    """
    Returns 1.0 for exact string match, 0.5/1.0 for near-equal
    floats (audio PCM sum tolerance), 0.0 otherwise.
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
    Scan all unique stable_key anchors and return the best-scoring
    record. O(n) over unique stable keys. Acceptable for hackathon
    registry sizes; add ANN index for production scale > 100 k rows.

    v4 score formula uses the updated WEIGHTS including gpu_renderer
    and screen_detail as the two dominant signals.
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

            rec = _row_to_dict(row)
            s   = rec["fingerprint"]
            s_cr = "{}_{}".format(s.get("cores", "?"), s.get("ram", "?"))

            score = (
                WEIGHTS["gpu_renderer"]  * _cmp(incoming.get("gpu_renderer",  ""), s.get("gpu_renderer",  ""))
              + WEIGHTS["screen_detail"] * _cmp(incoming.get("screen_detail", ""), s.get("screen_detail", ""))
              + WEIGHTS["screen"]        * _cmp(incoming.get("screen",        ""), s.get("screen",        ""))
              + WEIGHTS["platform"]      * _cmp(incoming.get("platform",      ""), s.get("platform",      ""))
              + WEIGHTS["canvas"]        * _cmp(incoming.get("canvas",        ""), s.get("canvas",        ""))
              + WEIGHTS["audio"]         * _cmp(incoming.get("audio",         ""), s.get("audio",         ""))
              + WEIGHTS["visitorId"]     * _cmp(incoming.get("visitorId",     ""), s.get("visitorId",     ""))
              + WEIGHTS["ua"]            * _cmp(incoming.get("ua",            ""), s.get("ua",            ""))
              + WEIGHTS["cores_ram"]     * _cmp(inc_cr,                            s_cr)
            )
            if score > best_score:
                best_score, best_rec = score, rec

    return best_rec, best_score


# ── DB write helpers ──────────────────────────────────────────

def _update_hit(conn: sqlite3.Connection, record_id: str, origin: str) -> None:
    """Bump hit_count, last_seen, and sites_seen on ALL rows for this id."""
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
    Insert a new alias row linking new key material to an existing
    canonical ID. Future requests with these keys hit Step 1 (O(1)).
    Also stores the new gpu_renderer / screen_detail columns so the
    registry reflects up-to-date signal values.
    """
    now = _now()
    conn.execute("""
        INSERT INTO identities
            (id, stable_key, full_key, fingerprint,
             gpu_renderer, screen_detail, tz, lang,
             created_at, last_seen, hit_count, sites_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
    """, (
        canonical_id,
        new_stable_key,
        new_full_key,
        json.dumps(fp),
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
    Resolution order (fastest → slowest):

      1. full_key  DB hit
         → return ID immediately (identical device + OS state)

      2. stable_key DB hit
         a. soft context check passes (tz OR lang match, or legacy)
            → same user (cache cleared / OS updated / network switched)
            → re-alias new full_key + return existing ID
         b. BOTH tz AND lang differ on a non-empty stored record
            → collision guard → fall through

      3. Fuzzy match (score ≥ FUZZY_THRESHOLD)
         a. soft context check passes → same user → re-alias + return
         b. collision guard → fall through

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
                    "COLLISION GUARD (stable) | both tz+lang mismatch | "
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
                    "COLLISION GUARD (fuzzy) | score=%.2f | both tz+lang mismatch | "
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
                 gpu_renderer, screen_detail, tz, lang,
                 created_at, last_seen, hit_count, sites_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        """, (
            new_id,
            stable_key,
            full_key,
            json.dumps(data),
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
    """Dev-only: inspect all stored identities (deduplicated by canonical ID)."""
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT id,
                   MIN(created_at)                   AS created_at,
                   MAX(last_seen)                    AS last_seen,
                   SUM(hit_count)                    AS hits,
                   GROUP_CONCAT(DISTINCT stable_key) AS stable_keys,
                   GROUP_CONCAT(DISTINCT tz)         AS tzs,
                   GROUP_CONCAT(DISTINCT lang)       AS langs,
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

        records.append({
            "id"            : row["id"],
            "stable_keys"   : row["stable_keys"].split(",")   if row["stable_keys"]   else [],
            "tzs"           : list(set(row["tzs"].split(",")))   if row["tzs"]   else [],
            "langs"         : list(set(row["langs"].split(","))) if row["langs"] else [],
            "gpu_renderers" : list(set(row["gpu_renderers"].split(","))) if row["gpu_renderers"] else [],
            "screen_details": list(set(row["screen_details"].split(","))) if row["screen_details"] else [],
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
    init_db()   # Idempotent: creates/migrates nitro_registry.db
    log.info("=" * 58)
    log.info("  NitroCommerce Identity Registry  v4.0.0")
    log.info("  http://0.0.0.0:8080")
    log.info("  Cross-site test:")
    log.info("    http://localhost:8080/?site=shop.com")
    log.info("    http://localhost:8080/?site=crow.com")
    log.info("    http://localhost:8080/?site=pewpie.com")
    log.info("  Registry:     http://localhost:8080/api/registry")
    log.info("  Raw rows:     http://localhost:8080/api/registry/raw")
    log.info("=" * 58)
    app.run(host="0.0.0.0", port=8080, debug=True)
