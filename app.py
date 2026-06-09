"""
================================================================
  app.py  —  NitroCommerce Cross-Site Identity Registry
  Version : 3.0.0  (Production & Hackathon Ready)
================================================================

  CHANGES FROM v2.0.0:
  ─────────────────────────────────────────────────────────────
  1. PERSISTENT STORAGE (SQLite):
     In-memory STABLE_INDEX / FULL_INDEX replaced with a local
     SQLite database (nitro_registry.db). Data survives server
     restarts. Indexed on full_key + stable_key for O(1) perf.

  2. CONTEXTUAL GATEKEEPER — Anti-Collision Guard:
     Hardware signals alone are not enough to distinguish two
     different people on identical M4 MacBook Air hardware.
     Safari does NOT noise-inject timezone or language, so we
     use those as cheap, reliable disambiguation signals.

     Rule:
       stable_key hit  OR  fuzzy score ≥ threshold
       AND tz   matches stored record
       AND lang matches stored record
       ──────────────────────────────────────────
       → SAME USER (cache cleared)  → return original ID
         + alias new keys in DB

       stable_key hit  OR  fuzzy score ≥ threshold
       BUT tz/lang mismatch
       ──────────────────────────────────────────
       → COLLISION (different user, same hardware) → mint new ID

  3. SAFARI-AWARE FUZZY WEIGHTS:
     Canvas + Audio demoted because Safari actively adds noise
     to those on every cache clear / private-browsing session.
     Screen + Platform promoted (pure physical hardware, immune
     to Safari's canvas/audio jitter).
     FUZZY_THRESHOLD lowered to 0.55 to catch same-device users
     despite canvas/audio drift, while the gatekeeper prevents
     false merges across different users.

  RESOLUTION PIPELINE (v3):
  ─────────────────────────────────────────────────────────────
  1. full_key  DB hit  → fast path (same OS, same browser state)
  2. stable_key DB hit
       a. tz + lang match → same user, OS/cache changed → re-alias
       b. tz / lang mismatch → COLLISION → fall through
  3. Fuzzy match
       a. score ≥ threshold AND tz + lang match → same user
       b. mismatch → COLLISION → fall through
  4. Mint new identity

  SIGNAL STABILITY TABLE (updated):
  ─────────────────────────────────────────────────────────────
  Signal          Safari-noised?  Changes on cache clear?  Weight role
  ─────────────── ─────────────  ──────────────────────── ──────────
  canvas hash     YES (jitter)   YES                       fuzzy (low)
  audio PCM sum   YES (jitter)   YES                       fuzzy (low)
  screen          NO             NO                        fuzzy (high)
  platform        NO             NO                        fuzzy (high)
  timezone        NO             NO                        gatekeeper
  language        NO             NO                        gatekeeper
  visitorId       YES            YES                       fuzzy (low)
  ua              YES (version)  YES                       fuzzy (low)
  cores/ram       NO             NO                        fuzzy (med)

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

# Lowered to 0.55: canvas/audio drift is expected on Safari cache
# clear; the tz+lang gatekeeper prevents false collisions.
FUZZY_THRESHOLD = 0.55

# Fuzzy weights — canvas/audio DEMOTED (Safari noise-injects them).
# screen/platform PROMOTED (physical hardware, immune to noise).
WEIGHTS = {
    "canvas"    : 0.10,   # DEMOTED — Safari jitter on cache clear
    "audio"     : 0.10,   # DEMOTED — Safari jitter on cache clear
    "screen"    : 0.30,   # PROMOTED — physical display, never changes
    "platform"  : 0.25,   # PROMOTED — CPU arch, never changes
    "visitorId" : 0.05,   # changes on OS/cache update
    "ua"        : 0.05,   # changes on OS update
    "cores_ram" : 0.15,   # solid HW hint (cores × ram combo)
}

# ── SQLite setup ──────────────────────────────────────────────

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nitro_registry.db")


def init_db() -> None:
    """
    Create the identities table and its indexes if they don't exist.

    Schema
    ──────
    id            TEXT  — the ntrx_... identifier (canonical)
    stable_key    TEXT  — SHA-256[:16] of canvas+audio+screen+platform
    full_key      TEXT  — SHA-256[:16] of stable signals + visitorId + ua
    fingerprint   TEXT  — JSON blob of the original signal map
    tz            TEXT  — timezone string (gatekeeper field)
    lang          TEXT  — language string (gatekeeper field)
    created_at    TEXT  — ISO-8601 UTC
    last_seen     TEXT  — ISO-8601 UTC
    hit_count     INT   — total successful resolutions
    sites_seen    TEXT  — JSON array of origin strings

    Indexes on full_key and stable_key give O(1) lookups.
    Multiple rows may share the same `id` (aliases after OS/cache
    update), but each (full_key, stable_key) pair is unique.
    """
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS identities (
                id          TEXT NOT NULL,
                stable_key  TEXT NOT NULL,
                full_key    TEXT NOT NULL,
                fingerprint TEXT NOT NULL DEFAULT '{}',
                tz          TEXT NOT NULL DEFAULT '',
                lang        TEXT NOT NULL DEFAULT '',
                created_at  TEXT NOT NULL,
                last_seen   TEXT NOT NULL,
                hit_count   INTEGER NOT NULL DEFAULT 1,
                sites_seen  TEXT NOT NULL DEFAULT '[]'
            )
        """)
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
    Permanent hardware anchor: canvas + audio + screen + platform.
    Does NOT include visitorId / ua (change on OS update) or
    tz / lang (used as gatekeeper fields, not key material).
    """
    raw = "|".join([
        fp.get("canvas",   ""),
        fp.get("audio",    ""),
        fp.get("screen",   ""),
        fp.get("platform", ""),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def make_full_key(fp: dict) -> str:
    """
    Fast-path key that also captures visitorId + ua.
    Exact-matches on same OS lifecycle; misses after cache clear
    or OS update (stable_key + gatekeeper catches those).
    """
    raw = "|".join([
        fp.get("canvas",    ""),
        fp.get("audio",     ""),
        fp.get("screen",    ""),
        fp.get("platform",  ""),
        fp.get("visitorId", ""),
        fp.get("ua",        ""),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


# ── Contextual gatekeeper ─────────────────────────────────────

def _context_matches(incoming: dict, stored_tz: str, stored_lang: str) -> bool:
    """
    Returns True only if BOTH timezone and language match.

    Safari does NOT apply noise to these fields — they are stable
    environmental signals that differ between users even on identical
    hardware.  A mismatch indicates a DIFFERENT USER on the same
    hardware model, not the same user after a cache clear.

    Empty stored values are treated as wildcard (legacy rows minted
    before v3 that lack this data won't incorrectly block matches).
    """
    incoming_tz   = incoming.get("tz",   "").strip()
    incoming_lang = incoming.get("lang", "").strip()

    tz_ok   = (not stored_tz)   or (incoming_tz   == stored_tz)
    lang_ok = (not stored_lang) or (incoming_lang == stored_lang)

    return tz_ok and lang_ok


# ── Signal comparison for fuzzy fallback ─────────────────────

def _cmp(a: str, b: str) -> float:
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
    Scan ALL unique stable_key anchors in the DB and return the
    best-scoring record plus its score.  O(n) over unique stable
    keys — acceptable for registry sizes up to ~100 k rows; add
    ANN index if you need to scale beyond that.
    """
    inc_cr = "{}_{}".format(incoming.get("cores", "?"), incoming.get("ram", "?"))

    with get_conn() as conn:
        # One canonical row per stable_key (the first row inserted)
        rows = conn.execute("""
            SELECT DISTINCT stable_key FROM identities
        """).fetchall()

        if not rows:
            return None, 0.0

        best_rec, best_score = None, 0.0

        for r in rows:
            row = conn.execute(
                "SELECT * FROM identities WHERE stable_key = ? ORDER BY created_at ASC LIMIT 1",
                (r["stable_key"],)
            ).fetchone()
            if not row:
                continue

            rec = _row_to_dict(row)
            s   = rec["fingerprint"]
            s_cr = "{}_{}".format(s.get("cores", "?"), s.get("ram", "?"))

            score = (
                WEIGHTS["canvas"]    * _cmp(incoming.get("canvas",    ""), s.get("canvas",    ""))
              + WEIGHTS["audio"]     * _cmp(incoming.get("audio",     ""), s.get("audio",     ""))
              + WEIGHTS["screen"]    * _cmp(incoming.get("screen",    ""), s.get("screen",    ""))
              + WEIGHTS["platform"]  * _cmp(incoming.get("platform",  ""), s.get("platform",  ""))
              + WEIGHTS["visitorId"] * _cmp(incoming.get("visitorId", ""), s.get("visitorId", ""))
              + WEIGHTS["ua"]        * _cmp(incoming.get("ua",        ""), s.get("ua",        ""))
              + WEIGHTS["cores_ram"] * _cmp(inc_cr,                        s_cr)
            )
            if score > best_score:
                best_score, best_rec = score, rec

    return best_rec, best_score


# ── DB write helpers ──────────────────────────────────────────

def _update_hit(conn: sqlite3.Connection, record_id: str, origin: str) -> None:
    """Bump hit count, last_seen, and sites_seen for ALL rows sharing this id."""
    now = _now()
    rows = conn.execute(
        "SELECT rowid, sites_seen FROM identities WHERE id = ?", (record_id,)
    ).fetchall()
    for row in rows:
        sites = json.loads(row["sites_seen"])
        if origin not in sites:
            sites.append(origin)
        conn.execute(
            "UPDATE identities SET hit_count = hit_count + 1, last_seen = ?, sites_seen = ? WHERE rowid = ?",
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
    Insert a new row that maps the new key pair to an existing
    canonical ID.  This makes future lookups O(1) again.
    """
    now = _now()
    conn.execute("""
        INSERT INTO identities
            (id, stable_key, full_key, fingerprint, tz, lang,
             created_at, last_seen, hit_count, sites_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
    """, (
        canonical_id,
        new_stable_key,
        new_full_key,
        json.dumps(fp),
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
         → return ID (same device, same OS, same browser state)

      2. stable_key DB hit
         a. tz + lang MATCH  → same user, cache/OS changed → re-alias + return
         b. tz / lang MISMATCH → COLLISION guard → fall through

      3. Fuzzy match (score ≥ FUZZY_THRESHOLD)
         a. tz + lang MATCH  → same user, canvas/audio drifted → re-alias + return
         b. tz / lang MISMATCH → COLLISION guard → fall through

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
                # Same user — cache cleared or OS updated
                _update_hit(conn, rec["id"], origin)
                _insert_alias(conn, rec["id"], stable_key, full_key, data, origin)
                log.info("STABLE HIT | %s | cache/OS change, re-aliased", rec["id"])
                return jsonify({"id": rec["id"]})
            else:
                # Different user on identical hardware model → collision guard
                log.info(
                    "COLLISION GUARD (stable) | tz/lang mismatch | stored=(%s,%s) incoming=(%s,%s)",
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
                (id, stable_key, full_key, fingerprint, tz, lang,
                 created_at, last_seen, hit_count, sites_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        """, (
            new_id,
            stable_key,
            full_key,
            json.dumps(data),
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
                   MIN(created_at) AS created_at,
                   MAX(last_seen)  AS last_seen,
                   SUM(hit_count)  AS hits,
                   GROUP_CONCAT(DISTINCT stable_key) AS stable_keys,
                   GROUP_CONCAT(DISTINCT tz)         AS tzs,
                   GROUP_CONCAT(DISTINCT lang)       AS langs
            FROM identities
            GROUP BY id
            ORDER BY created_at DESC
        """).fetchall()

    records = []
    for row in rows:
        # Collect all unique site origins across alias rows
        with get_conn() as conn:
            site_rows = conn.execute(
                "SELECT sites_seen FROM identities WHERE id = ?", (row["id"],)
            ).fetchall()
        sites: list = []
        for sr in site_rows:
            for s in json.loads(sr["sites_seen"]):
                if s not in sites:
                    sites.append(s)

        records.append({
            "id"          : row["id"],
            "stable_keys" : row["stable_keys"].split(",") if row["stable_keys"] else [],
            "tzs"         : list(set(row["tzs"].split(",")))  if row["tzs"]   else [],
            "langs"       : list(set(row["langs"].split(","))) if row["langs"] else [],
            "hits"        : row["hits"],
            "created_at"  : row["created_at"],
            "last_seen"   : row["last_seen"],
            "sites_seen"  : sites,
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
    init_db()   # Creates nitro_registry.db + indexes on first run
    log.info("=" * 58)
    log.info("  NitroCommerce Identity Registry  v3.0.0")
    log.info("  http://0.0.0.0:8080")
    log.info("  Cross-site test:")
    log.info("    http://localhost:8080/?site=shop.com")
    log.info("    http://localhost:8080/?site=crow.com")
    log.info("    http://localhost:8080/?site=pewpie.com")
    log.info("  Registry:     http://localhost:8080/api/registry")
    log.info("  Raw rows:     http://localhost:8080/api/registry/raw")
    log.info("=" * 58)
    app.run(host="0.0.0.0", port=8080, debug=True)