/**
 * ================================================================
 *  id-generator.js  —  NitroCommerce Cross-Site Identity SDK
 *  Version : 3.0.0
 * ================================================================
 *
 *  USAGE:
 *    <script type="text/javascript" src="//yoursite.com/id-generator.js"></script>
 *
 *  EXPOSES:
 *    window.iDx.config       — set config keys before DOMContentLoaded
 *    window.iDx.onIdAquired  — callback(ident: string) fired with the ID
 *
 * ================================================================
 *  THE ROOT CAUSE THIS VERSION FIXES
 * ================================================================
 *
 *  Two users on the SAME M4 MacBook Air model received the SAME ID.
 *
 *  WHY IT HAPPENED — a cascade of three failures:
 *
 *  1. canvas + audio in stable_key:
 *     Both users have the same GPU (same canvas hash) and same DAC
 *     chip (same audio PCM sum). These signals are HARDWARE signals —
 *     they do not differ between two people on identical hardware.
 *     They were in make_stable_key(), so both users hashed to the
 *     same stable_key. The first person through the door owned it,
 *     and the second person inherited their ID.
 *
 *  2. gpu_renderer is also identical on same-model hardware:
 *     "Apple M4 GPU" is the same string for every M4 MacBook Air.
 *
 *  3. screen_detail is identical if both users use default scaling:
 *     Same model → same native resolution → same DPR by default.
 *
 *  CORE INSIGHT:
 *  ─────────────────────────────────────────────────────────────
 *  No PURE HARDWARE signal can distinguish two users on the same
 *  hardware model. Hardware signals are per-DEVICE, not per-USER.
 *  The stable_key must contain at least one USER-level signal that
 *  is invariant for the same user across time but differs between
 *  different users.
 *
 *  THE FIX — font_hash (new in v3.0.0):
 *  ─────────────────────────────────────────────────────────────
 *  Installed font enumeration is the only browser fingerprint
 *  dimension that is:
 *    (a) USER-LEVEL — reflects the individual's installed software
 *        (Adobe CC, MS Office, Google Fonts desktop, design tools,
 *        dev environments, etc.)
 *    (b) NOT NOISED BY SAFARI — Safari does not randomize font
 *        availability; it would break web rendering
 *    (c) NETWORK-STABLE — unaffected by ISP, WiFi, or hotspot
 *    (d) CACHE-STABLE — survives Safari cache clears and restarts
 *    (e) OS-UPDATE STABLE — system fonts stay constant; only
 *        user-installed fonts change, and only when user acts
 *
 *  Two M4 MacBook Airs with different font libraries (one user has
 *  Adobe CC, the other doesn't; one has MS Office fonts, etc.)
 *  produce DIFFERENT font_hash values → different stable_keys →
 *  different IDs. Correctly.
 *
 *  Two M4 MacBook Airs where both users happen to have identical
 *  font sets (e.g., two fresh-out-of-box machines with zero extra
 *  fonts) → same font_hash → stable_key collision → the gatekeeper
 *  (hard AND on tz+lang) is the final line of defense. In practice
 *  this is extremely rare because even basic software installation
 *  (Xcode, Office, browsers) installs fonts.
 *
 *  FONT PROBE TECHNIQUE (CSS measurement — no canvas needed):
 *  ─────────────────────────────────────────────────────────────
 *  For each candidate font, render a test string in that font and
 *  measure its pixel width against a known fallback (monospace).
 *  If width differs from fallback → font is installed.
 *  This is the same technique used by FingerprintJS, panopticlick,
 *  and every serious fingerprinting library. It is synchronous,
 *  does not require canvas, and works in all browsers including
 *  Safari and Instagram in-app browser.
 *
 *  CANVAS + AUDIO REMOVED FROM STABLE KEY:
 *  ─────────────────────────────────────────────────────────────
 *  canvas and audio remain in the PAYLOAD (for fuzzy scoring on
 *  the backend) but are NO LONGER part of make_stable_key() input.
 *  They were causing same-hardware collisions AND were Safari-noised
 *  on cache clear — they were doing active harm in the key.
 *
 * ================================================================
 *  SIGNAL ROLES (v3):
 *
 *  Signal         Stable Key?  Fuzzy?  Notes
 *  ─────────────  ───────────  ──────  ──────────────────────────
 *  font_hash      YES          YES     USER-level, not hardware
 *  gpu_renderer   YES          YES     hardware (same-model = same)
 *  screen_detail  YES          YES     hardware + OS scaling
 *  platform       YES          YES     CPU arch
 *  canvas         NO           YES     Safari-noised, hw-identical
 *  audio          NO           YES     Safari-noised, hw-identical
 *  screen         NO           YES     legacy coverage
 *  visitorId      NO           YES     changes on OS/cache update
 *  ua             NO           YES     changes on OS update
 *  tz             NO           gatekeeper  soft context check
 *  lang           NO           gatekeeper  soft context check
 *  cores/ram      NO           YES     hardware hint
 * ================================================================
 *
 *  SAFARI / ITP NOTES:
 *    - IndexedDB primary store; localStorage backup.
 *    - No cookies read or written. No IP in payload.
 *
 *  INSTAGRAM IN-APP BROWSER NOTES:
 *    - SubtleCrypto unavailable → djb2 fallback hash.
 *    - OfflineAudioContext may be blocked → graceful fallback.
 *    - Font probe uses DOM spans → works everywhere.
 * ================================================================
 */

(function (win, doc) {
  "use strict";

  /* ─────────────────────────────────────────────────────────
   *  GLOBAL iDx OBJECT
   * ───────────────────────────────────────────────────────── */
  win.iDx = win.iDx || {};
  win.iDx.config      = win.iDx.config      || {};
  win.iDx.onIdAquired = win.iDx.onIdAquired || null;

  function cfg(key, fallback) {
    return (win.iDx.config && win.iDx.config[key] != null)
      ? win.iDx.config[key] : fallback;
  }

  var DEFAULT_SERVER = "http://localhost:8080";
  var LS_KEY         = "ntrx_id";
  var IDB_NAME       = "NtrxStore";
  var IDB_STORE      = "ids";
  var IDB_KEY        = "ntrx_id";
  var FPJS_URL       = "https://openfpcdn.io/fingerprintjs/v4/umd.min.js";

  /* ================================================================
   *  SECTION 1 — HASHING UTILITIES
   * ================================================================ */

  function hash(msg) {
    try {
      if (win.crypto && win.crypto.subtle && win.crypto.subtle.digest) {
        var buf = new TextEncoder().encode(msg);
        return win.crypto.subtle.digest("SHA-256", buf).then(function (ab) {
          return Array.from(new Uint8Array(ab))
            .map(function (b) { return b.toString(16).padStart(2, "0"); })
            .join("");
        });
      }
    } catch (e) { /* fall through */ }
    // djb2 fallback — Instagram in-app browser, no SubtleCrypto
    var h = 5381;
    for (var i = 0; i < msg.length; i++) {
      h = ((h << 5) + h) ^ msg.charCodeAt(i);
    }
    return Promise.resolve(
      (Math.abs(h) >>> 0).toString(16).padStart(8, "0") +
      "0000000000000000000000000000000000000000000000000000000000"
    );
  }

  /* ================================================================
   *  SECTION 2 — SIGNAL COLLECTORS
   * ================================================================ */

  /**
   * NEW (v3.0.0) — Installed font enumeration hash.
   *
   * Tests 120 candidate fonts by measuring rendered text width against
   * a monospace baseline. Fonts present produce a different width than
   * the fallback → they are included in the presence bitmask that gets
   * hashed into font_hash.
   *
   * WHY THIS WORKS AS A USER SIGNAL:
   *   Every piece of software a user installs can add fonts:
   *   Adobe CC          → 100s of Adobe fonts
   *   MS Office 365     → Arial, Calibri variants, etc.
   *   Xcode             → SF Pro, SF Mono, New York
   *   Google Chrome     → (none on macOS)
   *   Final Cut Pro     → Helvetica Neue variants
   *   Logic Pro         → no fonts, but noted for completeness
   *   Developer tools   → JetBrains Mono, Fira Code, etc.
   *   Design tools      → Figma installs no fonts; Sketch installs none
   *   Gaming / others   → varies widely
   *
   *   Two fresh-out-of-box M4 MacBook Airs with ZERO extra software
   *   will produce the same font_hash — this is the only remaining
   *   collision risk, mitigated by the tz+lang hard-AND gatekeeper.
   *   In practice it is extremely rare for two active users to have
   *   byte-for-byte identical software installation histories.
   *
   * TECHNIQUE: CSS width measurement via off-screen <span>
   *   - No canvas required → works in Instagram in-app browser
   *   - Synchronous → no async latency
   *   - Safari does NOT restrict this (it would break font rendering)
   *   - Returns Promise<string> (hex digest of presence bitmap)
   */
  function fontHashSignal() {
    // Candidate font list — broad coverage across user archetypes
    // (developer, designer, office worker, gamer, creative)
    var FONTS = [
      // macOS system (present on all Macs — used as baseline coverage)
      "Arial", "Helvetica", "Times New Roman", "Courier New", "Georgia",
      "Verdana", "Trebuchet MS", "Impact", "Comic Sans MS",
      // Apple / macOS extras
      "SF Pro Display", "SF Pro Text", "SF Mono", "New York",
      "Helvetica Neue", "Hiragino Sans", "Apple Garamond",
      "Futura", "Optima", "Palatino",
      // Adobe Creative Cloud
      "Adobe Caslon Pro", "Adobe Garamond Pro", "Myriad Pro",
      "Minion Pro", "Source Sans Pro", "Source Serif Pro",
      "Source Code Pro", "Trajan Pro", "Gill Sans",
      "Frutiger", "Univers", "Warnock Pro",
      // Microsoft Office
      "Calibri", "Cambria", "Candara", "Consolas", "Constantia",
      "Corbel", "Segoe UI", "Franklin Gothic Medium",
      "Book Antiqua", "Bookman Old Style", "Century Gothic",
      "Garamond", "Palatino Linotype", "Tahoma",
      // Developer fonts
      "JetBrains Mono", "Fira Code", "Fira Mono",
      "Cascadia Code", "Cascadia Mono",
      "Inconsolata", "Hack", "Roboto Mono",
      "IBM Plex Mono", "Space Mono", "Anonymous Pro",
      "Input Mono", "Operator Mono", "Dank Mono",
      // Google Fonts desktop installs
      "Roboto", "Open Sans", "Lato", "Oswald", "Raleway",
      "Nunito", "Montserrat", "Poppins", "Inter", "Noto Sans",
      // Design / creative tools
      "Proxima Nova", "Gotham", "Brandon Grotesque",
      "Circular", "Apercu", "Aktiv Grotesk",
      "FF DIN", "Avenir", "Avenir Next",
      // CJK (present if Asian language packs installed)
      "Hiragino Kaku Gothic ProN", "Hiragino Mincho ProN",
      "PingFang SC", "PingFang TC", "PingFang HK",
      "STHeiti", "STSong",
      // Misc / broad signal
      "Wingdings", "Wingdings 2", "Wingdings 3",
      "Symbol", "Webdings", "Marlett",
      "Arial Black", "Arial Narrow", "Arial Rounded MT Bold",
    ];

    try {
      // Use a hidden off-screen container to avoid layout shifts
      var container = doc.createElement("div");
      container.setAttribute("aria-hidden", "true");
      container.style.cssText = [
        "position:absolute", "top:-9999px", "left:-9999px",
        "visibility:hidden", "pointer-events:none",
        "white-space:nowrap", "font-size:72px",
      ].join(";");
      doc.body.appendChild(container);

      // Baseline: measure test string in monospace (always available)
      var TEST_STR  = "mmmmmmmmmmlli";
      var FALLBACK  = "monospace";

      function getWidth(fontName) {
        var span = doc.createElement("span");
        span.style.fontFamily = "'" + fontName + "'," + FALLBACK;
        span.textContent = TEST_STR;
        container.appendChild(span);
        var w = span.offsetWidth;
        container.removeChild(span);
        return w;
      }

      // Baseline width in pure monospace
      var baseSpan = doc.createElement("span");
      baseSpan.style.fontFamily = FALLBACK;
      baseSpan.textContent = TEST_STR;
      container.appendChild(baseSpan);
      var baseWidth = baseSpan.offsetWidth;
      container.removeChild(baseSpan);

      // Build presence string: "1" if font installed, "0" if not
      var bits = "";
      for (var i = 0; i < FONTS.length; i++) {
        bits += (getWidth(FONTS[i]) !== baseWidth) ? "1" : "0";
      }

      doc.body.removeChild(container);

      // Hash the full presence bitmap for a compact payload field
      return hash(bits);

    } catch (e) {
      return Promise.resolve("font_blocked");
    }
  }

  /**
   * Canvas fingerprint — kept for fuzzy scoring, NOT in stable_key.
   * Safari adds jitter on cache clear; same GPU = same hash anyway.
   * Returns Promise<string>.
   */
  function canvasSignal() {
    try {
      var el   = doc.createElement("canvas");
      el.width = 320; el.height = 80;
      var ctx  = el.getContext("2d");
      if (!ctx) return Promise.resolve("canvas_na");

      ctx.fillStyle = "rgba(80, 180, 60, 0.65)";
      ctx.fillRect(0, 0, 320, 80);
      ctx.font         = "bold 16px Arial, Helvetica, sans-serif";
      ctx.fillStyle    = "#1a6bcc";
      ctx.textBaseline = "top";
      ctx.fillText("NtrxFP \u{1F680} \u03A3 \u{1F441}", 6, 10);
      ctx.shadowOffsetX = 1; ctx.shadowOffsetY = 1;
      ctx.shadowBlur    = 3; ctx.shadowColor   = "rgba(0,0,0,0.35)";
      ctx.font          = "italic 12px 'Courier New', Courier, monospace";
      ctx.fillStyle     = "#e05c00";
      ctx.fillText("0123456789 AaBbCcDdEeFf XxYyZz", 6, 40);
      ctx.beginPath();
      ctx.arc(290, 40, 22, 0, Math.PI * 2);
      ctx.strokeStyle = "#7700cc";
      ctx.lineWidth   = 2.5;
      ctx.stroke();

      return hash(el.toDataURL("image/png"));
    } catch (e) {
      return Promise.resolve("canvas_blocked");
    }
  }

  /**
   * AudioContext fingerprint — kept for fuzzy scoring, NOT in stable_key.
   * Safari adds jitter on cache clear; same DAC = same hash anyway.
   * Returns Promise<string>.
   */
  function audioSignal() {
    return new Promise(function (resolve) {
      try {
        var OAC = win.OfflineAudioContext || win.webkitOfflineAudioContext;
        if (!OAC) return resolve("audio_na");

        var ctx  = new OAC(1, 4096, 44100);
        var osc  = ctx.createOscillator();
        var comp = ctx.createDynamicsCompressor();

        comp.threshold.setValueAtTime(-50,  ctx.currentTime);
        comp.knee.setValueAtTime(40,        ctx.currentTime);
        comp.ratio.setValueAtTime(12,       ctx.currentTime);
        comp.attack.setValueAtTime(0,       ctx.currentTime);
        comp.release.setValueAtTime(0.25,   ctx.currentTime);

        osc.type = "triangle";
        osc.frequency.setValueAtTime(1000, ctx.currentTime);
        osc.connect(comp);
        comp.connect(ctx.destination);
        osc.start(0);

        ctx.startRendering().then(function (buf) {
          var data = buf.getChannelData(0);
          var sum  = 0;
          for (var i = 0; i < data.length; i++) sum += Math.abs(data[i]);
          resolve(sum.toString());
        }).catch(function () { resolve("audio_fail"); });

      } catch (e) {
        resolve("audio_blocked");
      }
    });
  }

  /**
   * WebGL unmasked renderer — in stable_key as a hardware discriminator.
   * NOTE: Identical for all units of the same GPU model (e.g. all M4s
   * return "Apple M4 GPU"), but still included because it differentiates
   * across hardware generations (M1 vs M2 vs M3 vs M4, Intel vs ARM).
   * Returns a plain string (synchronous).
   */
  function gpuRendererSignal() {
    try {
      var canvas = doc.createElement("canvas");
      var gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
      if (!gl) return "webgl_na";

      var ext = gl.getExtension("WEBGL_debug_renderer_info");
      if (!ext) return "webgl_ext_na";

      var renderer = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || "unknown_renderer";
      var vendor   = gl.getParameter(ext.UNMASKED_VENDOR_WEBGL)   || "unknown_vendor";

      return (vendor + "|" + renderer).substring(0, 128);
    } catch (e) {
      return "webgl_blocked";
    }
  }

  /**
   * Screen metrics + device pixel ratio composite.
   * Reflects OS display scaling. Same model + same scaling = same value.
   * Included in stable_key for cross-generation differentiation.
   * Returns a plain string (synchronous). Format: "WxHxCDxDPR"
   */
  function screenDetailSignal() {
    try {
      var s   = win.screen || {};
      var dpr = win.devicePixelRatio || 1;
      return [s.width || "?", s.height || "?", s.colorDepth || "?", dpr].join("x");
    } catch (e) {
      return "screen_detail_blocked";
    }
  }

  /**
   * Static metadata. tz + lang are soft gatekeeper fields on backend.
   */
  function staticSignals() {
    var s = win.screen || {};
    return {
      screen  : (s.width  || "?") + "x" + (s.height || "?") + "x" + (s.colorDepth || "?"),
      platform: (navigator.platform  || "unknown").substring(0, 32),
      ua      : (navigator.userAgent || "unknown").substring(0, 200),
      tz      : (function () {
        try { return Intl.DateTimeFormat().resolvedOptions().timeZone; }
        catch (e) { return "unknown"; }
      })(),
      cores   : navigator.hardwareConcurrency || "?",
      ram     : navigator.deviceMemory        || "?",
      lang    : navigator.language            || "unknown",
    };
  }

  /* ================================================================
   *  SECTION 3 — LOCAL CACHE  (IndexedDB primary, localStorage backup)
   * ================================================================ */

  function openIDB() {
    return new Promise(function (resolve, reject) {
      if (!win.indexedDB) return reject(new Error("no_idb"));
      var req = win.indexedDB.open(IDB_NAME, 1);
      req.onupgradeneeded = function (e) {
        e.target.result.createObjectStore(IDB_STORE);
      };
      req.onsuccess = function (e) { resolve(e.target.result); };
      req.onerror   = function ()  { reject(new Error("idb_open_fail")); };
    });
  }

  function idbGet() {
    return openIDB().then(function (db) {
      return new Promise(function (resolve) {
        var req = db.transaction(IDB_STORE, "readonly")
                    .objectStore(IDB_STORE).get(IDB_KEY);
        req.onsuccess = function () { resolve(req.result || null); };
        req.onerror   = function () { resolve(null); };
      });
    }).catch(function () { return null; });
  }

  function idbSet(id) {
    return openIDB().then(function (db) {
      return new Promise(function (resolve) {
        var tx = db.transaction(IDB_STORE, "readwrite");
        tx.objectStore(IDB_STORE).put(id, IDB_KEY);
        tx.oncomplete = function () { resolve(); };
        tx.onerror    = function () { resolve(); };
      });
    }).catch(function () {});
  }

  function lsGet() {
    try {
      var v = win.localStorage.getItem(LS_KEY);
      return (v && v.indexOf("ntrx_") === 0) ? v : null;
    } catch (e) { return null; }
  }

  function lsSet(id) {
    try { win.localStorage.setItem(LS_KEY, id); } catch (e) {}
  }

  function getCached() {
    var ls = lsGet();
    if (ls) return Promise.resolve(ls);
    return idbGet();
  }

  function persist(id) {
    lsSet(id);
    return idbSet(id);
  }

  /* ================================================================
   *  SECTION 4 — OPTIONAL: FingerprintJS v4 LOADER
   * ================================================================ */

  function loadFPJS() {
    return new Promise(function (resolve) {
      if (win.FingerprintJS && typeof win.FingerprintJS.load === "function") {
        win.FingerprintJS.load().then(resolve).catch(function () { resolve(null); });
        return;
      }
      var s   = doc.createElement("script");
      s.src   = FPJS_URL;
      s.async = true;
      s.onload = function () {
        setTimeout(function () {
          if (win.FingerprintJS && typeof win.FingerprintJS.load === "function") {
            win.FingerprintJS.load().then(resolve).catch(function () { resolve(null); });
          } else {
            resolve(null);
          }
        }, 50);
      };
      s.onerror = function () { resolve(null); };
      (doc.head || doc.documentElement).appendChild(s);
    });
  }

  /* ================================================================
   *  SECTION 5 — LOCAL OFFLINE FALLBACK KEY
   * ================================================================ */

  function buildHardwareKey(fp) {
    var raw = [
      fp.font_hash    || "",   // USER-level signal — primary differentiator
      fp.gpu_renderer || "",
      fp.screen_detail|| "",
      fp.platform     || "",
      fp.visitorId    || "",
      fp.canvas       || "",
      fp.audio        || "",
    ].join("|");
    return hash(raw).then(function (h) { return h.substring(0, 12); });
  }

  /* ================================================================
   *  SECTION 6 — MAIN ORCHESTRATION
   * ================================================================ */

  function deliver(id) {
    console.log("ID: " + id);
    if (typeof win.iDx.onIdAquired === "function") {
      try { win.iDx.onIdAquired(id); } catch (e) {}
    }
  }

  function runTracker() {
    /* ── 1. Cache hit — instant return, no network ── */
    getCached().then(function (cached) {
      if (cached) {
        deliver(cached);
        return;
      }

      var serverBase = cfg("serverUrl", DEFAULT_SERVER).replace(/\/$/, "");
      var endpoint   = serverBase + "/api/get-id";

      // Synchronous signals collected immediately (before any async work)
      var gpuRenderer  = gpuRendererSignal();
      var screenDetail = screenDetailSignal();

      /* ── 2. Collect async signals in parallel ── */
      Promise.all([
        canvasSignal(),    // async — SubtleCrypto hash
        audioSignal(),     // async — OfflineAudioContext
        fontHashSignal(),  // async — SubtleCrypto hash of font bitmap
        loadFPJS()         // async — CDN script load
      ]).then(function (results) {
        var canvasHash = results[0];
        var audioHash  = results[1];
        var fontHash   = results[2];   // NEW — user-level differentiator
        var fpAgent    = results[3];

        var getFPVisitorId = fpAgent
          ? fpAgent.get().then(function (r) { return r.visitorId; })
              .catch(function () { return "fp_fail"; })
          : Promise.resolve("fp_skipped");

        return getFPVisitorId.then(function (visitorId) {
          var meta = staticSignals();

          /* ── 3. Build payload ── */
          var payload = {
            // USER-level signal (new — primary same-hardware differentiator)
            font_hash    : fontHash,

            // Hardware signals (in stable_key)
            gpu_renderer : gpuRenderer,
            screen_detail: screenDetail,
            platform     : meta.platform,

            // Fuzzy-only signals (NOT in stable_key)
            canvas       : canvasHash,
            audio        : audioHash,
            screen       : meta.screen,
            visitorId    : visitorId,
            ua           : meta.ua,
            cores        : meta.cores,
            ram          : meta.ram,

            // Gatekeeper fields (soft context check on backend)
            tz           : meta.tz,
            lang         : meta.lang
            // NOTE: IP address intentionally omitted
          };

          /* ── 4. POST to identity server ── */
          return fetch(endpoint, {
            method     : "POST",
            headers    : { "Content-Type": "application/json" },
            body       : JSON.stringify(payload),
            credentials: "omit"
          }).then(function (res) {
            if (!res.ok) throw new Error("server_" + res.status);
            return res.json();
          }).then(function (data) {
            var id = data.id;
            return persist(id).then(function () { return id; });
          });
        });
      }).then(function (id) {
        deliver(id);
      }).catch(function (err) {
        /* Server unreachable — derive local ID from best available signals */
        console.warn("[NitroTracker] Server unavailable, using local ID:", err.message);
        Promise.all([canvasSignal(), audioSignal(), fontHashSignal()]).then(function (sigs) {
          var meta = staticSignals();
          return buildHardwareKey({
            font_hash    : sigs[2],
            gpu_renderer : gpuRendererSignal(),
            screen_detail: screenDetailSignal(),
            platform     : meta.platform,
            visitorId    : "offline",
            canvas       : sigs[0],
            audio        : sigs[1],
          });
        }).then(function (hwKey) {
          var localId = "ntrx_local_" + hwKey + "_" + Date.now().toString(36);
          return persist(localId).then(function () { return localId; });
        }).then(function (localId) {
          deliver(localId);
        });
      });
    });
  }

  /* ─────────────────────────────────────────────────────────
   *  ENTRY POINT
   * ───────────────────────────────────────────────────────── */
  if (doc.readyState === "loading") {
    doc.addEventListener("DOMContentLoaded", runTracker);
  } else {
    // Script loaded async after DOM; run on next tick so host-page
    // inline scripts (iDx.onIdAquired assignment) execute first
    setTimeout(runTracker, 0);
  }

})(window, document);
