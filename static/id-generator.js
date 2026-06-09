/**
 * ================================================================
 *  id-generator.js  —  NitroCommerce Cross-Site Identity SDK
 *  Version : 1.0.0
 *  Author  : Hackathon Team
 * ================================================================
 *
 *  USAGE (one line per partner site):
 *    <script type="text/javascript" src="//yoursite.com/id-generator.js"></script>
 *
 *  EXPOSES:
 *    window.iDx.config       — set config keys before DOMContentLoaded
 *    window.iDx.onIdAquired  — callback(ident: string) fired with the ID
 *
 *  HOW IT WORKS:
 *    1. Collects hardware-bound browser signals (canvas GPU hash,
 *       AudioContext DAC hash, screen geometry, platform, UA).
 *    2. Derives a deterministic 12-char hardware key from those signals.
 *    3. Checks local cache (localStorage → IndexedDB) for a stored ID.
 *    4. If cached → returns immediately without a network call.
 *    5. If not cached → POSTs fingerprint to /api/get-id on the
 *       configured server, caches the returned ntrx_ ID, fires callback.
 *    6. Logs "ID: <id>" to console as required.
 *
 *  SAFARI / ITP NOTES:
 *    - IndexedDB is used as primary persistent store (outlasts LS under ITP).
 *    - localStorage is used as fast secondary store.
 *    - No cookies are read or written anywhere.
 *    - IP address is never included in fingerprint payload.
 *
 *  INSTAGRAM IN-APP BROWSER NOTES:
 *    - SubtleCrypto may be unavailable; djb2 fallback hash is used.
 *    - OfflineAudioContext may be blocked; graceful fallback included.
 *    - fetch() is available on all modern in-app browsers.
 * ================================================================
 */

(function (win, doc) {
  "use strict";

  /* ─────────────────────────────────────────────────────────
   *  GLOBAL iDx OBJECT  (exposed before any async work)
   *  The host page may set iDx.config and iDx.onIdAquired
   *  at any point before DOMContentLoaded fires.
   * ───────────────────────────────────────────────────────── */
  win.iDx = win.iDx || {};
  win.iDx.config      = win.iDx.config      || {};
  win.iDx.onIdAquired = win.iDx.onIdAquired || null;

  /* ─────────────────────────────────────────────────────────
   *  CONFIGURATION  (overridable via iDx.config)
   *  SERVER_URL   : where your Flask app.py is hosted
   *  FPJS_CDN_URL : optional — set to "" to skip FingerprintJS
   * ───────────────────────────────────────────────────────── */
  function cfg(key, fallback) {
    return (win.iDx.config && win.iDx.config[key] != null)
      ? win.iDx.config[key]
      : fallback;
  }

  var DEFAULT_SERVER = "";   // "" = same origin (works on any deployed domain)
  var LS_KEY         = "ntrx_id";
  var IDB_NAME       = "NtrxStore";
  var IDB_STORE      = "ids";
  var IDB_KEY        = "ntrx_id";
  // UMD build — works in Safari, Instagram browser, no ES module issues
  var FPJS_URL       = "https://openfpcdn.io/fingerprintjs/v4/umd.min.js";

  /* ================================================================
   *  SECTION 1 — HASHING UTILITIES
   * ================================================================ */

  /**
   * SHA-256 via SubtleCrypto. Falls back to djb2 if unavailable
   * (Instagram in-app browser on some Android versions).
   * Always returns a Promise<string>.
   */
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
    // djb2 fallback
    var h = 5381;
    for (var i = 0; i < msg.length; i++) {
      h = ((h << 5) + h) ^ msg.charCodeAt(i);
    }
    return Promise.resolve(
      (Math.abs(h) >>> 0).toString(16).padStart(8, "0") + "0000000000000000000000000000000000000000000000000000000000"
    );
  }

  /* ================================================================
   *  SECTION 2 — HARDWARE SIGNAL COLLECTORS
   * ================================================================ */

  /**
   * Canvas fingerprint: render layered text + shapes to expose
   * GPU sub-pixel antialiasing differences across hardware.
   * Returns Promise<string> (hex digest).
   */
  function canvasSignal() {
    try {
      var el   = doc.createElement("canvas");
      el.width = 320; el.height = 80;
      var ctx  = el.getContext("2d");
      if (!ctx) return Promise.resolve("canvas_na");

      ctx.fillStyle = "rgba(80, 180, 60, 0.65)";
      ctx.fillRect(0, 0, 320, 80);

      ctx.font      = "bold 16px Arial, Helvetica, sans-serif";
      ctx.fillStyle = "#1a6bcc";
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
   * AudioContext fingerprint: routes an oscillator through a
   * dynamics compressor; the PCM floating-point sum differs
   * per hardware DAC / DSP implementation.
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
   * Collect static, network-independent metadata.
   */
  function staticSignals() {
    var s = win.screen || {};
    return {
      screen  : (s.width||"?") + "x" + (s.height||"?") + "x" + (s.colorDepth||"?"),
      platform: (navigator.platform || "unknown").substring(0, 32),
      ua      : (navigator.userAgent || "unknown").substring(0, 200),
      tz      : (function () {
        try { return Intl.DateTimeFormat().resolvedOptions().timeZone; }
        catch(e) { return "unknown"; }
      })(),
      cores   : navigator.hardwareConcurrency || "?",
      ram     : navigator.deviceMemory || "?",
      lang    : navigator.language || "unknown"
    };
  }

  /* ================================================================
   *  SECTION 3 — LOCAL CACHE  (IndexedDB primary, localStorage backup)
   *  Safari ITP deletes localStorage for cross-site scripts after
   *  7 days of no interaction; IDB lasts longer in first-party context.
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
   *  Adds high-entropy visitorId (GPU/font/audio mix) as extra signal.
   *  Gracefully skipped if CDN fails or is blocked.
   * ================================================================ */

  function loadFPJS() {
    return new Promise(function (resolve) {
      // Already loaded and valid
      if (win.FingerprintJS && typeof win.FingerprintJS.load === "function") {
        win.FingerprintJS.load().then(resolve).catch(function () { resolve(null); });
        return;
      }
      var s   = doc.createElement("script");
      s.src   = FPJS_URL;
      s.async = true;
      s.onload  = function () {
        // Small delay to let UMD bundle register itself on window
        setTimeout(function () {
          if (win.FingerprintJS && typeof win.FingerprintJS.load === "function") {
            win.FingerprintJS.load().then(resolve).catch(function () { resolve(null); });
          } else {
            resolve(null); // FPJS loaded but unexpected format — skip gracefully
          }
        }, 50);
      };
      s.onerror = function () { resolve(null); }; // CDN blocked — skip gracefully
      (doc.head || doc.documentElement).appendChild(s);
    });
  }

  /* ================================================================
   *  SECTION 5 — HARDWARE KEY  (server-side mirror of build_hardware_hash)
   *  Combines the five most stable signals into a deterministic 12-char
   *  hex key.  Used here just to build the local-only ID suffix so
   *  IDs are human-readable and collision-resistant enough for a demo.
   * ================================================================ */

  function buildHardwareKey(fp) {
    var raw = [
      fp.visitorId || "",
      fp.canvas    || "",
      fp.audio     || "",
      fp.screen    || "",
      fp.platform  || ""
    ].join("|");
    return hash(raw).then(function (h) { return h.substring(0, 12); });
  }

  /* ================================================================
   *  SECTION 6 — MAIN ORCHESTRATION
   * ================================================================ */

  function deliver(id) {
    /* Required console format */
    console.log("ID: " + id);
    /* Fire host-page callback if registered */
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

      /* ── 2. Collect hardware signals in parallel ── */
      var serverBase = cfg("serverUrl", DEFAULT_SERVER).replace(/\/$/, "");
      var endpoint   = serverBase + "/api/get-id";

      Promise.all([
        canvasSignal(),
        audioSignal(),
        loadFPJS()
      ]).then(function (results) {
        var canvasHash = results[0];
        var audioHash  = results[1];
        var fpAgent    = results[2];   // may be null if CDN blocked

        var getFPVisitorId = fpAgent
          ? fpAgent.get().then(function (r) { return r.visitorId; })
              .catch(function () { return "fp_fail"; })
          : Promise.resolve("fp_skipped");

        return getFPVisitorId.then(function (visitorId) {
          var meta = staticSignals();

          /* ── 3. Build payload ── */
          var payload = {
            visitorId : visitorId,
            canvas    : canvasHash,
            audio     : audioHash,
            screen    : meta.screen,
            platform  : meta.platform,
            ua        : meta.ua,
            tz        : meta.tz,
            cores     : meta.cores,
            ram       : meta.ram,
            lang      : meta.lang
            /* NOTE: IP address intentionally omitted */
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
            /* ── 5. Cache locally ── */
            return persist(id).then(function () { return id; });
          });
        });
      }).then(function (id) {
        /* ── 6. Deliver ── */
        deliver(id);
      }).catch(function (err) {
        /* Server unreachable — derive a local ID from hardware signals
           so the callback still fires and the page isn't broken.       */
        console.warn("[NitroTracker] Server unavailable, using local ID:", err.message);
        Promise.all([canvasSignal(), audioSignal()]).then(function (sigs) {
          var meta = staticSignals();
          return buildHardwareKey({
            visitorId: "offline",
            canvas   : sigs[0],
            audio    : sigs[1],
            screen   : meta.screen,
            platform : meta.platform
          });
        }).then(function (hwKey) {
          /* Local IDs use "ntrx_local_" prefix to distinguish from server IDs */
          var localId = "ntrx_local_" + hwKey + "_" + Date.now().toString(36);
          return persist(localId).then(function () { return localId; });
        }).then(function (localId) {
          deliver(localId);
        });
      });
    });
  }

  /* ─────────────────────────────────────────────────────────
   *  ENTRY POINT — fire after DOM is interactive
   * ───────────────────────────────────────────────────────── */
  if (doc.readyState === "loading") {
    doc.addEventListener("DOMContentLoaded", runTracker);
  } else {
    /* Script loaded async after DOM — run on next tick so host-page
       inline scripts (including iDx.onIdAquired assignment) execute first */
    setTimeout(runTracker, 0);
  }

})(window, document);
