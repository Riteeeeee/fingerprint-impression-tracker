/**
 * ================================================================
 *  id-generator.js  —  NitroCommerce Cross-Site Identity SDK
 *  Version : 2.0.0
 * ================================================================
 *
 *  USAGE (one line per partner site):
 *    <script type="text/javascript" src="//yoursite.com/id-generator.js"></script>
 *
 *  EXPOSES:
 *    window.iDx.config       — set config keys before DOMContentLoaded
 *    window.iDx.onIdAquired  — callback(ident: string) fired with the ID
 *
 *  NEW IN v2.0.0:
 *  ─────────────────────────────────────────────────────────────
 *  gpu_renderer  — WebGL UNMASKED_RENDERER_WEBGL string extracted
 *                  via WEBGL_debug_renderer_info extension.
 *                  Encodes GPU micro-architecture (e.g. "Apple M4 GPU").
 *                  Safari does NOT noise-protect this. Completely
 *                  invariant across network switches, OS updates,
 *                  and cache clears. Falls back to "webgl_na" if
 *                  the extension is unavailable (e.g. blocked WebGL).
 *
 *  screen_detail — Combined string of screen.width × screen.height
 *                  × screen.colorDepth × window.devicePixelRatio.
 *                  Reflects OS-level display scaling, custom resolution
 *                  settings, and Dock/Menubar arrangement — all of which
 *                  differ between users on the same hardware model.
 *                  100% network-stable (never affected by ISP or WiFi).
 *
 *  Both new signals are included in the POST payload alongside all
 *  existing fields. The app.py v4.0.0 backend folds them into the
 *  stable_key hash, making each device's anchor uniquely tied to its
 *  physical GPU and display configuration.
 *
 *  SAFARI / ITP NOTES (unchanged from v1):
 *    - IndexedDB primary persistent store, localStorage backup.
 *    - No cookies read or written.
 *    - IP address never included in payload.
 *
 *  INSTAGRAM IN-APP BROWSER NOTES (unchanged):
 *    - SubtleCrypto may be unavailable; djb2 fallback used.
 *    - OfflineAudioContext may be blocked; graceful fallback included.
 *    - WebGL extension probe wrapped in try/catch; degrades cleanly.
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

  /* ─────────────────────────────────────────────────────────
   *  CONFIGURATION
   * ───────────────────────────────────────────────────────── */
  function cfg(key, fallback) {
    return (win.iDx.config && win.iDx.config[key] != null)
      ? win.iDx.config[key]
      : fallback;
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
    // djb2 fallback (Instagram in-app browser on some Android versions)
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
   *  SECTION 2 — HARDWARE SIGNAL COLLECTORS
   * ================================================================ */

  /**
   * Canvas fingerprint: layered text + shapes expose GPU sub-pixel
   * antialiasing differences. Returns Promise<string> (hex digest).
   * NOTE: Safari introduces jitter on cache clear. This signal is
   * included for coverage but carries low weight on the backend.
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
   * AudioContext fingerprint: PCM sum from oscillator + compressor.
   * NOTE: Safari introduces jitter on cache clear (low backend weight).
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
   * NEW (v2.0.0) — WebGL unmasked renderer string.
   *
   * WEBGL_debug_renderer_info exposes the true GPU renderer string
   * before any Safari privacy masking. On M4 MacBook Air this returns
   * something like "Apple M4 GPU", which uniquely identifies the GPU
   * micro-architecture. Safari does NOT apply noise or rotation to
   * this extension output. It is completely invariant across:
   *   - network switches (WiFi ↔ hotspot)
   *   - OS updates
   *   - Safari cache clears
   *   - private browsing windows
   *
   * Falls back to "webgl_na" if WebGL is unavailable or if the
   * extension is blocked (rare; only seen in very locked-down
   * enterprise profiles).
   *
   * Returns a plain string (synchronous — no hashing needed since
   * the raw string is already highly unique and readable in logs).
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

      // Combine vendor + renderer for maximum entropy.
      // e.g. "Apple|Apple M4 GPU" on M4 MacBook Air.
      return (vendor + "|" + renderer).substring(0, 128);
    } catch (e) {
      return "webgl_blocked";
    }
  }

  /**
   * NEW (v2.0.0) — Exact screen metrics + device pixel ratio.
   *
   * window.devicePixelRatio reflects the user's OS-level display
   * scaling setting (e.g. "More Space" vs "Default" in macOS Display
   * Preferences). Two M4 MacBook Airs with different scaling settings
   * will produce DIFFERENT screen_detail strings even if their raw
   * screen.width and screen.height are identical.
   *
   * colorDepth adds further separation. Together, the four values
   * form a composite that is:
   *   - Completely unaffected by network changes
   *   - Not noise-injected by Safari
   *   - Different for users who customise their display scaling
   *
   * Format: "WxHxCDxDPR"  e.g. "2560x1664x30x2"
   * Returns a plain string (synchronous).
   */
  function screenDetailSignal() {
    try {
      var s   = win.screen || {};
      var dpr = win.devicePixelRatio || 1;
      return [
        s.width      || "?",
        s.height     || "?",
        s.colorDepth || "?",
        dpr
      ].join("x");
    } catch (e) {
      return "screen_detail_blocked";
    }
  }

  /**
   * Static, network-independent metadata (unchanged from v1).
   * tz and lang are now used only as soft gatekeeper fields on the
   * backend, not as primary key material.
   */
  function staticSignals() {
    var s = win.screen || {};
    return {
      screen  : (s.width  || "?") + "x" + (s.height || "?") + "x" + (s.colorDepth || "?"),
      platform: (navigator.platform   || "unknown").substring(0, 32),
      ua      : (navigator.userAgent  || "unknown").substring(0, 200),
      tz      : (function () {
        try { return Intl.DateTimeFormat().resolvedOptions().timeZone; }
        catch (e) { return "unknown"; }
      })(),
      cores   : navigator.hardwareConcurrency || "?",
      ram     : navigator.deviceMemory        || "?",
      lang    : navigator.language            || "unknown"
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
   *  SECTION 5 — HARDWARE KEY  (local offline fallback)
   * ================================================================ */

  function buildHardwareKey(fp) {
    var raw = [
      fp.visitorId    || "",
      fp.canvas       || "",
      fp.audio        || "",
      fp.screen       || "",
      fp.platform     || "",
      fp.gpu_renderer || "",    // NEW — included for offline ID entropy
      fp.screen_detail|| ""     // NEW — included for offline ID entropy
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

      /* ── 2. Collect all signals in parallel ── */
      Promise.all([
        canvasSignal(),   // async (SubtleCrypto)
        audioSignal(),    // async (OfflineAudioContext)
        loadFPJS()        // async (CDN script load)
      ]).then(function (results) {
        var canvasHash = results[0];
        var audioHash  = results[1];
        var fpAgent    = results[2];

        // gpuRendererSignal and screenDetailSignal are synchronous —
        // collect them here, outside the inner Promise chain, so they
        // are available regardless of FingerprintJS CDN availability.
        var gpuRenderer  = gpuRendererSignal();    // NEW
        var screenDetail = screenDetailSignal();   // NEW

        var getFPVisitorId = fpAgent
          ? fpAgent.get().then(function (r) { return r.visitorId; })
              .catch(function () { return "fp_fail"; })
          : Promise.resolve("fp_skipped");

        return getFPVisitorId.then(function (visitorId) {
          var meta = staticSignals();

          /* ── 3. Build payload ── */
          var payload = {
            visitorId    : visitorId,
            canvas       : canvasHash,
            audio        : audioHash,
            screen       : meta.screen,
            platform     : meta.platform,
            ua           : meta.ua,
            tz           : meta.tz,
            cores        : meta.cores,
            ram          : meta.ram,
            lang         : meta.lang,
            gpu_renderer : gpuRenderer,    // NEW — WebGL unmasked renderer
            screen_detail: screenDetail    // NEW — w×h×colorDepth×DPR
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
            return persist(id).then(function () { return id; });
          });
        });
      }).then(function (id) {
        /* ── 5. Deliver ── */
        deliver(id);
      }).catch(function (err) {
        /* Server unreachable — derive a local ID from hardware signals */
        console.warn("[NitroTracker] Server unavailable, using local ID:", err.message);
        Promise.all([canvasSignal(), audioSignal()]).then(function (sigs) {
          var meta = staticSignals();
          return buildHardwareKey({
            visitorId    : "offline",
            canvas       : sigs[0],
            audio        : sigs[1],
            screen       : meta.screen,
            platform     : meta.platform,
            gpu_renderer : gpuRendererSignal(),   // NEW
            screen_detail: screenDetailSignal()   // NEW
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
    setTimeout(runTracker, 0);
  }

})(window, document);
