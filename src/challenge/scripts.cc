#include "challenge/scripts.h"

#include <string_view>

namespace bot_shield {

// Pure JS SHA-256: much faster than WebCrypto for millions of tiny inputs.
std::string_view CryptoJs() {
  static constexpr std::string_view kScript = R"js(
function sha256(m) {
  var K = sha256.K, i;
  if (!K) {
    K = sha256.K = []; sha256.H = [];
    var frac = function (x) { return ((x - Math.floor(x)) * 4294967296) | 0; };
    for (var p = 2, n = 0; n < 64; p++) {
      var prime = true;
      for (var f = 2; f * f <= p; f++) if (p % f === 0) { prime = false; break; }
      if (!prime) continue;
      if (n < 8) sha256.H[n] = frac(Math.pow(p, 1 / 2));
      K[n++] = frac(Math.pow(p, 1 / 3));
    }
  }
  var H = sha256.H.slice(), l = m.length, bl = ((l + 9 + 63) >> 6) << 6;
  var w = new Uint8Array(bl), W = new Array(64), bits = l * 8;
  w.set(m); w[l] = 0x80;
  w[bl - 4] = (bits >>> 24) & 255; w[bl - 3] = (bits >>> 16) & 255;
  w[bl - 2] = (bits >>> 8) & 255; w[bl - 1] = bits & 255;
  for (var o = 0; o < bl; o += 64) {
    for (i = 0; i < 16; i++) {
      W[i] = (w[o + 4 * i] << 24) | (w[o + 4 * i + 1] << 16) |
             (w[o + 4 * i + 2] << 8) | w[o + 4 * i + 3];
    }
    for (i = 16; i < 64; i++) {
      var x = W[i - 15], y = W[i - 2];
      var s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      var s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
    }
    var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f2 = H[5], g = H[6], h = H[7];
    for (i = 0; i < 64; i++) {
      var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      var t1 = (h + S1 + ((e & f2) ^ (~e & g)) + K[i] + W[i]) | 0;
      var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      var t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      h = g; g = f2; f2 = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0;
    H[3] = (H[3] + d) | 0; H[4] = (H[4] + e) | 0; H[5] = (H[5] + f2) | 0;
    H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
  }
  var out = new Uint8Array(32);
  for (i = 0; i < 8; i++) {
    out[4 * i] = H[i] >>> 24; out[4 * i + 1] = (H[i] >>> 16) & 255;
    out[4 * i + 2] = (H[i] >>> 8) & 255; out[4 * i + 3] = H[i] & 255;
  }
  return out;
}
function zeroBits(hash) {
  for (var bits = 0, i = 0; i < hash.length; i++) {
    if (hash[i] === 0) { bits += 8; continue; }
    for (var v = hash[i]; (v & 0x80) === 0; v <<= 1) bits++;
    break;
  }
  return bits;
}
function solve(nonce, difficulty) {
  var prefix = new TextEncoder().encode(nonce + ":");
  for (var counter = 0; ; counter++) {
    var digits = String(counter), input = new Uint8Array(prefix.length + digits.length);
    input.set(prefix);
    for (var j = 0; j < digits.length; j++) input[prefix.length + j] = digits.charCodeAt(j);
    if (zeroBits(sha256(input)) >= difficulty) return counter;
  }
}
function hex(bytes) {
  for (var s = "", i = 0; i < bytes.length; i++) s += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
  return s;
}
function h(text) { return hex(sha256(new TextEncoder().encode(String(text)))).slice(0, 16); }
function b64url(text) {
  return btoa(unescape(encodeURIComponent(text)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
)js";
  return kScript;
}

// Signals for the checks in Challenger (challenger.cc, CheckSignals). Raw
// canvas, WebGL parameter, audio and font values never leave the browser:
// only short hashes, the renderer string and counts do.
std::string_view ProbesJs() {
  static constexpr std::string_view kScript = R"js(
function isNative(f) {
  try {
    return typeof f === "function" &&
        /\{\s*\[native code\]\s*\}\s*$/.test(Function.prototype.toString.call(f));
  } catch (e) { return false; }
}
function getter(o, p) {
  try { var d = Object.getOwnPropertyDescriptor(o, p); return d && d.get; } catch (e) { return null; }
}
function workerInfo() {
  return new Promise(function (done) {
    try {
      var src = "postMessage([navigator.userAgent,navigator.platform," +
          "navigator.hardwareConcurrency,(navigator.languages||[]).join()])";
      var url = URL.createObjectURL(new Blob([src], { type: "text/javascript" }));
      var w = new Worker(url), t = setTimeout(function () { done(null); }, 1500);
      w.onmessage = function (e) { clearTimeout(t); done(e.data); w.terminate(); };
      w.onerror = function () { clearTimeout(t); done(null); };
    } catch (e) { done(null); }
  });
}
function audioHash() {
  return new Promise(function (done) {
    try {
      var A = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (!A) return done("none");
      var a = new A(1, 5000, 44100), o = a.createOscillator(), k = a.createDynamicsCompressor();
      o.type = "triangle"; o.frequency.value = 10000;
      k.threshold.value = -50; k.knee.value = 40; k.ratio.value = 12;
      k.attack.value = 0; k.release.value = 0.25;
      o.connect(k); k.connect(a.destination); o.start(0);
      var t = setTimeout(function () { done("timeout"); }, 1500);
      a.oncomplete = function (e) {
        clearTimeout(t);
        for (var d = e.renderedBuffer.getChannelData(0), s = 0, i = 4500; i < 5000; i++) s += Math.abs(d[i]);
        done(s.toFixed(6));
      };
      a.startRendering();
    } catch (e) { done("error"); }
  });
}
function probes() {
  var n = navigator, uad = n.userAgentData, r = {};
  r.wd = !!n.webdriver;
  r.lang = (n.languages || []).length;
  r.hc = n.hardwareConcurrency || 0;
  r.plat = n.platform || "";
  r.brands = uad && uad.brands ? uad.brands.map(function (b) { return b.brand; }) : [];
  try { r.tz = Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (e) { r.tz = ""; }
  r.ph = !!(window.callPhantom || window._phantom || window.__nightmare ||
            window.domAutomation || window.domAutomationController ||
            document.$cdc_asdjflasutopfhvcZLmcfl_ || window.__playwright__binding__ ||
            window.__pwInitScripts || window.__selenium_unwrapped || window._Selenium_IDE_Recorder);
  r.ua = h(n.userAgent);
  try {
    var c = document.createElement("canvas"); c.width = 220; c.height = 40;
    var x = c.getContext("2d");
    x.fillStyle = "#f60"; x.fillRect(110, 2, 60, 22);
    x.fillStyle = "#069"; x.font = "15px Arial"; x.fillText("LarpGuard,é☃🛡", 2, 18);
    x.fillStyle = "rgba(102,204,0,0.7)"; x.font = "17px serif"; x.fillText("LarpGuard,é☃🛡", 4, 30);
    x.globalCompositeOperation = "multiply"; x.fillStyle = "#c3c";
    x.beginPath(); x.arc(40, 20, 16, 0, 6.283); x.fill();
    var d1 = c.toDataURL(), d2 = c.toDataURL();
    r.cv = d1.length > 200 ? h(d1) : ""; r.cvn = d1 === d2 ? 0 : 1;
  } catch (e) { r.cv = ""; r.cvn = 0; }
  try {
    var gc = document.createElement("canvas");
    var g = gc.getContext("webgl") || gc.getContext("experimental-webgl");
    if (g) {
      var ext = g.getExtension("WEBGL_debug_renderer_info");
      r.glv = String(ext ? g.getParameter(ext.UNMASKED_VENDOR_WEBGL) : g.getParameter(g.VENDOR)).slice(0, 80);
      r.glr = String(ext ? g.getParameter(ext.UNMASKED_RENDERER_WEBGL) : g.getParameter(g.RENDERER)).slice(0, 120);
      r.glx = (g.getSupportedExtensions() || []).length;
      r.glp = h([g.getParameter(g.MAX_TEXTURE_SIZE), g.getParameter(g.MAX_RENDERBUFFER_SIZE),
                 g.getParameter(g.MAX_VERTEX_ATTRIBS), g.getParameter(g.MAX_VARYING_VECTORS)].join());
    } else { r.glr = "none"; }
  } catch (e) { r.glr = "error"; }
  try {
    var fonts = ["Arial", "Arial Black", "Calibri", "Cambria", "Consolas", "Courier New",
                 "Georgia", "Helvetica", "Helvetica Neue", "Segoe UI", "Tahoma",
                 "Times New Roman", "Trebuchet MS", "Verdana", "Menlo", "Monaco",
                 "SF Pro Text", "Roboto", "Noto Sans", "Ubuntu", "DejaVu Sans",
                 "Liberation Sans", "Cantarell", "Lucida Grande"];
    var m = document.createElement("canvas").getContext("2d"), t = "mmmmmmmmmmlli1WQ@#";
    var gen = ["monospace", "serif", "sans-serif"], base = {}, found = 0, mask = "";
    gen.forEach(function (b) { m.font = "72px " + b; base[b] = m.measureText(t).width; });
    fonts.forEach(function (f) {
      var hit = 0;
      gen.forEach(function (b) { m.font = "72px '" + f + "'," + b; if (m.measureText(t).width !== base[b]) hit = 1; });
      found += hit; mask += hit;
    });
    r.fn = found; r.fm = mask;
  } catch (e) { r.fn = -1; r.fm = ""; }
  var s = window.screen || {};
  r.sc = [s.width | 0, s.height | 0, s.availWidth | 0, s.availHeight | 0, s.colorDepth | 0,
          Math.round((window.devicePixelRatio || 1) * 100), window.outerWidth | 0,
          window.outerHeight | 0, window.innerWidth | 0, window.innerHeight | 0];
  r.pl = n.plugins ? n.plugins.length : -1;
  r.mt = n.maxTouchPoints | 0;
  var tampered = 0;
  [getter(Navigator.prototype, "webdriver"), getter(Navigator.prototype, "languages"),
   getter(Navigator.prototype, "plugins"), getter(Navigator.prototype, "hardwareConcurrency"),
   getter(Navigator.prototype, "userAgent"), Function.prototype.toString,
   HTMLCanvasElement.prototype.toDataURL,
   n.permissions && n.permissions.query].forEach(function (f) { if (f && !isNative(f)) tampered++; });
  ["webdriver", "languages", "plugins", "userAgent", "platform", "hardwareConcurrency"]
      .forEach(function (p) { if (Object.prototype.hasOwnProperty.call(n, p)) tampered++; });
  r.nt = tampered;
  // The DevTools protocol (Puppeteer, Playwright) serializes console
  // arguments, which reads this getter; a page without a debugger does not.
  r.cdp = 0;
  try {
    var err = new Error();
    Object.defineProperty(err, "stack", { configurable: true, get: function () { r.cdp = 1; return ""; } });
    console.debug(err);
  } catch (e) {}
  return r;
}
function collect(callback) {
  Promise.all([workerInfo(), audioHash()]).then(function (v) {
    var r = probes(), w = v[0], n = navigator;
    r.wm = w ? (w[0] !== n.userAgent ? 1 : 0) | (w[1] !== n.platform ? 2 : 0) |
               (w[2] !== n.hardwareConcurrency ? 4 : 0) |
               (w[3] !== (n.languages || []).join() ? 8 : 0) : -1;
    r.au = h(v[1]); r.aun = v[1] === "none" || v[1] === "error" || v[1] === "timeout" ? 1 : 0;
    setTimeout(function () { callback(r); }, 0);
  });
}
)js";
  return kScript;
}

std::string_view ChallengeJs() {
  static constexpr std::string_view kScript = R"js(
collect(function (s) {
  var started = Date.now(), counter = solve(N, D);
  s.ms = Date.now() - started;
  location.replace("/__bs/verify?n=" + encodeURIComponent(N) + "&c=" + counter +
                   "&s=" + b64url(JSON.stringify(s)));
});
)js";
  return kScript;
}

std::string_view WidgetJs() {
  static constexpr std::string_view kScript = R"js(
var bsSignals = new Promise(function (done) { collect(done); });
function bsCaptchaDone(token) {
  var status = document.getElementById("bs-status");
  if (status) status.textContent = "Verifying…";
  bsSignals.then(function (s) {
    var counter = solve(N, D);
    location.replace("/__bs/captcha/verify?n=" + encodeURIComponent(N) + "&c=" + counter +
                     "&t=" + encodeURIComponent(token) + "&s=" + b64url(JSON.stringify(s)));
  });
}
// The widget calls a global by name.
window.bsCaptchaDone = bsCaptchaDone;
)js";
  return kScript;
}

// Pointer trace: [x, y, ms since the image appeared] in image pixels,
// every movement over the page (also before the pointer reaches the
// image), at most 120 points; the server checks it looks like a hand.
std::string_view PuzzleJs() {
  static constexpr std::string_view kScript = R"js(
var bsSignals = new Promise(function (done) { collect(done); });
var img = document.getElementById("bs-p"), sample = document.getElementById("bs-s");
var info = document.getElementById("bs-status"), round = document.getElementById("bs-round");
var trace = [], shown = performance.now(), pointer = "", busy = false;
function local(e) {
  var r = img.getBoundingClientRect();
  return [Math.round((e.clientX - r.left) * img.naturalWidth / r.width),
          Math.round((e.clientY - r.top) * img.naturalHeight / r.height)];
}
document.addEventListener("pointermove", function (e) {
  pointer = e.pointerType || pointer;
  var p = local(e);
  trace.push([p[0], p[1], Math.round(e.timeStamp - shown)]);
  if (trace.length > 120) trace.shift();
}, { passive: true });
document.addEventListener("pointerdown", function (e) { pointer = e.pointerType || pointer; }, { passive: true });
function show(next) {
  N = next.n; img.src = next.image; sample.src = next.sample;
  if (round) round.textContent = next.round;
  trace = []; shown = performance.now(); busy = false;
}
img.addEventListener("click", function (e) {
  if (busy) return;
  busy = true;
  var p = local(e);
  var telemetry = { tr: e.isTrusted ? 1 : 0, pt: pointer || "mouse", ms: Math.round(e.timeStamp - shown),
                    p: trace.slice(-60) };
  info.textContent = "Checking…";
  bsSignals.then(function (s) {
    var counter = solve(N, D);
    var url = "/__bs/captcha/answer?n=" + encodeURIComponent(N) + "&c=" + counter +
              "&x=" + p[0] + "&y=" + p[1] + "&m=" + b64url(JSON.stringify(telemetry)) +
              "&s=" + b64url(JSON.stringify(s));
    return fetch(url, { credentials: "same-origin", cache: "no-store" });
  }).then(function (response) { return response.json(); }).then(function (j) {
    if (j.done) { info.textContent = "Done."; location.replace(j.done); return; }
    if (j.next) { info.textContent = j.message || ""; show(j.next); return; }
    info.textContent = j.message || "Something went wrong. Reload the page.";
  }).catch(function () { info.textContent = "Network error. Reload the page."; });
});
)js";
  return kScript;
}

}  // namespace bot_shield
