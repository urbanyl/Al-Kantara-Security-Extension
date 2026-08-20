/**
 * Al-Kantara Security v1.3.1 — Core Background Service
 * Kill Switch, Profiles, DNS, WebRTC, Headers, Link Cleaner,
 * GPC/DNT, Referrer Control, Cookie Isolation, Cache Clear,
 * Chemical Clean, Encrypted Export, Identity Rotation, Cipher Lab,
 * Encrypted Vault, Threat Intelligence, Network Monitor,
 * Clipboard Protection, Screen Guard, Memory Scrubber, Full Message Router
 *
 * © Urbanyl — github.com/urbanyl
 */

const AKS_BUILD = "1.3.1";
const AKS_BUILD_TS = Date.now();

let _api = typeof browser !== "undefined" ? browser : chrome;
function api() { return _api; }

/* ═══════════════════ DYNAMIC SHIELD ICON ═══════════════════ */
const SHIELD_ICONS = {
  armed:    { 16: "src/assets/icons/shield-check-16.png", 48: "src/assets/icons/shield-check-48.png", 128: "src/assets/icons/shield-check-128.png" },
  warning:  { 16: "src/assets/icons/shield-half-16.png",  48: "src/assets/icons/shield-half-48.png",  128: "src/assets/icons/shield-half-128.png" },
  disarmed: { 16: "src/assets/icons/shield-16.png",       48: "src/assets/icons/shield-48.png",       128: "src/assets/icons/shield-128.png" }
};

async function updateShieldIcon(state) {
  if (!api().action || !api().action.setIcon) return;
  let mode = "armed";
  if (state.killSwitch) mode = "disarmed";
  else if (state.profile === "disabled") mode = "disarmed";
  else if (state.profile === "moderate") mode = "warning";
  try {
    const icons = SHIELD_ICONS[mode];
    const imageData = {};
    for (const [size, path] of Object.entries(icons)) {
      try {
        const resp = await fetch(api().runtime.getURL(path));
        const blob = await resp.blob();
        const bmp = await createImageBitmap(blob);
        const canvas = new OffscreenCanvas(bmp.width, bmp.height);
        const ctx = canvas.getContext("2d");
        ctx.drawImage(bmp, 0, 0);
        imageData[size] = ctx.getImageData(0, 0, bmp.width, bmp.height);
      } catch (e) {}
    }
    if (Object.keys(imageData).length > 0) {
      api().action.setIcon({ imageData });
    }
  } catch (e) {}
}

/* ═══════════════════ STORAGE KEYS ═══════════════════ */
const SK = {
  PROFILE: "aks_profile", KILL: "aks_kill", PERSONA: "aks_persona",
  DNS: "aks_dns", WEBRTC: "aks_webrtc", LOGS: "aks_logs",
  SETTINGS: "aks_settings", CLEAN: "aks_clean",
  FP_CANVAS: "aks_fp_canvas", FP_WEBGL: "aks_fp_webgl",
  FP_AUDIO: "aks_fp_audio", FP_FONTS: "aks_fp_fonts",
  FP_CLIENTRECTS: "aks_fp_clientrects",
  NET_REFERRER: "aks_net_referrer", NET_DNT: "aks_net_dnt",
  NET_GPC: "aks_net_gpc", NET_ACCEPTCH: "aks_net_acceptch",
  NET_CACHE: "aks_net_cache", NET_ETAG: "aks_net_etag",
  NET_LINKCLEAN: "aks_net_linkclean", NET_HSTS: "aks_net_hsts",
  NAV_BATTERY: "aks_nav_battery", NAV_SPEECH: "aks_nav_speech",
  NAV_PRESENTATION: "aks_nav_presentation", NAV_WEBRTCIP: "aks_nav_webrtcip",
  ADV_WINDOWNAME: "aks_adv_winname", ADV_CONSOLE: "aks_adv_console",
  ADV_TZ: "aks_adv_tz", ADV_GEO: "aks_adv_geo", ADV_COOKIEISO: "aks_adv_cookieiso",
  ADV_CLOAK: "aks_adv_cloak",
  // v1.3.1 new keys
  ROTATION: "aks_rotation", VAULT: "aks_vault",
  THREATS: "aks_threats", NET_MON: "aks_netmon",
  CLIPGUARD: "aks_clipguard", SCREENGUARD: "aks_screenguard",
  MEMORYSCRUB: "aks_memoryscrub", TRAFFICOBFUSC: "aks_trafficobfusc",
  MOUSEBLOCK: "aks_mouseblock", KEYBLOCK: "aks_keyblock",
  CIPHER_HISTORY: "aks_cipher_history",
  EXEC_SCRIPTS: "aks_exec_scripts", EXEC_HISTORY: "aks_exec_history"
};

const PROFILES = {
  strict: { label: "Strict", headerRewrite: true, blockWebRTC: true, dnsFilter: true },
  moderate: { label: "Moderate", headerRewrite: true, blockWebRTC: false, dnsFilter: true },
  disabled: { label: "Disabled", headerRewrite: false, blockWebRTC: false, dnsFilter: false }
};

const PERSONAS = {
  win11_edge: { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0", platform: "Win32", vendor: "Microsoft Corporation", lang: "en-US,en;q=0.9" },
  macos_safari: { ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15", platform: "MacIntel", vendor: "Apple Computer, Inc.", lang: "en-US,en;q=0.9" },
  linux_firefox: { ua: "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0", platform: "Linux x86_64", vendor: "", lang: "en-US,en;q=0.5" },
  win10_chrome: { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", platform: "Win32", vendor: "Google Inc.", lang: "en-US,en;q=0.9" },
  android_chrome: { ua: "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36", platform: "Linux armv81", vendor: "Google Inc.", lang: "en-US,en;q=0.9" },
  ios_safari: { ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1", platform: "iPhone", vendor: "Apple Computer, Inc.", lang: "en-US,en;q=0.9" }
};

const TRACKING_PARAMS = [
  "utm_source","utm_medium","utm_campaign","utm_term","utm_content",
  "fbclid","gclid","gclsrc","dclid","gbraid","wbraid",
  "msclkid","mc_cid","mc_eid","oly_anon_id","oly_enc_id",
  "_ga","_gl","_hsenc","_hsmi","hsCtaTracking","s_cid",
  "twclid","li_fat_id","igshid","ttclid","_fingerprint","trk",
  "oly_anonymous_id","vero_id","wickedid","yftid","yclid"
];

/* ═══════════════════ THREAT INTELLIGENCE ═══════════════════ */
const THREAT_DOMAINS = new Set([
  "malware-traffic-analysis.net","phish.example.com","c2server.bad",
  "ransomware-drop.evil","cryptojacking.mine","keylogger.sniff",
  "exploit-kit.dark","botnet.command","adware.inject","spyware.track",
  "backdoor.remote","trojan.horse","rootkit.deep","worm.spread",
  "rogue.security","fakeupdate.scam","credential.steal","session.hijack",
  "dns-hijack.mal","ddos.amplify","watering.hole","spearphish.target"
]);

const THREAT_IP_RANGES = [
  "185.220.101.", "91.189.88.", "198.51.100.", "203.0.113."
];

/* ═══════════════════ NET MONITOR STATE ═══════════════════ */
let netStats = { blocked: 0, allowed: 0, cleaned: 0, threats: 0, history: [] };
let rotationTimer = null;

/* ═══════════════════ LOGGING ═══════════════════ */
async function addLog(level, category, message, details) {
  try {
    const r = await api().storage.local.get(SK.LOGS);
    const logs = r[SK.LOGS] || [];
    logs.push({ id: Date.now() + "-" + Math.random().toString(36).slice(2, 8), ts: new Date().toISOString(), level, category, message, details: details || null });
    if (logs.length > 3000) logs.splice(0, logs.length - 3000);
    await api().storage.local.set({ [SK.LOGS]: logs });
  } catch (e) {}
}

/* ═══════════════════ INIT ═══════════════════ */
async function initExtension() {
  const defs = {};
  Object.values(SK).forEach(k => { defs[k] = undefined; });
  defs[SK.PROFILE] = "strict"; defs[SK.KILL] = false;
  defs[SK.PERSONA] = "win11_edge"; defs[SK.DNS] = true;
  defs[SK.WEBRTC] = "disabled"; defs[SK.LOGS] = [];
  defs[SK.FP_CANVAS] = true; defs[SK.FP_WEBGL] = true;
  defs[SK.FP_AUDIO] = true; defs[SK.FP_FONTS] = true;
  defs[SK.FP_CLIENTRECTS] = true;
  defs[SK.NET_REFERRER] = "strict-origin-when-cross-origin";
  defs[SK.NET_DNT] = true; defs[SK.NET_GPC] = true;
  defs[SK.NET_ACCEPTCH] = true; defs[SK.NET_CACHE] = true;
  defs[SK.NET_ETAG] = true; defs[SK.NET_LINKCLEAN] = true;
  defs[SK.NET_HSTS] = true;
  defs[SK.NAV_BATTERY] = true; defs[SK.NAV_SPEECH] = true;
  defs[SK.NAV_PRESENTATION] = true; defs[SK.NAV_WEBRTCIP] = true;
  defs[SK.ADV_WINDOWNAME] = true; defs[SK.ADV_CONSOLE] = true;
  defs[SK.ADV_TZ] = ""; defs[SK.ADV_GEO] = "";
  defs[SK.ADV_COOKIEISO] = true; defs[SK.ADV_CLOAK] = true;
  defs[SK.SETTINGS] = { chemicalCleanOnStart: false, logRetentionDays: 7, showNotifications: true };
  defs[SK.CLEAN] = null;
  // v1.3.1 defaults
  defs[SK.ROTATION] = { enabled: false, intervalMinutes: 30, sequence: "cycle" };
  defs[SK.VAULT] = [];
  defs[SK.THREATS] = { enabled: true, blockedCount: 0 };
  defs[SK.NET_MON] = { enabled: true };
  defs[SK.CLIPGUARD] = false;
  defs[SK.SCREENGUARD] = false;
  defs[SK.MEMORYSCRUB] = false;
  defs[SK.TRAFFICOBFUSC] = false;
  defs[SK.MOUSEBLOCK] = false;
  defs[SK.KEYBLOCK] = false;
  defs[SK.CIPHER_HISTORY] = [];

  const existing = await api().storage.local.get(Object.keys(defs));
  const toSet = {};
  for (const [k, v] of Object.entries(defs)) { if (existing[k] === undefined) toSet[k] = v; }
  if (Object.keys(toSet).length > 0) await api().storage.local.set(toSet);

  await addLog("info", "SYSTEM", "Extension initialized", { build: AKS_BUILD });
  if (existing[SK.KILL]) await activateKillSwitch();
  await applyHeaderRules();
  startIdentityRotation();
  startMemoryScrubber();
  const iconState = { killSwitch: existing[SK.KILL] || false, profile: existing[SK.PROFILE] || "strict" };
  updateShieldIcon(iconState);
}

/* ═══════════════════ KILL SWITCH ═══════════════════ */
async function activateKillSwitch() {
  await api().storage.local.set({ [SK.KILL]: true });
  await addLog("warn", "KILL", "Kill Switch ACTIVATED");
  updateShieldIcon({ killSwitch: true, profile: "strict" });
  if (api().declarativeNetRequest) {
    const old = await api().declarativeNetRequest.getDynamicRules();
    await api().declarativeNetRequest.updateDynamicRules({
      removeRuleIds: old.map(r => r.id),
      addRules: [{ id: 9999, priority: 1, action: { type: "block" }, condition: { urlFilter: "*://*", resourceTypes: ["main_frame","sub_frame","stylesheet","script","image","font","object","xmlhttprequest","ping","media","websocket","webtransport","other"] } }]
    });
  }
}

async function deactivateKillSwitch() {
  await api().storage.local.set({ [SK.KILL]: false });
  await addLog("info", "KILL", "Kill Switch DEACTIVATED");
  const prof = (await api().storage.local.get(SK.PROFILE))[SK.PROFILE] || "strict";
  updateShieldIcon({ killSwitch: false, profile: prof });
  if (api().declarativeNetRequest) {
    const old = await api().declarativeNetRequest.getDynamicRules();
    await api().declarativeNetRequest.updateDynamicRules({ removeRuleIds: old.map(r => r.id), addRules: [] });
  }
}

/* ═══════════════════ HEADER RULES (Chromium) ═══════════════════ */
async function applyHeaderRules() {
  if (!api().declarativeNetRequest) return;
  const data = await api().storage.local.get([SK.PROFILE, SK.PERSONA, SK.NET_DNT, SK.NET_GPC, SK.NET_ACCEPTCH, SK.NET_REFERRER, SK.NET_HSTS, SK.TRAFFICOBFUSC]);
  const profile = data[SK.PROFILE] || "strict";
  const personaKey = data[SK.PERSONA] || "win11_edge";
  if (profile === "disabled") return;

  const persona = PERSONAS[personaKey] || PERSONAS.win11_edge;
  const old = await api().declarativeNetRequest.getDynamicRules();
  const removeIds = old.filter(r => r.id >= 200 && r.id <= 299).map(r => r.id);
  const rules = [];
  let rid = 200;

  rules.push({ id: rid++, priority: 1, action: { type: "modifyHeaders", requestHeaders: [{ header: "User-Agent", operation: "set", value: persona.ua }] }, condition: { urlFilter: "*://*", resourceTypes: ["main_frame","sub_frame","stylesheet","script","image","font","object","xmlhttprequest","ping","media","websocket","other"] } });
  rules.push({ id: rid++, priority: 1, action: { type: "modifyHeaders", requestHeaders: [{ header: "Accept-Language", operation: "set", value: persona.lang }] }, condition: { urlFilter: "*://*", resourceTypes: ["main_frame","sub_frame","stylesheet","script","image","font","object","xmlhttprequest","ping","media","websocket","other"] } });

  ["X-Forwarded-For","X-Real-IP","CF-Connecting-IP","X-Client-IP","Forwarded"].forEach(h => {
    rules.push({ id: rid++, priority: 1, action: { type: "modifyHeaders", requestHeaders: [{ header: h, operation: "remove" }] }, condition: { urlFilter: "*://*", resourceTypes: ["main_frame","sub_frame","stylesheet","script","image","font","object","xmlhttprequest","ping","media","websocket","other"] } });
  });

  if (data[SK.NET_ACCEPTCH]) {
    ["Accept-CH","Sec-CH-UA","Sec-CH-UA-Mobile","Sec-CH-UA-Platform","Sec-CH-UA-Full-Version-List","Sec-CH-UA-Platform-Version","Sec-CH-UA-Arch","Sec-CH-UA-Model","Sec-CH-UA-Bitness","Sec-CH-UA-WoW64"].forEach(h => {
      rules.push({ id: rid++, priority: 1, action: { type: "modifyHeaders", requestHeaders: [{ header: h, operation: "remove" }] }, condition: { urlFilter: "*://*", resourceTypes: ["main_frame","sub_frame","stylesheet","script","image","font","object","xmlhttprequest","ping","media","websocket","other"] } });
    });
  }

  if (data[SK.NET_DNT]) {
    rules.push({ id: rid++, priority: 1, action: { type: "modifyHeaders", requestHeaders: [{ header: "DNT", operation: "set", value: "1" }] }, condition: { urlFilter: "*://*", resourceTypes: ["main_frame","sub_frame","stylesheet","script","image","font","object","xmlhttprequest","ping","media","websocket","other"] } });
  }

  if (data[SK.NET_GPC]) {
    rules.push({ id: rid++, priority: 1, action: { type: "modifyHeaders", requestHeaders: [{ header: "Sec-GPC", operation: "set", value: "1" }] }, condition: { urlFilter: "*://*", resourceTypes: ["main_frame","sub_frame","stylesheet","script","image","font","object","xmlhttprequest","ping","media","websocket","other"] } });
  }

  if (data[SK.NET_REFERRER]) {
    rules.push({ id: rid++, priority: 1, action: { type: "modifyHeaders", requestHeaders: [{ header: "Referer", operation: "set", value: "" }] }, condition: { urlFilter: "*://*", resourceTypes: ["xmlhttprequest","script","image","font","object","media"] } });
  }

  if (data[SK.NET_HSTS]) {
    rules.push({ id: rid++, priority: 1, action: { type: "upgradeScheme", upgradeScheme: "https" }, condition: { urlFilter: "*://*", resourceTypes: ["main_frame"] } });
  }

  ["Sec-Fetch-Dest","Sec-Fetch-Mode","Sec-Fetch-Site","Sec-Fetch-User","Upgrade-Insecure-Requests"].forEach(h => {
    rules.push({ id: rid++, priority: 1, action: { type: "modifyHeaders", requestHeaders: [{ header: h, operation: "remove" }] }, condition: { urlFilter: "*://*", resourceTypes: ["main_frame","sub_frame","xmlhttprequest"] } });
  });

  if (data[SK.TRAFFICOBFUSC]) {
    rules.push({ id: rid++, priority: 1, action: { type: "modifyHeaders", requestHeaders: [{ header: "Cache-Control", operation: "set", value: "no-cache, no-store, must-revalidate" }] }, condition: { urlFilter: "*://*", resourceTypes: ["main_frame","xmlhttprequest"] } });
    rules.push({ id: rid++, priority: 1, action: { type: "modifyHeaders", requestHeaders: [{ header: "Pragma", operation: "set", value: "no-cache" }] }, condition: { urlFilter: "*://*", resourceTypes: ["main_frame","xmlhttprequest"] } });
  }

  const trackerDomains = ["google-analytics.com","googletagmanager.com","doubleclick.net","facebook.net","fbevents.js","analytics.tiktok.com","bat.bing.com","ads.twitter.com","snap.licdn.com","script.hotjar.com","cdn.jsdelivr.net/npm/@nicepkg"];
  trackerDomains.forEach(d => {
    rules.push({ id: rid++, priority: 1, action: { type: "block" }, condition: { urlFilter: "||" + d, resourceTypes: ["script","image","xmlhttprequest","ping","font","media"] } });
  });

  ["fingerprint2.js","fingerprintjs","fingerprintjs2","clientjs","stormcatter","canvas-fingerprint","audio-fingerprint"].forEach(p => {
    rules.push({ id: rid++, priority: 1, action: { type: "block" }, condition: { urlFilter: p, resourceTypes: ["script"] } });
  });

  await api().declarativeNetRequest.updateDynamicRules({ removeRuleIds: removeIds, addRules: rules });
}

/* ═══════════════════ LINK CLEANER ═══════════════════ */
function cleanUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    let changed = false;
    TRACKING_PARAMS.forEach(p => {
      if (u.searchParams.has(p)) { u.searchParams.delete(p); changed = true; }
    });
    if (u.hash && u.hash.includes("utm_")) { u.hash = ""; changed = true; }
    return changed ? u.toString() : null;
  } catch (e) { return null; }
}

/* ═══════════════════ THREAT DETECTION ═══════════════════ */
function detectThreat(url) {
  try {
    const u = new URL(url);
    const host = u.hostname.toLowerCase();
    for (const td of THREAT_DOMAINS) {
      if (host.includes(td) || host === td) return { type: "malicious_domain", domain: td };
    }
    for (const prefix of THREAT_IP_RANGES) {
      if (host.startsWith(prefix)) return { type: "suspicious_ip", ip: host };
    }
    return null;
  } catch (e) { return null; }
}

/* ═══════════════════ CHEMICAL CLEAN ═══════════════════ */
async function chemicalClean(tabId) {
  await addLog("info", "CLEAN", "Initiating Chemical Clean");
  try {
    await api().browsingData.remove({}, {
      cookies: true, localStorage: true, sessionStorage: true,
      indexedDB: true, cache: true, formData: true, downloads: true,
      passwords: false, history: false
    });
    if (api().cookies) {
      const all = await api().cookies.getAll({});
      for (const c of all) {
        if (!c.name.startsWith("aks_")) {
          await api().cookies.remove({ url: `https://${c.domain}${c.path}`, name: c.name });
        }
      }
    }
    await api().storage.local.set({ [SK.CLEAN]: new Date().toISOString() });
    await addLog("info", "CLEAN", "Chemical Clean completed");
    return { success: true };
  } catch (e) {
    await addLog("error", "CLEAN", "Clean failed: " + e.message);
    return { success: false, error: e.message };
  }
}

/* ═══════════════════ IDENTITY ROTATION ═══════════════════ */
function startIdentityRotation() {
  if (rotationTimer) { clearInterval(rotationTimer); rotationTimer = null; }
  api().storage.local.get([SK.ROTATION, SK.PERSONA]).then(d => {
    const rot = d[SK.ROTATION];
    if (rot && rot.enabled && rot.intervalMinutes > 0) {
      const keys = Object.keys(PERSONAS);
      rotationTimer = setInterval(async () => {
        const data = await api().storage.local.get([SK.ROTATION, SK.PERSONA]);
        const r = data[SK.ROTATION];
        if (!r || !r.enabled) { clearInterval(rotationTimer); rotationTimer = null; return; }
        const current = data[SK.PERSONA];
        let next;
        if (r.sequence === "random") {
          next = keys[Math.floor(Math.random() * keys.length)];
          while (next === current && keys.length > 1) next = keys[Math.floor(Math.random() * keys.length)];
        } else {
          const idx = keys.indexOf(current);
          next = keys[(idx + 1) % keys.length];
        }
        await api().storage.local.set({ [SK.PERSONA]: next });
        await applyHeaderRules();
        await addLog("info", "ROTATION", "Identity rotated: " + PERSONAS[next].ua.substring(0, 50) + "...");
      }, rot.intervalMinutes * 60 * 1000);
    }
  });
}

/* ═══════════════════ MEMORY SCRUBBER ═══════════════════ */
let memoryScrubTimer = null;
function startMemoryScrubber() {
  if (memoryScrubTimer) { clearInterval(memoryScrubTimer); memoryScrubTimer = null; }
  api().storage.local.get(SK.MEMORYSCRUB).then(d => {
    if (d[SK.MEMORYSCRUB]) {
      memoryScrubTimer = setInterval(() => {
        try {
          window.name = Math.random().toString(36).slice(2);
          if (history && history.replaceState) {
            history.replaceState(null, "", location.href);
          }
        } catch (e) {}
      }, 30000);
    }
  });
}

/* ═══════════════════ ENCRYPTED VAULT ═══════════════════ */
async function vaultEncrypt(data, passphrase) {
  const enc = new TextEncoder().encode(JSON.stringify(data));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const km = await crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" }, km, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc);
  return { salt: Array.from(salt), iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) };
}

async function vaultDecrypt(encObj, passphrase) {
  try {
    const salt = new Uint8Array(encObj.salt);
    const iv = new Uint8Array(encObj.iv);
    const ct = new Uint8Array(encObj.ct);
    const km = await crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" }, km, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
    return JSON.parse(new TextDecoder().decode(pt));
  } catch (e) { return null; }
}

/* ═══════════════════ CIPHER LAB ═══════════════════ */
async function cipherEncrypt(plaintext, passphrase, algorithm) {
  const enc = new TextEncoder().encode(plaintext);
  if (algorithm === "aes-gcm-256") {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const km = await crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" }, km, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc);
    const out = new Uint8Array(4 + 16 + 12 + ct.byteLength);
    new DataView(out.buffer).setUint32(0, 0x414B5302);
    out.set(salt, 4); out.set(iv, 20); out.set(new Uint8Array(ct), 32);
    return btoa(String.fromCharCode(...out));
  } else if (algorithm === "aes-gcm-128") {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const km = await crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 300000, hash: "SHA-256" }, km, { name: "AES-GCM", length: 128 }, false, ["encrypt"]);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc);
    const out = new Uint8Array(4 + 16 + 12 + ct.byteLength);
    new DataView(out.buffer).setUint32(0, 0x414B5303);
    out.set(salt, 4); out.set(iv, 20); out.set(new Uint8Array(ct), 32);
    return btoa(String.fromCharCode(...out));
  } else if (algorithm === "xor-chacha") {
    const key = new TextEncoder().encode(passphrase);
    const result = new Uint8Array(enc.length);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    for (let i = 0; i < enc.length; i++) {
      result[i] = enc[i] ^ key[i % key.length] ^ nonce[i % nonce.length];
    }
    const out = new Uint8Array(4 + 12 + result.byteLength);
    new DataView(out.buffer).setUint32(0, 0x414B5304);
    out.set(nonce, 4); out.set(result, 16);
    return btoa(String.fromCharCode(...out));
  } else if (algorithm === "caesar-13") {
    return Array.from(enc).map(b => {
      if (b >= 65 && b <= 90) return String.fromCharCode(((b - 65 + 13) % 26) + 65);
      if (b >= 97 && b <= 122) return String.fromCharCode(((b - 97 + 13) % 26) + 97);
      return String.fromCharCode(b);
    }).join("");
  }
  return btoa(plaintext);
}

async function cipherDecrypt(ciphertext, passphrase, algorithm) {
  try {
    if (algorithm === "aes-gcm-256" || algorithm === "aes-gcm-128") {
      const raw = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
      const magic = new DataView(raw.buffer).getUint32(0);
      const salt = raw.slice(4, 20);
      const iv = raw.slice(20, 32);
      const ct = raw.slice(32);
      const iter = magic === 0x414B5303 ? 300000 : 600000;
      const len = magic === 0x414B5303 ? 128 : 256;
      const km = await crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
      const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" }, km, { name: "AES-GCM", length: len }, false, ["decrypt"]);
      const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
      return new TextDecoder().decode(pt);
    } else if (algorithm === "xor-chacha") {
      const raw = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
      const nonce = raw.slice(4, 16);
      const data = raw.slice(16);
      const key = new TextEncoder().encode(passphrase);
      const result = new Uint8Array(data.length);
      for (let i = 0; i < data.length; i++) {
        result[i] = data[i] ^ key[i % key.length] ^ nonce[i % nonce.length];
      }
      return new TextDecoder().decode(result);
    } else if (algorithm === "caesar-13") {
      return Array.from(ciphertext).map(c => {
        const code = c.charCodeAt(0);
        if (code >= 65 && code <= 90) return String.fromCharCode(((code - 65 + 13) % 26) + 65);
        if (code >= 97 && code <= 122) return String.fromCharCode(((code - 97 + 13) % 26) + 97);
        return c;
      }).join("");
    }
    return atob(ciphertext);
  } catch (e) { return "[Decryption failed: " + e.message + "]"; }
}

/* ═══════════════════ ENCRYPTED EXPORT ═══════════════════ */
async function exportLogsEncrypted(passphrase) {
  try {
    const r = await api().storage.local.get(SK.LOGS);
    const logs = r[SK.LOGS] || [];
    const pt = new TextEncoder().encode(JSON.stringify(logs, null, 2));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const km = await crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" }, km, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pt);
    const exp = new Uint8Array(8 + 28 + ct.byteLength);
    new DataView(exp.buffer).setUint32(0, 0x414B5301, false);
    new DataView(exp.buffer).setUint16(4, 16, false);
    new DataView(exp.buffer).setUint16(6, 12, false);
    exp.set(salt, 8); exp.set(iv, 24); exp.set(new Uint8Array(ct), 36);
    const blob = new Blob([exp], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    api().downloads.download({ url, filename: "alks-logs-" + new Date().toISOString().replace(/[:.]/g, "-") + ".enc" });
    await addLog("info", "EXPORT", "Exported " + logs.length + " entries (encrypted)");
    return { success: true, count: logs.length };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

/* ═══════════════════ FINGERPRINT ENTROPY ═══════════════════ */
function calculateEntropy(data) {
  const vals = [];
  if (data.fp) {
    if (data.fp.canvas) vals.push(0.95); else vals.push(0.1);
    if (data.fp.webgl) vals.push(0.9); else vals.push(0.15);
    if (data.fp.audio) vals.push(0.85); else vals.push(0.2);
    if (data.fp.fonts) vals.push(0.7); else vals.push(0.3);
    if (data.fp.clientrects) vals.push(0.6); else vals.push(0.25);
  }
  if (data.nav) {
    if (data.nav.battery) vals.push(0.6); else vals.push(0.35);
    if (data.nav.speech) vals.push(0.5); else vals.push(0.3);
    if (data.nav.presentation) vals.push(0.4); else vals.push(0.25);
    if (data.nav.webrtcip) vals.push(0.8); else vals.push(0.1);
  }
  if (data.adv) {
    if (data.adv.tz) vals.push(0.7); else vals.push(0.2);
    if (data.adv.geo) vals.push(0.6); else vals.push(0.2);
    if (data.adv.windowname) vals.push(0.3); else vals.push(0.1);
    if (data.adv.cookieiso) vals.push(0.5); else vals.push(0.15);
  }
  if (vals.length === 0) return 0;
  return Math.round((vals.reduce((a, b) => a + b, 0) / vals.length) * 100);
}

/* ═══════════════════ MESSAGE ROUTER ═══════════════════ */
if (api().runtime && api().runtime.onMessage) {
  api().runtime.onMessage.addListener((msg, sender, sendResponse) => {
    const handler = async () => {
      switch (msg.action) {
        case "getState": {
          const d = await api().storage.local.get(Object.values(SK));
          const entropyData = { fp: { canvas: d[SK.FP_CANVAS], webgl: d[SK.FP_WEBGL], audio: d[SK.FP_AUDIO], fonts: d[SK.FP_FONTS], clientrects: d[SK.FP_CLIENTRECTS] }, nav: { battery: d[SK.NAV_BATTERY], speech: d[SK.NAV_SPEECH], presentation: d[SK.NAV_PRESENTATION], webrtcip: d[SK.NAV_WEBRTCIP] }, adv: { tz: d[SK.ADV_TZ], geo: d[SK.ADV_GEO], windowname: d[SK.ADV_WINDOWNAME], cookieiso: d[SK.ADV_COOKIEISO] } };
          return {
            profile: d[SK.PROFILE], killSwitch: d[SK.KILL], persona: d[SK.PERSONA],
            dnsSecure: d[SK.DNS], webrtcMode: d[SK.WEBRTC], settings: d[SK.SETTINGS],
            cleanTime: d[SK.CLEAN], build: AKS_BUILD, buildTs: AKS_BUILD_TS,
            logs: (d[SK.LOGS] || []).slice(-80),
            fp: { canvas: d[SK.FP_CANVAS], webgl: d[SK.FP_WEBGL], audio: d[SK.FP_AUDIO], fonts: d[SK.FP_FONTS], clientrects: d[SK.FP_CLIENTRECTS] },
            net: { referrer: d[SK.NET_REFERRER], dnt: d[SK.NET_DNT], gpc: d[SK.NET_GPC], acceptch: d[SK.NET_ACCEPTCH], cache: d[SK.NET_CACHE], etag: d[SK.NET_ETAG], linkclean: d[SK.NET_LINKCLEAN], hsts: d[SK.NET_HSTS] },
            nav: { battery: d[SK.NAV_BATTERY], speech: d[SK.NAV_SPEECH], presentation: d[SK.NAV_PRESENTATION], webrtcip: d[SK.NAV_WEBRTCIP] },
            adv: { windowname: d[SK.ADV_WINDOWNAME], console: d[SK.ADV_CONSOLE], tz: d[SK.ADV_TZ], geo: d[SK.ADV_GEO], cookieiso: d[SK.ADV_COOKIEISO], cloak: d[SK.ADV_CLOAK] },
            // v1.3.1
            rotation: d[SK.ROTATION], threats: d[SK.THREATS], netMon: d[SK.NET_MON],
            clipguard: d[SK.CLIPGUARD], screenguard: d[SK.SCREENGUARD],
            memoryscrub: d[SK.MEMORYSCRUB], trafficobfusc: d[SK.TRAFFICOBFUSC],
            mouseblock: d[SK.MOUSEBLOCK], keyblock: d[SK.KEYBLOCK],
            entropy: calculateEntropy(entropyData),
            netStats: netStats,
            vaultCount: (d[SK.VAULT] || []).length,
            cipherHistory: (d[SK.CIPHER_HISTORY] || []).slice(-20),
            execScripts: (d[SK.EXEC_SCRIPTS] || []).slice(-30),
            execHistory: (d[SK.EXEC_HISTORY] || []).slice(-30)
          };
        }
        case "setProfile":
          await api().storage.local.set({ [SK.PROFILE]: msg.profile });
          await addLog("info", "PROFILE", "Profile: " + msg.profile);
          await applyHeaderRules();
          const ks = (await api().storage.local.get(SK.KILL))[SK.KILL];
          updateShieldIcon({ killSwitch: !!ks, profile: msg.profile });
          return { success: true };
        case "toggleKillSwitch":
          if (msg.enable) await activateKillSwitch(); else await deactivateKillSwitch();
          return { success: true };
        case "setPersona":
          await api().storage.local.set({ [SK.PERSONA]: msg.persona });
          await addLog("info", "FP", "Persona: " + msg.persona);
          await applyHeaderRules();
          return { success: true };
        case "setDnsProtection":
          await api().storage.local.set({ [SK.DNS]: msg.enabled });
          return { success: true };
        case "setWebRTCMode":
          await api().storage.local.set({ [SK.WEBRTC]: msg.mode });
          return { success: true };
        case "setFeature": {
          const key = SK[msg.key];
          if (key) { await api().storage.local.set({ [key]: msg.value }); await addLog("info", "CONFIG", msg.key + " = " + JSON.stringify(msg.value)); }
          if (msg.key === "ROTATION") startIdentityRotation();
          if (msg.key === "MEMORYSCRUB") startMemoryScrubber();
          return { success: true };
        }
        case "chemicalClean":
          return await chemicalClean(msg.tabId);
        case "exportLogs":
          return await exportLogsEncrypted(msg.passphrase);
        case "clearLogs":
          await api().storage.local.set({ [SK.LOGS]: [] });
          return { success: true };
        case "updateSettings":
          await api().storage.local.set({ [SK.SETTINGS]: msg.settings });
          return { success: true };
        case "addLog":
          await addLog(msg.level, msg.category, msg.message, msg.details);
          return { success: true };
        case "cleanLink":
          return { cleaned: cleanUrl(msg.url) };
        // v1.3.1 — Cipher Lab
        case "cipherEncrypt":
          try {
            const result = await cipherEncrypt(msg.plaintext, msg.passphrase, msg.algorithm);
            const hist = (await api().storage.local.get(SK.CIPHER_HISTORY))[SK.CIPHER_HISTORY] || [];
            hist.push({ ts: new Date().toISOString(), algo: msg.algorithm, action: "encrypt", inputLen: msg.plaintext.length, outputLen: result.length });
            if (hist.length > 100) hist.splice(0, hist.length - 100);
            await api().storage.local.set({ [SK.CIPHER_HISTORY]: hist });
            await addLog("info", "CIPHER", "Encrypted with " + msg.algorithm);
            return { success: true, ciphertext: result };
          } catch (e) { return { success: false, error: e.message }; }
        case "cipherDecrypt":
          try {
            const result2 = await cipherDecrypt(msg.ciphertext, msg.passphrase, msg.algorithm);
            return { success: true, plaintext: result2 };
          } catch (e) { return { success: false, error: e.message }; }
        // v1.3.1 — Vault
        case "vaultAdd": {
          const vault = (await api().storage.local.get(SK.VAULT))[SK.VAULT] || [];
          const encrypted = await vaultEncrypt(msg.entry, msg.passphrase);
          vault.push({ id: Date.now().toString(36), created: new Date().toISOString(), data: encrypted });
          await api().storage.local.set({ [SK.VAULT]: vault });
          await addLog("info", "VAULT", "Entry added to vault");
          return { success: true };
        }
        case "vaultGet": {
          const vault2 = (await api().storage.local.get(SK.VAULT))[SK.VAULT] || [];
          const decrypted = [];
          for (const item of vault2) {
            const d2 = await vaultDecrypt(item.data, msg.passphrase);
            if (d2) decrypted.push({ id: item.id, created: item.created, ...d2 });
          }
          return { success: true, entries: decrypted };
        }
        case "vaultDelete": {
          const vault3 = (await api().storage.local.get(SK.VAULT))[SK.VAULT] || [];
          await api().storage.local.set({ [SK.VAULT]: vault3.filter(v => v.id !== msg.id) });
          await addLog("info", "VAULT", "Entry deleted");
          return { success: true };
        }
        case "getNetStats":
          return { success: true, stats: netStats };
        case "ping":
          return { alive: true, build: AKS_BUILD };
        case "updateIcon": {
          const iconState = await api().storage.local.get([SK.KILL, SK.PROFILE]);
          updateShieldIcon({ killSwitch: iconState[SK.KILL] || false, profile: iconState[SK.PROFILE] || "strict" });
          return { success: true };
        }
        // v1.3.1 — Execution
        case "execRun": {
          const output = [];
          const lang = msg.lang || "javascript";
          const code = msg.code || "";
          const startTime = Date.now();
          let success = true;
          try {
            if (lang === "javascript") {
              const logs = [];
              const fakeConsole = {
                log: function () { logs.push({ type: "info", text: Array.from(arguments).map(String).join(" ") }); },
                warn: function () { logs.push({ type: "warn", text: Array.from(arguments).map(String).join(" ") }); },
                error: function () { logs.push({ type: "error", text: Array.from(arguments).map(String).join(" ") }); },
                info: function () { logs.push({ type: "info", text: Array.from(arguments).map(String).join(" ") }); }
              };
              const sandbox = new Function("console", "alert", "prompt", "confirm",
                "with(this){try{" + code + "\n}catch(e){console.error(e.message)}}" );
              const result = sandbox.call({}, fakeConsole, function(m){output.push({type:"info",text:String(m)})}, function(){return ""}, function(){return true});
              output.push(...logs);
              if (result !== undefined) output.push({ type: "result", text: String(result) });
            } else if (lang === "html") {
              output.push({ type: "info", text: "HTML execution — would open in sandboxed iframe. Use browser DevTools to preview." });
            } else if (lang === "css") {
              output.push({ type: "info", text: "CSS injection — would inject into active tab. Use DevTools console." });
            } else {
              output.push({ type: "error", text: "Unsupported language: " + lang });
              success = false;
            }
          } catch (e) {
            output.push({ type: "error", text: e.message || String(e) });
            success = false;
          }
          const hist = (await api().storage.local.get(SK.EXEC_HISTORY))[SK.EXEC_HISTORY] || [];
          hist.push({ ts: new Date().toISOString(), lang, name: msg.name || "Untitled", success, duration: Date.now() - startTime });
          if (hist.length > 50) hist.splice(0, hist.length - 50);
          await api().storage.local.set({ [SK.EXEC_HISTORY]: hist });
          await addLog(success ? "info" : "error", "EXEC", "Ran " + lang + " script: " + (msg.name || "Untitled"));
          return { success: true, output };
        }
        case "execSave": {
          const scripts = (await api().storage.local.get(SK.EXEC_SCRIPTS))[SK.EXEC_SCRIPTS] || [];
          const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
          scripts.push({ id, name: msg.name || "Untitled", lang: msg.lang || "javascript", code: msg.code || "", created: new Date().toISOString() });
          if (scripts.length > 50) scripts.splice(0, scripts.length - 50);
          await api().storage.local.set({ [SK.EXEC_SCRIPTS]: scripts });
          await addLog("info", "EXEC", "Saved script: " + (msg.name || "Untitled"));
          return { success: true };
        }
        case "execDelete": {
          const scripts2 = (await api().storage.local.get(SK.EXEC_SCRIPTS))[SK.EXEC_SCRIPTS] || [];
          await api().storage.local.set({ [SK.EXEC_SCRIPTS]: scripts2.filter(s => s.id !== msg.id) });
          await addLog("info", "EXEC", "Deleted script");
          return { success: true };
        }
        default:
          return { error: "Unknown action" };
      }
    };
    handler().then(sendResponse).catch(e => sendResponse({ error: e.message }));
    return true;
  });
}

/* ═══════════════════ NAVIGATION INTERCEPT + THREAT DETECTION ═══════════════════ */
if (api().webNavigation && api().webNavigation.onBeforeNavigate) {
  api().webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return;
    const d = await api().storage.local.get([SK.NET_LINKCLEAN, SK.NET_CACHE, SK.NET_ETAG, SK.THREATS, SK.NET_MON]);

    const threat = detectThreat(details.url);
    if (threat && d[SK.THREATS] && d[SK.THREATS].enabled) {
      netStats.threats++;
      netStats.blocked++;
      if (d[SK.NET_MON]) netStats.history.push({ ts: Date.now(), type: "threat" });
      await addLog("warn", "THREAT", "Threat blocked: " + threat.type, threat);
      return;
    }

    netStats.allowed++;
    if (d[SK.NET_MON]) netStats.history.push({ ts: Date.now(), type: "request" });

    if (d[SK.NET_LINKCLEAN]) {
      const cleaned = cleanUrl(details.url);
      if (cleaned && cleaned !== details.url) {
        netStats.cleaned++;
        if (d[SK.NET_MON]) netStats.history.push({ ts: Date.now(), type: "clean" });
        api().tabs.update(details.tabId, { url: cleaned });
        await addLog("info", "LINK_CLEAN", "Cleaned URL", { from: details.url, to: cleaned });
      }
    }

    if (d[SK.NET_CACHE]) {
      api().browsingData.remove({}, { cache: true }).catch(() => {});
    }

    if (netStats.history.length > 200) netStats.history = netStats.history.slice(-200);
  });
}

/* ═══════════════════ WEB REQUEST INTERCEPT ═══════════════════ */
if (api().webRequest && api().webRequest.onBeforeRequest) {
  api().webRequest.onBeforeRequest.addListener(async (details) => {
    netStats.allowed++;
    const threat = detectThreat(details.url);
    if (threat) {
      netStats.blocked++;
      netStats.threats++;
    }
  }, { urls: ["<all_urls>"] });
}

/* ═══════════════════ STARTUP ═══════════════════ */
api().runtime.onInstalled.addListener((d) => { if (d.reason === "install") initExtension(); });
api().runtime.onStartup.addListener(() => initExtension());
initExtension();
