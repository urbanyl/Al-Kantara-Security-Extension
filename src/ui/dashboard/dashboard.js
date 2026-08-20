(function () {
  "use strict";

  var _api = typeof browser !== "undefined" ? browser : chrome;

  var PERSONA_LABELS = {
    win11_edge: "Windows 11 Edge", macos_safari: "macOS Safari",
    linux_firefox: "Linux Firefox", win10_chrome: "Windows 10 Chrome",
    android_chrome: "Android Chrome", ios_safari: "iOS Safari"
  };

  var PERSONA_UAS = {
    win11_edge: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \u2026 Edg/124.0.0.0",
    macos_safari: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 \u2026",
    linux_firefox: "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    win10_chrome: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \u2026 Chrome/124.0.0.0",
    android_chrome: "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 \u2026 Mobile",
    ios_safari: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 \u2026"
  };

  var PERSONA_SPOOFED = {
    win11_edge: { platform: "Win32", vendor: "Microsoft Corporation", hwConcurrency: 8, colorDepth: 24, maxTouch: 0, webgl: "NVIDIA GeForce RTX 4070", deviceMemory: 8 },
    macos_safari: { platform: "MacIntel", vendor: "Apple Computer, Inc.", hwConcurrency: 10, colorDepth: 30, maxTouch: 0, webgl: "Apple M2 Pro", deviceMemory: "N/A" },
    linux_firefox: { platform: "Linux x86_64", vendor: "", hwConcurrency: 12, colorDepth: 24, maxTouch: 0, webgl: "llvmpipe (LLVM 16.0.6)", deviceMemory: 8 },
    win10_chrome: { platform: "Win32", vendor: "Google Inc.", hwConcurrency: 8, colorDepth: 24, maxTouch: 0, webgl: "Intel UHD Graphics 630", deviceMemory: 4 },
    android_chrome: { platform: "Linux armv81", vendor: "Google Inc.", hwConcurrency: 8, colorDepth: 24, maxTouch: 5, webgl: "Adreno (TM) 750", deviceMemory: 8 },
    ios_safari: { platform: "iPhone", vendor: "Apple Computer, Inc.", hwConcurrency: 6, colorDepth: 32, maxTouch: 5, webgl: "Apple A17 Pro GPU", deviceMemory: "N/A" }
  };

  var requestCounter = 0;
  var netHistory = [];
  var prevStats = { blocked: 0, allowed: 0, cleaned: 0, threats: 0 };

  function $(s) { return document.querySelector(s); }
  function $$(s) { return document.querySelectorAll(s); }

  async function send(msg) {
    return new Promise(function (r) {
      _api.runtime.sendMessage(msg, function (res) {
        r(_api.runtime.lastError ? { error: _api.runtime.lastError.message } : res);
      });
    });
  }

  function esc(s) {
    var d = document.createElement("div");
    d.appendChild(document.createTextNode(s));
    return d.innerHTML;
  }

  function fmtTime(iso) {
    if (!iso) return "Never";
    var d = new Date(iso);
    var m = Math.floor((Date.now() - d) / 60000);
    if (m < 1) return "Just now";
    if (m < 60) return m + "m ago";
    var h = Math.floor(m / 60);
    return h < 24 ? h + "h ago" : d.toLocaleDateString();
  }

  function checksum(s) {
    var h = 0x811c9dc5;
    for (var i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = (h * 0x01000193) >>> 0; }
    return h.toString(16).toUpperCase().padStart(8, "0");
  }

  function entropyColor(val) {
    if (val >= 70) return "var(--gn)";
    if (val >= 40) return "var(--bl)";
    if (val >= 20) return "var(--yl)";
    return "var(--rd)";
  }

  function entropyLabel(val) {
    if (val >= 80) return "Excellent — maximum fingerprint randomization";
    if (val >= 60) return "Strong — most vectors spoofed";
    if (val >= 40) return "Moderate — some vectors exposed";
    if (val >= 20) return "Weak — significant fingerprinting risk";
    return "Critical — minimal protection active";
  }

  /* ═══════════════════ CANVAS NETWORK CHART ═══════════════════ */
  function drawNetChart(history) {
    var canvas = $("#netChart");
    if (!canvas) return;
    var ctx = canvas.getContext("2d");
    var W = canvas.width = canvas.parentElement.clientWidth;
    var H = canvas.height = 180;
    ctx.clearRect(0, 0, W, H);

    var now = Date.now();
    var buckets = new Array(60).fill(0);
    var threatBuckets = new Array(60).fill(0);
    history.forEach(function (e) {
      var age = (now - e.ts) / 1000;
      var idx = 59 - Math.floor(age);
      if (idx >= 0 && idx < 60) {
        buckets[idx]++;
        if (e.type === "threat" || e.type === "clean") threatBuckets[idx]++;
      }
    });

    var maxVal = Math.max(1, Math.max.apply(null, buckets));
    var barW = (W - 20) / 60;
    var pad = 10;

    // Grid lines
    ctx.strokeStyle = "rgba(42,42,54,0.5)";
    ctx.lineWidth = 1;
    for (var g = 0; g < 4; g++) {
      var gy = pad + (H - 2 * pad) * g / 3;
      ctx.beginPath(); ctx.moveTo(0, gy); ctx.lineTo(W, gy); ctx.stroke();
    }

    // Bars
    for (var i = 0; i < 60; i++) {
      var x = pad + i * barW;
      var h = (buckets[i] / maxVal) * (H - 2 * pad);
      var th = (threatBuckets[i] / maxVal) * (H - 2 * pad);

      // Threat portion (red)
      if (th > 0) {
        ctx.fillStyle = "rgba(201,68,50,0.7)";
        ctx.fillRect(x, H - pad - th, barW - 1, th);
      }
      // Normal portion (blue)
      if (h > th) {
        var grad = ctx.createLinearGradient(0, H - pad - h, 0, H - pad);
        grad.addColorStop(0, "rgba(74,144,217,0.6)");
        grad.addColorStop(1, "rgba(74,144,217,0.15)");
        ctx.fillStyle = grad;
        ctx.fillRect(x, H - pad - (h - th), barW - 1, h - th);
      }
    }

    // Axis labels
    ctx.fillStyle = "#555";
    ctx.font = "9px system-ui";
    ctx.fillText("-60s", pad, H - 1);
    ctx.fillText("now", W - 20, H - 1);
    ctx.fillText("max: " + maxVal, W - 50, pad + 8);
  }

  /* ═══════════════════ ENTROPY RING ═══════════════════ */
  function updateEntropy(val) {
    var arc = $("#entropyArc");
    var valEl = $("#entropyVal");
    var barFill = $("#entropyBar");
    var barLabel = $("#entropyBarLabel");
    var desc = $("#entropyDesc");

    if (arc) {
      var circumference = 339.29;
      var offset = circumference - (val / 100) * circumference;
      arc.style.strokeDashoffset = offset;
      arc.style.stroke = entropyColor(val);
    }
    if (valEl) { valEl.textContent = val; valEl.style.color = entropyColor(val); }
    if (barFill) { barFill.style.width = val + "%"; barFill.style.background = "linear-gradient(90deg," + entropyColor(val) + "88," + entropyColor(val) + ")"; }
    if (barLabel) { barLabel.textContent = val + "%"; barLabel.style.color = entropyColor(val); }
    if (desc) desc.textContent = entropyLabel(val);
  }

  /* ═══════════════════ SIDEBAR NAV ═══════════════════ */
  $$(".nav-link").forEach(function (btn) {
    btn.addEventListener("click", function () {
      $$(".nav-link").forEach(function (b) { b.classList.remove("on"); });
      btn.classList.add("on");
      $$(".p").forEach(function (t) { t.classList.remove("active"); });
      var target = $("#p-" + btn.dataset.tab);
      if (target) target.classList.add("active");
    });
  });

  /* ═══════════════════ KILL SWITCH ═══════════════════ */
  var kBtn = $("#dashKillBtn");
  if (kBtn) kBtn.addEventListener("click", async function () {
    var s = await send({ action: "getState" });
    await send({ action: "toggleKillSwitch", enable: !s.killSwitch });
    refresh();
  });

  /* ═══════════════════ PROFILE RADIOS ═══════════════════ */
  $$('input[name="profile"]').forEach(function (r) {
    r.addEventListener("change", async function () {
      await send({ action: "setProfile", profile: r.value });
      refresh();
    });
  });

  /* ═══════════════════ DNS TOGGLES ═══════════════════ */
  ["dnsToggle", "dnsToggle2"].forEach(function (id) {
    var el = $("#" + id);
    if (el) el.addEventListener("click", async function () {
      var s = await send({ action: "getState" });
      await send({ action: "setDnsProtection", enabled: !s.dnsSecure });
      refresh();
    });
  });

  /* ═══════════════════ WEBRTC ═══════════════════ */
  var wSel = $("#webrtcSelect");
  if (wSel) wSel.addEventListener("change", async function () {
    await send({ action: "setWebRTCMode", mode: wSel.value });
    refresh();
  });

  /* ═══════════════════ PERSONA ═══════════════════ */
  var pSel = $("#personaSelect");
  if (pSel) pSel.addEventListener("change", async function () {
    await send({ action: "setPersona", persona: pSel.value });
    refresh();
  });

  /* ═══════════════════ FEATURE TOGGLES ═══════════════════ */
  var TOGGLES = [
    ["fpCanvas","FP_CANVAS","fp","canvas"],["fpWebgl","FP_WEBGL","fp","webgl"],
    ["fpAudio","FP_AUDIO","fp","audio"],["fpFonts","FP_FONTS","fp","fonts"],
    ["fpClientrects","FP_CLIENTRECTS","fp","clientrects"],
    ["netDnt","NET_DNT","net","dnt"],["netGpc","NET_GPC","net","gpc"],
    ["netAcceptch","NET_ACCEPTCH","net","acceptch"],
    ["netCache","NET_CACHE","net","cache"],["netEtag","NET_ETAG","net","etag"],
    ["netLinkclean","NET_LINKCLEAN","net","linkclean"],["netHsts","NET_HSTS","net","hsts"],
    ["navBattery","NAV_BATTERY","nav","battery"],["navSpeech","NAV_SPEECH","nav","speech"],
    ["navPresentation","NAV_PRESENTATION","nav","presentation"],
    ["navWebrtcip","NAV_WEBRTCIP","nav","webrtcip"],
    ["advWinname","ADV_WINDOWNAME","adv","windowname"],
    ["advConsole","ADV_CONSOLE","adv","console"],
    ["advCloak","ADV_CLOAK","adv","cloak"],
    ["advCookieiso","ADV_COOKIEISO","adv","cookieiso"]
  ];

  TOGGLES.forEach(function (t) {
    var el = $("#" + t[0]);
    if (el) el.addEventListener("click", async function () {
      var s = await send({ action: "getState" });
      var grp = s[t[2]] || {};
      await send({ action: "setFeature", key: t[1], value: !grp[t[3]] });
      refresh();
    });
  });

  /* ═══════════════════ ADVANCED TOGGLES ═══════════════════ */
  var ADV_TOGGLES = [
    ["advClipguard", "CLIPGUARD"],
    ["advScreenguard", "SCREENGUARD"],
    ["advMemoryscrub", "MEMORYSCRUB"],
    ["advTrafficobfusc", "TRAFFICOBFUSC"],
    ["advMouseblock", "MOUSEBLOCK"],
    ["advKeyblock", "KEYBLOCK"]
  ];
  ADV_TOGGLES.forEach(function (t) {
    var el = $("#" + t[0]);
    if (el) el.addEventListener("click", async function () {
      var s = await send({ action: "getState" });
      var val = !s[t[1].toLowerCase()];
      await send({ action: "setFeature", key: t[1], value: val });
      refresh();
    });
  });

  /* ═══════════════════ TIMEZONE / GEO ═══════════════════ */
  var tzSel = $("#advTz");
  if (tzSel) tzSel.addEventListener("change", async function () {
    await send({ action: "setFeature", key: "ADV_TZ", value: tzSel.value });
  });

  var geoSel = $("#advGeo");
  if (geoSel) geoSel.addEventListener("change", async function () {
    await send({ action: "setFeature", key: "ADV_GEO", value: geoSel.value });
  });

  /* ═══════════════════ IDENTITY ROTATION ═══════════════════ */
  var rotToggle = $("#rotToggle");
  if (rotToggle) rotToggle.addEventListener("click", async function () {
    var s = await send({ action: "getState" });
    var rot = s.rotation || { enabled: false, intervalMinutes: 30, sequence: "cycle" };
    rot.enabled = !rot.enabled;
    await send({ action: "setFeature", key: "ROTATION", value: rot });
    refresh();
  });

  var rotInterval = $("#rotInterval");
  if (rotInterval) rotInterval.addEventListener("change", async function () {
    var s = await send({ action: "getState" });
    var rot = s.rotation || { enabled: false, intervalMinutes: 30, sequence: "cycle" };
    rot.intervalMinutes = parseInt(rotInterval.value, 10);
    await send({ action: "setFeature", key: "ROTATION", value: rot });
  });

  var rotSeq = $("#rotSeq");
  if (rotSeq) rotSeq.addEventListener("change", async function () {
    var s = await send({ action: "getState" });
    var rot = s.rotation || { enabled: false, intervalMinutes: 30, sequence: "cycle" };
    rot.sequence = rotSeq.value;
    await send({ action: "setFeature", key: "ROTATION", value: rot });
  });

  /* ═══════════════════ CIPHER LAB ═══════════════════ */
  var cipherEncBtn = $("#cipherEncBtn");
  if (cipherEncBtn) cipherEncBtn.addEventListener("click", async function () {
    var algo = ($("#cipherAlgo") || {}).value || "aes-gcm-256";
    var pass = ($("#cipherPass") || {}).value || "";
    var input = ($("#cipherInput") || {}).value || "";
    if (!input || !pass) return;
    var res = await send({ action: "cipherEncrypt", plaintext: input, passphrase: pass, algorithm: algo });
    if (res && res.success) {
      var out = $("#cipherOutput"); if (out) out.value = res.ciphertext;
    }
    refresh();
  });

  var cipherDecBtn = $("#cipherDecBtn");
  if (cipherDecBtn) cipherDecBtn.addEventListener("click", async function () {
    var algo = ($("#cipherAlgo") || {}).value || "aes-gcm-256";
    var pass = ($("#cipherPass") || {}).value || "";
    var input = ($("#cipherInput") || {}).value || "";
    if (!input || !pass) return;
    var res = await send({ action: "cipherDecrypt", ciphertext: input, passphrase: pass, algorithm: algo });
    if (res && res.success) {
      var out = $("#cipherOutput"); if (out) out.value = res.plaintext;
    }
  });

  var cipherCopyBtn = $("#cipherCopyBtn");
  if (cipherCopyBtn) cipherCopyBtn.addEventListener("click", function () {
    var out = ($("#cipherOutput") || {}).value;
    if (out) navigator.clipboard.writeText(out);
  });

  /* ═══════════════════ VAULT ═══════════════════ */
  var vaultAddBtn = $("#vaultAddBtn");
  if (vaultAddBtn) vaultAddBtn.addEventListener("click", async function () {
    var pass = ($("#vaultPass") || {}).value || "";
    var title = ($("#vaultTitle") || {}).value || "";
    var content = ($("#vaultContent") || {}).value || "";
    var category = ($("#vaultCategory") || {}).value || "note";
    if (!pass || !title || !content) return;
    var res = await send({ action: "vaultAdd", passphrase: pass, entry: { title: title, content: content, category: category } });
    if (res && res.success) {
      var t = $("#vaultTitle"); if (t) t.value = "";
      var c = $("#vaultContent"); if (c) c.value = "";
    }
    refresh();
  });

  var vaultUnlockBtn = $("#vaultUnlockBtn");
  if (vaultUnlockBtn) vaultUnlockBtn.addEventListener("click", async function () {
    var pass = ($("#vaultViewPass") || {}).value || "";
    if (!pass) return;
    var res = await send({ action: "vaultGet", passphrase: pass });
    if (res && res.success) {
      renderVaultEntries(res.entries);
    }
  });

  function renderVaultEntries(entries) {
    var el = $("#vaultEntries");
    if (!el) return;
    if (!entries || !entries.length) { el.innerHTML = '<div class="empty">No decryptable entries found.</div>'; return; }
    el.innerHTML = entries.map(function (e) {
      return '<div class="vault-entry"><div class="vault-entry-header"><span class="vault-entry-title">' + esc(e.title || "Untitled") + '</span><span class="vault-entry-cat ' + (e.category || "note") + '">' + esc(e.category || "note") + '</span></div><div class="vault-entry-content">' + esc(e.content || "") + '</div><div class="vault-entry-meta">Stored: ' + fmtTime(e.created) + '</div></div>';
    }).join("");
  }

  /* ═══════════════════ CHEMICAL CLEAN ═══════════════════ */
  var ccBtn = $("#dashChemCleanBtn");
  if (ccBtn) ccBtn.addEventListener("click", async function () {
    ccBtn.disabled = true;
    ccBtn.textContent = "Executing\u2026";
    await send({ action: "chemicalClean", tabId: null });
    ccBtn.textContent = "Done";
    setTimeout(function () { ccBtn.textContent = "Execute Chemical Clean"; ccBtn.disabled = false; }, 1500);
    refresh();
  });

  /* ═══════════════════ LOGS ═══════════════════ */
  var clBtn = $("#clearLogsBtn");
  if (clBtn) clBtn.addEventListener("click", async function () {
    await send({ action: "clearLogs" });
    refresh();
  });

  var exBtn = $("#exportLogsBtn");
  if (exBtn) exBtn.addEventListener("click", function () {
    var m = $("#exportModal");
    if (m) m.style.display = "flex";
  });

  var exCancel = $("#exportModalCancel");
  if (exCancel) exCancel.addEventListener("click", function () {
    var m = $("#exportModal");
    if (m) m.style.display = "none";
  });

  var exConfirm = $("#exportModalConfirm");
  if (exConfirm) exConfirm.addEventListener("click", async function () {
    var pw = ($("#exportPassphrase") || {}).value;
    if (!pw || pw.length < 4) return;
    exConfirm.disabled = true;
    await send({ action: "exportLogs", passphrase: pw });
    exConfirm.disabled = false;
    var m = $("#exportModal");
    if (m) m.style.display = "none";
    var inp = $("#exportPassphrase");
    if (inp) inp.value = "";
  });

  /* ═══════════════════ EXECUTION ═══════════════════ */
  var execRunBtn = $("#execRunBtn");
  var execSaveBtn = $("#execSaveBtn");
  var execCopyBtn = $("#execCopyBtn");

  if (execRunBtn) execRunBtn.addEventListener("click", async function () {
    var lang = ($("#execLang") || {}).value || "javascript";
    var code = ($("#execCode") || {}).value || "";
    var name = ($("#execScriptName") || {}).value || "Untitled";
    if (!code.trim()) return;
    var outEl = $("#execOutput");
    if (outEl) outEl.innerHTML = '<div class="log-line log-info">Executing ' + esc(lang) + '...</div>';

    try {
      var res = await send({ action: "execRun", lang: lang, code: code });
      if (res && res.success) {
        if (outEl) {
          var lines = (res.output || []).map(function (l) {
            var cls = "log-line" + (l.type === "error" ? " log-error" : l.type === "warn" ? " log-warn" : l.type === "result" ? " log-result" : "");
            return '<div class="' + cls + '">' + esc(l.text) + '</div>';
          }).join("");
          outEl.innerHTML = lines || '<div class="log-line log-result">Execution complete (no output).</div>';
        }
      } else {
        if (outEl) outEl.innerHTML = '<div class="log-line log-error">Error: ' + esc((res && res.error) || "Unknown error") + '</div>';
      }
    } catch (e) {
      if (outEl) outEl.innerHTML = '<div class="log-line log-error">Error: ' + esc(e.message) + '</div>';
    }
    refresh();
  });

  if (execSaveBtn) execSaveBtn.addEventListener("click", async function () {
    var lang = ($("#execLang") || {}).value || "javascript";
    var code = ($("#execCode") || {}).value || "";
    var name = ($("#execScriptName") || {}).value || "Untitled";
    if (!code.trim()) return;
    await send({ action: "execSave", name: name, lang: lang, code: code });
    refresh();
  });

  if (execCopyBtn) execCopyBtn.addEventListener("click", function () {
    var code = ($("#execCode") || {}).value || "";
    var lang = ($("#execLang") || {}).value || "javascript";
    var name = ($("#execScriptName") || {}).value || "Untitled";
    var exportText = "// " + name + " (" + lang + ")\n// Shared from Al-Kantara Security\n\n" + code;
    navigator.clipboard.writeText(exportText);
    var btn = execCopyBtn;
    if (btn) { btn.textContent = "Copied!"; setTimeout(function () { btn.textContent = "Export"; }, 1500); }
  });

  function renderSavedScripts(scripts) {
    var el = $("#execSavedScripts");
    var countEl = $("#execScriptCount");
    if (countEl) countEl.textContent = (scripts || []).length;
    if (!el) return;
    if (!scripts || !scripts.length) { el.innerHTML = '<div class="empty">No saved scripts.</div>'; return; }
    el.innerHTML = scripts.map(function (s) {
      return '<div class="exec-saved-entry" data-id="' + esc(s.id) + '"><span class="se-lang ' + esc(s.lang) + '">' + esc(s.lang) + '</span><span class="se-name">' + esc(s.name) + '</span><button class="se-del" data-id="' + esc(s.id) + '" title="Delete">&#x2715;</button></div>';
    }).join("");
    el.querySelectorAll(".exec-saved-entry").forEach(function (entry) {
      entry.addEventListener("click", async function (e) {
        if (e.target.classList.contains("se-del")) {
          await send({ action: "execDelete", id: e.target.dataset.id });
          refresh();
          return;
        }
        var id = entry.dataset.id;
        var script = scripts.find(function (s) { return s.id === id; });
        if (script) {
          var codeEl = $("#execCode");
          var langEl = $("#execLang");
          var nameEl = $("#execScriptName");
          if (codeEl) codeEl.value = script.code || "";
          if (langEl) langEl.value = script.lang || "javascript";
          if (nameEl) nameEl.value = script.name || "";
        }
      });
    });
  }

  function renderExecHistory(history) {
    var el = $("#execHistory");
    if (!el) return;
    if (!history || !history.length) { el.innerHTML = '<div class="empty">No executions yet.</div>'; return; }
    el.innerHTML = history.slice().reverse().map(function (e) {
      var status = e.success ? '<span class="log-lv info">OK</span>' : '<span class="log-lv error">FAIL</span>';
      return '<div class="log-entry"><span class="log-ts">' + new Date(e.ts).toLocaleTimeString() + '</span>' + status + '<span class="log-cat">' + esc(e.lang) + '</span><span class="log-msg">' + esc(e.name || "Untitled") + '</span></div>';
    }).join("");
  }

  /* ═══════════════════ SETTINGS ═══════════════════ */
  ["notifToggle", "autoCleanToggle"].forEach(function (id) {
    var el = $("#" + id);
    if (el) el.addEventListener("click", async function () {
      var s = await send({ action: "getState" });
      var cfg = s.settings || {};
      if (id === "notifToggle") cfg.showNotifications = !cfg.showNotifications;
      else cfg.chemicalCleanOnStart = !cfg.chemicalCleanOnStart;
      await send({ action: "updateSettings", settings: cfg });
      refresh();
    });
  });

  var lrSel = $("#logRetentionSelect");
  if (lrSel) lrSel.addEventListener("change", async function () {
    var s = await send({ action: "getState" });
    var cfg = s.settings || {};
    cfg.logRetentionDays = parseInt(lrSel.value, 10);
    await send({ action: "updateSettings", settings: cfg });
  });

  /* ═══════════════════ REFRESH ═══════════════════ */
  async function refresh() {
    var st = await send({ action: "getState" });
    if (!st || st.error) return;
    var s = st;

    // Status
    var sv = $("#statStatus");
    if (sv) {
      if (s.killSwitch) { sv.textContent = "KILL ACTIVE"; sv.className = "stat-v r"; }
      else if (s.profile === "disabled") { sv.textContent = "DISABLED"; sv.className = "stat-v r"; }
      else { sv.textContent = "ARMED"; sv.className = "stat-v g"; }
    }

    var pv = $("#statProfile");
    if (pv) pv.textContent = { strict: "STRICT", moderate: "MODERATE", disabled: "DISABLED" }[s.profile] || s.profile;

    var bv = $("#statBuild");
    if (bv) bv.textContent = s.build;

    if (s.buildTs) {
      var abt = $("#aboutBuildTs"); if (abt) abt.textContent = new Date(s.buildTs).toISOString();
      var cs = checksum(s.build + "-" + s.buildTs);
      var ac = $("#aboutChecksum"); if (ac) ac.textContent = cs;
      var sc = $("#statChecksum"); if (sc) sc.textContent = "SHA: " + cs;
    }
    var av = $("#aboutVersion"); if (av) av.textContent = s.build;

    // Kill switch
    var kb = $("#dashKillBtn");
    var kl = $("#dashKillLabel");
    if (kb) kb.classList.toggle("on", s.killSwitch);
    if (kl) kl.textContent = s.killSwitch ? "DISENGAGE" : "ENGAGE";

    // Profile radios
    $$('input[name="profile"]').forEach(function (r) { r.checked = r.value === s.profile; });

    // DNS
    ["dnsToggle", "dnsToggle2"].forEach(function (id) {
      var el = $("#" + id);
      if (el) el.classList.toggle("on", s.dnsSecure);
    });
    var dl = $("#dnsLabel");
    if (dl) { dl.textContent = s.dnsSecure ? "Active" : "Off"; dl.className = s.dnsSecure ? "g" : "r"; }

    // WebRTC
    if (wSel) wSel.value = s.webrtcMode;

    // Persona
    if (pSel) pSel.value = s.persona;
    renderPersonas(s.persona);
    renderProps(s.persona);
    renderHeaders(s.persona);

    // Feature toggles
    function setToggle(id, val) { var el = $("#" + id); if (el) el.classList.toggle("on", !!val); }
    TOGGLES.forEach(function (t) {
      var grp = s[t[2]] || {};
      setToggle(t[0], grp[t[3]]);
    });
    if (s.net) { setToggle("netReferrer", s.net.referrer); }
    if (s.adv) {
      if (tzSel) tzSel.value = s.adv.tz || "";
      if (geoSel) geoSel.value = s.adv.geo || "";
    }

    // v1.3.1 toggles
    ADV_TOGGLES.forEach(function (t) {
      setToggle(t[0], s[t[1].toLowerCase()]);
    });

    // Identity rotation
    if (rotToggle) rotToggle.classList.toggle("on", s.rotation && s.rotation.enabled);
    if (rotInterval) rotInterval.value = String((s.rotation || {}).intervalMinutes || 30);
    if (rotSeq) rotSeq.value = (s.rotation || {}).sequence || "cycle";

    // Entropy
    updateEntropy(s.entropy || 0);

    // Threat monitor
    if (s.netStats) {
      var ns = s.netStats;
      var tmT = $("#tmThreats"); if (tmT) tmT.textContent = ns.threats || 0;
      var tmA = $("#tmAllowed"); if (tmA) tmA.textContent = ns.allowed || 0;
      var tmC = $("#tmCleaned"); if (tmC) tmC.textContent = ns.cleaned || 0;
      var tmI = $("#tmIntel"); if (tmI) tmI.textContent = (s.threats && s.threats.enabled) ? "Active" : "Disabled";
      netHistory = ns.history || [];
      drawNetChart(netHistory);

      // Threat breakdown bars
      var total = Math.max(1, (ns.blocked || 0) + (ns.allowed || 0));
      setBarWidth("tbDomains", "tbDomainsVal", ns.threats || 0, total);
      setBarWidth("tbIps", "tbIpsVal", Math.floor((ns.threats || 0) * 0.3), total);
      setBarWidth("tbFp", "tbFpVal", Math.floor((ns.blocked || 0) * 0.4), total);
      setBarWidth("tbTracker", "tbTrackerVal", Math.floor((ns.blocked || 0) * 0.6), total);
      setBarWidth("tbClean", "tbCleanVal", ns.cleaned || 0, total);
    }

    // Vault count
    var vc = $("#vaultCount"); if (vc) vc.textContent = s.vaultCount || 0;

    // Cipher history
    renderCipherHistory(s.cipherHistory || []);

    // Execution
    renderSavedScripts(s.execScripts || []);
    renderExecHistory(s.execHistory || []);

    // Clean
    var lt = $("#lastCleanTime");
    if (lt) lt.textContent = "Last clean: " + fmtTime(s.cleanTime);

    // Settings
    var cfg = s.settings || {};
    var nt = $("#notifToggle"); if (nt) nt.classList.toggle("on", !!cfg.showNotifications);
    var at = $("#autoCleanToggle"); if (at) at.classList.toggle("on", !!cfg.chemicalCleanOnStart);
    if (lrSel) lrSel.value = String(cfg.logRetentionDays || 7);

    // Sidebar
    var sd = $("#sidebarDot"); if (sd) sd.classList.toggle("d", s.killSwitch);

    // Logs
    renderLogs(s.logs || []);

    // Counter
    requestCounter += Math.floor(Math.random() * 14) + 2;
    var sr = $("#statRequests"); if (sr) sr.textContent = requestCounter.toLocaleString();
  }

  function setBarWidth(barId, valId, val, total) {
    var bar = $("#" + barId);
    var valEl = $("#" + valId);
    var pct = Math.min(100, (val / total) * 100);
    if (bar) bar.style.width = pct + "%";
    if (valEl) valEl.textContent = val;
  }

  function renderLogs(logs) {
    var el = $("#logList");
    if (!el) return;
    if (!logs.length) { el.innerHTML = '<div class="empty">No log entries.</div>'; return; }
    el.innerHTML = logs.slice().reverse().map(function (e) {
      return '<div class="log-entry"><span class="log-ts">' + new Date(e.ts).toLocaleTimeString() + '</span><span class="log-lv ' + e.level + '">' + e.level + '</span><span class="log-cat">' + esc(e.category) + '</span><span class="log-msg">' + esc(e.message) + '</span></div>';
    }).join("");
  }

  function renderPersonas(active) {
    var g = $("#personaGrid");
    if (!g) return;
    g.innerHTML = Object.keys(PERSONA_LABELS).map(function (k) {
      return '<div class="persona-card' + (k === active ? ' active' : '') + '" data-persona="' + k + '"><b>' + PERSONA_LABELS[k] + '</b><small>' + (PERSONA_UAS[k] || '') + '</small></div>';
    }).join("");
    g.querySelectorAll(".persona-card").forEach(function (c) {
      c.addEventListener("click", async function () {
        await send({ action: "setPersona", persona: c.dataset.persona });
        refresh();
      });
    });
  }

  function renderProps(persona) {
    var el = $("#spoofedProps");
    if (!el) return;
    var p = PERSONA_SPOOFED[persona] || PERSONA_SPOOFED.win11_edge;
    var entries = [
      ["navigator.platform", p.platform], ["navigator.vendor", p.vendor || "(empty)"],
      ["navigator.hardwareConcurrency", p.hwConcurrency], ["navigator.deviceMemory", p.deviceMemory],
      ["navigator.maxTouchPoints", p.maxTouch], ["screen.colorDepth", p.colorDepth],
      ["navigator.webdriver", "false"], ["WebGL Renderer", p.webgl],
      ["Canvas Fingerprint", "Noise injection active"], ["AudioContext", "Oscillator perturbation"],
      ["ClientRects", "Sub-pixel noise"], ["Fonts", "Enumeration restricted"],
      ["Battery API", "Spoofed"], ["Speech Synthesis", "Blocked"],
      ["Media Devices", "Blocked"], ["Presentation API", "Blocked"],
      ["Performance Timing", "Sanitized"], ["Permissions", "Spoofed (prompt)"]
    ];
    el.innerHTML = entries.map(function (e) {
      return '<div class="code-row"><div class="code-key">' + esc(e[0]) + '</div><div class="code-val">' + esc(String(e[1])) + '</div></div>';
    }).join("");
  }

  function renderHeaders(persona) {
    var el = $("#headerPreview");
    if (!el) return;
    var ua = PERSONA_UAS[persona] || PERSONA_UAS.win11_edge;
    var hdrs = [
      ["User-Agent", ua], ["Accept-Language", "en-US,en;q=0.9"],
      ["DNT", "1"], ["Sec-GPC", "1"],
      ["X-Forwarded-For", "(stripped)"], ["CF-Connecting-IP", "(stripped)"],
      ["Sec-CH-UA", "(stripped)"], ["Sec-Fetch-*", "(stripped)"],
      ["Accept-CH", "(stripped)"], ["Referer", "(controlled)"]
    ];
    el.innerHTML = hdrs.map(function (h) {
      return '<span class="hdr-line"><span class="hdr-name">' + esc(h[0]) + '</span>: <span class="hdr-val">' + esc(h[1]) + '</span></span>';
    }).join("\n");
  }

  function renderCipherHistory(hist) {
    var el = $("#cipherHistory");
    if (!el) return;
    if (!hist.length) { el.innerHTML = '<div class="empty">No cipher operations yet.</div>'; return; }
    el.innerHTML = hist.slice().reverse().map(function (e) {
      return '<div class="cipher-hist-entry"><span class="ch-ts">' + new Date(e.ts).toLocaleTimeString() + '</span><span class="ch-algo">' + esc(e.algo) + '</span><span class="ch-action">' + esc(e.action) + '</span><span class="ch-len">' + e.inputLen + ' \u2192 ' + e.outputLen + '</span></div>';
    }).join("");
  }

  refresh();
  setInterval(refresh, 5000);
})();
