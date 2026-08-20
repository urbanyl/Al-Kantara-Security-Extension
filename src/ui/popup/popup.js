(function () {
  "use strict";

  var _api = typeof browser !== "undefined" ? browser : chrome;

  function $$(s) { return document.querySelectorAll(s); }

  async function send(msg) {
    return new Promise(function (r) {
      _api.runtime.sendMessage(msg, function (res) {
        r(_api.runtime.lastError ? { error: _api.runtime.lastError.message } : res);
      });
    });
  }

  function fmtTime(iso) {
    if (!iso) return "Never";
    var m = Math.floor((Date.now() - new Date(iso)) / 60000);
    if (m < 1) return "Just now";
    if (m < 60) return m + "m ago";
    var h = Math.floor(m / 60);
    return h < 24 ? h + "h ago" : new Date(iso).toLocaleDateString();
  }

  function prettyProfile(p) {
    var names = { strict: "Strict", moderate: "Moderate", disabled: "Disabled" };
    return names[p] || p;
  }

  function prettyPersona(p) {
    var names = {
      win11_edge: "Win 11 Edge", macos_safari: "macOS Safari",
      linux_firefox: "Linux Firefox", win10_chrome: "Win 10 Chrome",
      android_chrome: "Android", ios_safari: "iOS Safari"
    };
    return names[p] || p;
  }

  $$(".tabs .tab").forEach(function (btn) {
    btn.addEventListener("click", async function () {
      await send({ action: "setProfile", profile: btn.dataset.profile });
      await send({ action: "updateIcon" });
      refresh();
    });
  });

  var ksBtn = document.getElementById("killSwitchBtn");
  if (ksBtn) ksBtn.addEventListener("click", async function () {
    var s = await send({ action: "getState" });
    await send({ action: "toggleKillSwitch", enable: !s.killSwitch });
    await send({ action: "updateIcon" });
    refresh();
  });

  var ccBtn = document.getElementById("chemicalCleanBtn");
  if (ccBtn) ccBtn.addEventListener("click", async function () {
    ccBtn.disabled = true;
    ccBtn.textContent = "Cleaning\u2026";
    await send({ action: "chemicalClean", tabId: null });
    ccBtn.textContent = "Done";
    setTimeout(function () { ccBtn.textContent = "Chemical Clean"; ccBtn.disabled = false; }, 1500);
    refresh();
  });

  var dbBtn = document.getElementById("openDashboardBtn");
  if (dbBtn) dbBtn.addEventListener("click", function () {
    _api.tabs.create({ url: _api.runtime.getURL("src/ui/dashboard/dashboard.html") });
  });

  async function refresh() {
    var s = await send({ action: "getState" });
    if (!s || s.error) return;

    var sd = document.getElementById("statusDot");
    var sk = document.getElementById("statStatus");
    var sl = document.getElementById("killSwitchLabel");
    var ss = document.getElementById("killSwitchStatus");
    var sv = document.getElementById("killSwitchBtn");
    var sb = document.getElementById("buildVersion");

    if (sb) sb.textContent = "v" + (s.build || "1.0.0");

    if (s.killSwitch) {
      if (sd) { sd.className = "led d"; }
      if (sk) { sk.textContent = "KILL ACTIVE"; sk.className = "stat-v r"; }
      if (sl) sl.textContent = "DISENGAGE";
      if (ss) ss.textContent = "Traffic blocked";
      if (sv) sv.classList.add("on");
    } else if (s.profile === "disabled") {
      if (sd) { sd.className = "led d"; }
      if (sk) { sk.textContent = "DISABLED"; sk.className = "stat-v r"; }
      if (sl) sl.textContent = "KILL SWITCH";
      if (ss) ss.textContent = "Protections off";
      if (sv) sv.classList.remove("on");
    } else {
      if (sd) { sd.className = "led"; }
      if (sk) { sk.textContent = "ARMED"; sk.className = "stat-v g"; }
      if (sl) sl.textContent = "KILL SWITCH";
      if (ss) ss.textContent = "System active";
      if (sv) sv.classList.remove("on");
    }

    var tp = document.getElementById("telemetryPersona");
    var td = document.getElementById("telemetryDns");
    var tw = document.getElementById("telemetryWebrtc");
    var tc = document.getElementById("telemetryClean");

    if (tp) tp.textContent = prettyPersona(s.persona);
    if (td) { td.textContent = s.dnsSecure ? "Active" : "Off"; td.className = s.dnsSecure ? "g" : "r"; }
    if (tw) tw.textContent = s.webrtcMode === "disabled" ? "Blocked" : s.webrtcMode;
    if (tc) tc.textContent = fmtTime(s.cleanTime);

    $$(".tabs .tab").forEach(function (b) {
      var active = b.dataset.profile === s.profile;
      b.classList.toggle("on", active);
    });
  }

  refresh();
  setInterval(refresh, 3000);
})();
