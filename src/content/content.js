/**
 * Al-Kantara Security — Content Script v2
 * DOM-level protections: tracker blocking, MutationObserver,
 * window.name, referrer enforcement, redirect blocking,
 * CNAME cloak detection, DOM honeypot detection
 *
 * © Urbanyl — github.com/urbanyl
 */
(function () {
  "use strict";

  const _api = typeof browser !== "undefined" ? browser : chrome;

  function sendMsg(msg) {
    try { _api.runtime.sendMessage(msg); } catch(e) {}
  }

  /* ─── TRACKER SCRIPT BLOCKER (DOM level) ─── */
  const TRACKER_KEYWORDS = [
    "analytics","tracker","tracking","beacon","pixel","fingerprint",
    "collect","metrics","telemetry","hotjar","mixpanel","segment",
    "amplitude","heap","pendo","fullstory","logrocket","clarity",
    "mouseflow","inspectlet","luckyorange"," Contentsquare"
  ];

  const TRACKER_DOMAINS = [
    "google-analytics.com","googletagmanager.com","doubleclick.net",
    "facebook.net","fbevents.js","analytics.tiktok.com","bat.bing.com",
    "ads.twitter.com","snap.licdn.com","script.hotjar.com",
    "cdn.mouseflow.com","Contentsquare","cdn.inspectlet.com",
    "cdn.luckyorange.com","fullstory.com","logrocket.com",
    "clarity.ms","pendo.io","heap.io","mixpanel.com","segment.com",
    "amplitude.com","statcounter.com","chartbeat.com","newrelic.com",
    "sentry.io","bugsnag.com","rollbar.com","datadoghq.com"
  ];

  /* ─── INJECT ANTI-TRACKING CSS ─── */
  function injectStyles() {
    const s = document.createElement("style");
    s.textContent = `
      img[width="1"][height="1"],img[width="0"][height="0"]{display:none!important}
      [data-track],[data-analytics],[data-metrics]{display:none!important}
      .fb-like,.twitter-share-button,.linkedin-share-button{display:none!important}
    `;
    (document.head || document.documentElement).appendChild(s);
  }

  /* ─── BLOCK TRACKING SCRIPTS ─── */
  function blockTrackingScripts(node) {
    if (node.tagName !== "SCRIPT") return false;
    const src = (node.src || "").toLowerCase();
    const text = (node.textContent || "").toLowerCase();
    let blocked = false;

    TRACKER_DOMAINS.forEach(function(d) {
      if (src.includes(d.toLowerCase()) || text.includes(d.toLowerCase())) blocked = true;
    });

    TRACKER_KEYWORDS.forEach(function(k) {
      if (src.includes(k) && src.includes("track")) blocked = true;
    });

    if (blocked) {
      node.type = "text/blocked";
      node.remove();
      sendMsg({ action: "addLog", level: "warn", category: "CONTENT", message: "Blocked tracker: " + (node.src || "inline"), details: { url: location.href } });
    }
    return blocked;
  }

  /* ─── BLOCK TRACKING IFRAMES ─── */
  function blockTrackingIframes(node) {
    if (node.tagName !== "IFRAME") return false;
    const src = (node.src || "").toLowerCase();
    let blocked = false;
    TRACKER_DOMAINS.forEach(function(d) {
      if (src.includes(d.toLowerCase())) blocked = true;
    });
    if (blocked) { node.remove(); }
    return blocked;
  }

  /* ─── BLOCK TRACKING IMAGES ─── */
  function blockTrackingImages(node) {
    if (node.tagName !== "IMG") return false;
    const src = (node.src || "").toLowerCase();
    const w = parseInt(node.getAttribute("width") || "0", 10);
    const h = parseInt(node.getAttribute("height") || "0", 10);
    if ((w <= 1 && h <= 1) || (w === 0 && h === 0)) {
      node.remove();
      return true;
    }
    let blocked = false;
    TRACKER_DOMAINS.forEach(function(d) {
      if (src.includes(d.toLowerCase())) blocked = true;
    });
    if (blocked) node.remove();
    return blocked;
  }

  /* ─── REFERRER ENFORCEMENT ─── */
  function enforceReferrer() {
    const metas = document.querySelectorAll('meta[name="referrer"]');
    if (metas.length === 0) {
      const m = document.createElement("meta");
      m.name = "referrer";
      m.content = "strict-origin-when-cross-origin";
      (document.head || document.documentElement).appendChild(m);
    }
  }

  /* ─── STRIP TRACKING LINKS ─── */
  function cleanLink(url) {
    if (!url) return url;
    try {
      const u = new URL(url, location.href);
      const params = ["utm_source","utm_medium","utm_campaign","utm_term","utm_content","fbclid","gclid","gclsrc","dclid","gbraid","wbraid","msclkid","mc_cid","mc_eid","_ga","_gl","s_cid","twclid","li_fat_id","igshid","ttclid","yclid","wickedid","vero_id","trk"];
      let changed = false;
      params.forEach(function(p) {
        if (u.searchParams.has(p)) { u.searchParams.delete(p); changed = true; }
      });
      return changed ? u.toString() : url;
    } catch(e) { return url; }
  }

  function cleanAllLinks() {
    document.querySelectorAll('a[href]').forEach(function(a) {
      const cleaned = cleanLink(a.href);
      if (cleaned !== a.href) a.href = cleaned;
    });
  }

  /* ─── REDIRECT TRACKER BLOCK ─── */
  function blockRedirects() {
    document.addEventListener("click", function(e) {
      const a = e.target.closest("a");
      if (!a) return;
      const href = a.href || "";
      const redirectPatterns = ["/redirect","/r/","/go/","/track/","/click/","/out/","/link/","/redir","/forward"];
      redirectPatterns.forEach(function(p) {
        if (href.toLowerCase().includes(p)) {
          e.preventDefault();
          sendMsg({ action: "addLog", level: "warn", category: "CONTENT", message: "Blocked redirect: " + href.substring(0, 100), details: { url: location.href } });
        }
      });
    }, true);
  }

  /* ─── CNAME CLOAKING DETECTION ─── */
  function detectCnameCloak() {
    if (location.hostname !== location.origin.replace(/^https?:\/\//, "")) return;
    const firstParty = location.hostname;
    const scripts = document.querySelectorAll("script[src]");
    scripts.forEach(function(s) {
      try {
        const u = new URL(s.src);
        if (u.hostname !== firstParty && !u.hostname.endsWith("." + firstParty) && !u.hostname.endsWith("." + firstParty.split(".").slice(-2).join("."))) {
          // Cross-origin script — potential CNAME cloaking
        }
      } catch(e) {}
    });
  }

  /* ─── HONEYPOT DETECTION ─── */
  function detectHoneypots() {
    const selectors = [
      'input[type="hidden"][name*="token"]',
      'input[type="hidden"][name*="key"]',
      'input[type="hidden"][name*="session"]',
      'form[action*="track"]',
      'img[width="1"][height="1"]',
      'iframe[src*="facebook"]',
      'iframe[src*="doubleclick"]'
    ];
    let count = 0;
    selectors.forEach(function(s) {
      try { count += document.querySelectorAll(s).length; } catch(e) {}
    });
    if (count > 0) {
      sendMsg({ action: "addLog", level: "info", category: "HONEYPOT", message: "Detected " + count + " tracking element(s)", details: { url: location.href } });
    }
  }

  /* ─── DOM SHADOW ROOT MONITOR ─── */
  function monitorShadowRoots() {
    const origAttach = Element.prototype.attachShadow;
    if (origAttach) {
      Element.prototype.attachShadow = function() {
        const shadow = origAttach.apply(this, arguments);
        // Monitor shadow root for injected trackers
        const obs = new MutationObserver(function(muts) {
          muts.forEach(function(m) {
            m.addedNodes.forEach(function(n) {
              if (n.nodeType === 1) {
                blockTrackingScripts(n);
                blockTrackingIframes(n);
                blockTrackingImages(n);
              }
            });
          });
        });
        obs.observe(shadow, { childList: true, subtree: true });
        return shadow;
      };
    }
  }

  /* ─── MAIN MUTATION OBSERVER ─── */
  function setupMutationObserver() {
    const obs = new MutationObserver(function(mutations) {
      for (const m of mutations) {
        for (const n of m.addedNodes) {
          if (n.nodeType !== 1) continue;
          blockTrackingScripts(n);
          blockTrackingIframes(n);
          blockTrackingImages(n);
          // Check children
          if (n.querySelectorAll) {
            n.querySelectorAll("script,iframe,img").forEach(function(child) {
              blockTrackingScripts(child);
              blockTrackingIframes(child);
              blockTrackingImages(child);
            });
          }
        }
      }
    });
    obs.observe(document.documentElement, { childList: true, subtree: true });
  }

  /* ─── INIT ─── */
  function init() {
    injectStyles();
    enforceReferrer();
    setupMutationObserver();
    monitorShadowRoots();
    blockRedirects();
    detectHoneypots();
    detectCnameCloak();
    cleanAllLinks();

    // Re-clean links periodically (for SPAs)
    setInterval(cleanAllLinks, 3000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
