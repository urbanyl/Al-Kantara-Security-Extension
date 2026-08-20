/**
 * Al-Kantara Security — WebRequest Interceptor
 * Manages HTTP header rewriting and request blocking per profile.
 *
 * Chromium: Uses declarativeNetRequest (in background.js rules.json)
 * Firefox:  Uses webRequest.onBeforeSendHeaders (blocking)
 *
 * © Urbanyl — github.com/urbanyl
 */

(function () {
  "use strict";

  const _api = typeof browser !== "undefined" ? browser : chrome;
  function api() { return _api; }

  const HEADER_TARGETS = [
    "User-Agent",
    "Accept-Language",
    "Accept",
    "Sec-CH-UA",
    "Sec-CH-UA-Mobile",
    "Sec-CH-UA-Platform",
    "Sec-Fetch-Dest",
    "Sec-Fetch-Mode",
    "Sec-Fetch-Site",
    "Sec-Fetch-User",
    "Sec-CH-UA-Full-Version-List"
  ];

  function shouldBlockHeader(headerName) {
    const blocked = [
      "x-forwarded-for",
      "x-real-ip",
      "cf-connecting-ip",
      "x-client-ip",
      "forwarded"
    ];
    return blocked.includes(headerName.toLowerCase());
  }

  function modifyHeaders(headers, profile) {
    if (!headers || !Array.isArray(headers)) return headers;

    const persona = profile.persona || {};
    const modified = headers.map(h => {
      const name = h.name.toLowerCase();

      if (name === "user-agent" && persona.ua) {
        return { name: h.name, value: persona.ua };
      }

      if (name === "accept-language" && persona.lang) {
        return { name: h.name, value: persona.lang };
      }

      if (name === "sec-ch-ua" && persona.ua) {
        const brandMatch = persona.ua.match(/Chrome\/([\d.]+)/);
        const ver = brandMatch ? brandMatch[1].split(".")[0] : "124";
        return { name: h.name, value: `"Chromium";v="${ver}", "Not(A:Brand";v="8", "Microsoft Edge";v="${ver}"` };
      }

      if (name === "sec-ch-ua-mobile") {
        return { name: h.name, value: "?0" };
      }

      if (name === "sec-ch-ua-platform" && persona.platform) {
        return { name: h.name, value: `"${persona.platform}"` };
      }

      if (shouldBlockHeader(h.name)) {
        return null;
      }

      return h;
    }).filter(Boolean);

    return modified;
  }

  if (api().webRequest && api().webRequest.onBeforeSendHeaders) {
    api().storage.local.get(["aks_active_profile", "aks_fingerprint_persona", "aks_header_overrides"], (data) => {
      const profileId = data.aks_active_profile || "strict";
      const personaKey = data.aks_fingerprint_persona || "win11_edge";

      const PERSONAS = {
        win11_edge:     { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",                          platform: "Win32",     lang: "en-US,en;q=0.9" },
        macos_safari:   { ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",                                        platform: "MacIntel",  lang: "en-US,en;q=0.9" },
        linux_firefox:  { ua: "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",                                                                                  platform: "Linux x86_64", lang: "en-US,en;q=0.5" },
        win10_chrome:   { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",                                         platform: "Win32",     lang: "en-US,en;q=0.9" },
        android_chrome: { ua: "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",                                platform: "Linux armv81", lang: "en-US,en;q=0.9" },
        ios_safari:     { ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",                  platform: "iPhone",    lang: "en-US,en;q=0.9" }
      };

      function listener(details) {
        if (profileId === "disabled") return { requestHeaders: details.requestHeaders };

        const shouldRewrite = PROFILES_REWRITE[profileId] || false;
        if (!shouldRewrite) return { requestHeaders: details.requestHeaders };

        const persona = PERSONAS[personaKey] || PERSONAS.win11_edge;
        const modified = modifyHeaders(details.requestHeaders, { persona });

        return { requestHeaders: modified };
      }

      const PROFILES_REWRITE = { strict: true, moderate: true, disabled: false };

      api().webRequest.onBeforeSendHeaders.addListener(
        listener,
        { urls: ["<all_urls>"] },
        ["blocking", "requestHeaders", "extraHeaders"]
      );
    });
  }
})();
