<p align="center">
  <img src="shields/256.png" width="96" alt="Al-Kantara Security">
</p>

<h1 align="center">Al-Kantara Security</h1>

<p align="center">
  <strong>Zero-trust browser defense. No telemetry. No compromises.</strong><br>
  50+ anti-fingerprint vectors. Live threat intelligence. Encrypted vault. Code execution lab.
</p>

<p align="center">
  <a href="https://github.com/urbanyl/Al-Kantara-Security-Extension/releases"><img src="https://img.shields.io/badge/version-1.3.1-blue?style=flat-square" alt="Version"></a>
  <a href="https://github.com/urbanyl/Al-Kantara-Security-Extension/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
  <a href="#"><img src="https://img.shields.io/badge/chrome-MV3-brightgreen?style=flat-square&logo=googlechrome" alt="Chrome MV3"></a>
  <a href="#"><img src="https://img.shields.io/badge/firefox-MV2-orange?style=flat-square&logo=firefoxbrowser" alt="Firefox MV2"></a>
  <a href="#"><img src="https://img.shields.io/badge/protect-50%2B%20vectors-red?style=flat-square" alt="50+ Protections"></a>
  <a href="#"><img src="https://img.shields.io/badge/encryption-AES--256--GCM-yellow?style=flat-square" alt="AES-256-GCM"></a>
  <a href="#"><img src="https://img.shields.io/badge/zero--telemetry-black?style=flat-square" alt="Zero Telemetry"></a>
</p>

---

## What is this?

Al-Kantara Security is a browser extension built for people who take privacy seriously. It blocks fingerprinting, rewrites network headers, encrypts your data locally, monitors threats in real time, and lets you run code directly in your browser.

It stores **nothing on external servers**. Everything stays on your machine.

Works on **Chrome, Edge, Brave** (Manifest V3) and **Firefox** (Manifest V2).

---

## Core Protections

### Anti-Fingerprint (19 vectors)
| Vector | Method |
|---|---|
| Canvas | Per-pixel noise injection on toDataURL/toBlob |
| WebGL | Vendor + renderer spoof, extension list override |
| AudioContext | Oscillator frequency + AudioBuffer perturbation |
| Fonts | Enumeration restricted to common system fonts |
| ClientRects | Sub-pixel noise on getBoundingClientRect |
| Navigator | Platform, vendor, languages, hwConcurrency, deviceMemory spoof |
| WebRTC | Full IP leak block (RTCPeerConnection + getUserMedia) |
| Battery API | Spoofed charging state + level |
| Speech Synthesis | Voice enumeration blocked |
| Presentation API | Cast device detection prevented |
| Performance Timing | Navigation timing sanitized |
| Permissions API | All queries return "prompt" |
| Timezone | Date/Intl.DateTimeFormat override |
| Geolocation | Navigator.geolocation spoof |
| Mouse Events | Timing randomization to prevent movement tracking |
| Keystroke Timing | Jitter added to keyboard event timestamps |
| Window.name | Randomized on every page load |
| Console | Sanitized to prevent console fingerprinting |
| Locks API | Enumeration fingerprinting blocked |

### Network Shield (12 vectors)
- **Header rewrite**: User-Agent + Accept-Language per persona
- **Privacy headers**: DNT:1 + Sec-GPC:1 (legally binding under CCPA/CPRA)
- **Strip leaks**: Accept-CH, Sec-Fetch-*, X-Forwarded-For, CF-Connecting-IP, X-Real-IP, Forwarded
- **Strict referrer**: Stripped on cross-origin + all subresource requests
- **Force HTTPS**: HSTS upgrade on all requests
- **ETag block**: Cached responses cleared to prevent ETag fingerprinting
- **Link cleaner**: Strips 30+ tracking params (utm_*, fbclid, gclid, mc_eid, etc.)
- **Cache clear**: Purged on every navigation
- **Traffic obfuscation**: Adds cache/pragmas to mimic normal browsing

### Threat Intelligence
- **22+ known malicious domains** database
- Suspicious IP range detection (RFC 1918, link-local, cloud metadata)
- Fingerprint script blocking (fingerprintJS,-clientjs, etc.)
- Tracker domain blocking (GA, GTM, DCM, FB Pixel, TikTok, Bing Ads...)
- Live network activity graph (60-second rolling window)
- Threat breakdown bars with real-time counts

### Cipher Lab
| Algorithm | Details |
|---|---|
| AES-256-GCM | Authenticated encryption, PBKDF2 600k iterations |
| AES-128-GCM | Fast authenticated encryption, PBKDF2 300k iterations |
| XOR ChaCha | Stream cipher with ChaCha-derived nonce |
| ROT13 | Classical Caesar substitution |

Full encrypt/decrypt with passphrase. Operation history logged.

### Encrypted Vault
- AES-256-GCM encryption with PBKDF2 key derivation
- Categories: Credentials, Secure Notes, API Keys, Identity Data
- Add, unlock, delete entries
- Stored locally, never leaves your browser

### Identity Rotation
- Auto-rotate persona at configurable intervals (5min to 2 hours)
- Sequential cycle or random selection
- 6 built-in personas: Win 11 Edge, macOS Safari, Linux Firefox, Win 10 Chrome, Android Chrome, iOS Safari

### Code Execution Lab
- Write and run **JavaScript** directly in the browser
- HTML preview mode
- CSS injection mode
- Save scripts with custom names
- Export scripts to clipboard for sharing
- Execution history with status tracking
- Runs at your own risk — no sandbox guarantees

### Chemical Clean
6-step data purge:
1. Overwrite localStorage + sessionStorage with random data
2. Purge IndexedDB
3. Expire all cookies
4. Clear HTTP cache
5. Purge autofill data
6. Clear download history

### Extra Shields
- Clipboard guard (auto-wipe after 30s + read event spoof)
- Screen capture guard (invisible watermark + API block)
- Memory scrubber (periodic window.name + history cleanup)
- Cookie isolation (SameSite=Lax + Secure enforced)
- CNAME cloaking detector

---

## Install

### Chrome / Edge / Brave
```bash
git clone https://github.com/urbanyl/Al-Kantara-Security-Extension.git
```
1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the `Al-Kantara-Security` folder

### Firefox
1. Rename `manifest.firefox.json` to `manifest.json`
2. Open `about:debugging#/runtime/this-firefox`
3. Click **Load Temporary Add-on**
4. Select any file inside the folder

---

## Dashboard (12 tabs)

| Tab | Purpose |
|---|---|
| Overview | Status, kill switch, profiles, entropy meter |
| Threat Monitor | Live network graph, threat breakdown, event feed |
| Fingerprint | Canvas, WebGL, audio, fonts toggles + persona grid |
| Network | Headers, traffic control, DNS, header preview |
| Navigator | Hardware + other API protections |
| Cipher Lab | Encrypt/decrypt with 4 algorithms |
| Encrypted Vault | Store encrypted entries |
| Advanced | Identity rotation, clipboard guard, memory scrubber |
| Chemical Clean | Full data purge |
| Logs | Event history with encrypted export |
| Execution | Code editor, run/save/share scripts |
| Settings | Notifications, auto-clean, log retention |

---

## Tech Stack

- **Pure JavaScript** — zero dependencies, zero frameworks
- **Web Crypto API** — AES-256-GCM, PBKDF2, SHA-256
- **Chrome Declarative Net Request** — header rewriting + blocking
- **Canvas 2D** — live network activity charts
- **Service Worker** (MV3) / **Background Script** (MV2)
- **OffscreenCanvas** — dynamic shield icon generation

---

## Permissions

| Permission | Purpose |
|---|---|
| `storage` | Save settings, vault, scripts, logs |
| `tabs` | Tab management + icon updates |
| `webRequest` | Request monitoring + threat detection |
| `declarativeNetRequest` | Header rewriting + tracker blocking |
| `browsingData` | Chemical Clean data purge |
| `cookies` | Cookie isolation + management |
| `webNavigation` | URL cleaning on navigation |
| `downloads` | Encrypted log export |

---

## Author

**Urbanyl** — [github.com/urbanyl](https://github.com/urbanyl)

Built with precision. Released with purpose.

---

## License

MIT
