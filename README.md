# TrustScore Anti-Phishing Extension

Behavioral TrustScore detector that scores pages (0–100 with 100 being "safe") using URL, DOM, behavior, and SSL/mixed-content signals, then surfaces a widget/banner plus popup breakdown.

## What’s inside
- `manifest.json` — MV3 manifest for background, content script, popup, options.
- `background.js` — TrustScore engine, storage, allowlist, history.
- `contentScript.js` — signal collectors, behavior observers, in-page widget/banner.
- `popup.*` — popup UI showing score, breakdown, reasons, history.
- `options.*` — sensitivity/allowlist/backend toggles.

## Quick test in Chrome/Edge
1) Open `chrome://extensions` (or `edge://extensions`), enable Developer mode.  
2) “Load unpacked” → select this folder.  
3) Pin the extension, browse to pages (HTTP logins, etc.) and watch the widget/banner; click the icon for the popup.

## Test in Safari (required for shipping)
1) In Xcode: File → New → Project → Safari Web Extension App, point it at this folder for the extension source.  
2) Run the generated macOS app; click “Quit and Open Safari Extension Preferences”.  
3) In Safari Settings → Extensions, enable the extension and allow it on all websites.  
4) Browse and verify the in-page widget/banner and popup.

## Notes / next steps
- Allowlist, sensitivity profiles, and history are stored locally via `chrome.storage`.  
- Network lookups are not enabled yet; `enableBackend` flag is future-facing.  
- Tweak risk weights/reasons in `background.js` and signal heuristics in `contentScript.js` as you iterate.  
- For Firefox, MV3 support may need adjustments; Chrome/Edge/Safari are the primary targets.  
- Keep `manifest.json` and icons at the root when loading unpacked.  
- Optional: add automated tests around `computeTrustScore` and the signal evaluators.
