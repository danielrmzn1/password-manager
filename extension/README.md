# Password Manager — Chromium extension (MV3)

The optional browser companion for the Password Manager desktop app. It finds
the sign-in form on a page and fills one login that **you** pick from the popup.

It is not a password manager of its own: it has no vault, no master password and
no storage of credentials. Every secret comes from the desktop app, one at a
time, over a loopback bridge, and only while that app is unlocked.

Plain JavaScript and CSS — no build step, no bundler, no dependencies. Load the
folder as-is.

## Install

1. Open `chrome://extensions` (Chrome, Edge, Brave, Vivaldi, Chromium…).
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and select this `extension/` folder.
4. Pin the extension so its popup is one click away.

The extension has no icon files, so Chromium shows a lettered placeholder. That
is deliberate: referencing icons that do not exist stops an extension loading.

## Pair it with the desktop app

Pairing is one-time per browser profile, and needs the vault **unlocked** —
the bridge token is stored inside the vault, encrypted.

1. In the desktop app, go to **Settings → Browser extension**.
2. Switch on **Allow the browser extension to connect**.
3. Click **Pair extension**. A 6-digit code appears; it is valid for two
   minutes, single-use, and allows five wrong attempts before the window closes.
4. Open this extension's popup, type the code, click **Pair**.

The desktop dialog closes itself when pairing completes. To undo it, use
**Unpair** in either the popup footer or the desktop settings — the token is
revoked on the desktop side and deleted from the browser.

## Using it

Open the popup on a sign-in page:

- **Paired and unlocked** — the popup lists the logins whose saved site matches
  the page's host, showing title and username (never a password). Click one and
  it is filled into the page and the popup closes.
- **Nothing matches** — the popup names the host it searched for, so a mismatch
  between (say) `accounts.example.com` and an entry saved for `example.net` is
  obvious.
- **Vault locked** — the popup says so and offers **Retry**. No autofill happens
  while the desktop app is locked.
- **Desktop app not running, or the bridge switched off** — the popup explains
  what to check.

Filling only ever happens from your click on a specific entry. There is no
automatic fill, no fill on page load, and no keyboard shortcut that fills without
a choice.

## What it stores

In `chrome.storage.local`, on this browser profile only:

| Key | Value |
|---|---|
| `bridgeToken` | The bearer token issued at pairing |
| `bridgePairedAt` | Timestamp of pairing, for display/debugging |

In `chrome.storage.session` (memory-only, cleared when the browser closes;
falls back to `local` on Chromium builds without it):

| Key | Value |
|---|---|
| `bridgePort` | The discovered bridge port, re-verified before use |

**No vault data at rest.** No entries, usernames, passwords, URLs or search
results are cached. Credential lists live only in the open popup; a fetched
password exists only for the length of the one message that carries it into the
page.

## Permissions, and why each one

| Permission | Why |
|---|---|
| `storage` | The token and the cached port, above. |
| `activeTab` | Read the active tab's URL (to ask which logins match) and message/inject its content script — granted only for the tab you open the popup on, only when you open it. |
| `scripting` | Re-inject `content.js` into a tab that was already open when the extension was installed or reloaded. |
| `http://127.0.0.1:8391/*` … `8395/*` | The five ports the desktop bridge may bind. Nothing else. |
| `content_scripts` on `<all_urls>` | A sign-in form can be on any site, and detection has to happen before you know you want to fill. |

Deliberately **not** requested: `tabs` (broad access to every tab's URL and
title), `<all_urls>` host permissions (which would let the extension read and
change any page's data at will), `webRequest`, `cookies`, `clipboardWrite`,
`notifications`.

## How it works

```
popup.js ──message──> background.js ──HTTP──> 127.0.0.1:839x (desktop app)
                            │
                            └──message──> content.js (fills the form)
```

- **`background.js`** (service worker) owns port discovery, the token and every
  bridge call. It probes ports 8391–8395 for `GET /health` and only accepts a
  port whose response says `app: "password-manager"`, so it cannot be fooled by
  some other service on the range. MV3 stops the worker whenever it likes, so
  nothing lives in memory that cannot be rebuilt from storage.
- **`content.js`** detects and fills. It never receives the token and makes no
  network requests. It only ever gets a single username/password, in response to
  a click you made.
- **`popup.js`** renders state and never sees a password.

Message API the popup uses (all replies are `{ ok: true, … }` or
`{ ok: false, error, kind }`):

| Message | Reply |
|---|---|
| `{ type: "status" }` | `{ ok, state, paired, locked, port, version }` where `state` is `unreachable`, `disabled`, `unpaired`, `locked` or `ready` |
| `{ type: "pair", code }` | `{ ok }` |
| `{ type: "unpair" }` | `{ ok, revoked }` |
| `{ type: "credentials", url }` | `{ ok, entries: [{ id, title, username }] }` |
| `{ type: "fill", id, tabId }` | `{ ok, filledUsername, filledPassword }` |
| `{ type: "detect", tabId }` | `{ ok, found, hasUsernameField, passwordFields }` |

`content.js` may send `{ type: "detected", … }` and nothing else — the worker
rejects every other message type that arrives from a tab, so a compromised page
cannot drive the bridge even if it found a way to reach the worker.

### Form detection

Finds visible `input[type="password"]` elements (non-zero size, not
`display:none`/`visibility:hidden`/`opacity:0`, not disabled or read-only),
following open shadow roots. With several, an explicit
`autocomplete="current-password"` wins over the first one.

The username field is then chosen from the containing `<form>` — and only from
there, so a username can never land in an unrelated field elsewhere on the page.
When the password field is in no form at all (the single-page-app case) the search
widens to the field's shadow root and then the whole document. In order of
preference: `autocomplete="username"`, `autocomplete="email"`, `type="email"`,
then the nearest visible text/email/tel input *before* the password field. Fields
before the password field beat fields after it, and obvious non-usernames (search
boxes, one-time-code inputs, coupon fields) are skipped. A password-only form is
handled: the password is filled, the missing username is simply not.

Filling focuses the field, sets `value`, then dispatches bubbling `input` and
`change` events so React, Vue, Angular and friends observe the change rather
than reverting it. Focus is left in the password field so Enter submits.

### Known limitations

- **Top frame only.** A login form inside an iframe is not filled. The
  alternative — running in every frame — means broadcasting a password to
  third-party frames on the page, which is not a trade worth making.
- **Chromium only.** MV3 as written here (service worker, `chrome.*` promises).
  Firefox would need a small compatibility shim.
- Closed shadow roots are invisible to any extension, so forms inside them
  cannot be detected.

## Security notes

Full rationale and threat model: [`docs/extension-bridge.md`](../docs/extension-bridge.md).

The bridge is a **loopback HTTP listener**, chosen over native messaging because
native messaging needs a per-browser, per-OS host manifest naming a stable
extension ID — a large amount of installer machinery that breaks silently. The
honest cost of that choice: a loopback socket is reachable by **any local
process**, not only the browser. What stands in front of it:

- Off by default; the user enables it explicitly in desktop settings.
- Bound to `127.0.0.1`, never a routable address.
- Pairing needs a 6-digit code shown in the desktop UI: 2-minute window,
  5 attempts, compared in constant time.
- Every other endpoint needs a 256-bit bearer token issued at pairing.
- The request `Origin` must equal the `chrome-extension://<id>` recorded at
  pairing, so web pages (which cannot forge `Origin`) and other extensions are
  refused even with a token.
- All credential endpoints return `423 Locked` unless the vault is unlocked.
- The token is persisted on the desktop side inside `bridge.enc`, encrypted with
  the vault key.
- Every fill emits a `bridge://fill` event, so the desktop app can surface that
  a credential was released.

**Residual risk:** a malicious process running as your user that can read this
browser profile's extension storage can extract the bridge token and then request
credentials for any domain *while the vault is unlocked*. A process with that
access can already read the browser's own password store and log your keystrokes,
so it does not meaningfully change the threat model — but it is a real difference
from native messaging, and it is why the feature is opt-in. If you do not want a
local listener at all, leave the bridge switched off; the desktop app is fully
usable without it.

Note that pairing is per browser profile: pair each profile you want to use, and
unpair a profile you no longer trust.

## Troubleshooting

**"Desktop app not reachable"** — is the app running? Has its vault been
unlocked at least once since launch? Is **Allow the browser extension to
connect** on? The desktop settings screen shows `Listening on 127.0.0.1:<port>`
when the bridge is up; if all five ports are taken by other software, the bridge
cannot start.

**"The desktop app no longer recognises this extension"** — the desktop side was
unpaired (or the vault was recreated). Pair again; the extension discards the
dead token by itself.

**Nothing fills, but an entry was there** — the form may be in an iframe (not
supported), inside a closed shadow root, or built after the popup looked. Close
and reopen the popup to re-scan.

**Pairing says the code is wrong when it is not** — codes expire after two
minutes. Start pairing again in the desktop app for a fresh code.

**After editing this extension's files**, hit reload on `chrome://extensions`.
Tabs that were already open get `content.js` re-injected on demand, so you do
not need to reload every page. To watch the worker's console, use **Inspect
views: service worker** on the extension's card.

## Files

| File | Role |
|---|---|
| `manifest.json` | MV3 manifest: permissions, worker, popup, content script |
| `background.js` | Service worker: port discovery, token, all bridge calls |
| `content.js` | Form detection and filling |
| `popup.html` / `popup.css` / `popup.js` | Pairing UI and credential picker |
