# Desktop ↔ browser extension bridge

Status: **implemented**. Decision record plus the wire protocol between the
desktop app and the Chromium MV3 extension in [`extension/`](../extension).

## Decision: loopback HTTP, not native messaging

Two options were on the table.

**Native messaging** — the browser launches the desktop app (or a helper) as a
child process and talks over stdio. It is the more contained design: no listening
socket, and the OS enforces that only the browser can start the host.

It was **rejected as the primary mechanism** because of what it costs to
install. Native messaging needs a JSON host manifest written to a
browser-specific, OS-specific directory (`~/.config/google-chrome/NativeMessagingHosts/`,
`%LOCALAPPDATA%\Google\Chrome\User Data\NativeMessagingHosts\`, `~/Library/…`),
one per browser *and* per Chromium variant (Chrome, Edge, Brave, Chromium,
Vivaldi…), and the manifest must name the extension's ID up front — which is not
stable for an unpacked or self-distributed extension. That is a large amount of
per-platform installer machinery, and it breaks silently when a user installs a
different Chromium build.

**Chosen: a loopback HTTP listener** bound to `127.0.0.1`, enabled explicitly by
the user from desktop settings, with an authenticated pairing step. It works
identically on every Chromium variant and every OS with no installer support at
all. This is the same approach Bitwarden and KeePassXC-style bridges take in
practice.

### What that costs, honestly

A loopback socket is reachable by **any local process**, not just the browser. The
protections below are what stand between that socket and the vault, and they are
meaningful but not equivalent to native messaging's process isolation:

| Protection | Stops |
|---|---|
| Off by default; user must enable it in settings | Anything at all, until the user opts in |
| Bound to `127.0.0.1` only | Access from other machines on the network |
| Pairing requires a 6-digit code shown in the desktop UI, valid 2 minutes, 5 attempts | A local process pairing itself without the user's knowledge |
| Every authenticated request needs a 256-bit bearer token issued at pairing | Unpaired local processes reading credentials |
| `Origin` must equal the `chrome-extension://<id>` recorded at pairing | Web pages (browsers refuse to forge `Origin`) and other extensions |
| All credential endpoints return `423 Locked` unless the vault is unlocked | Anything while the app is locked |
| Token stored in `bridge.enc`, encrypted with the vault DEK | Reading the token off disk without the master password |

The residual risk: a malicious process running **as the same user** that can read
the browser's extension storage can extract the token and then request
credentials for any domain while the vault is unlocked. A process with that level
of access can also read the browser's own password store and keylog the master
password, so this does not meaningfully change the threat model — but it is a real
difference from native messaging and is the reason this feature is opt-in.

Native messaging remains a sensible future addition for users who want it; the
protocol below would be reused unchanged over stdio.

## Transport

- Listener: `127.0.0.1`, first free port in **8391–8395**.
- The extension probes that range for `GET /health` and remembers the port.
- CORS: `chrome-extension://` origins only.
- JSON request and response bodies.

Port scanning rather than a fixed port means a conflicting service does not
disable the feature. The port is not a secret and provides no protection.

## Endpoints

`GET /health` — unauthenticated. The only endpoint that answers before pairing;
it exists so the extension can discover the port and show the right UI.

```json
{ "app": "password-manager", "version": "0.1.0", "locked": true, "paired": false }
```

`POST /pair` — exchanges the code shown in desktop settings for a token.
Requires the vault to be **unlocked** (the token is persisted encrypted under the
vault's data key).

```json
→ { "code": "418630", "extension_id": "abcdefghijklmnopabcdefghijklmnop" }
← { "token": "<43-char base64url>" }
```

Wrong codes are compared in constant time and counted; 5 failures end the pairing
window. The window also expires after 120 seconds.

All remaining endpoints require `Authorization: Bearer <token>` **and** a matching
`Origin`.

`GET /status` → `{ "locked": false }`

`POST /credentials` — candidate logins for a page. **Never returns a password.**

```json
→ { "url": "https://login.example.com/session" }
← { "entries": [ { "id": "…", "title": "Example", "username": "daniel" } ] }
```

Matching is by host, on whole DNS labels: an entry saved for `example.com`
matches `login.example.com` but never `notexample.com`. See
[`src-tauri/src/domain.rs`](../src-tauri/src/domain.rs).

`POST /fill` — returns the secret for one entry the user picked.

```json
→ { "id": "…" }
← { "username": "daniel", "password": "…" }
```

The user's click on a specific entry in the extension popup **is** the
confirmation; the extension never fills without one. Each fill emits a
`bridge://fill` event so the desktop app can surface that a credential was
released.

`POST /unpair` — revokes the calling token.

## Status codes

| Code | Meaning |
|---|---|
| 200 | OK |
| 400 | Malformed body or unparseable URL |
| 401 | Missing/invalid token, or `Origin` mismatch |
| 403 | Pairing not in progress, code wrong, or attempts exhausted |
| 404 | Entry not found |
| 423 | Vault locked — the extension must prompt the user to unlock the desktop app |
| 503 | Bridge disabled in settings |

## Extension side

`extension/` is a Manifest V3 extension:

- `background.js` — service worker; owns port discovery, the token, and all
  bridge calls. Content scripts never hold the token.
- `content.js` — detects sign-in forms and fills them on instruction.
- `popup.html` / `popup.js` — pairing UI and the credential picker.

Form detection looks for a password input, then walks the containing form for the
best username candidate (`autocomplete="username"`, then `type="email"`, then a
preceding text input). Fill dispatches real `input` and `change` events so React
and similar frameworks observe the change.

The extension holds **no vault data at rest** — only the bridge token and the
discovered port.
