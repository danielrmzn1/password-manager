# Roadmap

The tracking document for planned features. Check items off as they land; add new scope here so it doesn't get lost. Product-level descriptions live in [README.md](../README.md), agent guidance in [AGENTS.md](../AGENTS.md).

**Status legend:** `[ ]` not started · `[~]` in progress · `[x]` done

---

## Milestone 0 — Project scaffold ✅

- [x] Tauri 2 + React 19 + TypeScript + Vite scaffold
- [x] Tailwind CSS 4 + shadcn/ui (Nova preset) with base component set
- [x] README, AGENTS.md, GitHub repo (`danielrmzn1/password-manager`)

## Milestone 1 — Vault core & master password ✅

The foundation everything else depends on. All crypto in Rust.

- [x] **Vault format decision** — documented in [docs/vault-format.md](vault-format.md) (encrypted blob layout, versioning, entry schema: title, username, password, URL/domain, notes, custom fields, timestamps)
- [x] **Key derivation** — Argon2id from master password (m=64 MiB, t=3, p=4); parameters stored in the vault header and authenticated as AEAD associated data, so the cost cannot be downgraded. The key is never persisted.
- [x] **Encryption layer** — XChaCha20-Poly1305 (RustCrypto), two-level keys (master key wraps a random data key), `zeroize` on all key material
- [x] **Initial setup flow** — first launch: create master password with live zxcvbn strength feedback, create local vault
- [x] **Unlock screen** — master password required; wrong-password handling is inline and indistinguishable from a corrupt wrap by design
- [x] **Auto-lock** — configurable inactivity timeout, default 5 min, enforced in the Rust backend (not the webview) and immune to system suspend
- [x] **Local vault persistence** — atomic, `fsync`ed, `0600` writes with a `.bak` of the previous revision

## Milestone 2 — Vault UI (CRUD) ✅

- [x] Entry list with search/filter
- [x] Entry detail view — reveal-on-click for secrets, copy-to-clipboard
- [x] Clipboard auto-clear after configurable timeout (default 30 s, driven from Rust; only clears if the clipboard still holds the copied value)
- [x] Create/edit/delete entries (passwords and free-form secrets/notes)
- [x] Settings screen (lock timeout, clipboard timeout, theme)
- [x] Dark/light mode

## Milestone 3 — Password generator ✅

Strong, flexible, highly configurable. CSPRNG only (`getrandom`), with rejection sampling so there is no modulo bias.

- [x] **Character mode** — configurable: length, uppercase, lowercase, digits, special characters with a **user-selectable set of which special chars** to include, exclude-ambiguous option (`0O1lI`)
- [x] **Passphrase mode** — word-based diceware using the real EFF large wordlist (7776 words, 12.9 bits/word): word count, separator, capitalization, optional digit/symbol injection
- [x] Strength/entropy indicator
- [x] Generator embedded in the entry create/edit form + standalone generator screen
- [x] Saved generator presets (stored in the vault, so they sync)

## Milestone 4 — S3-compatible sync (Cloudflare R2 primary) ✅

Multi-device sync via a user-owned bucket. Bucket only ever sees ciphertext.

- [x] **Storage backend config UI** — endpoint, bucket, prefix, access key, secret key, path-style toggle; custom endpoints so any S3-compatible service works (R2, AWS S3, MinIO, Backblaze B2), with a "test connection" check
- [x] S3 credentials stored encrypted in `sync.enc` under the vault data key — never plaintext on disk
- [x] **Rust S3 client** — `aws-sdk-s3` with custom endpoint support, plus `RequestChecksumCalculation::WhenRequired` which is what makes uploads work against R2
- [x] **Sync protocol** — documented in [docs/sync-protocol.md](sync-protocol.md): ETag change detection, conditional writes (`If-Match`/`If-None-Match`) for concurrency, per-entry last-write-wins merge with tombstones
- [x] Manual sync + sync-on-unlock/on-save
- [x] Offline behavior — app fully usable without connectivity; sync failures are reported as status, never blocking a local write

> Not verified against a live R2 bucket — that needs real credentials. The client is built and unit-tested, and the R2-specific configuration is in place, but the first run against a real bucket should be treated as the acceptance test. See "Known gaps" below.

## Milestone 5 — Browser extension (Chromium, MV3) ✅

Optional companion, user-enabled from the desktop app.

- [x] **Desktop ↔ extension bridge decision** — loopback HTTP over native messaging, with the reasoning and threat model in [docs/extension-bridge.md](extension-bridge.md)
- [x] Enable/disable extension pairing from desktop app settings (off by default; 6-digit code, 2-minute window, 5 attempts, token stored encrypted under the vault key)
- [x] **Sign-in form detection** on web pages
- [x] **Domain matching** — suggests credentials for the current domain, matching on whole DNS labels so `notexample.com` never matches `example.com`
- [x] Autofill username/password on user confirmation (the click on a specific entry is the confirmation)
- [x] Respect app lock state — every credential endpoint returns `423 Locked` while the vault is locked

> Not verified in a real browser — that needs a Chromium instance with the extension loaded unpacked. Same caveat as R2 above.

## Milestone 6 — Polish & distribution

- [~] App icon / branding — a neutral placeholder keyhole mark is generated and wired up; final branding is blocked on the **commercial name, which is still undecided**
- [x] Tighten Tauri CSP (was `null`) and audit capabilities — the webview now gets only `core:event:default` plus `opener:allow-open-url` scoped to http/https; clipboard and file dialogs are driven from Rust so the webview has neither permission
- [~] Windows/macOS/Linux builds + code signing — cross-platform bundling runs in [CI](../.github/workflows/build.yml); **signing is documented but not enabled** because it needs certificates only the project owner can obtain ([docs/distribution.md](distribution.md))
- [ ] Auto-updates — **not wired up.** Requires a signing keypair whose private half must not enter the repo; exact steps in [docs/distribution.md](distribution.md). Shipping a placeholder pubkey would silently break every update.
- [x] Import from other password managers — header-driven CSV import covering Bitwarden, Chrome, Firefox, 1Password, LastPass and KeePass exports
- [x] Vault backup/export (encrypted) — self-contained `.pmv` with its own password and fresh key material; restore merges rather than replaces. There is deliberately **no plaintext export**.

---

## Known gaps and deliberate trade-offs

Worth reading before trusting this with real secrets.

- **No live-service verification.** The R2/S3 client and the browser extension are implemented and unit-tested but have not been exercised against a real bucket or a real browser. Those are the two highest-value next tests.
- **Field-level edits do not merge.** Two devices editing the same entry concurrently keep one version wholesale. Fixing this needs per-field timestamps, i.e. a format change.
- **Sync ordering depends on wall clocks.** "Newer" means a larger `updated_at`; a badly skewed device clock can make its edits systematically win or lose.
- **No rollback protection on the remote.** An attacker who can write to the bucket can serve an older genuine revision. Because the merge is union-based the effect is resurrected deletions rather than lost current entries; a signed revision chain would close this.
- **Memory scrubbing is best-effort.** Key material uses `Zeroizing`, and entries scrub their secret fields on drop, but `Vec` reallocation and serde's intermediate buffers can leave copies in freed heap pages that safe Rust cannot reach.
- **Tombstones expire after 180 days.** A device offline longer than that can resurrect deleted entries.
- **No IDNA/punycode normalisation in domain matching.** `domain.rs` lowercases ASCII only, so an entry saved against an internationalised domain in Unicode form (`bücher.example`) will not match the punycode host a browser actually reports (`xn--bcher-kva.example`). The failure is safe in direction — it declines to offer a credential rather than offering it to the wrong site — but it means IDN sites need their URL stored in punycode form to autofill. Fixing this needs an IDNA crate.
- **Domain matching has no Public Suffix List.** An entry saved against a bare public suffix (`co.uk`) would match any host under it. Entry URLs come from the user's own vault, so the attacker-controlled side (the page host) is still fully guarded by the label-boundary check.
- **The loopback bridge is reachable by any local process.** It is off by default and protected by pairing, a bearer token and an origin check — but a malicious process running as the same user could extract the token from the browser profile. See [docs/extension-bridge.md](extension-bridge.md) for the full reasoning.
- **`assess_master_password` receives the candidate password over IPC.** It is never stored, hashed or logged, but it does cross the webview boundary; a fully paranoid design would score entirely in the webview.

## Ideas / unscoped

Things mentioned or worth considering but not yet committed to a milestone:

- TOTP (2FA code) storage and generation — CSV import already preserves TOTP secrets as a hidden custom field, so the data survives until this lands
- Password health report (reused/weak/old passwords) — `password_updated_at` is already tracked per entry for this
- Breach checking (e.g. k-anonymity HIBP lookup)
- Firefox/Safari extension variants
- OS keychain as an alternative store for S3 credentials (rejected as the primary mechanism because it is unavailable on many headless/WSL setups)
- Argon2id parameter re-tuning on unlock, so vaults created on weak hardware can be upgraded
