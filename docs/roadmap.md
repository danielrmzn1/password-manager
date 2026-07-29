# Roadmap

The tracking document for planned features. Check items off as they land; add new scope here so it doesn't get lost. Product-level descriptions live in [README.md](../README.md), agent guidance in [AGENTS.md](../AGENTS.md).

**Status legend:** `[ ]` not started · `[~]` in progress · `[x]` done

---

## Milestone 0 — Project scaffold ✅

- [x] Tauri 2 + React 19 + TypeScript + Vite scaffold
- [x] Tailwind CSS 4 + shadcn/ui (Nova preset) with base component set
- [x] README, AGENTS.md, GitHub repo (`danielrmzn1/password-manager`)

## Milestone 1 — Vault core & master password

The foundation everything else depends on. All crypto in Rust.

- [ ] **Vault format decision** — documented in `docs/` (encrypted blob layout, versioning, entry schema: title, username, password, URL/domain, notes, custom fields, timestamps)
- [ ] **Key derivation** — Argon2id from master password; parameters documented and stored alongside the vault (never the key)
- [ ] **Encryption layer** — AEAD (AES-256-GCM or XChaCha20-Poly1305 via RustCrypto), zeroize key material
- [ ] **Initial setup flow** — first launch: create master password (with strength feedback), create local vault
- [ ] **Unlock screen** — master password required to view/edit anything; wrong-password handling
- [ ] **Auto-lock** — lock after configurable inactivity timeout (safe default, e.g. 5 min)
- [ ] **Local vault persistence** — encrypted vault file on disk as the source of truth between syncs

## Milestone 2 — Vault UI (CRUD)

- [ ] Entry list with search/filter
- [ ] Entry detail view — reveal-on-click for secrets, copy-to-clipboard
- [ ] Clipboard auto-clear after configurable timeout
- [ ] Create/edit/delete entries (passwords and free-form secrets/notes)
- [ ] Settings screen (lock timeout, clipboard timeout, theme)
- [ ] Dark/light mode

## Milestone 3 — Password generator

Strong, flexible, highly configurable. CSPRNG only (`OsRng`/`getrandom`).

- [ ] **Character mode** — configurable: length, uppercase, lowercase, digits, special characters with a **user-selectable set of which special chars** to include, exclude-ambiguous option (`0O1lI`)
- [ ] **Passphrase mode** — word-based (diceware-style): word count, separator, capitalization, optional digit/symbol injection
- [ ] Strength/entropy indicator
- [ ] Generator embedded in the entry create/edit form + standalone generator screen
- [ ] Saved generator presets

## Milestone 4 — S3-compatible sync (Cloudflare R2 primary)

Multi-device sync via a user-owned bucket. Bucket only ever sees ciphertext.

- [ ] **Storage backend config UI** — endpoint, bucket, access key, secret key; custom endpoint support so any S3-compatible service works (R2, AWS S3, MinIO, Backblaze B2)
- [ ] S3 credentials stored encrypted (or OS keychain) — never plaintext on disk
- [ ] **Rust S3 client** — upload/download encrypted vault (custom endpoint support required for R2)
- [ ] **Sync protocol** — documented in `docs/`: change detection, multi-device conflict handling (e.g. last-write-wins vs merge), tested against R2 specifically
- [ ] Manual sync + sync-on-unlock/on-save
- [ ] Offline behavior — app fully usable without connectivity, sync when available

## Milestone 5 — Browser extension (Chromium, MV3)

Optional companion, user-enabled from the desktop app.

- [ ] **Desktop ↔ extension bridge decision** — native messaging vs localhost bridge; documented in `docs/`
- [ ] Enable/disable extension pairing from desktop app settings
- [ ] **Sign-in form detection** on web pages
- [ ] **Domain matching** — suggest credentials for the current domain
- [ ] Autofill username/password on user confirmation
- [ ] Respect app lock state — no autofill while the vault is locked

## Milestone 6 — Polish & distribution

- [ ] App icon / branding (commercial name TBD)
- [ ] Tighten Tauri CSP (currently `null`) and audit capabilities
- [ ] Windows/macOS/Linux builds + code signing
- [ ] Auto-updates
- [ ] Import from other password managers (CSV, Bitwarden, etc.)
- [ ] Vault backup/export (encrypted)

---

## Ideas / unscoped

Things mentioned or worth considering but not yet committed to a milestone:

- TOTP (2FA code) storage and generation
- Password health report (reused/weak/old passwords)
- Breach checking (e.g. k-anonymity HIBP lookup)
- Firefox/Safari extension variants
