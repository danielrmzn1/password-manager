# AGENTS.md

Instructions for AI coding agents working on this repository.

## What this project is

A desktop password manager built with **Tauri 2**. Design goals: simple, intuitive, modern. Core features (in rough priority order):

1. **Encrypted vault synced to S3-compatible storage** — passwords/secrets are encrypted client-side and stored in a user-owned bucket (primary target: Cloudflare R2; must work with any S3-compatible API). This enables multi-device use.
2. **Password generator** — strong, flexible, highly configurable: length, upper/lowercase, digits, special characters (user can choose *which* ones), passphrase (word-based) mode, etc.
3. **Chromium browser extension (optional, user-enabled)** — detects sign-in forms and suggests autofilling credentials matched by domain.
4. **Master password** — set during initial setup; required to unlock the app before viewing/editing any secret.

Milestones 1–5 are implemented. See **`docs/roadmap.md`** for current status, and read its "Known gaps and deliberate trade-offs" section before making claims about what this app guarantees.

## Tech stack

- **Desktop shell:** Tauri 2 (Rust 2021 edition) in `src-tauri/`
- **Cryptography:** RustCrypto — `argon2`, `chacha20poly1305`, `zeroize`, `subtle`, `getrandom`
- **Sync:** `aws-sdk-s3` (custom endpoints), extension bridge on `axum`
- **Frontend:** React 19, TypeScript 5.8 (strict), Vite 7
- **Styling:** Tailwind CSS 4 + shadcn/ui (Radix flavor, Nova preset: Geist font, Lucide icons)
- **Package manager:** pnpm (v11)

## Commands

```bash
pnpm install          # install frontend deps
pnpm tauri dev        # run the desktop app (Vite + Rust, hot reload)
pnpm tauri build      # production desktop bundle
pnpm dev              # Vite dev server only (port 1420, strict)
pnpm build            # tsc type-check + vite build — run this to validate frontend changes
pnpm exec tsc --noEmit  # type-check only (safe to run concurrently; does not touch dist/)
cargo test            # run inside src-tauri/ — the Rust test suite (~180 tests)
cargo clippy --all-targets   # lint Rust code; CI treats warnings as errors
cargo fmt             # CI runs `cargo fmt --check`
```

Always run `pnpm build` after frontend changes, and `cargo test && cargo clippy --all-targets && cargo fmt` (from `src-tauri/`) after Rust changes.

## Repository layout

```
src/                    React frontend
  components/ui/        shadcn/ui components (generated — see conventions below)
  components/           shared app components (AppShell, SecretField, PasswordStrength, …)
  components/settings/  settings sections
  screens/              Onboarding, Unlock, VaultScreen, GeneratorScreen, SettingsScreen
  lib/api.ts            the ENTIRE typed backend boundary — every invoke goes through here
  lib/format.ts         presentation helpers
  App.tsx               root: bootstrap, lock routing, backend event subscriptions
  index.css             Tailwind 4 entry, shadcn theme tokens, --strength-* tokens
src-tauri/              Rust backend
  src/crypto/           kdf.rs, aead.rs, random.rs, b64.rs — ALL cryptography lives here
  src/vault/            container.rs (file format), model.rs (schema), manager.rs (lock state)
  src/sync/             mod.rs (orchestration), s3.rs (transport), merge.rs (merge rules)
  src/generator/        mod.rs + the embedded EFF wordlist
  src/bridge.rs         loopback HTTP listener for the browser extension
  src/domain.rs         host extraction and matching (credential-disclosure sensitive)
  src/transfer.rs       CSV import, encrypted backup/export
  src/commands.rs       the Tauri command surface
  src/state.rs          AppState + event names
  capabilities/         Tauri capability/permission JSON — keep minimal
  tauri.conf.json       app config (window, CSP, bundle, identifier)
extension/              Chromium MV3 extension (plain JS, no build step)
docs/                   vault-format.md, sync-protocol.md, extension-bridge.md, distribution.md, roadmap.md
```

## Conventions

### Frontend

- Import project files via the `@/` alias (maps to `src/`), e.g. `import { Button } from "@/components/ui/button"`.
- **All backend calls go through `src/lib/api.ts`.** Do not call `invoke` directly from a component. Command *argument* names are camelCase (Tauri converts them); payload *struct fields* are snake_case (plain serde).
- Use shadcn/ui components; add new ones with `pnpm dlx shadcn@latest add <component> -y` rather than hand-writing primitives. Currently installed: alert-dialog, badge, button, card, checkbox, dialog, dropdown-menu, input, label, progress, scroll-area, select, separator, slider, sonner, switch, tabs, textarea, tooltip.
- Do not manually edit files in `src/components/ui/` unless a customization is genuinely needed.
- **Tailwind 4 is CSS-first**: there is no `tailwind.config.js`. Theme tokens live in `src/index.css` under `@theme` / CSS variables. Dark mode uses the `.dark` class (`@custom-variant dark`).
- Use semantic color tokens (`bg-background`, `text-foreground`, `text-muted-foreground`, `border-border`, …), never hard-coded palette colors, so dark mode keeps working. Password strength has its own tokens: `bg-strength-weakest|weak|fair|strong|strongest` and the matching `text-strength-*`.
- TypeScript is strict with `noUnusedLocals`/`noUnusedParameters` — the build fails on violations.

### Rust / Tauri

- Frontend ↔ backend communication goes through Tauri commands (`#[tauri::command]` in `src-tauri/src/commands.rs`, registered in `invoke_handler` in `lib.rs`) and events (names in `src/state.rs`).
- Any new native capability must be declared in `src-tauri/capabilities/`. The current set is intentionally tiny (`core:event:default` plus a scoped `opener:allow-open-url`) — **do not add `core:default` back**, and prefer driving a capability from Rust over granting it to the webview.
- Never hold a `std::sync::MutexGuard` across an `await`. Sync code takes a snapshot under the lock, releases it, then does network I/O.

### pnpm quirk

pnpm 11 blocks dependency build scripts by default. Approved scripts live in `pnpm-workspace.yaml` under `allowBuilds` (currently only `esbuild`). If a new dependency needs a postinstall script, add it there — do not disable the mechanism globally.

## Security principles (non-negotiable)

This is a password manager. Treat every change as security-sensitive:

- **All encryption/decryption and key derivation happens in the Rust backend**, never in JavaScript. The frontend requests operations via commands and receives only what it must display.
- **Secrets are pull-only across the IPC boundary.** `vault_list_entries` and `vault_get_entry` return no passwords. A secret crosses into the webview only via `vault_reveal_field` for one explicitly revealed field. To copy, use `vault_copy_field`, which moves the value vault → clipboard inside Rust so it never enters JS at all. Do not add a command that returns whole entries including secrets.
- Secrets are encrypted client-side **before** leaving the device. Remote storage (R2/S3) must only ever receive ciphertext. S3 credentials themselves are secrets — they live encrypted in `sync.enc` under the vault data key, never in plaintext config.
- Derive keys from the master password with a memory-hard KDF (Argon2id). Never store or log the master password or derived keys. Zeroize key material (`zeroize`). **Never derive `Debug` on a type holding key material** — write a redacting impl (see `vault::container::UnlockedVault`).
- Use vetted crates for crypto (`chacha20poly1305`, `argon2` from RustCrypto). **Never implement crypto primitives by hand.**
- Password generation must use a cryptographically secure RNG (`crate::crypto::random`, which wraps `getrandom`), never `Math.random()`. Sample uniformly by rejection — `% n` is biased.
- Never log secrets, keys, or vault contents — not even at debug level. **There is deliberately no `From<serde_json::Error>` on `AppError`**, because serde messages embed the offending value; map payload parse failures to `AppError::Corrupt` explicitly.
- Auto-lock, clipboard clearing, and similar hygiene features default to the safe option, and are enforced in the backend rather than the webview.
- Changes to the vault container or the sync protocol must be reflected in `docs/vault-format.md` / `docs/sync-protocol.md` as part of the same change, and bump the relevant version constant.
