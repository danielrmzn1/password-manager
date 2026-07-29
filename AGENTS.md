# AGENTS.md

Instructions for AI coding agents working on this repository.

## What this project is

A desktop password manager built with **Tauri 2**. Design goals: simple, intuitive, modern. Core features (in rough priority order):

1. **Encrypted vault synced to S3-compatible storage** — passwords/secrets are encrypted client-side and stored in a user-owned bucket (primary target: Cloudflare R2; must work with any S3-compatible API). This enables multi-device use.
2. **Password generator** — strong, flexible, highly configurable: length, upper/lowercase, digits, special characters (user can choose *which* ones), passphrase (word-based) mode, etc.
3. **Chromium browser extension (optional, user-enabled)** — detects sign-in forms and suggests autofilling credentials matched by domain.
4. **Master password** — set during initial setup; required to unlock the app before viewing/editing any secret.

## Tech stack

- **Desktop shell:** Tauri 2 (Rust 2021 edition) in `src-tauri/`
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
cargo check           # run inside src-tauri/ — validate Rust changes quickly
cargo clippy          # lint Rust code
```

Always run `pnpm build` after frontend changes and `cargo check` (from `src-tauri/`) after Rust changes.

## Repository layout

```
src/                    React frontend
  components/ui/        shadcn/ui components (generated — see conventions below)
  lib/utils.ts          cn() class-merge helper
  App.tsx               root component
  main.tsx              entry point
  index.css             Tailwind 4 entry, shadcn theme tokens (oklch CSS variables)
src-tauri/              Rust backend
  src/main.rs           binary entry (delegates to lib.rs)
  src/lib.rs            tauri::Builder setup, command registration
  capabilities/         Tauri capability/permission JSON files
  tauri.conf.json       app config (window, bundle, identifier: com.danielrmzn1.password-manager)
```

## Conventions

### Frontend

- Import project files via the `@/` alias (maps to `src/`), e.g. `import { Button } from "@/components/ui/button"`.
- Use shadcn/ui components; add new ones with `pnpm dlx shadcn@latest add <component> -y` rather than hand-writing primitives. Currently installed: button, input, label, card, dialog, dropdown-menu, select, checkbox, switch, slider, tabs, separator, badge, tooltip, sonner, scroll-area.
- Do not manually edit files in `src/components/ui/` unless a customization is genuinely needed.
- **Tailwind 4 is CSS-first**: there is no `tailwind.config.js`. Theme tokens live in `src/index.css` under `@theme` / CSS variables. Dark mode uses the `.dark` class (`@custom-variant dark`).
- Use semantic color tokens (`bg-background`, `text-foreground`, `text-muted-foreground`, `border-border`, …), never hard-coded palette colors, so dark mode keeps working.
- TypeScript is strict with `noUnusedLocals`/`noUnusedParameters` — the build fails on violations.

### Rust / Tauri

- Frontend ↔ backend communication goes through Tauri commands (`#[tauri::command]` in `src-tauri/src/lib.rs`, registered in `invoke_handler`) and, when needed, events.
- Any new native capability must be declared in `src-tauri/capabilities/` — keep permissions minimal.
- `tauri.conf.json` currently has `"csp": null`; when tightening security, prefer configuring a real CSP over disabling it.

### pnpm quirk

pnpm 11 blocks dependency build scripts by default. Approved scripts live in `pnpm-workspace.yaml` under `allowBuilds` (currently only `esbuild`). If a new dependency needs a postinstall script, add it there — do not disable the mechanism globally.

## Security principles (non-negotiable)

This is a password manager. Treat every change as security-sensitive:

- **All encryption/decryption and key derivation happens in the Rust backend**, never in JavaScript. The frontend requests operations via commands and receives only what it must display.
- Secrets are encrypted client-side **before** leaving the device. Remote storage (R2/S3) must only ever receive ciphertext. S3 credentials themselves are secrets — store them encrypted (or in the OS keychain), never in plaintext config.
- Derive keys from the master password with a memory-hard KDF (Argon2id). Never store or log the master password or derived keys. Zeroize key material in memory when possible (`zeroize` crate).
- Use vetted crates for crypto (e.g. `aes-gcm` or `chacha20poly1305` from RustCrypto, `argon2`). **Never implement crypto primitives by hand.**
- Password generation must use a cryptographically secure RNG (`rand::rngs::OsRng` / `getrandom`), never `Math.random()`.
- Never log secrets, keys, or vault contents — not even at debug level. Be careful with error messages that could embed secret material.
- Auto-lock behavior, clipboard clearing timeouts, and similar hygiene features should default to the safe option.

## Roadmap context (not yet implemented)

The authoritative feature tracker is **`docs/roadmap.md`** — consult it before starting feature work and check items off (or add newly discovered scope) as part of any change that affects it.

Planned modules that do not exist yet — keep them in mind when structuring code:

- `src-tauri` — vault format & crypto layer, S3/R2 storage client (likely `aws-sdk-s3` or `rust-s3` with custom endpoint support), password/passphrase generator, app-lock state machine.
- `src` — onboarding/setup flow (master password + storage config), unlock screen, vault list/detail/edit views, generator UI, settings.
- `extension/` (future) — Chromium MV3 extension talking to the desktop app (likely via native messaging or a localhost bridge) for sign-in form detection and autofill.

When implementing a feature that touches the vault format or the sync protocol, document the format/protocol decision in the repo (e.g. `docs/`) as part of the change.
