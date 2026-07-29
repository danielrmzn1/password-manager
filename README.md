# Password Manager

> Working title — a commercial name is TBD.

A simple, intuitive, and modern desktop password manager built with [Tauri](https://tauri.app). Your passwords and secrets are encrypted locally and stored on **your own** S3-compatible storage (Cloudflare R2 is the primary target), so your vault syncs across all your devices without ever trusting a third-party server with plaintext data.

## Features

> The project is in early scaffolding stage. The features below describe the product goals — see [docs/roadmap.md](docs/roadmap.md) for the milestone-by-milestone tracking.

1. **Secure, encrypted vault** — passwords and secrets are encrypted client-side (the master key never leaves your device) and persisted to any S3-compatible object storage: Cloudflare R2, AWS S3, MinIO, Backblaze B2, etc. This makes multi-device sync possible while keeping you in control of your data.
2. **Powerful password generator** — highly configurable: length, uppercase/lowercase, digits, special characters (with a custom character allowlist), passphrases (word-based), and more.
3. **Browser extension (Chromium-based)** — optional companion extension that detects sign-in forms and, based on the current domain, offers to autofill matching credentials from your vault.
4. **Master password** — set up on first launch. Unlocking the app is required to view or edit any password or secret.

## Tech stack

| Layer | Technology |
|---|---|
| Desktop shell | Tauri 2 (Rust) |
| Frontend | React 19 + TypeScript 5.8 + Vite 7 |
| Styling | Tailwind CSS 4 + shadcn/ui (Radix, Nova preset, Geist font, Lucide icons) |
| Package manager | pnpm |

## Getting started

### Prerequisites

- [Node.js](https://nodejs.org) ≥ 20 and [pnpm](https://pnpm.io)
- [Rust](https://rustup.rs) (stable toolchain)
- Tauri OS-level dependencies — see the [Tauri prerequisites guide](https://tauri.app/start/prerequisites/) (on Linux: `webkit2gtk`, `libayatana-appindicator`, etc.)

### Develop

```bash
pnpm install
pnpm tauri dev     # run the desktop app with hot reload
```

### Build

```bash
pnpm tauri build   # produce a distributable desktop bundle
```

Other useful commands:

```bash
pnpm dev           # frontend only (Vite dev server on port 1420)
pnpm build         # type-check (tsc) + production frontend build
cargo check        # from src-tauri/: compile-check the Rust backend
```

## Project structure

```
├── src/                  # React frontend
│   ├── components/ui/    # shadcn/ui components
│   ├── lib/              # shared utilities (cn, ...)
│   ├── App.tsx
│   ├── main.tsx
│   └── index.css         # Tailwind 4 entry + shadcn theme tokens
├── src-tauri/            # Rust backend (Tauri 2)
│   ├── src/              # commands, state, crypto, storage
│   ├── capabilities/     # Tauri permission capabilities
│   └── tauri.conf.json   # app configuration
├── AGENTS.md             # instructions for AI coding agents
└── README.md
```

## Security model (planned)

- The vault is encrypted **client-side** before it is uploaded anywhere. The S3 bucket only ever sees ciphertext.
- The encryption key is derived from the master password with a modern KDF (e.g. Argon2id); the master password and derived keys are never persisted or transmitted.
- The Rust backend owns all cryptography and secret handling; the React frontend never holds long-lived plaintext secrets.

## License

TBD.
