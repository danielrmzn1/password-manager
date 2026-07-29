# Password Manager

> Working title — a commercial name is TBD.

A simple, intuitive, and modern desktop password manager built with [Tauri](https://tauri.app). Your passwords and secrets are encrypted locally and stored on **your own** S3-compatible storage (Cloudflare R2 is the primary target), so your vault syncs across all your devices without ever trusting a third-party server with plaintext data.

## Features

Milestones 1–5 are implemented; see [docs/roadmap.md](docs/roadmap.md) for exactly what is done, what is still open, and the **known gaps** worth reading before trusting this with real secrets.

1. **Secure, encrypted vault** — Argon2id key derivation and XChaCha20-Poly1305 authenticated encryption, all in Rust. The vault file is useless without your master password, and the plaintext header is authenticated so its KDF cost cannot be downgraded.
2. **Bring-your-own storage sync** — replicate an encrypted blob to Cloudflare R2, AWS S3, MinIO, Backblaze B2 or anything else speaking S3. Conditional writes prevent two devices from silently overwriting each other, and merging is per entry, so concurrent edits to different entries both survive.
3. **Powerful password generator** — length, character classes, a **user-selectable set of special characters**, exclude-ambiguous, plus diceware passphrases from the real EFF 7776-word list. CSPRNG only, sampled without modulo bias.
4. **Browser extension (Chromium, MV3)** — optional, off by default. Detects sign-in forms, suggests credentials matched on whole DNS labels, and fills only on an explicit click. Never fills while the vault is locked.
5. **Master password + auto-lock** — required to view or edit anything. Auto-lock is enforced in the Rust backend and survives system suspend.

## Security model

- The vault is encrypted **client-side** before it is uploaded anywhere. The S3 bucket only ever sees ciphertext.
- Two-level keys: Argon2id derives a master key from your password, which wraps a random data key. Changing your master password re-wraps that key instead of re-encrypting the vault, and the master key is discarded immediately after unlock — an unlocked session holds only the data key.
- **Secrets are pull-only across the IPC boundary.** The entry list and detail views receive no passwords at all. A secret reaches the UI only when you reveal that one field, and copy-to-clipboard moves the value vault → clipboard entirely inside Rust so it never enters the webview.
- The webview is granted a deliberately tiny capability set — no clipboard permission, no filesystem permission, no dialog permission — because those operations are driven from Rust. See [`src-tauri/capabilities/default.json`](src-tauri/capabilities/default.json).
- There is **no plaintext export** and no password recovery. If the master password is lost, the vault cannot be decrypted by anyone.

Format and protocol decisions are written down, not implied:

| Document | Covers |
|---|---|
| [docs/vault-format.md](docs/vault-format.md) | The `.pmv` container, key hierarchy, entry schema, on-disk layout |
| [docs/sync-protocol.md](docs/sync-protocol.md) | Change detection, conditional writes, the merge algorithm, threat notes |
| [docs/extension-bridge.md](docs/extension-bridge.md) | Why loopback HTTP over native messaging, pairing, the wire protocol |
| [docs/distribution.md](docs/distribution.md) | Builds, code signing, auto-update setup |

## Tech stack

| Layer | Technology |
|---|---|
| Desktop shell | Tauri 2 (Rust) |
| Cryptography | RustCrypto — `argon2`, `chacha20poly1305`, `zeroize`, `getrandom` |
| Sync | `aws-sdk-s3` with custom endpoint support |
| Extension bridge | `axum` on 127.0.0.1 |
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

On first launch you either create a new vault or connect this device to an existing one in your bucket.

### Build

```bash
pnpm tauri build   # produce a distributable desktop bundle
```

Other useful commands:

```bash
pnpm dev           # frontend only (Vite dev server on port 1420)
pnpm build         # type-check (tsc) + production frontend build
cargo test         # from src-tauri/: run the Rust test suite
cargo clippy       # from src-tauri/: lint the Rust backend
```

### Browser extension

The extension is not packaged; load it unpacked:

1. Enable the bridge in the desktop app under **Settings → Browser extension**.
2. Open `chrome://extensions`, turn on Developer mode, choose **Load unpacked**, and select [`extension/`](extension).
3. Click the extension, then pair it with the 6-digit code the desktop app shows.

## Project structure

```
├── src/                    # React frontend
│   ├── components/         # shared components + ui/ (shadcn)
│   ├── screens/            # Onboarding, Unlock, Vault, Generator, Settings
│   ├── lib/api.ts          # the entire typed backend boundary
│   └── index.css           # Tailwind 4 entry + theme tokens
├── src-tauri/              # Rust backend
│   ├── src/crypto/         # Argon2id, XChaCha20-Poly1305, CSPRNG — all crypto lives here
│   ├── src/vault/          # container format, data model, lock state machine
│   ├── src/sync/           # S3 client + merge algorithm
│   ├── src/generator/      # password/passphrase generation + EFF wordlist
│   ├── src/bridge.rs       # loopback listener for the extension
│   ├── src/commands.rs     # the Tauri command surface
│   └── capabilities/       # Tauri permissions (deliberately minimal)
├── extension/              # Chromium MV3 extension
├── docs/                   # format, protocol and distribution decisions
├── AGENTS.md               # instructions for AI coding agents
└── README.md
```

## License

TBD.
