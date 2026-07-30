# Building, signing and distributing

Status: **partially implemented.** Cross-platform builds run in CI
([`.github/workflows/build.yml`](../.github/workflows/build.yml)). Code signing
and auto-updates need secrets that only the project owner can generate — the
exact steps are below, but they are deliberately **not** wired up, because
committing a placeholder signing key or update endpoint produces a build that
looks signed and is not.

## Local builds

```bash
pnpm install
pnpm tauri build          # bundle for the current platform
```

Artifacts land in `src-tauri/target/release/bundle/`.

| Platform | Produces |
|---|---|
| Linux | `.deb`, `.rpm`, `.AppImage` |
| Windows | `.msi` (WiX), `.exe` (NSIS) |
| macOS | `.app`, `.dmg` |

Tauri does not cross-compile: each target needs a runner of that OS, which is
why the CI workflow uses a matrix.

## App icon

`src-tauri/icons/` is generated from `src-tauri/icons/icon-source.png`:

```bash
pnpm tauri icon src-tauri/icons/icon-source.png
```

The current mark is a **placeholder** — a neutral keyhole glyph. Final branding
is blocked on the commercial name, which is still to be decided (see
[roadmap.md](roadmap.md)). Replace `icon-source.png` with a 1024×1024 PNG and
re-run the command above; also update `public/icon.png`, which is the favicon
used inside the webview.

## Code signing

Unsigned builds are not merely untidy: on macOS, Gatekeeper refuses to launch
them without an explicit override, and on Windows, SmartScreen warns users away.
For a password manager, that warning is exactly the wrong first impression.

### Windows

Requires an Authenticode certificate (OV or, for immediate SmartScreen
reputation, EV — an EV certificate normally lives on a hardware token or a cloud
HSM). Then in `tauri.conf.json`:

```jsonc
"bundle": {
  "windows": {
    "certificateThumbprint": "<SHA-1 thumbprint of the cert in the cert store>",
    "digestAlgorithm": "sha256",
    "timestampUrl": "http://timestamp.digicert.com"
  }
}
```

In CI, import the `.pfx` from a secret before building. A timestamp URL matters:
without it, signatures stop validating when the certificate expires.

### macOS

Requires a paid Apple Developer account, a "Developer ID Application"
certificate, and **notarization** (stapling alone is not enough for Gatekeeper on
a downloaded `.dmg`).

```bash
export APPLE_CERTIFICATE="<base64 of the .p12>"
export APPLE_CERTIFICATE_PASSWORD="…"
export APPLE_SIGNING_IDENTITY="Developer ID Application: Name (TEAMID)"
export APPLE_ID="…"
export APPLE_PASSWORD="<app-specific password>"
export APPLE_TEAM_ID="…"
pnpm tauri build
```

Tauri notarizes automatically when `APPLE_ID`, `APPLE_PASSWORD` and
`APPLE_TEAM_ID` are all present.

Because this app derives keys with Argon2id and holds them in memory, also
consider setting the hardened-runtime entitlement
`com.apple.security.cs.disable-executable-page-protection` **off** (it is off by
default — do not enable it) and leaving `get-task-allow` unset in release
builds, so another process cannot attach a debugger and read the vault key out of
memory.

### Linux

`.deb` and `.rpm` are conventionally signed by the repository rather than the
package. AppImages can be signed with `gpg`; Tauri supports this via
`bundle.linux.appimage.files` plus a detached signature published alongside the
artifact.

## Auto-updates

`tauri-plugin-updater` is **not currently enabled.** Enabling it is a small
change, but it requires a keypair whose private half must never enter the repo.

1. Generate a signing keypair:

   ```bash
   pnpm tauri signer generate -w ~/.tauri/password-manager.key
   ```

   Keep the private key and its password out of the repository. In CI they
   become `TAURI_SIGNING_PRIVATE_KEY` and
   `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`.

2. Add the dependency and register the plugin:

   ```toml
   # src-tauri/Cargo.toml
   tauri-plugin-updater = "2"
   ```
   ```rust
   // src-tauri/src/lib.rs, inside the builder chain
   .plugin(tauri_plugin_updater::Builder::new().build())
   ```

3. Configure it, pasting the **public** key from step 1:

   ```jsonc
   // tauri.conf.json
   "plugins": {
     "updater": {
       "endpoints": ["https://<your-host>/password-manager/{{target}}-{{arch}}/{{current_version}}"],
       "pubkey": "<public key from step 1>"
     }
   }
   ```

4. Add `updater` to the bundle targets so CI emits the `.sig` files the plugin
   checks, and publish a `latest.json` manifest at the endpoint.

Two things to get right:

- **The update endpoint must be HTTPS.** The signature check is the real defence,
  but plaintext HTTP leaks which version each user runs.
- **Never ship a build whose `pubkey` does not match the key used to sign the
  update artifacts.** The plugin will reject every update, and users will sit on a
  stale version silently.

Because an auto-updater is a remote-code-execution channel by design, it is
worth gating updates behind an explicit user confirmation for this app rather
than installing silently.

## Reproducibility notes

- `Cargo.lock` and `pnpm-lock.yaml` are committed; CI installs with
  `--frozen-lockfile`.
- The release profile sets `lto = true`, `codegen-units = 1`, `opt-level = "s"`
  and `strip = true` (see `src-tauri/Cargo.toml`), which keeps binaries small and
  removes symbol names that would make the crypto paths easier to locate.
