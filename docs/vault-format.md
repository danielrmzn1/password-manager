# Vault format (`.pmv`, format version 1)

Status: **implemented**. This is the authoritative description of the on-disk /
on-remote vault container. Any change to the container requires bumping
`format_version` and adding a migration path.

Related: [sync-protocol.md](sync-protocol.md) describes how this file is
replicated between devices. The same bytes are used locally and remotely — the
S3 object *is* a `.pmv` file.

## Goals

1. The file is useless without the master password. Everything except the
   parameters needed to *derive* a key is encrypted.
2. Tampering with the unencrypted parameters (e.g. lowering the KDF cost, or
   swapping in another device's wrapped key) must cause decryption to fail
   rather than silently weaken security.
3. Changing the master password must not require rewriting/re-encrypting every
   entry, and must not change the key that ciphertext is bound to.
4. Old clients must fail loudly on newer formats; newer clients must not
   silently discard fields written by other versions.

## Container layout

A `.pmv` file is a binary envelope with a plaintext (but *authenticated*) JSON
header followed by a single AEAD-sealed payload.

```
offset          size          field
------          ----          -----
0               8             magic            = "PMVAULT1" (ASCII)
8               1             format_version   = 0x01
9               4             header_len       = u32, big-endian
13              header_len    header           = UTF-8 JSON (see below)
13+header_len   remainder     payload          = AEAD ciphertext || 16-byte tag
```

`magic || format_version || header_len || header` — that is, **the entire byte
prefix of the file before the ciphertext** — is used verbatim as the AEAD
associated data (AAD) for the payload. Because the AAD is the raw bytes read
from the file, there is no JSON canonicalization step and therefore no
canonicalization mismatch to exploit. Flipping a single bit anywhere in the
header (KDF cost, salt, revision, device id) makes payload decryption fail.

### Header JSON

```jsonc
{
  "vault_id": "0f1e…",          // uuid v4, stable for the life of the vault
  "kdf": {
    "algorithm": "argon2id",
    "version": 19,               // 0x13
    "m_cost_kib": 65536,         // 64 MiB
    "t_cost": 3,
    "p_cost": 4,
    "salt": "<base64, 16 bytes>"
  },
  "wrapped_dek": {
    "cipher": "xchacha20poly1305",
    "nonce": "<base64, 24 bytes>",
    "ciphertext": "<base64, 48 bytes>"   // 32-byte DEK + 16-byte tag
  },
  "payload": {
    "cipher": "xchacha20poly1305",
    "nonce": "<base64, 24 bytes>"
  },
  "revision": 42,                // monotonic; incremented on every save
  "updated_at": 1753800000000,   // unix epoch milliseconds
  "device_id": "9a2c…"           // uuid of the device that wrote this revision
}
```

The header deliberately contains **no** secret material: the salt, the nonces
and the wrapped key are all safe to expose. It contains no password hash
either, so the file cannot be fed to an offline verifier any faster than
attempting a real decryption.

## Key hierarchy

Two levels, so that a master-password change is O(1) instead of O(vault):

```
master password ──Argon2id(salt, m=64MiB, t=3, p=4)──> MK (32 bytes)
                                                        │
                    wrapped_dek = XChaCha20-Poly1305(MK)┤
                                                        ▼
                                                       DEK (32 bytes, random)
                                                        │
                             payload = XChaCha20-Poly1305(DEK)
```

- **MK** (master key) — Argon2id output, 32 bytes. Never persisted. Held in
  memory only while the vault is unlocked, in a `Zeroizing` buffer.
- **DEK** (data encryption key) — 32 random bytes from the OS CSPRNG, generated
  once at vault creation and *never* changed. All payload ciphertext is bound
  to it.

**DEK wrapping.** `wrapped_dek.ciphertext = XChaCha20Poly1305(key = MK,
nonce = wrapped_dek.nonce, plaintext = DEK, aad = kdf_aad)` where `kdf_aad` is
a deterministic, non-JSON byte string:

```
"pmv1:kdf:" || algorithm || ":" || m_cost_kib || ":" || t_cost || ":" || p_cost || ":" || salt_bytes
```

Binding the wrap to the KDF parameters is what stops a "cost downgrade" attack:
an attacker who rewrites `m_cost_kib` to `8` to make cracking cheap changes the
AAD, so unwrapping fails outright instead of yielding a weakly-protected key.

**Payload sealing.** `payload = XChaCha20Poly1305(key = DEK, nonce =
payload.nonce, plaintext = serde_json(VaultPayload), aad = file_prefix_bytes)`.

A fresh 24-byte random nonce is drawn on *every* save, for both the wrap and
the payload. XChaCha20's 192-bit nonce makes random nonce selection safe
(collision probability is negligible), which matters here because two devices
can encrypt concurrently without coordinating a counter.

**Changing the master password** re-derives MK with a *fresh salt* and rewrites
only `kdf` + `wrapped_dek`. The DEK, and therefore the payload, is untouched.

**Unlock** is: derive MK → unwrap DEK → decrypt payload. A wrong password fails
at the unwrap step with an AEAD tag mismatch; there is no separate password
verifier to attack, and the failure is indistinguishable from a corrupt file by
design (the UI distinguishes them only by whether the header parsed).

## Algorithm choices

| Role | Choice | Why |
|---|---|---|
| KDF | Argon2id, m=64 MiB, t=3, p=4, 32-byte output | Memory-hard, side-channel-resistant hybrid mode. Exceeds the OWASP floor (19 MiB / t=2). Parameters live in the header so they can be raised later without breaking old vaults. |
| AEAD | XChaCha20-Poly1305 | 192-bit nonce ⇒ random nonces are safe with no counter state to sync across devices. Constant-time in software on every target, unlike AES without AES-NI. |
| CSPRNG | `getrandom` (OS entropy) | No userspace PRNG state to seed, fork, or leak. |
| Encoding | JSON | Debuggable header; the payload is JSON too, which keeps schema evolution cheap. |

AES-256-GCM was the alternative. It was rejected because its 96-bit nonce makes
random-nonce reuse a real risk over a vault's lifetime across multiple devices,
and because performance on non-AES-NI hardware is both worse and not
guaranteed constant-time.

## Payload schema

The decrypted payload is JSON:

```jsonc
{
  "schema": 1,
  "entries": [ /* VaultEntry */ ],
  "tombstones": [ { "id": "uuid", "deleted_at": 1753800000000 } ],
  "generator_presets": [ /* GeneratorPreset */ ]
}
```

### `VaultEntry`

```jsonc
{
  "id": "uuid v4",
  "kind": "login" | "note",
  "title": "GitHub",
  "username": "daniel",
  "password": "…",
  "urls": ["https://github.com/login"],
  "notes": "free-form text",
  "custom_fields": [
    { "id": "uuid", "label": "Recovery code", "value": "…", "secret": true }
  ],
  "tags": ["dev"],
  "favorite": false,
  "created_at": 1753800000000,
  "updated_at": 1753800000000,
  "password_updated_at": 1753800000000
}
```

- `kind` distinguishes a credential (`login`) from a free-form secret (`note`).
  Both use the same struct; a note simply leaves the credential fields empty.
- `custom_fields[].secret` drives reveal-on-click in the UI; it does **not**
  change how the value is stored (everything in the payload is equally
  encrypted).
- `password_updated_at` is tracked separately from `updated_at` so a future
  password-health report can flag stale passwords without a schema change.
- Timestamps are unix epoch **milliseconds** (i64), UTC. No timezone or
  serialization-format ambiguity, and they sort correctly as integers.

### Tombstones

Deleting an entry appends `{id, deleted_at}` to `tombstones` and removes it
from `entries`. Without this, a delete on device A would be silently resurrected
by device B on the next merge. Tombstones are retained for **180 days** and then
garbage-collected; a device offline for longer than that may resurrect an entry,
which is the standard trade-off and is documented in the sync protocol.

### Forward compatibility

`VaultEntry` carries a `#[serde(flatten)]` catch-all map. Fields written by a
newer client that this client does not understand are preserved verbatim and
written back on save, so an older client cannot silently strip data from a
vault shared with a newer one. A payload with `schema` greater than the
supported version is rejected outright rather than opened lossily.

## Files on disk

All paths are relative to the Tauri app data directory
(`~/.local/share/com.danielrmzn1.password-manager` on Linux,
`%APPDATA%\com.danielrmzn1.password-manager` on Windows,
`~/Library/Application Support/com.danielrmzn1.password-manager` on macOS).

| File | Contents | Protection |
|---|---|---|
| `vault.pmv` | The vault container described above | Encrypted (master password) |
| `sync.enc` | S3 endpoint, bucket, prefix, access key id, secret access key | Encrypted with the vault **DEK** — see below |
| `settings.json` | Lock timeout, clipboard timeout, theme, sync toggles | Plaintext, non-secret device preferences only |
| `device.json` | This device's `device_id` | Plaintext, non-secret |

Writes are **atomic**: the new content is written to a `.tmp` sibling, `fsync`ed,
then `rename`d over the target. A crash mid-save therefore leaves either the
previous vault or the new one, never a truncated file. A `.bak` copy of the
previous revision is kept alongside `vault.pmv`.

### Why S3 credentials live in a separate local file

They are stored in `sync.enc`, encrypted with the vault's DEK using the same
AEAD construction, rather than inside the synced payload. Two reasons:

1. **No chicken-and-egg.** Credentials inside the synced vault would be needed
   in order to download the vault that contains them. A new device could never
   bootstrap.
2. **Per-device credentials.** Each device can hold its own scoped S3 token, so
   losing one device means revoking one token instead of rotating the vault's
   only credential.

The OS keychain (`keyring`) was considered as the store instead. It was rejected
as the *primary* mechanism because it is unavailable or non-functional on
headless and many Linux/WSL setups, which would make sync silently
unconfigurable there. Keychain support remains a reasonable future addition
layered on top of this file.
