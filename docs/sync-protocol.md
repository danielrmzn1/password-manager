# Sync protocol (S3-compatible, Cloudflare R2 primary)

Status: **implemented**. Companion to [vault-format.md](vault-format.md), which
defines the bytes being replicated.

## Model

One object in a user-owned bucket holds the whole vault:

```
s3://<bucket>/<prefix>/vault.pmv
```

That object is byte-identical to the local `vault.pmv` — a `.pmv` container as
specified in [vault-format.md](vault-format.md). **The bucket only ever receives
ciphertext.** Neither the storage provider nor anyone with read access to the
bucket can learn anything beyond the vault's size, its revision counter, and how
often it changes (the header is plaintext but authenticated; it contains no
secret material).

There is no server component. Sync is a client-side read-merge-write against
plain object storage, which is what makes "bring your own bucket" possible.

## Configuration

| Field | Example | Notes |
|---|---|---|
| `endpoint` | `https://<account>.r2.cloudflarestorage.com` | Custom endpoints are required, not optional — this is what makes R2/MinIO/B2 work. |
| `region` | `auto` | R2 requires the literal `auto`. AWS S3 needs a real region. |
| `bucket` | `my-vault` | |
| `prefix` | `` or `devices/laptop` | Optional key prefix. |
| `access_key_id` / `secret_access_key` | | **Secret.** |
| `force_path_style` | `true` for MinIO | R2 and S3 work either way. |

Credentials are stored in `sync.enc`, encrypted with the vault's DEK
(XChaCha20-Poly1305, AAD = `"pmv1:sync:" || vault_id`). They are therefore
readable only while the vault is unlocked, and the file cannot be transplanted to
a different vault. See [vault-format.md](vault-format.md#why-s3-credentials-live-in-a-separate-local-file)
for why they are not stored inside the synced payload.

The same file also carries non-secret sync bookkeeping (`last_etag`,
`last_pushed_revision`, `last_synced_at`); it is kept in the encrypted file
purely so there is one file to manage rather than two.

## Change detection

The object's **ETag** is the version token. It is opaque — no assumption is made
that it is an MD5 of the content, because R2 and multipart uploads break that
assumption.

After every successful push or pull the client records the ETag it observed.
A sync then proceeds as:

1. `HEAD` the object.
   - **404** → the remote has no vault yet. Push with `If-None-Match: *`.
   - **ETag == `last_etag`** → nobody else has written since our last sync. If
     `local_revision > last_pushed_revision`, push with `If-Match: <etag>`;
     otherwise there is nothing to do.
   - **ETag != `last_etag`** → the remote moved. Go to step 2.
2. `GET` the object, decrypt it with the local master key, and **merge**
   (below).
3. `PUT` the merged container with `If-Match: <etag observed in step 1>`.

## Concurrency: conditional writes

Every upload is conditional, which is what prevents the classic
lost-update on shared object storage — two devices both `GET`, both merge, both
`PUT`, and the slower write silently discards the faster one's changes.

- Creating the object for the first time uses `If-None-Match: *`.
- Replacing a known version uses `If-Match: <etag>`.

A `412 Precondition Failed` means another device wrote in between. The client
re-runs the whole sequence from step 1, up to **3 attempts**, then reports
`sync_conflict` and leaves local data untouched. Because merging is
deterministic and commutative over the inputs, a retry converges.

> **Compatibility note.** Conditional writes are supported by Cloudflare R2, AWS
> S3 and MinIO. If a service rejects the precondition header as unimplemented
> (`501`, or `NotImplemented`), the client falls back to an unconditional `PUT`
> and surfaces a warning, because a working-but-racy sync is more useful than no
> sync. On such a service, two devices writing in the same instant can lose the
> slower write's changes.

## Merge algorithm

Whole-file last-write-wins was rejected: two devices each adding a different
entry offline would lose one of them entirely. Merging is **per entry**, so
concurrent edits to *different* entries always both survive.

Given local payload `L` and remote payload `R`:

1. **Tombstones.** Union by entry id, keeping the greater `deleted_at`.
2. **Entries.** For each id present in either side:
   - If it exists on both, keep the copy with the greater `updated_at`.
     An exact tie keeps the **local** copy, so the operation is deterministic.
   - Let `t` be that id's tombstone, if any.
     - `t.deleted_at >= winner.updated_at` → the entry stays deleted.
     - `t.deleted_at <  winner.updated_at` → the entry was edited *after* being
       deleted elsewhere, so the edit wins and the entry is resurrected.
3. **Generator presets.** Union by id; local wins a conflict.
4. **Unknown (`extra`) fields.** Union by key; local wins a conflict. This is how
   data written by a newer client survives a round trip through an older one.
5. Tombstones older than 180 days are dropped.
6. The merged result is written as revision `max(L.revision, R.revision) + 1`.

### Consequences worth knowing

- **Field-level edits do not merge.** Two devices editing *the same* entry
  concurrently keep one version wholesale; the other is lost. Field-level
  merging would need per-field timestamps, which is a format change and is not
  worth the size cost for the collision rate involved.
- **Clock skew matters.** "Newer" means a larger `updated_at`, taken from each
  device's wall clock. A device whose clock is badly wrong can have its edits
  systematically win or lose. Revision counters cannot substitute here: they are
  per-vault-lineage, not per-entry, so they say nothing about which of two
  concurrent entry edits happened later.
- **A device offline longer than the tombstone retention (180 days) can
  resurrect deleted entries.** This is the standard trade-off for bounded
  tombstone growth.

## Vault identity

The remote header's `vault_id` must equal the local one. A mismatch aborts with
`sync_vault_mismatch` and changes nothing, which is what stops a mistyped bucket
or prefix from merging two unrelated vaults into each other or overwriting one
with the other.

Connecting a *new* device to an existing remote vault is the explicit
"connect to existing" flow: the remote container is downloaded, unlocked with the
master password, and **adopted** wholesale (its `vault_id`, KDF parameters and
wrapped DEK become the local ones). No merge happens, because there is nothing
local to merge.

## When sync runs

- **Manual** — the user presses Sync.
- **On unlock** — pull remote changes (default on).
- **On save** — push after any change (default on).

All three are best-effort. Sync failure never blocks a local operation.

## Offline behaviour

The local `vault.pmv` is the source of truth for the running app; sync is a
replication step layered on top. With no connectivity:

- The app opens, unlocks, reads and writes normally.
- Pushes and pulls fail and are reported in the UI as a sync status, not as an
  error dialog that interrupts work.
- `last_pushed_revision` stays behind `revision`, so the next successful sync
  pushes the accumulated local changes.

Nothing queues or retries in the background: the next sync recomputes what is
needed from the revision counters and the ETag, so there is no queue to
corrupt or replay.

## Threat notes

- **The bucket holder learns metadata**, not contents: object size, ETag,
  modification times, revision counter and `device_id` values from the plaintext
  header. If that metadata matters, it argues for a bucket only you can read.
- **Rollback.** A bucket-write-capable attacker can serve an *older* genuine
  revision. The client detects this only in that the revision counter goes
  backwards; it does not currently refuse such a merge. Because the merge is
  union-based, the practical effect is that entries deleted after that revision
  could reappear — not that current entries are lost. Hardening this properly
  needs a signed revision chain and is future work.
- **Credentials are per-device by design.** Each device holds its own S3 token in
  its own `sync.enc`, so a lost device is remediated by revoking one token rather
  than rotating one shared credential.
