//! Multi-device sync against user-owned S3-compatible storage.
//!
//! The protocol is specified in `docs/sync-protocol.md`. This module owns the
//! configuration (including its encrypted persistence) and the read-merge-write
//! orchestration; [`merge`] owns the merge rules and [`s3`] owns the transport.

pub mod merge;
pub mod s3;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto::aead::{self, SealedBlob};
use crate::crypto::kdf::Key32;
use crate::error::{AppError, Result};
use crate::state::AppState;
use crate::storage::{self, Paths};
use crate::vault::container;
use crate::vault::model::now_ms;

use self::merge::MergeOutcome;
use self::s3::{RemoteError, S3Store};

/// Object name inside the configured prefix.
pub const OBJECT_NAME: &str = "vault.pmv";

/// How many times a conditional write is retried after losing a race.
const MAX_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    #[serde(default)]
    pub prefix: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    #[serde(default)]
    pub force_path_style: bool,
}

impl Drop for SyncConfig {
    fn drop(&mut self) {
        self.secret_access_key.zeroize();
    }
}

impl SyncConfig {
    pub fn object_key(&self) -> String {
        let prefix = self.prefix.trim().trim_matches('/');
        if prefix.is_empty() {
            OBJECT_NAME.to_string()
        } else {
            format!("{prefix}/{OBJECT_NAME}")
        }
    }

    pub fn validate(&self) -> Result<()> {
        let endpoint = self.endpoint.trim();
        let rest = if let Some(rest) = endpoint.strip_prefix("https://") {
            rest
        } else if let Some(rest) = endpoint.strip_prefix("http://") {
            let host = rest.split(['/', ':']).next().unwrap_or("");
            // Plaintext HTTP would expose the request signature and the
            // ciphertext to anyone on the path. Allowed only for a local
            // MinIO-style dev server, where there is no network to sniff.
            if !matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1") {
                return Err(AppError::InvalidOptions(
                    "the endpoint must use https:// (http:// is only allowed for localhost)".into(),
                ));
            }
            rest
        } else {
            return Err(AppError::InvalidOptions(
                "the endpoint must start with https://".into(),
            ));
        };

        if rest.split('/').next().unwrap_or("").is_empty() {
            return Err(AppError::InvalidOptions(
                "the endpoint is missing a hostname".into(),
            ));
        }
        if self.bucket.trim().is_empty() {
            return Err(AppError::InvalidOptions("a bucket name is required".into()));
        }
        if self.access_key_id.trim().is_empty() || self.secret_access_key.is_empty() {
            return Err(AppError::InvalidOptions(
                "an access key id and secret access key are required".into(),
            ));
        }
        if self.prefix.contains("..") {
            return Err(AppError::InvalidOptions(
                "the prefix must not contain '..'".into(),
            ));
        }
        Ok(())
    }

    /// The shape sent to the UI: everything except the secret key, which is
    /// reported only as "set" or "not set".
    pub fn redacted(&self) -> SyncConfigView {
        SyncConfigView {
            endpoint: self.endpoint.clone(),
            region: self.region.clone(),
            bucket: self.bucket.clone(),
            prefix: self.prefix.clone(),
            access_key_id: self.access_key_id.clone(),
            has_secret_access_key: !self.secret_access_key.is_empty(),
            force_path_style: self.force_path_style,
            object_key: self.object_key(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncConfigView {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub prefix: String,
    pub access_key_id: String,
    pub has_secret_access_key: bool,
    pub force_path_style: bool,
    pub object_key: String,
}

/// Non-secret bookkeeping, stored alongside the credentials purely so there is
/// one file to manage.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncState {
    #[serde(default)]
    pub last_etag: Option<String>,
    #[serde(default)]
    pub last_pushed_revision: u64,
    #[serde(default)]
    pub last_synced_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncFile {
    pub config: SyncConfig,
    #[serde(default)]
    pub state: SyncState,
}

/// AAD for `sync.enc`, binding the file to one vault so it cannot be moved
/// between vaults.
fn sync_aad(vault_id: Uuid) -> Vec<u8> {
    let mut aad = b"pmv1:sync:".to_vec();
    aad.extend_from_slice(vault_id.as_bytes());
    aad
}

pub fn load_sync_file(paths: &Paths, dek: &Key32, vault_id: Uuid) -> Result<Option<SyncFile>> {
    let path = paths.sync();
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = storage::read_file(&path)?;
    let blob: SealedBlob =
        serde_json::from_slice(&bytes).map_err(|_| AppError::Corrupt("malformed sync file"))?;
    let plaintext = aead::open(dek, &blob, &sync_aad(vault_id))?;
    let file: SyncFile =
        // Discarded on purpose: a serde message here could embed the secret key.
        serde_json::from_slice(&plaintext).map_err(|_| AppError::Corrupt("malformed sync file"))?;
    Ok(Some(file))
}

pub fn save_sync_file(paths: &Paths, dek: &Key32, vault_id: Uuid, file: &SyncFile) -> Result<()> {
    let plaintext = zeroize::Zeroizing::new(
        serde_json::to_vec(file)
            .map_err(|_| AppError::Other("could not serialize the sync configuration".into()))?,
    );
    let blob = aead::seal(dek, &plaintext, &sync_aad(vault_id))?;
    let encoded = serde_json::to_vec(&blob)
        .map_err(|_| AppError::Other("could not serialize the sync configuration".into()))?;
    paths.ensure_dir()?;
    storage::write_atomic(&paths.sync(), &encoded)
}

pub fn delete_sync_file(paths: &Paths) -> Result<()> {
    let path = paths.sync();
    if path.is_file() {
        std::fs::remove_file(&path)
            .map_err(|e| AppError::io("could not remove the sync configuration", e))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncAction {
    /// Local and remote already agreed.
    UpToDate,
    /// The remote object did not exist and was created.
    CreatedRemote,
    /// Local changes were uploaded; the remote had not moved.
    Pushed,
    /// Remote changes were merged in and the result uploaded.
    Merged,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncReport {
    pub action: SyncAction,
    pub outcome: MergeOutcome,
    pub revision: u64,
    pub synced_at: i64,
    /// Set when sync succeeded but in a degraded mode worth telling the user
    /// about (currently: the service does not support conditional writes).
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncStatus {
    pub state: &'static str,
    pub message: Option<String>,
}

impl SyncStatus {
    pub fn syncing() -> Self {
        Self {
            state: "syncing",
            message: None,
        }
    }
    pub fn idle() -> Self {
        Self {
            state: "idle",
            message: None,
        }
    }
    pub fn error(message: String) -> Self {
        Self {
            state: "error",
            message: Some(message),
        }
    }
}

/// Everything `run_sync` needs from the vault, captured while holding the lock
/// so no guard is held across an `await`.
///
/// Deliberately does **not** carry the payload or the key wrapping. Those are
/// re-read under the lock at commit time, because the mutex is released across the
/// network round-trip and a snapshot taken beforehand may be stale by then — see
/// the merge step in [`run_sync`].
struct LocalSnapshot {
    vault_id: Uuid,
    revision: u64,
    dek: Key32,
    /// The exact bytes currently on disk, uploaded verbatim on the push-only path
    /// so the local file and the remote object stay byte-identical.
    bytes: Vec<u8>,
}

/// Capture local vault state and sync bookkeeping.
///
/// Called once per attempt rather than once per sync: a previous attempt may
/// already have merged and persisted a new revision, and continuing from a stale
/// snapshot would redo the merge against outdated entries and could move the
/// local revision backwards.
fn snapshot_local(state: &AppState) -> Result<(LocalSnapshot, SyncState)> {
    let vault = state.vault();
    if !vault.is_unlocked() {
        return Err(AppError::Locked);
    }

    let (vault_id, _kdf, _wrapped_dek) = vault.header_parts()?;
    let snapshot = LocalSnapshot {
        vault_id,
        revision: vault.revision()?,
        dek: vault.dek()?,
        bytes: storage::read_file(&vault.paths().vault())?,
    };

    let sync_state = load_sync_file(&state.paths, &snapshot.dek, vault_id)?
        .map(|f| f.state)
        .unwrap_or_default();

    Ok((snapshot, sync_state))
}

/// Persist updated sync bookkeeping. Best effort: failing to record an ETag
/// only costs one redundant download next time.
fn record_state(state: &AppState, dek: &Key32, vault_id: Uuid, new_state: SyncState) {
    let existing = load_sync_file(&state.paths, dek, vault_id).ok().flatten();
    if let Some(mut file) = existing {
        file.state = new_state;
        let _ = save_sync_file(&state.paths, dek, vault_id, &file);
    }
}

/// Run one full sync cycle.
pub async fn run_sync(state: &AppState) -> Result<SyncReport> {
    // The configuration cannot change mid-sync, so the client is built once.
    let config = {
        let guard = state.sync_config();
        guard.as_ref().ok_or(AppError::SyncNotConfigured)?.clone()
    };
    let store = S3Store::new(&config)?;
    let mut warning: Option<String> = None;

    for attempt in 1..=MAX_ATTEMPTS {
        // Local state is re-read every attempt — see `snapshot_local`.
        let (local, sync_state) = snapshot_local(state)?;
        let remote_etag = store.head().await.map_err(AppError::from)?;

        // --- Case 1: nothing there yet. Create it. ---
        let Some(etag) = remote_etag else {
            let result = store.put_if_absent(local.bytes.clone()).await;
            let new_etag = match result {
                Ok(etag) => etag,
                Err(RemoteError::PreconditionFailed) => continue, // someone beat us
                Err(RemoteError::PreconditionUnsupported) => {
                    warning = Some(unsupported_warning());
                    store
                        .put_unconditional(local.bytes.clone())
                        .await
                        .map_err(AppError::from)?
                }
                Err(other) => return Err(other.into()),
            };

            let recorded = SyncState {
                last_etag: new_etag,
                last_pushed_revision: local.revision,
                last_synced_at: now_ms(),
            };
            record_state(state, &local.dek, local.vault_id, recorded.clone());
            return Ok(SyncReport {
                action: SyncAction::CreatedRemote,
                outcome: MergeOutcome::default(),
                revision: local.revision,
                synced_at: recorded.last_synced_at,
                warning,
            });
        };

        let remote_unchanged = sync_state.last_etag.as_deref() == Some(etag.as_str());

        // --- Case 2: remote has not moved since our last sync. ---
        if remote_unchanged {
            if local.revision <= sync_state.last_pushed_revision {
                // Nothing was written, so the previously recorded timestamp is
                // still the correct "last synced" value.
                return Ok(SyncReport {
                    action: SyncAction::UpToDate,
                    outcome: MergeOutcome::default(),
                    revision: local.revision,
                    synced_at: sync_state.last_synced_at,
                    warning,
                });
            }

            let result = store.put_if_match(local.bytes.clone(), &etag).await;
            let new_etag = match result {
                Ok(etag) => etag,
                // Lost the race: fall through to a fresh HEAD and re-evaluate.
                Err(RemoteError::PreconditionFailed) => continue,
                Err(RemoteError::PreconditionUnsupported) => {
                    warning = Some(unsupported_warning());
                    store
                        .put_unconditional(local.bytes.clone())
                        .await
                        .map_err(AppError::from)?
                }
                Err(other) => return Err(other.into()),
            };

            let recorded = SyncState {
                last_etag: new_etag,
                last_pushed_revision: local.revision,
                last_synced_at: now_ms(),
            };
            record_state(state, &local.dek, local.vault_id, recorded.clone());
            return Ok(SyncReport {
                action: SyncAction::Pushed,
                outcome: MergeOutcome::default(),
                revision: local.revision,
                synced_at: recorded.last_synced_at,
                warning,
            });
        }

        // --- Case 3: remote moved. Pull, merge, push. ---
        let remote_object = store
            .get()
            .await
            .map_err(AppError::from)?
            // Vanished between HEAD and GET; retry.
            .ok_or(AppError::SyncConflict);
        let remote_object = match remote_object {
            Ok(obj) => obj,
            Err(_) if attempt < MAX_ATTEMPTS => continue,
            Err(e) => return Err(e),
        };

        let parsed = container::parse(&remote_object.bytes)?;
        if parsed.vault_id() != local.vault_id {
            return Err(AppError::SyncVaultMismatch(format!(
                "remote vault {} does not match this device's vault {}",
                parsed.vault_id(),
                local.vault_id
            )));
        }

        // Decrypting with our DEK proves the remote revision was written by a
        // device that holds this vault's data key. Because the *whole header* is
        // this ciphertext's associated data, that also authenticates the remote
        // header — which is what makes adopting its KDF parameters and wrapped
        // key safe below.
        let remote_payload = parsed.decrypt_payload(&local.dek)?;
        let remote_revision = parsed.revision();

        // When the wrapped key differs from ours, one side has changed the master
        // password. Prefer whichever header was written later by wall clock.
        //
        // The revision counter cannot answer this: revisions advance per local
        // save, so a device that has simply saved more often can hold a *higher*
        // revision while carrying an *older* key wrapping — and picking by
        // revision would then silently revert the password change. `updated_at`
        // lives in the header, which is authenticated as this ciphertext's
        // associated data, so it cannot be forged by anyone without the data key.
        // Residual risk: a badly skewed device clock can still pick wrong.
        let local_header_updated_at = container::parse(&local.bytes)
            .map(|c| c.header.updated_at)
            .unwrap_or(0);
        let remote_wrap_is_newer = parsed.header.updated_at > local_header_updated_at;

        let (outcome, next_revision, merged_bytes) = {
            // Re-read the payload under the lock. The vault mutex was released
            // across the HEAD/GET round-trip above, so the user may have created
            // or edited an entry in the meantime; merging `local.payload` and
            // writing that back would silently discard those saves.
            let mut vault = state.vault();
            let live_payload = vault.payload_snapshot()?;
            let live_revision = vault.revision()?;
            let (live_vault_id, live_kdf, live_wrapped) = vault.header_parts()?;

            if live_vault_id != parsed.vault_id() {
                return Err(AppError::SyncVaultMismatch(format!(
                    "remote vault {} does not match this device's vault {live_vault_id}",
                    parsed.vault_id(),
                )));
            }

            let (merged, outcome) = merge::merge(&live_payload, &remote_payload);
            let next_revision = live_revision.max(remote_revision) + 1;

            let (kdf, wrapped_dek) = if remote_wrap_is_newer {
                (parsed.header.kdf.clone(), parsed.header.wrapped_dek.clone())
            } else {
                (live_kdf, live_wrapped)
            };

            let bytes = vault.apply_sync_result(merged, kdf, wrapped_dek, next_revision)?;
            (outcome, next_revision, bytes)
        };

        let result = store.put_if_match(merged_bytes.clone(), &etag).await;
        let new_etag = match result {
            Ok(etag) => etag,
            Err(RemoteError::PreconditionFailed) if attempt < MAX_ATTEMPTS => {
                // The merge is already saved locally, which is safe and means
                // the retry re-merges from the newer remote without losing work.
                continue;
            }
            Err(RemoteError::PreconditionUnsupported) => {
                warning = Some(unsupported_warning());
                store
                    .put_unconditional(merged_bytes)
                    .await
                    .map_err(AppError::from)?
            }
            Err(other) => return Err(other.into()),
        };

        let recorded = SyncState {
            last_etag: new_etag,
            last_pushed_revision: next_revision,
            last_synced_at: now_ms(),
        };
        record_state(state, &local.dek, local.vault_id, recorded.clone());

        return Ok(SyncReport {
            action: SyncAction::Merged,
            outcome,
            revision: next_revision,
            synced_at: recorded.last_synced_at,
            warning,
        });
    }

    Err(AppError::SyncConflict)
}

fn unsupported_warning() -> String {
    "This storage service does not support conditional writes, so simultaneous \
     changes from two devices could overwrite each other."
        .to_string()
}

/// Download a remote vault and adopt it on this device.
///
/// Used when connecting a second device: there is nothing local to merge, so the
/// remote vault's identity and key wrapping are taken wholesale.
pub async fn connect_existing(
    state: &AppState,
    config: SyncConfig,
    master_password: &str,
) -> Result<u64> {
    config.validate()?;
    let store = S3Store::new(&config)?;

    let remote = store
        .get()
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::Sync("no vault found at that bucket and prefix".into()))?;

    let parsed = container::parse(&remote.bytes)?;
    let unlocked = parsed.unlock(master_password)?;
    let revision = unlocked.header.revision;
    let vault_id = unlocked.header.vault_id;
    let dek = unlocked.dek.clone();

    {
        let mut vault = state.vault();
        vault.adopt(unlocked.header, unlocked.dek, unlocked.payload)?;
    }

    save_sync_file(
        &state.paths,
        &dek,
        vault_id,
        &SyncFile {
            config: config.clone(),
            state: SyncState {
                last_etag: remote.etag,
                last_pushed_revision: revision,
                last_synced_at: now_ms(),
            },
        },
    )?;
    *state.sync_config() = Some(config);

    Ok(revision)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sentinel distinct from any field *name*, so "did the secret leak?"
    /// assertions cannot be satisfied by the schema itself.
    const SECRET: &str = "s3cr3t-4cc3ss-k3y-sentinel";

    fn config() -> SyncConfig {
        SyncConfig {
            endpoint: "https://acct.r2.cloudflarestorage.com".into(),
            region: "auto".into(),
            bucket: "bucket".into(),
            prefix: String::new(),
            access_key_id: "key".into(),
            secret_access_key: SECRET.into(),
            force_path_style: false,
        }
    }

    #[test]
    fn object_key_handles_prefix_variants() {
        let mut c = config();
        assert_eq!(c.object_key(), "vault.pmv");

        c.prefix = "devices".into();
        assert_eq!(c.object_key(), "devices/vault.pmv");

        c.prefix = "/devices/laptop/".into();
        assert_eq!(c.object_key(), "devices/laptop/vault.pmv");

        c.prefix = "   ".into();
        assert_eq!(c.object_key(), "vault.pmv");
    }

    #[test]
    fn validate_accepts_common_providers() {
        for endpoint in [
            "https://acct.r2.cloudflarestorage.com",
            "https://s3.us-east-1.amazonaws.com",
            "https://s3.us-west-002.backblazeb2.com",
            "http://localhost:9000",
            "http://127.0.0.1:9000",
        ] {
            let mut c = config();
            c.endpoint = endpoint.into();
            assert!(c.validate().is_ok(), "{endpoint} should be accepted");
        }
    }

    #[test]
    fn validate_rejects_plaintext_http_to_a_remote_host() {
        let mut c = config();
        c.endpoint = "http://example.com".into();
        assert!(c.validate().is_err());

        // ...but not to a local dev server.
        c.endpoint = "http://localhost:9000".into();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn validate_rejects_incomplete_configuration() {
        let mut c = config();
        c.endpoint = "ftp://example.com".into();
        assert!(c.validate().is_err());

        let mut c = config();
        c.endpoint = "https://".into();
        assert!(c.validate().is_err());

        let mut c = config();
        c.bucket = "  ".into();
        assert!(c.validate().is_err());

        let mut c = config();
        c.access_key_id = String::new();
        assert!(c.validate().is_err());

        let mut c = config();
        c.secret_access_key = String::new();
        assert!(c.validate().is_err());

        let mut c = config();
        c.prefix = "../../etc".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn redacted_view_never_carries_the_secret_key() {
        let json = serde_json::to_string(&config().redacted()).unwrap();
        assert!(!json.contains(SECRET), "the secret key leaked: {json}");
        assert!(json.contains("has_secret_access_key\":true"));
        assert!(json.contains("acct.r2.cloudflarestorage.com"));
    }

    #[test]
    fn sync_file_round_trips_encrypted_and_is_bound_to_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().to_path_buf());
        paths.ensure_dir().unwrap();

        let dek = aead::generate_key().unwrap();
        let vault_id = Uuid::new_v4();
        let file = SyncFile {
            config: config(),
            state: SyncState {
                last_etag: Some("\"abc\"".into()),
                last_pushed_revision: 7,
                last_synced_at: 12345,
            },
        };

        save_sync_file(&paths, &dek, vault_id, &file).unwrap();

        // The credential must not be readable on disk.
        let raw = std::fs::read(paths.sync()).unwrap();
        assert!(
            !raw.windows(SECRET.len()).any(|w| w == SECRET.as_bytes()),
            "the secret access key leaked into sync.enc"
        );

        let loaded = load_sync_file(&paths, &dek, vault_id).unwrap().unwrap();
        assert_eq!(loaded.config.bucket, "bucket");
        assert_eq!(loaded.config.secret_access_key, SECRET);
        assert_eq!(loaded.state.last_pushed_revision, 7);
        assert_eq!(loaded.state.last_etag.as_deref(), Some("\"abc\""));

        // A different vault id must not be able to read it.
        assert!(load_sync_file(&paths, &dek, Uuid::new_v4()).is_err());
        // Nor a different key.
        let other = aead::generate_key().unwrap();
        assert!(load_sync_file(&paths, &other, vault_id).is_err());
    }

    #[test]
    fn missing_sync_file_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().to_path_buf());
        paths.ensure_dir().unwrap();
        let dek = aead::generate_key().unwrap();
        assert!(load_sync_file(&paths, &dek, Uuid::new_v4())
            .unwrap()
            .is_none());
    }

    #[test]
    fn deleting_the_sync_file_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().to_path_buf());
        paths.ensure_dir().unwrap();
        delete_sync_file(&paths).unwrap();

        let dek = aead::generate_key().unwrap();
        let vault_id = Uuid::new_v4();
        save_sync_file(
            &paths,
            &dek,
            vault_id,
            &SyncFile {
                config: config(),
                state: SyncState::default(),
            },
        )
        .unwrap();
        assert!(paths.sync().is_file());
        delete_sync_file(&paths).unwrap();
        assert!(!paths.sync().is_file());
        delete_sync_file(&paths).unwrap();
    }

    #[test]
    fn corrupt_sync_file_is_reported_not_panicked() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().to_path_buf());
        paths.ensure_dir().unwrap();
        std::fs::write(paths.sync(), b"not json").unwrap();

        let dek = aead::generate_key().unwrap();
        assert!(load_sync_file(&paths, &dek, Uuid::new_v4()).is_err());
    }
}
