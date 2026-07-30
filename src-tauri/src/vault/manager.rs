//! The lock state machine and every mutation of vault contents.
//!
//! Invariants this type enforces:
//!
//! - No vault data is reachable without a prior successful [`VaultManager::unlock`].
//! - The master key is never retained. Only the DEK lives in an unlocked
//!   session, because writing a revision reuses the existing `wrapped_dek`.
//! - Every mutation persists immediately. There is no "unsaved changes" state to
//!   lose on an auto-lock.

use std::fs;
use std::time::{Duration, Instant, SystemTime};

use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::crypto::aead::{self, SealedBlob};
use crate::crypto::kdf::{self, KdfParams, Key32};
use crate::error::{AppError, Result};
use crate::generator::{self, GeneratorPreset};
use crate::storage::{self, Paths};
use crate::vault::container::{self, VaultHeader};
use crate::vault::model::{
    now_ms, CustomField, EntryDetail, EntryInput, EntrySummary, FieldSelector, Tombstone,
    VaultEntry, VaultPayload,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    /// No vault on this device yet — the setup flow should run.
    Uninitialized,
    Locked,
    Unlocked,
}

/// State that exists only while unlocked.
struct Session {
    dek: Key32,
    vault_id: Uuid,
    kdf: KdfParams,
    wrapped_dek: SealedBlob,
    revision: u64,
    payload: VaultPayload,
    /// Monotonic clock, for idle measurement.
    last_activity: Instant,
    /// Wall clock, as a backstop for the monotonic clock. On Linux and Windows
    /// `Instant` does not advance while the machine is suspended, so a laptop
    /// closed for eight hours would otherwise come back still unlocked.
    last_activity_wall: SystemTime,
}

pub struct VaultManager {
    paths: Paths,
    device_id: Uuid,
    session: Option<Session>,
}

impl VaultManager {
    pub fn new(paths: Paths, device_id: Uuid) -> Self {
        Self {
            paths,
            device_id,
            session: None,
        }
    }

    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    pub fn device_id(&self) -> Uuid {
        self.device_id
    }

    pub fn status(&self) -> VaultStatus {
        if self.session.is_some() {
            VaultStatus::Unlocked
        } else if self.paths.vault_exists() {
            VaultStatus::Locked
        } else {
            VaultStatus::Uninitialized
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.session.is_some()
    }

    fn session(&self) -> Result<&Session> {
        self.session.as_ref().ok_or(AppError::Locked)
    }

    fn session_mut(&mut self) -> Result<&mut Session> {
        self.session.as_mut().ok_or(AppError::Locked)
    }

    // -- lifecycle ---------------------------------------------------------

    /// Create a brand new vault. Fails if one already exists, so an accidental
    /// re-run of setup can never destroy secrets.
    pub fn create(&mut self, master_password: &str) -> Result<()> {
        if self.paths.vault_exists() {
            return Err(AppError::VaultExists);
        }
        generator::enforce_master_password_policy(master_password)?;

        let payload = VaultPayload::default();
        let (bytes, unlocked) = container::create(master_password, &payload, self.device_id)?;

        self.paths.ensure_dir()?;
        storage::write_atomic(&self.paths.vault(), &bytes)?;

        self.session = Some(Session::new(unlocked));
        Ok(())
    }

    pub fn unlock(&mut self, master_password: &str) -> Result<()> {
        if !self.paths.vault_exists() {
            return Err(AppError::NoVault);
        }
        let bytes = storage::read_file(&self.paths.vault())?;
        let unlocked = container::parse(&bytes)?.unlock(master_password)?;
        self.session = Some(Session::new(unlocked));
        Ok(())
    }

    /// Drop the session. The DEK and every decrypted entry are zeroized by their
    /// `Drop` impls as the session is released.
    pub fn lock(&mut self) {
        self.session = None;
    }

    /// Record user activity, deferring auto-lock.
    pub fn touch(&mut self) {
        if let Some(session) = self.session.as_mut() {
            session.last_activity = Instant::now();
            session.last_activity_wall = SystemTime::now();
        }
    }

    /// Idle time, taking whichever clock reports more elapsed time.
    ///
    /// The wall clock catches suspend/resume; the monotonic clock catches a wall
    /// clock that was moved backwards. Taking the maximum means neither can be
    /// used to keep a vault unlocked longer than the configured timeout.
    pub fn idle_time(&self) -> Option<Duration> {
        let session = self.session.as_ref()?;
        let monotonic = session.last_activity.elapsed();
        let wall = SystemTime::now()
            .duration_since(session.last_activity_wall)
            .unwrap_or(Duration::ZERO);
        Some(monotonic.max(wall))
    }

    /// Whether the vault should be locked now, given a timeout in seconds
    /// (`0` disables auto-lock).
    pub fn should_auto_lock(&self, timeout_secs: u64) -> bool {
        if timeout_secs == 0 {
            return false;
        }
        self.idle_time()
            .is_some_and(|idle| idle >= Duration::from_secs(timeout_secs))
    }

    pub fn change_master_password(&mut self, current: &str, new: &str) -> Result<()> {
        let (kdf_params, wrapped) = {
            let session = self.session()?;

            // Verify the current password by re-deriving and unwrapping, then
            // comparing in constant time against the DEK we already hold.
            let master_key = kdf::derive_master_key(current, &session.kdf)?;
            let unwrapped = aead::open(&master_key, &session.wrapped_dek, &session.kdf.aad())
                .map_err(|_| AppError::InvalidMasterPassword)?;
            if !bool::from(unwrapped.as_slice().ct_eq(session.dek.as_ref())) {
                return Err(AppError::InvalidMasterPassword);
            }

            generator::enforce_master_password_policy(new)?;
            container::rewrap_dek(&session.dek, new)?
        };

        // Swap the new wrapping in, then roll back if the write fails. Without the
        // rollback the session would hold a wrapping that is not on disk, and the
        // next unrelated save would silently commit the password change the user
        // was just told had failed.
        let (previous_kdf, previous_wrapped) = {
            let session = self.session_mut()?;
            let previous = (session.kdf.clone(), session.wrapped_dek.clone());
            session.kdf = kdf_params;
            session.wrapped_dek = wrapped;
            previous
        };

        if let Err(err) = self.persist() {
            if let Ok(session) = self.session_mut() {
                session.kdf = previous_kdf;
                session.wrapped_dek = previous_wrapped;
            }
            return Err(err);
        }
        Ok(())
    }

    // -- persistence -------------------------------------------------------

    /// Write the current payload as the next revision.
    fn persist(&mut self) -> Result<()> {
        let (bytes, next_revision) = {
            let session = self.session()?;
            let next_revision = session.revision + 1;
            let bytes = container::write(
                session.vault_id,
                &session.kdf,
                &session.wrapped_dek,
                &session.dek,
                &session.payload,
                next_revision,
                self.device_id,
            )?;
            (bytes, next_revision)
        };

        // Keep the previous revision around. Best effort: a failed backup must
        // not block saving new data.
        if self.paths.vault_exists() {
            let _ = fs::copy(self.paths.vault(), self.paths.vault_backup());
        }
        storage::write_atomic(&self.paths.vault(), &bytes)?;

        // Only advance the in-memory revision once the write succeeded.
        self.session_mut()?.revision = next_revision;
        Ok(())
    }

    // -- reads -------------------------------------------------------------

    /// Entry summaries, favourites first then title order. Carries no secrets.
    pub fn list_entries(&self) -> Result<Vec<EntrySummary>> {
        let session = self.session()?;
        let mut summaries: Vec<EntrySummary> = session
            .payload
            .entries
            .iter()
            .map(|e| e.summary())
            .collect();
        summaries.sort_by(|a, b| {
            b.favorite
                .cmp(&a.favorite)
                .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(summaries)
    }

    pub fn get_entry(&self, id: Uuid) -> Result<EntryDetail> {
        self.session()?
            .payload
            .find(id)
            .map(|e| e.detail())
            .ok_or(AppError::EntryNotFound)
    }

    /// Read a single secret field. This is the only path by which a stored
    /// secret value leaves the backend.
    pub fn reveal(&self, id: Uuid, selector: &FieldSelector) -> Result<String> {
        let entry = self
            .session()?
            .payload
            .find(id)
            .ok_or(AppError::EntryNotFound)?;

        Ok(match selector {
            FieldSelector::Password => entry.password.clone(),
            FieldSelector::Username => entry.username.clone(),
            FieldSelector::Notes => entry.notes.clone(),
            FieldSelector::Custom { id: field_id } => entry
                .custom_fields
                .iter()
                .find(|f| f.id == *field_id)
                .ok_or(AppError::EntryNotFound)?
                .value
                .clone(),
        })
    }

    pub fn entry_count(&self) -> Result<usize> {
        Ok(self.session()?.payload.entries.len())
    }

    // -- writes ------------------------------------------------------------

    pub fn create_entry(&mut self, input: EntryInput) -> Result<Uuid> {
        let title = input.title.trim().to_string();
        if title.is_empty() {
            return Err(AppError::InvalidOptions("a title is required".into()));
        }

        let mut entry = VaultEntry::new(input.kind);
        entry.title = title;
        entry.username = input.username;
        entry.password = input.password.unwrap_or_default();
        entry.urls = clean_list(input.urls);
        entry.notes = input.notes;
        entry.tags = clean_list(input.tags);
        entry.favorite = input.favorite;
        entry.custom_fields = input
            .custom_fields
            .into_iter()
            .map(|f| CustomField {
                id: f.id.unwrap_or_else(Uuid::new_v4),
                label: f.label,
                value: f.value.unwrap_or_default(),
                secret: f.secret,
            })
            .collect();

        let id = entry.id;
        self.session_mut()?.payload.entries.push(entry);
        self.persist()?;
        Ok(id)
    }

    pub fn update_entry(&mut self, id: Uuid, input: EntryInput) -> Result<()> {
        let title = input.title.trim().to_string();
        if title.is_empty() {
            return Err(AppError::InvalidOptions("a title is required".into()));
        }

        {
            let session = self.session_mut()?;
            let entry = session
                .payload
                .find_mut(id)
                .ok_or(AppError::EntryNotFound)?;

            entry.kind = input.kind;
            entry.title = title;
            entry.username = input.username;
            entry.urls = clean_list(input.urls);
            entry.notes = input.notes;
            entry.tags = clean_list(input.tags);
            entry.favorite = input.favorite;

            // `None` means "the form never held the password", which is the
            // normal case: the edit form is populated without it.
            if let Some(new_password) = input.password {
                if new_password != entry.password {
                    entry.password = new_password;
                    entry.password_updated_at = now_ms();
                }
            }

            // Merge custom fields, preserving values the form did not receive.
            let mut merged = Vec::with_capacity(input.custom_fields.len());
            for field in input.custom_fields {
                let existing = field
                    .id
                    .and_then(|fid| entry.custom_fields.iter().find(|f| f.id == fid));
                merged.push(CustomField {
                    id: field.id.unwrap_or_else(Uuid::new_v4),
                    label: field.label,
                    value: match field.value {
                        Some(v) => v,
                        None => existing.map(|f| f.value.clone()).unwrap_or_default(),
                    },
                    secret: field.secret,
                });
            }
            entry.custom_fields = merged;
            entry.updated_at = now_ms();
        }

        self.persist()
    }

    pub fn delete_entry(&mut self, id: Uuid) -> Result<()> {
        {
            let session = self.session_mut()?;
            let before = session.payload.entries.len();
            session.payload.entries.retain(|e| e.id != id);
            if session.payload.entries.len() == before {
                return Err(AppError::EntryNotFound);
            }
            // Without a tombstone, another device that still holds this entry
            // would push it straight back on the next merge.
            session.payload.tombstones.push(Tombstone {
                id,
                deleted_at: now_ms(),
            });
            session.payload.gc_tombstones(now_ms());
        }
        self.persist()
    }

    pub fn set_favorite(&mut self, id: Uuid, favorite: bool) -> Result<()> {
        {
            let session = self.session_mut()?;
            let entry = session
                .payload
                .find_mut(id)
                .ok_or(AppError::EntryNotFound)?;
            entry.favorite = favorite;
            entry.updated_at = now_ms();
        }
        self.persist()
    }

    // -- generator presets -------------------------------------------------

    pub fn list_presets(&self) -> Result<Vec<GeneratorPreset>> {
        Ok(self.session()?.payload.generator_presets.clone())
    }

    pub fn save_preset(&mut self, mut preset: GeneratorPreset) -> Result<Uuid> {
        if preset.name.trim().is_empty() {
            return Err(AppError::InvalidOptions("a preset name is required".into()));
        }
        preset.name = preset.name.trim().to_string();
        if preset.created_at == 0 {
            preset.created_at = now_ms();
        }

        let id = preset.id;
        {
            let presets = &mut self.session_mut()?.payload.generator_presets;
            match presets.iter_mut().find(|p| p.id == id) {
                Some(existing) => *existing = preset,
                None => presets.push(preset),
            }
        }
        self.persist()?;
        Ok(id)
    }

    pub fn delete_preset(&mut self, id: Uuid) -> Result<()> {
        {
            let presets = &mut self.session_mut()?.payload.generator_presets;
            let before = presets.len();
            presets.retain(|p| p.id != id);
            if presets.len() == before {
                return Err(AppError::EntryNotFound);
            }
        }
        self.persist()
    }

    // -- accessors used by the sync and bridge layers ----------------------

    pub fn vault_id(&self) -> Result<Uuid> {
        Ok(self.session()?.vault_id)
    }

    pub fn revision(&self) -> Result<u64> {
        Ok(self.session()?.revision)
    }

    /// A copy of the DEK, for encrypting the sync credential file.
    pub fn dek(&self) -> Result<Key32> {
        Ok(self.session()?.dek.clone())
    }

    pub fn payload_snapshot(&self) -> Result<VaultPayload> {
        Ok(self.session()?.payload.clone())
    }

    pub fn header_parts(&self) -> Result<(Uuid, KdfParams, SealedBlob)> {
        let session = self.session()?;
        Ok((
            session.vault_id,
            session.kdf.clone(),
            session.wrapped_dek.clone(),
        ))
    }

    /// Serialize the current state as a container, without persisting it.
    /// Used to produce the bytes to upload.
    pub fn serialize_current(&self) -> Result<Vec<u8>> {
        let session = self.session()?;
        container::write(
            session.vault_id,
            &session.kdf,
            &session.wrapped_dek,
            &session.dek,
            &session.payload,
            session.revision,
            self.device_id,
        )
    }

    /// Replace the payload with a merged one and persist it as a new revision.
    pub fn replace_payload(&mut self, payload: VaultPayload) -> Result<()> {
        self.session_mut()?.payload = payload;
        self.persist()
    }

    /// Commit a merge result at an explicit revision, returning the exact bytes
    /// written to disk so the caller can upload the identical object.
    ///
    /// The revision is supplied rather than incremented because both sides of a
    /// sync must agree on the number.
    pub fn apply_sync_result(
        &mut self,
        payload: VaultPayload,
        kdf: KdfParams,
        wrapped_dek: SealedBlob,
        revision: u64,
    ) -> Result<Vec<u8>> {
        {
            let session = self.session_mut()?;
            session.payload = payload;
            session.kdf = kdf;
            session.wrapped_dek = wrapped_dek;
            session.revision = revision;
        }

        let bytes = {
            let session = self.session()?;
            container::write(
                session.vault_id,
                &session.kdf,
                &session.wrapped_dek,
                &session.dek,
                &session.payload,
                session.revision,
                self.device_id,
            )?
        };

        if self.paths.vault_exists() {
            let _ = fs::copy(self.paths.vault(), self.paths.vault_backup());
        }
        storage::write_atomic(&self.paths.vault(), &bytes)?;
        Ok(bytes)
    }

    /// Entries whose stored URLs match `host`, for the browser extension.
    ///
    /// Returns only non-secret fields; fetching the password is a separate,
    /// explicitly-confirmed step.
    pub fn find_by_host(&self, host: &str) -> Result<Vec<EntrySummary>> {
        let session = self.session()?;
        let mut matches: Vec<EntrySummary> = session
            .payload
            .entries
            .iter()
            .filter(|e| {
                !e.password.is_empty()
                    && e.urls
                        .iter()
                        .any(|url| crate::domain::matches_host(url, host))
            })
            .map(|e| e.summary())
            .collect();
        matches.sort_by(|a, b| {
            b.favorite
                .cmp(&a.favorite)
                .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
        });
        Ok(matches)
    }

    /// The username and password for one entry, for autofill.
    pub fn credentials_for(&self, id: Uuid) -> Result<(String, String)> {
        let entry = self
            .session()?
            .payload
            .find(id)
            .ok_or(AppError::EntryNotFound)?;
        Ok((entry.username.clone(), entry.password.clone()))
    }

    /// Adopt a remote vault's identity and keys wholesale. Used when a device
    /// first connects to an existing remote vault.
    pub fn adopt(&mut self, header: VaultHeader, dek: Key32, payload: VaultPayload) -> Result<()> {
        let bytes = container::write(
            header.vault_id,
            &header.kdf,
            &header.wrapped_dek,
            &dek,
            &payload,
            header.revision,
            self.device_id,
        )?;
        self.paths.ensure_dir()?;
        if self.paths.vault_exists() {
            let _ = fs::copy(self.paths.vault(), self.paths.vault_backup());
        }
        storage::write_atomic(&self.paths.vault(), &bytes)?;

        self.session = Some(Session {
            dek,
            vault_id: header.vault_id,
            kdf: header.kdf,
            wrapped_dek: header.wrapped_dek,
            revision: header.revision,
            payload,
            last_activity: Instant::now(),
            last_activity_wall: SystemTime::now(),
        });
        Ok(())
    }
}

impl Session {
    fn new(unlocked: container::UnlockedVault) -> Self {
        Self {
            dek: unlocked.dek,
            vault_id: unlocked.header.vault_id,
            kdf: unlocked.header.kdf,
            wrapped_dek: unlocked.header.wrapped_dek,
            revision: unlocked.header.revision,
            payload: unlocked.payload,
            last_activity: Instant::now(),
            last_activity_wall: SystemTime::now(),
        }
    }
}

/// Trim entries and drop blanks from a user-supplied string list.
fn clean_list(items: Vec<String>) -> Vec<String> {
    items
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::model::{CustomFieldInput, EntryKind};

    const PW: &str = "correct-horse-battery-staple-9";
    const PW2: &str = "another-entirely-different-passphrase-4";

    fn manager() -> (tempfile::TempDir, VaultManager) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().to_path_buf());
        paths.ensure_dir().unwrap();
        let m = VaultManager::new(paths, Uuid::new_v4());
        (dir, m)
    }

    fn login(title: &str, password: &str) -> EntryInput {
        EntryInput {
            kind: EntryKind::Login,
            title: title.into(),
            username: "user".into(),
            password: Some(password.into()),
            urls: vec!["https://example.com".into()],
            notes: String::new(),
            custom_fields: vec![],
            tags: vec![],
            favorite: false,
        }
    }

    #[test]
    fn status_progresses_through_the_lifecycle() {
        let (_d, mut m) = manager();
        assert_eq!(m.status(), VaultStatus::Uninitialized);

        m.create(PW).unwrap();
        assert_eq!(m.status(), VaultStatus::Unlocked);

        m.lock();
        assert_eq!(m.status(), VaultStatus::Locked);

        m.unlock(PW).unwrap();
        assert_eq!(m.status(), VaultStatus::Unlocked);
    }

    #[test]
    fn locked_manager_refuses_every_read_and_write() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();
        let id = m.create_entry(login("Example", "s3cret")).unwrap();
        m.lock();

        assert!(matches!(m.list_entries(), Err(AppError::Locked)));
        assert!(matches!(m.get_entry(id), Err(AppError::Locked)));
        assert!(matches!(
            m.reveal(id, &FieldSelector::Password),
            Err(AppError::Locked)
        ));
        assert!(matches!(m.entry_count(), Err(AppError::Locked)));
        assert!(matches!(m.list_presets(), Err(AppError::Locked)));
        assert!(matches!(m.dek(), Err(AppError::Locked)));
        assert!(matches!(
            m.create_entry(login("Nope", "x")),
            Err(AppError::Locked)
        ));
        assert!(matches!(m.delete_entry(id), Err(AppError::Locked)));
        assert!(matches!(
            m.update_entry(id, login("Nope", "x")),
            Err(AppError::Locked)
        ));
        assert!(matches!(
            m.change_master_password(PW, PW2),
            Err(AppError::Locked)
        ));
    }

    #[test]
    fn cannot_create_over_an_existing_vault() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();
        m.lock();
        assert!(matches!(m.create(PW2), Err(AppError::VaultExists)));
    }

    #[test]
    fn weak_master_password_is_refused_at_creation() {
        let (_d, mut m) = manager();
        assert!(matches!(
            m.create("password"),
            Err(AppError::WeakMasterPassword(_))
        ));
        assert_eq!(m.status(), VaultStatus::Uninitialized);
    }

    #[test]
    fn unlock_requires_the_right_password() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();
        m.lock();
        assert!(matches!(
            m.unlock("wrong-password-entirely"),
            Err(AppError::InvalidMasterPassword)
        ));
        assert_eq!(m.status(), VaultStatus::Locked);
        m.unlock(PW).unwrap();
    }

    #[test]
    fn unlock_without_a_vault_reports_no_vault() {
        let (_d, mut m) = manager();
        assert!(matches!(m.unlock(PW), Err(AppError::NoVault)));
    }

    #[test]
    fn entries_survive_lock_and_unlock() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();
        let id = m.create_entry(login("GitHub", "gh-secret")).unwrap();

        m.lock();
        m.unlock(PW).unwrap();

        assert_eq!(m.entry_count().unwrap(), 1);
        assert_eq!(m.get_entry(id).unwrap().title, "GitHub");
        assert_eq!(m.reveal(id, &FieldSelector::Password).unwrap(), "gh-secret");
    }

    #[test]
    fn every_mutation_persists_immediately() {
        let (dir, mut m) = manager();
        m.create(PW).unwrap();
        let id = m.create_entry(login("Persisted", "value")).unwrap();

        // A brand-new manager over the same directory sees the entry, proving it
        // reached disk rather than only memory.
        let fresh_paths = Paths::new(dir.path().to_path_buf());
        let mut fresh = VaultManager::new(fresh_paths, Uuid::new_v4());
        fresh.unlock(PW).unwrap();
        assert_eq!(fresh.get_entry(id).unwrap().title, "Persisted");
    }

    #[test]
    fn revision_advances_on_each_save() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();
        assert_eq!(m.revision().unwrap(), 1);
        m.create_entry(login("One", "a")).unwrap();
        assert_eq!(m.revision().unwrap(), 2);
        m.create_entry(login("Two", "b")).unwrap();
        assert_eq!(m.revision().unwrap(), 3);
    }

    #[test]
    fn a_backup_of_the_previous_revision_is_kept() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();
        assert!(!m.paths.vault_backup().exists());
        m.create_entry(login("One", "a")).unwrap();
        assert!(m.paths.vault_backup().exists());
    }

    #[test]
    fn update_preserves_the_password_when_none_is_supplied() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();
        let id = m.create_entry(login("Site", "original")).unwrap();

        let mut edit = login("Site Renamed", "ignored");
        edit.password = None;
        m.update_entry(id, edit).unwrap();

        assert_eq!(m.get_entry(id).unwrap().title, "Site Renamed");
        assert_eq!(m.reveal(id, &FieldSelector::Password).unwrap(), "original");
    }

    #[test]
    fn password_updated_at_moves_only_on_a_real_change() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();
        let id = m.create_entry(login("Site", "original")).unwrap();
        let first = m.get_entry(id).unwrap().password_updated_at;

        // Same value re-submitted: timestamp must not move.
        m.update_entry(id, login("Site", "original")).unwrap();
        assert_eq!(m.get_entry(id).unwrap().password_updated_at, first);

        std::thread::sleep(Duration::from_millis(2));
        m.update_entry(id, login("Site", "changed")).unwrap();
        assert!(m.get_entry(id).unwrap().password_updated_at > first);
    }

    #[test]
    fn custom_field_values_survive_an_edit_that_omits_them() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();

        let mut input = login("Site", "pw");
        input.custom_fields = vec![CustomFieldInput {
            id: None,
            label: "Recovery".into(),
            value: Some("recovery-code".into()),
            secret: true,
        }];
        let id = m.create_entry(input).unwrap();

        let field_id = m.get_entry(id).unwrap().custom_fields[0].id;

        // The edit form received the label but not the secret value.
        let mut edit = login("Site", "pw");
        edit.password = None;
        edit.custom_fields = vec![CustomFieldInput {
            id: Some(field_id),
            label: "Recovery code".into(),
            value: None,
            secret: true,
        }];
        m.update_entry(id, edit).unwrap();

        let detail = m.get_entry(id).unwrap();
        assert_eq!(detail.custom_fields[0].label, "Recovery code");
        assert_eq!(
            detail.custom_fields[0].value, None,
            "secret must stay masked"
        );
        assert_eq!(
            m.reveal(id, &FieldSelector::Custom { id: field_id })
                .unwrap(),
            "recovery-code"
        );
    }

    #[test]
    fn delete_leaves_a_tombstone() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();
        let id = m.create_entry(login("Doomed", "x")).unwrap();

        m.delete_entry(id).unwrap();
        assert!(matches!(m.get_entry(id), Err(AppError::EntryNotFound)));

        let payload = m.payload_snapshot().unwrap();
        assert!(payload.is_deleted(id), "no tombstone recorded");
        assert!(matches!(m.delete_entry(id), Err(AppError::EntryNotFound)));
    }

    #[test]
    fn titles_are_required_and_trimmed() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();

        let mut blank = login("   ", "x");
        blank.title = "   ".into();
        assert!(matches!(
            m.create_entry(blank),
            Err(AppError::InvalidOptions(_))
        ));

        let id = m.create_entry(login("  Spaced  ", "x")).unwrap();
        assert_eq!(m.get_entry(id).unwrap().title, "Spaced");
    }

    #[test]
    fn blank_urls_and_tags_are_dropped() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();
        let mut input = login("Site", "x");
        input.urls = vec!["  https://a.test ".into(), "   ".into(), String::new()];
        input.tags = vec!["  dev ".into(), "".into()];
        let id = m.create_entry(input).unwrap();

        let detail = m.get_entry(id).unwrap();
        assert_eq!(detail.urls, vec!["https://a.test"]);
        assert_eq!(detail.tags, vec!["dev"]);
    }

    #[test]
    fn listing_sorts_favourites_first_then_by_title() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();
        m.create_entry(login("zeta", "x")).unwrap();
        m.create_entry(login("Alpha", "x")).unwrap();
        let fav = m.create_entry(login("middle", "x")).unwrap();
        m.set_favorite(fav, true).unwrap();

        let titles: Vec<String> = m
            .list_entries()
            .unwrap()
            .into_iter()
            .map(|e| e.title)
            .collect();
        assert_eq!(titles, vec!["middle", "Alpha", "zeta"]);
    }

    #[test]
    fn reveal_rejects_unknown_ids_and_fields() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();
        let id = m.create_entry(login("Site", "x")).unwrap();

        assert!(matches!(
            m.reveal(Uuid::new_v4(), &FieldSelector::Password),
            Err(AppError::EntryNotFound)
        ));
        assert!(matches!(
            m.reveal(id, &FieldSelector::Custom { id: Uuid::new_v4() }),
            Err(AppError::EntryNotFound)
        ));
    }

    // -- master password change -------------------------------------------

    #[test]
    fn master_password_change_takes_effect() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();
        let id = m.create_entry(login("Site", "keep-me")).unwrap();

        m.change_master_password(PW, PW2).unwrap();
        m.lock();

        assert!(matches!(m.unlock(PW), Err(AppError::InvalidMasterPassword)));
        m.unlock(PW2).unwrap();
        assert_eq!(m.reveal(id, &FieldSelector::Password).unwrap(), "keep-me");
    }

    #[test]
    fn master_password_change_requires_the_current_password() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();
        assert!(matches!(
            m.change_master_password("not-the-current-one", PW2),
            Err(AppError::InvalidMasterPassword)
        ));
        // Original password still works.
        m.lock();
        m.unlock(PW).unwrap();
    }

    #[test]
    fn master_password_change_enforces_the_policy() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();
        assert!(matches!(
            m.change_master_password(PW, "weak"),
            Err(AppError::WeakMasterPassword(_))
        ));
        m.lock();
        m.unlock(PW).unwrap();
    }

    // -- auto-lock ---------------------------------------------------------

    #[test]
    fn auto_lock_triggers_only_after_the_timeout() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();

        assert!(!m.should_auto_lock(300));
        // A zero timeout means auto-lock is disabled.
        assert!(!m.should_auto_lock(0));
        // A zero-second timeout that is enabled fires immediately once any time
        // has passed; 1 second has not passed yet.
        assert!(!m.should_auto_lock(1));

        std::thread::sleep(Duration::from_millis(1100));
        assert!(m.should_auto_lock(1));
    }

    #[test]
    fn touch_defers_auto_lock() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();
        std::thread::sleep(Duration::from_millis(1100));
        assert!(m.should_auto_lock(1));

        m.touch();
        assert!(!m.should_auto_lock(1));
    }

    #[test]
    fn a_locked_vault_never_reports_idle_time() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();
        m.lock();
        assert!(m.idle_time().is_none());
        assert!(!m.should_auto_lock(1));
        // touch() on a locked vault is a no-op rather than a panic.
        m.touch();
    }

    // -- presets -----------------------------------------------------------

    #[test]
    fn presets_can_be_saved_updated_and_deleted() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();

        let preset = GeneratorPreset {
            id: Uuid::new_v4(),
            name: "  Long alphanumeric  ".into(),
            options: crate::generator::GeneratorOptions::default(),
            created_at: 0,
        };
        let id = m.save_preset(preset.clone()).unwrap();

        let listed = m.list_presets().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "Long alphanumeric", "name not trimmed");
        assert!(listed[0].created_at > 0, "created_at not stamped");

        let mut renamed = preset;
        renamed.name = "Renamed".into();
        m.save_preset(renamed).unwrap();
        assert_eq!(
            m.list_presets().unwrap().len(),
            1,
            "upsert created a duplicate"
        );
        assert_eq!(m.list_presets().unwrap()[0].name, "Renamed");

        m.delete_preset(id).unwrap();
        assert!(m.list_presets().unwrap().is_empty());
        assert!(matches!(m.delete_preset(id), Err(AppError::EntryNotFound)));
    }

    #[test]
    fn preset_requires_a_name() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();
        let preset = GeneratorPreset {
            id: Uuid::new_v4(),
            name: "   ".into(),
            options: crate::generator::GeneratorOptions::default(),
            created_at: 0,
        };
        assert!(matches!(
            m.save_preset(preset),
            Err(AppError::InvalidOptions(_))
        ));
    }

    // -- sync integration points -------------------------------------------

    /// `run_sync` re-snapshots on every retry attempt, which is only correct if
    /// `apply_sync_result` leaves the session and the disk agreeing on the
    /// revision and payload it was handed.
    #[test]
    fn apply_sync_result_is_immediately_visible_to_a_fresh_snapshot() {
        let (dir, mut m) = manager();
        m.create(PW).unwrap();
        m.create_entry(login("Local", "local-secret")).unwrap();

        let (_vault_id, kdf, wrapped) = m.header_parts().unwrap();
        let mut merged = m.payload_snapshot().unwrap();
        let mut incoming = VaultEntry::new(EntryKind::Login);
        incoming.title = "FromRemote".into();
        incoming.password = "remote-secret".into();
        merged.entries.push(incoming);

        let bytes = m.apply_sync_result(merged, kdf, wrapped, 42).unwrap();

        // The session reflects the applied revision, so a re-snapshot on a retry
        // cannot compute a revision that moves backwards.
        assert_eq!(m.revision().unwrap(), 42);
        assert_eq!(m.payload_snapshot().unwrap().entries.len(), 2);

        // The returned bytes are what landed on disk, so uploading them keeps the
        // local file and the remote object byte-identical.
        assert_eq!(
            storage::read_file(&m.paths.vault()).unwrap(),
            bytes,
            "returned bytes differ from the persisted file"
        );

        // And it really round-trips under the same master password.
        let mut fresh = VaultManager::new(Paths::new(dir.path().to_path_buf()), Uuid::new_v4());
        fresh.unlock(PW).unwrap();
        assert_eq!(fresh.revision().unwrap(), 42);
        let titles: Vec<String> = fresh
            .list_entries()
            .unwrap()
            .into_iter()
            .map(|e| e.title)
            .collect();
        assert!(titles.contains(&"FromRemote".to_string()));
        assert!(titles.contains(&"Local".to_string()));
    }

    #[test]
    fn find_by_host_matches_on_label_boundaries_only() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();

        let mut github = login("GitHub", "gh");
        github.urls = vec!["https://github.com/login".into()];
        m.create_entry(github).unwrap();

        // An entry with no password must not be offered for autofill.
        let mut passwordless = login("No password", "");
        passwordless.password = Some(String::new());
        passwordless.urls = vec!["https://github.com".into()];
        m.create_entry(passwordless).unwrap();

        assert_eq!(m.find_by_host("github.com").unwrap().len(), 1);
        assert_eq!(m.find_by_host("gist.github.com").unwrap().len(), 1);
        assert!(m.find_by_host("notgithub.com").unwrap().is_empty());
        assert!(m.find_by_host("github.com.evil.test").unwrap().is_empty());
    }

    #[test]
    fn credentials_for_requires_an_unlocked_vault() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();
        let id = m.create_entry(login("Site", "the-password")).unwrap();

        let (user, password) = m.credentials_for(id).unwrap();
        assert_eq!(user, "user");
        assert_eq!(password, "the-password");

        m.lock();
        assert!(matches!(m.credentials_for(id), Err(AppError::Locked)));
        assert!(matches!(
            m.find_by_host("example.com"),
            Err(AppError::Locked)
        ));
    }

    #[test]
    fn presets_persist_across_a_lock_cycle() {
        let (_d, mut m) = manager();
        m.create(PW).unwrap();
        m.save_preset(GeneratorPreset {
            id: Uuid::new_v4(),
            name: "Kept".into(),
            options: crate::generator::GeneratorOptions::default(),
            created_at: 0,
        })
        .unwrap();

        m.lock();
        m.unlock(PW).unwrap();
        assert_eq!(m.list_presets().unwrap()[0].name, "Kept");
    }
}
