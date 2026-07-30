//! The decrypted vault payload and the DTOs exposed to the frontend.
//!
//! # Why there are separate "summary"/"detail" types
//!
//! The frontend is a webview. Anything handed to it lives in JS heap memory we
//! do not control and cannot scrub. So the IPC boundary is treated as a
//! privilege boundary: list and detail views receive **no secret values at
//! all**. A secret crosses into JS only when the user explicitly reveals that
//! one field, and copy-to-clipboard is performed entirely in Rust so the value
//! never crosses at all.
//!
//! See [`crate::vault::model::FieldSelector`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

/// Version of the *payload* schema (distinct from the container's
/// `format_version`). Bump when entry structure changes incompatibly.
pub const SCHEMA_VERSION: u32 = 1;

/// How long deletions are remembered so they are not resurrected by a device
/// that has been offline. 180 days.
pub const TOMBSTONE_RETENTION_MS: i64 = 180 * 24 * 60 * 60 * 1000;

/// Current wall-clock time in unix epoch milliseconds.
///
/// Saturates rather than panicking if the system clock is set before 1970.
pub fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    /// A credential: username + password + URLs.
    #[default]
    Login,
    /// A free-form secret or note with no credential fields.
    Note,
}

/// A user-defined extra field on an entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomField {
    pub id: Uuid,
    pub label: String,
    pub value: String,
    /// Whether the value should be masked in the UI. Does not affect storage —
    /// the whole payload is equally encrypted either way.
    #[serde(default)]
    pub secret: bool,
}

impl Drop for CustomField {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// One vault record.
///
/// `extra` preserves fields written by a newer release so that opening a shared
/// vault with an older client does not silently strip data from it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: Uuid,
    #[serde(default)]
    pub kind: EntryKind,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub updated_at: i64,
    /// Tracked separately from `updated_at` so a future password-health report
    /// can flag stale passwords without a schema change.
    #[serde(default)]
    pub password_updated_at: i64,
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// Best-effort scrubbing of the secret-bearing fields.
///
/// This is explicitly *best effort*: `Vec<VaultEntry>` reallocation and serde's
/// intermediate buffers can leave copies in freed heap pages that safe Rust
/// cannot reach. Scrubbing the obvious long-lived copies still meaningfully
/// shrinks the window in which a core dump or swapped page exposes a password.
impl Drop for VaultEntry {
    fn drop(&mut self) {
        self.password.zeroize();
        self.notes.zeroize();
        self.username.zeroize();
    }
}

impl VaultEntry {
    pub fn new(kind: EntryKind) -> Self {
        let now = now_ms();
        Self {
            id: Uuid::new_v4(),
            kind,
            title: String::new(),
            username: String::new(),
            password: String::new(),
            urls: Vec::new(),
            notes: String::new(),
            custom_fields: Vec::new(),
            tags: Vec::new(),
            favorite: false,
            created_at: now,
            updated_at: now,
            password_updated_at: now,
            extra: BTreeMap::new(),
        }
    }

    pub fn summary(&self) -> EntrySummary {
        EntrySummary {
            id: self.id,
            kind: self.kind,
            title: self.title.clone(),
            username: self.username.clone(),
            urls: self.urls.clone(),
            tags: self.tags.clone(),
            favorite: self.favorite,
            updated_at: self.updated_at,
            has_password: !self.password.is_empty(),
            has_notes: !self.notes.is_empty(),
            custom_field_count: self.custom_fields.len(),
        }
    }

    pub fn detail(&self) -> EntryDetail {
        EntryDetail {
            id: self.id,
            kind: self.kind,
            title: self.title.clone(),
            username: self.username.clone(),
            urls: self.urls.clone(),
            tags: self.tags.clone(),
            favorite: self.favorite,
            created_at: self.created_at,
            updated_at: self.updated_at,
            password_updated_at: self.password_updated_at,
            has_password: !self.password.is_empty(),
            has_notes: !self.notes.is_empty(),
            // Notes are shown inline in the detail view and are not masked, so
            // they are included. Passwords never are.
            notes: self.notes.clone(),
            custom_fields: self
                .custom_fields
                .iter()
                .map(|f| CustomFieldView {
                    id: f.id,
                    label: f.label.clone(),
                    secret: f.secret,
                    value: if f.secret {
                        None
                    } else {
                        Some(f.value.clone())
                    },
                })
                .collect(),
        }
    }
}

/// Records that an entry was deleted, so the deletion survives a merge with a
/// device that still has the entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Tombstone {
    pub id: Uuid,
    pub deleted_at: i64,
}

/// The decrypted vault body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultPayload {
    pub schema: u32,
    #[serde(default)]
    pub entries: Vec<VaultEntry>,
    #[serde(default)]
    pub tombstones: Vec<Tombstone>,
    #[serde(default)]
    pub generator_presets: Vec<crate::generator::GeneratorPreset>,
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl Default for VaultPayload {
    fn default() -> Self {
        Self {
            schema: SCHEMA_VERSION,
            entries: Vec::new(),
            tombstones: Vec::new(),
            generator_presets: Vec::new(),
            extra: BTreeMap::new(),
        }
    }
}

impl VaultPayload {
    pub fn find(&self, id: Uuid) -> Option<&VaultEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub fn find_mut(&mut self, id: Uuid) -> Option<&mut VaultEntry> {
        self.entries.iter_mut().find(|e| e.id == id)
    }

    pub fn is_deleted(&self, id: Uuid) -> bool {
        self.tombstones.iter().any(|t| t.id == id)
    }

    /// Drop tombstones older than the retention window.
    pub fn gc_tombstones(&mut self, now: i64) {
        self.tombstones
            .retain(|t| now.saturating_sub(t.deleted_at) < TOMBSTONE_RETENTION_MS);
    }
}

// ---------------------------------------------------------------------------
// DTOs sent to the frontend. None of these carry a password.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct EntrySummary {
    pub id: Uuid,
    pub kind: EntryKind,
    pub title: String,
    pub username: String,
    pub urls: Vec<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub updated_at: i64,
    pub has_password: bool,
    pub has_notes: bool,
    pub custom_field_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CustomFieldView {
    pub id: Uuid,
    pub label: String,
    pub secret: bool,
    /// `None` when `secret` is true — the value must be fetched with an explicit
    /// reveal.
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EntryDetail {
    pub id: Uuid,
    pub kind: EntryKind,
    pub title: String,
    pub username: String,
    pub urls: Vec<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub created_at: i64,
    pub updated_at: i64,
    pub password_updated_at: i64,
    pub has_password: bool,
    pub has_notes: bool,
    pub notes: String,
    pub custom_fields: Vec<CustomFieldView>,
}

/// Identifies a single secret field, for reveal and clipboard-copy operations.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "field", rename_all = "snake_case")]
pub enum FieldSelector {
    Password,
    Username,
    Notes,
    Custom { id: Uuid },
}

/// What the frontend sends when creating or updating an entry.
///
/// Optional secret fields mean "leave unchanged" on update, which lets the edit
/// form round-trip an entry without ever having received its password.
#[derive(Debug, Clone, Deserialize)]
pub struct EntryInput {
    #[serde(default)]
    pub kind: EntryKind,
    pub title: String,
    #[serde(default)]
    pub username: String,
    /// `None` = leave the stored password untouched.
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub custom_fields: Vec<CustomFieldInput>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CustomFieldInput {
    /// Absent for a newly added field.
    #[serde(default)]
    pub id: Option<Uuid>,
    pub label: String,
    /// `None` = keep the existing value for this field id.
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub secret: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_and_detail_never_expose_the_password() {
        let mut e = VaultEntry::new(EntryKind::Login);
        e.title = "GitHub".into();
        e.username = "daniel".into();
        e.password = "sup3r-s3cret".into();
        e.notes = "a note".into();
        e.custom_fields.push(CustomField {
            id: Uuid::new_v4(),
            label: "Recovery".into(),
            value: "hidden-value".into(),
            secret: true,
        });
        e.custom_fields.push(CustomField {
            id: Uuid::new_v4(),
            label: "Plan".into(),
            value: "pro".into(),
            secret: false,
        });

        let summary = serde_json::to_string(&e.summary()).unwrap();
        assert!(!summary.contains("sup3r-s3cret"));
        assert!(!summary.contains("hidden-value"));
        assert!(summary.contains("\"has_password\":true"));

        let detail = serde_json::to_string(&e.detail()).unwrap();
        assert!(!detail.contains("sup3r-s3cret"));
        assert!(!detail.contains("hidden-value"));
        // Non-secret custom fields and notes are shown inline.
        assert!(detail.contains("pro"));
        assert!(detail.contains("a note"));
    }

    #[test]
    fn unknown_fields_survive_a_round_trip() {
        let json = r#"{
            "id": "6f1c4e60-0f4a-4d5c-9c9d-2f3f5b7a1111",
            "kind": "login",
            "title": "Example",
            "created_at": 1,
            "updated_at": 2,
            "totp_secret": "JBSWY3DPEHPK3PXP",
            "future_flag": true
        }"#;
        let entry: VaultEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.extra.len(), 2);

        let back = serde_json::to_value(&entry).unwrap();
        assert_eq!(back["totp_secret"], "JBSWY3DPEHPK3PXP");
        assert_eq!(back["future_flag"], true);
    }

    #[test]
    fn tombstone_gc_respects_the_retention_window() {
        let mut payload = VaultPayload::default();
        let now = 1_000_000_000_000i64;
        payload.tombstones.push(Tombstone {
            id: Uuid::new_v4(),
            deleted_at: now - TOMBSTONE_RETENTION_MS - 1,
        });
        let keep = Uuid::new_v4();
        payload.tombstones.push(Tombstone {
            id: keep,
            deleted_at: now - 1000,
        });

        payload.gc_tombstones(now);
        assert_eq!(payload.tombstones.len(), 1);
        assert_eq!(payload.tombstones[0].id, keep);
    }

    #[test]
    fn payload_defaults_fill_in_missing_collections() {
        let payload: VaultPayload = serde_json::from_str(r#"{"schema":1}"#).unwrap();
        assert!(payload.entries.is_empty());
        assert!(payload.tombstones.is_empty());
        assert!(payload.generator_presets.is_empty());
    }
}
