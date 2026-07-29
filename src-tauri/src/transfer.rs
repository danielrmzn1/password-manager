//! Import from other password managers, and encrypted vault backup/export.
//!
//! Export is **encrypted only**. There is deliberately no plaintext export: a
//! CSV of every password is the single most dangerous artifact a password manager
//! can produce, and offering it invites users to leave one in their Downloads
//! folder. A backup is a self-contained `.pmv` container with its own password.

use std::collections::HashSet;

use serde::Serialize;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::generator;
use crate::vault::container;
use crate::vault::model::{now_ms, CustomField, EntryKind, VaultEntry, VaultPayload};

#[derive(Debug, Clone, Default, Serialize)]
pub struct ImportReport {
    pub imported: usize,
    /// Rows skipped because an entry with the same title and username already
    /// existed.
    pub duplicates: usize,
    /// Rows skipped because they carried no usable data.
    pub empty_rows: usize,
    pub warnings: Vec<String>,
}

/// Column aliases seen across the common exporters (Bitwarden, Chrome, Firefox,
/// 1Password, LastPass, KeePass, Safari).
const TITLE_KEYS: &[&str] = &["name", "title", "account", "display name", "entry"];
const USERNAME_KEYS: &[&str] = &[
    "login_username",
    "username",
    "user name",
    "user",
    "login name",
    "login",
    "email",
    "e-mail",
];
const PASSWORD_KEYS: &[&str] = &["login_password", "password", "pass", "pwd"];
const URL_KEYS: &[&str] = &[
    "login_uri",
    "url",
    "uri",
    "website",
    "web site",
    "login_url",
    "hostname",
];
const NOTES_KEYS: &[&str] = &["notes", "note", "comment", "comments", "extra"];
const TOTP_KEYS: &[&str] = &["login_totp", "totp", "otpauth", "otp secret", "otp"];
const FOLDER_KEYS: &[&str] = &["folder", "group", "grouping", "category", "collection"];
const FAVORITE_KEYS: &[&str] = &["favorite", "favourite", "starred"];

fn normalize(header: &str) -> String {
    header
        .trim()
        .trim_start_matches('\u{feff}') // strip a UTF-8 BOM on the first column
        .to_lowercase()
        .replace(['_', '-'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Index of the first header matching any alias.
fn find_column(headers: &[String], keys: &[&str]) -> Option<usize> {
    // Exact match first, so `password` wins over `password hint`.
    for key in keys {
        let normalized_key = normalize(key);
        if let Some(idx) = headers.iter().position(|h| *h == normalized_key) {
            return Some(idx);
        }
    }
    for key in keys {
        let normalized_key = normalize(key);
        if let Some(idx) = headers.iter().position(|h| h.contains(&normalized_key)) {
            return Some(idx);
        }
    }
    None
}

/// Parse a CSV export into vault entries.
///
/// Column detection is header-driven rather than format-specific, which covers
/// every mainstream exporter with one code path.
pub fn parse_csv(text: &str) -> Result<(Vec<VaultEntry>, ImportReport)> {
    let mut report = ImportReport::default();

    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(true)
        .from_reader(text.as_bytes());

    let headers: Vec<String> = reader
        .headers()
        .map_err(|e| AppError::Import(format!("could not read the CSV header row: {e}")))?
        .iter()
        .map(normalize)
        .collect();

    if headers.is_empty() {
        return Err(AppError::Import("the file has no header row".into()));
    }

    let title_col = find_column(&headers, TITLE_KEYS);
    let username_col = find_column(&headers, USERNAME_KEYS);
    let password_col = find_column(&headers, PASSWORD_KEYS);
    let url_col = find_column(&headers, URL_KEYS);
    let notes_col = find_column(&headers, NOTES_KEYS);
    let totp_col = find_column(&headers, TOTP_KEYS);
    let folder_col = find_column(&headers, FOLDER_KEYS);
    let favorite_col = find_column(&headers, FAVORITE_KEYS);

    if title_col.is_none() && username_col.is_none() && password_col.is_none() {
        return Err(AppError::Import(
            "could not recognise any name, username or password column in this file".into(),
        ));
    }
    if password_col.is_none() {
        report
            .warnings
            .push("No password column was found; entries were imported without passwords.".into());
    }

    let get = |record: &csv::StringRecord, col: Option<usize>| -> String {
        col.and_then(|i| record.get(i))
            .unwrap_or_default()
            .trim()
            .to_string()
    };

    let mut entries = Vec::new();
    for (row_number, record) in reader.records().enumerate() {
        let record = match record {
            Ok(record) => record,
            Err(e) => {
                report
                    .warnings
                    .push(format!("Skipped row {}: {e}", row_number + 2));
                continue;
            }
        };

        let title = get(&record, title_col);
        let username = get(&record, username_col);
        let password = get(&record, password_col);
        let url = get(&record, url_col);
        let notes = get(&record, notes_col);
        let totp = get(&record, totp_col);

        if title.is_empty() && username.is_empty() && password.is_empty() && notes.is_empty() {
            report.empty_rows += 1;
            continue;
        }

        let mut entry = VaultEntry::new(if password.is_empty() && !notes.is_empty() {
            EntryKind::Note
        } else {
            EntryKind::Login
        });

        // Fall back to something recognisable rather than importing a blank row.
        entry.title = if !title.is_empty() {
            title
        } else if !url.is_empty() {
            crate::domain::host_of(&url).unwrap_or_else(|| url.clone())
        } else if !username.is_empty() {
            username.clone()
        } else {
            "Imported entry".to_string()
        };

        entry.username = username;
        entry.password = password;
        entry.notes = notes;
        if !url.is_empty() {
            entry.urls.push(url);
        }

        let folder = get(&record, folder_col);
        if !folder.is_empty() {
            // Folders become tags: the vault model is flat by design.
            entry.tags.push(folder);
        }

        let favorite = get(&record, favorite_col).to_lowercase();
        entry.favorite = matches!(favorite.as_str(), "1" | "true" | "yes" | "y");

        if !totp.is_empty() {
            // TOTP is not a first-class feature yet, so preserve it as a secret
            // custom field rather than dropping it on the floor.
            entry.custom_fields.push(CustomField {
                id: Uuid::new_v4(),
                label: "TOTP".to_string(),
                value: totp,
                secret: true,
            });
        }

        entries.push(entry);
    }

    Ok((entries, report))
}

/// Add `incoming` entries to `payload`, skipping ones that look already present.
pub fn merge_imported(
    payload: &mut VaultPayload,
    incoming: Vec<VaultEntry>,
    report: &mut ImportReport,
) {
    let existing: HashSet<(String, String)> = payload
        .entries
        .iter()
        .map(|e| (e.title.to_lowercase(), e.username.to_lowercase()))
        .collect();

    let mut seen_in_batch: HashSet<(String, String)> = HashSet::new();

    for entry in incoming {
        let key = (entry.title.to_lowercase(), entry.username.to_lowercase());
        if existing.contains(&key) || !seen_in_batch.insert(key) {
            report.duplicates += 1;
            continue;
        }

        // Restoring a backup re-adds entries under their original ids. If one of
        // those ids was deleted since the backup was taken, its tombstone is still
        // present and the next sync merge would delete the restored entry again —
        // so drop the tombstone as part of the restore.
        payload.tombstones.retain(|t| t.id != entry.id);

        payload.entries.push(entry);
        report.imported += 1;
    }
}

/// Produce a self-contained encrypted backup of `payload`.
///
/// The backup is a normal `.pmv` container with a **fresh** salt and a fresh
/// data key, protected by `backup_password`. It shares no key material with the
/// live vault, so handing a backup to someone does not expose the live vault even
/// if the backup password later leaks.
pub fn export_backup(
    payload: &VaultPayload,
    backup_password: &str,
    device_id: Uuid,
) -> Result<Vec<u8>> {
    generator::enforce_master_password_policy(backup_password)?;
    let (bytes, _unlocked) = container::create(backup_password, payload, device_id)?;
    Ok(bytes)
}

/// Read a `.pmv` backup, returning its entries for merging.
pub fn read_backup(bytes: &[u8], backup_password: &str) -> Result<Vec<VaultEntry>> {
    let parsed = container::parse(bytes)?;
    let unlocked = parsed.unlock(backup_password)?;
    Ok(unlocked.payload.entries.clone())
}

/// A suggested filename for an export, e.g. `vault-backup-1753800000000.pmv`.
pub fn suggested_backup_filename() -> String {
    format!("vault-backup-{}.pmv", now_ms())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_a_bitwarden_export() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                   Work,1,login,GitHub,some notes,,0,https://github.com,daniel,gh-pass,JBSWY3DPEHPK3PXP\n\
                   ,0,login,Example,,,0,https://example.com,user@example.com,ex-pass,\n";

        let (entries, report) = parse_csv(csv).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);

        let gh = &entries[0];
        assert_eq!(gh.title, "GitHub");
        assert_eq!(gh.username, "daniel");
        assert_eq!(gh.password, "gh-pass");
        assert_eq!(gh.urls, vec!["https://github.com"]);
        assert_eq!(gh.notes, "some notes");
        assert_eq!(gh.tags, vec!["Work"]);
        assert!(gh.favorite);
        assert_eq!(gh.custom_fields.len(), 1);
        assert_eq!(gh.custom_fields[0].label, "TOTP");
        assert_eq!(gh.custom_fields[0].value, "JBSWY3DPEHPK3PXP");
        assert!(gh.custom_fields[0].secret);

        assert_eq!(entries[1].username, "user@example.com");
        assert!(!entries[1].favorite);
        assert!(entries[1].tags.is_empty());
    }

    #[test]
    fn imports_a_chrome_export() {
        let csv = "name,url,username,password\n\
                   example.com,https://example.com/login,daniel,secret1\n";
        let (entries, _) = parse_csv(csv).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "example.com");
        assert_eq!(entries[0].password, "secret1");
        assert_eq!(entries[0].urls, vec!["https://example.com/login"]);
    }

    #[test]
    fn imports_a_lastpass_style_export() {
        let csv = "url,username,password,totp,extra,name,grouping,fav\n\
                   https://site.test,me,pw,,a note,Site,Personal,0\n";
        let (entries, _) = parse_csv(csv).unwrap();
        assert_eq!(entries[0].title, "Site");
        assert_eq!(entries[0].notes, "a note");
        assert_eq!(entries[0].tags, vec!["Personal"]);
    }

    #[test]
    fn handles_a_bom_and_odd_header_casing() {
        let csv = "\u{feff}Name,Login Name,Password\nSite,daniel,pw\n";
        let (entries, _) = parse_csv(csv).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "Site");
        assert_eq!(entries[0].username, "daniel");
        assert_eq!(entries[0].password, "pw");
    }

    #[test]
    fn quoted_fields_with_commas_and_newlines_survive() {
        let csv = "name,username,password,notes\n\
                   \"Bank, National\",me,\"pa,ss\",\"line one\nline two\"\n";
        let (entries, _) = parse_csv(csv).unwrap();
        assert_eq!(entries[0].title, "Bank, National");
        assert_eq!(entries[0].password, "pa,ss");
        assert_eq!(entries[0].notes, "line one\nline two");
    }

    #[test]
    fn exact_header_match_beats_a_substring_match() {
        // `password hint` must not be picked in preference to `password`.
        let csv = "name,password hint,password\nSite,my hint,real-password\n";
        let (entries, _) = parse_csv(csv).unwrap();
        assert_eq!(entries[0].password, "real-password");
    }

    #[test]
    fn rows_with_no_usable_data_are_counted_not_imported() {
        let csv = "name,username,password\nSite,me,pw\n,,\n,,\n";
        let (entries, report) = parse_csv(csv).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(report.empty_rows, 2);
    }

    #[test]
    fn a_row_without_a_title_falls_back_to_the_host() {
        let csv = "name,url,username,password\n,https://fallback.test/login,me,pw\n";
        let (entries, _) = parse_csv(csv).unwrap();
        assert_eq!(entries[0].title, "fallback.test");
    }

    #[test]
    fn notes_only_rows_become_note_entries() {
        let csv = "name,notes\nMy secret note,the body\n";
        let (entries, _) = parse_csv(csv).unwrap();
        assert_eq!(entries[0].kind, EntryKind::Note);
        assert_eq!(entries[0].notes, "the body");
    }

    #[test]
    fn unrecognisable_files_are_rejected_with_a_clear_error() {
        let err = parse_csv("alpha,beta,gamma\n1,2,3\n").unwrap_err();
        assert!(matches!(err, AppError::Import(_)), "{err:?}");
    }

    #[test]
    fn a_missing_password_column_warns_but_still_imports() {
        let csv = "name,username\nSite,daniel\n";
        let (entries, report) = parse_csv(csv).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].password.is_empty());
        assert_eq!(report.warnings.len(), 1);
    }

    #[test]
    fn empty_input_is_rejected_rather_than_panicking() {
        assert!(parse_csv("").is_err());
    }

    #[test]
    fn merge_skips_duplicates_within_the_batch_and_against_the_vault() {
        let mut payload = VaultPayload::default();
        let mut existing = VaultEntry::new(EntryKind::Login);
        existing.title = "GitHub".into();
        existing.username = "daniel".into();
        payload.entries.push(existing);

        let csv = "name,username,password\n\
                   GitHub,daniel,dup\n\
                   github,DANIEL,also-dup\n\
                   GitLab,daniel,fresh\n\
                   GitLab,daniel,batch-dup\n";
        let (entries, mut report) = parse_csv(csv).unwrap();
        merge_imported(&mut payload, entries, &mut report);

        assert_eq!(report.imported, 1);
        assert_eq!(report.duplicates, 3);
        assert_eq!(payload.entries.len(), 2);
        assert!(payload.entries.iter().any(|e| e.title == "GitLab"));
    }

    // -- backup round trip -------------------------------------------------

    fn payload_with_secret() -> VaultPayload {
        let mut payload = VaultPayload::default();
        let mut entry = VaultEntry::new(EntryKind::Login);
        entry.title = "Backed up".into();
        entry.password = "the-backed-up-secret".into();
        payload.entries.push(entry);
        payload
    }

    /// Restoring an entry that was deleted after the backup was taken must clear
    /// its tombstone, or the next sync merge deletes the restored entry again.
    #[test]
    fn restoring_a_deleted_entry_clears_its_tombstone() {
        use crate::vault::model::Tombstone;

        let mut restored = VaultEntry::new(EntryKind::Login);
        restored.title = "Deleted then restored".into();
        let id = restored.id;

        let mut payload = VaultPayload::default();
        payload.tombstones.push(Tombstone {
            id,
            deleted_at: now_ms(),
        });

        let mut report = ImportReport::default();
        merge_imported(&mut payload, vec![restored], &mut report);

        assert_eq!(report.imported, 1);
        assert!(
            !payload.is_deleted(id),
            "the tombstone survived the restore, so a merge would delete it again"
        );

        // And the restore is stable through a merge with itself.
        let (merged, _) = crate::sync::merge::merge(&payload, &VaultPayload::default());
        assert_eq!(merged.entries.len(), 1);
    }

    #[test]
    fn backup_round_trips_and_is_encrypted() {
        let password = "a-strong-backup-passphrase-42";
        let bytes = export_backup(&payload_with_secret(), password, Uuid::new_v4()).unwrap();

        assert!(
            !bytes
                .windows(b"the-backed-up-secret".len())
                .any(|w| w == b"the-backed-up-secret"),
            "backup is not encrypted"
        );

        let restored = read_backup(&bytes, password).unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].password, "the-backed-up-secret");

        assert!(read_backup(&bytes, "the-wrong-password-entirely").is_err());
    }

    #[test]
    fn backup_uses_fresh_key_material_each_time() {
        let password = "a-strong-backup-passphrase-42";
        let a = export_backup(&payload_with_secret(), password, Uuid::new_v4()).unwrap();
        let b = export_backup(&payload_with_secret(), password, Uuid::new_v4()).unwrap();

        let salt_a = container::parse(&a).unwrap().header.kdf.salt.clone();
        let salt_b = container::parse(&b).unwrap().header.kdf.salt.clone();
        assert_ne!(salt_a, salt_b, "backups must not share a salt");
    }

    #[test]
    fn backup_enforces_the_password_policy() {
        assert!(matches!(
            export_backup(&payload_with_secret(), "weak", Uuid::new_v4()),
            Err(AppError::WeakMasterPassword(_))
        ));
    }

    #[test]
    fn reading_a_non_backup_file_fails_cleanly() {
        assert!(read_backup(b"not a vault at all", "whatever-password-here").is_err());
        assert!(read_backup(&[], "whatever-password-here").is_err());
    }

    #[test]
    fn suggested_filename_has_the_right_extension() {
        assert!(suggested_backup_filename().ends_with(".pmv"));
    }
}
