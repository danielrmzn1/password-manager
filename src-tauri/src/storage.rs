//! Filesystem layout and durable, atomic file writes.
//!
//! Every secret-bearing file goes through [`write_atomic`], which writes to a
//! temporary sibling, `fsync`s it, then renames over the target. A crash or a
//! power loss mid-save therefore leaves either the previous file or the new one
//! — never a half-written vault, which would be unrecoverable.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AppError, Result};

pub const VAULT_FILE: &str = "vault.pmv";
pub const VAULT_BACKUP_FILE: &str = "vault.pmv.bak";
pub const SYNC_FILE: &str = "sync.enc";
pub const BRIDGE_FILE: &str = "bridge.enc";
pub const SETTINGS_FILE: &str = "settings.json";
pub const DEVICE_FILE: &str = "device.json";

#[derive(Debug, Clone)]
pub struct Paths {
    pub data_dir: PathBuf,
}

impl Paths {
    pub fn new(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    pub fn vault(&self) -> PathBuf {
        self.data_dir.join(VAULT_FILE)
    }
    pub fn vault_backup(&self) -> PathBuf {
        self.data_dir.join(VAULT_BACKUP_FILE)
    }
    pub fn sync(&self) -> PathBuf {
        self.data_dir.join(SYNC_FILE)
    }
    pub fn bridge(&self) -> PathBuf {
        self.data_dir.join(BRIDGE_FILE)
    }
    pub fn settings(&self) -> PathBuf {
        self.data_dir.join(SETTINGS_FILE)
    }
    pub fn device(&self) -> PathBuf {
        self.data_dir.join(DEVICE_FILE)
    }

    pub fn ensure_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.data_dir)
            .map_err(|e| AppError::io("could not create the application data directory", e))?;
        restrict_permissions(&self.data_dir)?;
        Ok(())
    }

    pub fn vault_exists(&self) -> bool {
        self.vault().is_file()
    }
}

/// Tighten permissions so other users on the machine cannot read the vault.
///
/// On Unix this is `0700` for directories and `0600` for files. On Windows the
/// per-user profile directory already restricts access and there is no direct
/// mode equivalent, so this is a no-op there.
#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let meta = fs::metadata(path).map_err(|e| AppError::io("could not stat a data file", e))?;
    let mode = if meta.is_dir() { 0o700 } else { 0o600 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| AppError::io("could not restrict permissions on a data file", e))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// Write `bytes` to `path` atomically and durably.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| AppError::Other("invalid data path".into()))?;
    fs::create_dir_all(parent)
        .map_err(|e| AppError::io("could not create the application data directory", e))?;

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| AppError::Other("invalid data path".into()))?;

    // The staging name is unique per call. A fixed `.{name}.tmp` would let two
    // concurrent writers of the same target interleave their writes into one
    // staging file and then rename a corrupt mixture into place. Nothing in the
    // app currently writes the same file from two threads at once, but
    // `sync.enc` is written from spawned sync tasks, so this is cheap insurance.
    let unique = {
        let mut bytes = [0u8; 8];
        // A failure here is not worth aborting a save for; fall back to the pid,
        // which still distinguishes processes.
        if crate::crypto::random::fill(&mut bytes).is_err() {
            bytes[..4].copy_from_slice(&std::process::id().to_le_bytes());
        }
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    let tmp = parent.join(format!(".{file_name}.{unique}.tmp"));

    {
        let mut file = fs::File::create(&tmp)
            .map_err(|e| AppError::io("could not open a temporary file for writing", e))?;
        // Restrict before writing the payload, so the secret is never briefly
        // readable by other users.
        restrict_permissions(&tmp)?;
        file.write_all(bytes)
            .map_err(|e| AppError::io("could not write to a temporary file", e))?;
        file.flush()
            .map_err(|e| AppError::io("could not flush a temporary file", e))?;
        // Without this the rename can be durable while the contents are not.
        file.sync_all()
            .map_err(|e| AppError::io("could not fsync a temporary file", e))?;
    }

    fs::rename(&tmp, path).map_err(|e| {
        // Best effort: do not leave the temporary file behind on failure.
        let _ = fs::remove_file(&tmp);
        AppError::io("could not replace the data file", e)
    })?;

    // Persist the directory entry itself. Not available on Windows; harmless
    // to skip there because NTFS metadata ordering already covers this.
    #[cfg(unix)]
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| AppError::io("could not read a data file", e))
}

/// A stable identifier for this installation.
///
/// Written to the vault header so the sync layer can tell "my own last upload"
/// apart from "another device's upload". It is a random UUID with no relation to
/// any hardware identifier, so it carries no fingerprinting value.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeviceFile {
    device_id: Uuid,
}

pub fn load_or_create_device_id(paths: &Paths) -> Result<Uuid> {
    let path = paths.device();
    if path.is_file() {
        if let Ok(bytes) = fs::read(&path) {
            if let Ok(parsed) = serde_json::from_slice::<DeviceFile>(&bytes) {
                return Ok(parsed.device_id);
            }
        }
        // A corrupt device file is not worth failing startup over: mint a new id.
    }

    let device_id = Uuid::new_v4();
    let bytes = serde_json::to_vec_pretty(&DeviceFile { device_id })
        .map_err(|_| AppError::Other("could not serialize the device file".into()))?;
    paths.ensure_dir()?;
    write_atomic(&path, &bytes)?;
    Ok(device_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_paths() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().to_path_buf());
        paths.ensure_dir().unwrap();
        (dir, paths)
    }

    #[test]
    fn atomic_write_creates_and_replaces() {
        let (_dir, paths) = temp_paths();
        let target = paths.vault();

        write_atomic(&target, b"first").unwrap();
        assert_eq!(read_file(&target).unwrap(), b"first");

        write_atomic(&target, b"second-and-longer").unwrap();
        assert_eq!(read_file(&target).unwrap(), b"second-and-longer");
    }

    #[test]
    fn atomic_write_leaves_no_temporary_files() {
        let (_dir, paths) = temp_paths();
        write_atomic(&paths.vault(), b"data").unwrap();

        let leftovers: Vec<_> = fs::read_dir(&paths.data_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn written_files_are_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, paths) = temp_paths();
        write_atomic(&paths.vault(), b"secret").unwrap();

        let mode = fs::metadata(paths.vault()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "vault file mode is {mode:o}");

        let dir_mode = fs::metadata(&paths.data_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "data dir mode is {dir_mode:o}");
    }

    #[test]
    fn device_id_is_stable_across_calls() {
        let (_dir, paths) = temp_paths();
        let first = load_or_create_device_id(&paths).unwrap();
        let second = load_or_create_device_id(&paths).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn corrupt_device_file_is_replaced_rather_than_fatal() {
        let (_dir, paths) = temp_paths();
        fs::write(paths.device(), b"not json at all").unwrap();
        let id = load_or_create_device_id(&paths).unwrap();
        assert_eq!(load_or_create_device_id(&paths).unwrap(), id);
    }

    #[test]
    fn vault_exists_reflects_reality() {
        let (_dir, paths) = temp_paths();
        assert!(!paths.vault_exists());
        write_atomic(&paths.vault(), b"x").unwrap();
        assert!(paths.vault_exists());
    }
}
