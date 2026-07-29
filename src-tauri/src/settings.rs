//! Device-local, non-secret preferences.
//!
//! These are stored as plaintext JSON on purpose: they must be readable before
//! the vault is unlocked (the lock screen needs the theme, the auto-lock timer
//! needs its timeout). Nothing secret is allowed in here — S3 credentials live
//! in the encrypted `sync.enc`, see [`crate::sync`].

use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::storage::{self, Paths};

/// Five minutes. Chosen as the default because it is the shortest timeout that
/// does not make ordinary use annoying — per AGENTS.md, hygiene features default
/// to the safe option.
pub const DEFAULT_LOCK_TIMEOUT_SECS: u64 = 300;
/// Thirty seconds is long enough to paste into a login form and short enough
/// that a forgotten clipboard is not left holding a password.
pub const DEFAULT_CLIPBOARD_CLEAR_SECS: u64 = 30;

const MAX_LOCK_TIMEOUT_SECS: u64 = 24 * 60 * 60;
const MAX_CLIPBOARD_CLEAR_SECS: u64 = 10 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    #[default]
    System,
    Light,
    Dark,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Seconds of inactivity before the vault locks. `0` disables auto-lock.
    pub lock_timeout_secs: u64,
    /// Seconds before a copied secret is cleared from the clipboard. `0`
    /// disables clearing.
    pub clipboard_clear_secs: u64,
    pub theme: Theme,
    /// Lock as soon as the window loses focus. Off by default because it makes
    /// copy-pasting into a browser painful.
    pub lock_on_blur: bool,
    /// Pull remote changes right after a successful unlock.
    pub sync_on_unlock: bool,
    /// Push after every change to the vault.
    pub sync_on_save: bool,
    /// Whether the browser-extension bridge listener is allowed to run.
    pub bridge_enabled: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            lock_timeout_secs: DEFAULT_LOCK_TIMEOUT_SECS,
            clipboard_clear_secs: DEFAULT_CLIPBOARD_CLEAR_SECS,
            theme: Theme::System,
            lock_on_blur: false,
            sync_on_unlock: true,
            sync_on_save: true,
            bridge_enabled: false,
        }
    }
}

impl Settings {
    /// Clamp values into supported ranges. Applied on both load and save so a
    /// hand-edited settings file cannot disable protections by accident or set a
    /// nonsensical timeout.
    pub fn sanitize(&mut self) {
        self.lock_timeout_secs = self.lock_timeout_secs.min(MAX_LOCK_TIMEOUT_SECS);
        self.clipboard_clear_secs = self.clipboard_clear_secs.min(MAX_CLIPBOARD_CLEAR_SECS);
    }

    pub fn load(paths: &Paths) -> Self {
        let path = paths.settings();
        let mut settings = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Settings>(&bytes).ok())
            // A missing or unreadable settings file must not stop the app from
            // starting; falling back to defaults is both safe and expected on
            // first launch.
            .unwrap_or_default();
        settings.sanitize();
        settings
    }

    pub fn save(&mut self, paths: &Paths) -> Result<()> {
        self.sanitize();
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|_| AppError::Other("could not serialize settings".into()))?;
        paths.ensure_dir()?;
        storage::write_atomic(&paths.settings(), &bytes)
    }
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
    fn defaults_are_the_safe_options() {
        let s = Settings::default();
        assert_eq!(s.lock_timeout_secs, 300);
        assert_eq!(s.clipboard_clear_secs, 30);
        assert!(!s.bridge_enabled, "the extension bridge must be opt-in");
        assert_eq!(s.theme, Theme::System);
    }

    #[test]
    fn round_trips_through_disk() {
        let (_dir, paths) = temp_paths();
        let mut s = Settings {
            lock_timeout_secs: 60,
            theme: Theme::Dark,
            bridge_enabled: true,
            ..Default::default()
        };
        s.save(&paths).unwrap();

        let loaded = Settings::load(&paths);
        assert_eq!(loaded.lock_timeout_secs, 60);
        assert_eq!(loaded.theme, Theme::Dark);
        assert!(loaded.bridge_enabled);
    }

    #[test]
    fn missing_file_yields_defaults() {
        let (_dir, paths) = temp_paths();
        let loaded = Settings::load(&paths);
        assert_eq!(loaded.lock_timeout_secs, DEFAULT_LOCK_TIMEOUT_SECS);
    }

    #[test]
    fn corrupt_file_yields_defaults_rather_than_failing() {
        let (_dir, paths) = temp_paths();
        std::fs::write(paths.settings(), b"{ not json").unwrap();
        assert_eq!(
            Settings::load(&paths).lock_timeout_secs,
            DEFAULT_LOCK_TIMEOUT_SECS
        );
    }

    #[test]
    fn partial_file_keeps_defaults_for_absent_fields() {
        let (_dir, paths) = temp_paths();
        std::fs::write(paths.settings(), br#"{"theme":"light"}"#).unwrap();
        let loaded = Settings::load(&paths);
        assert_eq!(loaded.theme, Theme::Light);
        assert_eq!(loaded.clipboard_clear_secs, DEFAULT_CLIPBOARD_CLEAR_SECS);
    }

    #[test]
    fn absurd_values_are_clamped() {
        let (_dir, paths) = temp_paths();
        std::fs::write(
            paths.settings(),
            br#"{"lock_timeout_secs": 99999999, "clipboard_clear_secs": 99999999}"#,
        )
        .unwrap();
        let loaded = Settings::load(&paths);
        assert_eq!(loaded.lock_timeout_secs, MAX_LOCK_TIMEOUT_SECS);
        assert_eq!(loaded.clipboard_clear_secs, MAX_CLIPBOARD_CLEAR_SECS);
    }

    #[test]
    fn zero_means_disabled_and_is_preserved() {
        let mut s = Settings {
            lock_timeout_secs: 0,
            clipboard_clear_secs: 0,
            ..Default::default()
        };
        s.sanitize();
        assert_eq!(s.lock_timeout_secs, 0);
        assert_eq!(s.clipboard_clear_secs, 0);
    }

    #[test]
    fn settings_file_contains_no_secrets() {
        // Guards against someone adding a credential field here later.
        let json = serde_json::to_string(&Settings::default()).unwrap();
        for banned in ["password", "secret", "access_key", "token", "key"] {
            assert!(
                !json.to_lowercase().contains(banned),
                "settings must not carry a {banned:?} field: {json}"
            );
        }
    }
}
