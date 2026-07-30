//! Shared application state and the events the backend pushes to the UI.

use std::sync::atomic::AtomicU64;
use std::sync::Mutex;

use crate::settings::Settings;
use crate::storage::Paths;
use crate::sync::SyncConfig;
use crate::vault::manager::VaultManager;

/// Event names. The frontend subscribes to these rather than polling.
pub mod events {
    /// The vault was locked. Payload: `{ "reason": "timeout" | "manual" | "blur" }`.
    pub const LOCKED: &str = "vault://locked";
    /// Vault contents changed underneath the UI (e.g. a sync merge landed).
    pub const CHANGED: &str = "vault://changed";
    /// A copied secret was wiped from the clipboard.
    pub const CLIPBOARD_CLEARED: &str = "clipboard://cleared";
    /// Sync progress. Payload: [`crate::sync::SyncStatus`].
    pub const SYNC_STATUS: &str = "sync://status";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockReason {
    Timeout,
    Manual,
    Blur,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LockedEvent {
    pub reason: LockReason,
}

pub struct AppState {
    pub vault: Mutex<VaultManager>,
    pub settings: Mutex<Settings>,
    pub paths: Paths,
    /// Bumped on every clipboard write, so a pending auto-clear task can tell
    /// whether it is still the most recent copy before wiping anything.
    pub clipboard_generation: AtomicU64,
    /// Decrypted sync configuration, populated on unlock and dropped on lock.
    pub sync_config: Mutex<Option<SyncConfig>>,
    /// A shutdown handle for the extension bridge listener, when running.
    pub bridge: Mutex<Option<crate::bridge::BridgeHandle>>,
}

impl AppState {
    pub fn new(paths: Paths, settings: Settings, vault: VaultManager) -> Self {
        Self {
            vault: Mutex::new(vault),
            settings: Mutex::new(settings),
            paths,
            clipboard_generation: AtomicU64::new(0),
            sync_config: Mutex::new(None),
            bridge: Mutex::new(None),
        }
    }

    /// Lock helpers. A poisoned mutex means another thread panicked while
    /// holding vault state; recovering the guard is safe here because every
    /// mutation either completes or leaves the previous value intact, and
    /// refusing to ever unlock again would be worse for the user than
    /// continuing.
    pub fn vault(&self) -> std::sync::MutexGuard<'_, VaultManager> {
        self.vault.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn settings(&self) -> std::sync::MutexGuard<'_, Settings> {
        self.settings.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn sync_config(&self) -> std::sync::MutexGuard<'_, Option<SyncConfig>> {
        self.sync_config.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn bridge(&self) -> std::sync::MutexGuard<'_, Option<crate::bridge::BridgeHandle>> {
        self.bridge.lock().unwrap_or_else(|e| e.into_inner())
    }
}
