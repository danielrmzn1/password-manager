//! A local-first, end-to-end encrypted password manager.
//!
//! Module map:
//!
//! - [`crypto`] — the only place cryptography happens (Argon2id, XChaCha20-Poly1305, CSPRNG).
//! - [`vault`] — container format, data model, and the lock state machine.
//! - [`generator`] — password and passphrase generation.
//! - [`sync`] — S3-compatible replication and the merge algorithm.
//! - [`bridge`] — loopback listener for the browser extension.
//! - [`commands`] — the Tauri command surface, i.e. the webview's entire API.
//!
//! Design notes live in `docs/`: `vault-format.md`, `sync-protocol.md`,
//! `extension-bridge.md`.

pub mod bridge;
pub mod clipboard;
pub mod commands;
pub mod crypto;
pub mod domain;
pub mod error;
pub mod generator;
pub mod settings;
pub mod state;
pub mod storage;
pub mod sync;
pub mod transfer;
pub mod vault;

use std::time::Duration;

use tauri::{Emitter, Manager};

use crate::settings::Settings;
use crate::state::{AppState, LockReason};
use crate::storage::Paths;
use crate::vault::manager::VaultManager;

/// How often the auto-lock timer is evaluated. Fine-grained enough that the
/// vault locks promptly after the configured timeout without busy-waiting.
const LOCK_TICK: Duration = Duration::from_secs(5);

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            let paths = Paths::new(data_dir);
            paths.ensure_dir()?;

            let device_id = storage::load_or_create_device_id(&paths)?;
            let settings = Settings::load(&paths);
            let vault = VaultManager::new(paths.clone(), device_id);

            app.manage(AppState::new(paths, settings.clone(), vault));

            spawn_auto_lock(app.handle().clone());

            // The bridge is opt-in; only listen if the user has turned it on.
            if settings.bridge_enabled {
                commands::start_bridge(app.handle().clone());
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Focused(false) = event {
                let app = window.app_handle();
                let state = app.state::<AppState>();
                if state.settings().lock_on_blur && state.vault().is_unlocked() {
                    commands::lock_now(app, &state, LockReason::Blur);
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            // bootstrap & lock state
            commands::app_bootstrap,
            commands::vault_lock_state,
            commands::vault_touch,
            // setup / unlock
            commands::vault_assess_password,
            commands::vault_setup,
            commands::vault_unlock,
            commands::vault_lock,
            commands::vault_change_master_password,
            // entries
            commands::vault_list_entries,
            commands::vault_get_entry,
            commands::vault_reveal_field,
            commands::vault_copy_field,
            commands::vault_create_entry,
            commands::vault_update_entry,
            commands::vault_delete_entry,
            commands::vault_set_favorite,
            // generator
            commands::generator_capabilities,
            commands::generator_generate,
            commands::generator_list_presets,
            commands::generator_save_preset,
            commands::generator_delete_preset,
            // clipboard
            commands::clipboard_copy,
            commands::clipboard_clear,
            // settings
            commands::settings_get,
            commands::settings_update,
            // sync
            commands::sync_get_config,
            commands::sync_set_config,
            commands::sync_clear_config,
            commands::sync_test_config,
            commands::sync_now,
            commands::sync_connect_existing,
            // browser extension bridge
            commands::bridge_info,
            commands::bridge_begin_pairing,
            commands::bridge_cancel_pairing,
            commands::bridge_unpair,
            // import / export
            commands::transfer_import_csv,
            commands::transfer_import_backup,
            commands::transfer_export_backup,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// Poll the idle timer and lock the vault when it expires.
///
/// Enforced in the backend rather than the frontend on purpose: a wedged or
/// crashed webview must not be able to keep the vault unlocked indefinitely.
fn spawn_auto_lock(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(LOCK_TICK).await;

            let state = app.state::<AppState>();
            let timeout = state.settings().lock_timeout_secs;

            let should_lock = {
                let vault = state.vault();
                vault.is_unlocked() && vault.should_auto_lock(timeout)
            };

            if should_lock {
                state.vault().lock();
                *state.sync_config() = None;
                let _ = app.emit(
                    state::events::LOCKED,
                    state::LockedEvent {
                        reason: LockReason::Timeout,
                    },
                );
            }
        }
    });
}
