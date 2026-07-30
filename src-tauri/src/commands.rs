//! The Tauri command surface — the entire boundary between the webview and the
//! vault.
//!
//! Two rules hold throughout:
//!
//! 1. **Secrets are pull-only.** Nothing here returns a stored password unless the
//!    command's whole purpose is to reveal one specific field the user asked for.
//!    Copy-to-clipboard does not return the value at all.
//! 2. **Every read and write goes through [`VaultManager`], which refuses when
//!    locked.** There is no path that reads plaintext without an unlock.

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use uuid::Uuid;

use crate::clipboard;
use crate::error::{AppError, Result};
use crate::generator::{
    self, GeneratedSecret, GeneratorCapabilities, GeneratorOptions, GeneratorPreset,
    PasswordAssessment,
};
use crate::settings::Settings;
use crate::state::{events, AppState, LockReason, LockedEvent};
use crate::sync::{self, SyncConfig, SyncConfigView, SyncReport, SyncStatus};
use crate::transfer::{self, ImportReport};
use crate::vault::manager::VaultStatus;
use crate::vault::model::{EntryDetail, EntryInput, EntrySummary, FieldSelector};

// ---------------------------------------------------------------------------
// Bootstrap / lock state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Bootstrap {
    pub status: VaultStatus,
    pub settings: Settings,
    pub capabilities: GeneratorCapabilities,
    pub version: String,
    pub sync_configured: bool,
    pub bridge_running: bool,
    pub bridge_paired: bool,
}

#[tauri::command]
pub fn app_bootstrap(state: State<'_, AppState>) -> Bootstrap {
    let status = state.vault().status();
    let bridge = state.bridge();
    Bootstrap {
        status,
        settings: state.settings().clone(),
        capabilities: generator::capabilities(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        // Whether a sync config exists on disk; its contents need the DEK.
        sync_configured: state.paths.sync().is_file(),
        bridge_running: bridge.is_some(),
        bridge_paired: bridge.as_ref().is_some_and(|b| b.is_paired()),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LockState {
    pub status: VaultStatus,
    pub idle_secs: u64,
    pub lock_timeout_secs: u64,
}

#[tauri::command]
pub fn vault_lock_state(state: State<'_, AppState>) -> LockState {
    let vault = state.vault();
    LockState {
        status: vault.status(),
        idle_secs: vault.idle_time().map(|d| d.as_secs()).unwrap_or(0),
        lock_timeout_secs: state.settings().lock_timeout_secs,
    }
}

/// Record user activity so the auto-lock timer restarts.
#[tauri::command]
pub fn vault_touch(state: State<'_, AppState>) {
    state.vault().touch();
}

// ---------------------------------------------------------------------------
// Setup / unlock / lock
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn vault_assess_password(password: String) -> PasswordAssessment {
    generator::assess_master_password(&password)
}

#[tauri::command]
pub fn vault_setup(
    app: AppHandle,
    state: State<'_, AppState>,
    master_password: String,
) -> Result<()> {
    state.vault().create(&master_password)?;
    after_unlock(&app, &state);
    Ok(())
}

#[tauri::command]
pub fn vault_unlock(
    app: AppHandle,
    state: State<'_, AppState>,
    master_password: String,
) -> Result<()> {
    state.vault().unlock(&master_password)?;
    after_unlock(&app, &state);

    if state.settings().sync_on_unlock && state.sync_config().is_some() {
        spawn_background_sync(app);
    }
    Ok(())
}

#[tauri::command]
pub fn vault_lock(app: AppHandle, state: State<'_, AppState>) {
    lock_now(&app, &state, LockReason::Manual);
}

#[tauri::command]
pub fn vault_change_master_password(
    state: State<'_, AppState>,
    current_password: String,
    new_password: String,
) -> Result<()> {
    state
        .vault()
        .change_master_password(&current_password, &new_password)
}

/// Shared post-unlock wiring: load the sync configuration and restore any
/// browser-extension pairing, both of which are encrypted under the vault key and
/// so only become available now.
fn after_unlock(app: &AppHandle, state: &AppState) {
    let (dek, vault_id) = {
        let vault = state.vault();
        match (vault.dek(), vault.vault_id()) {
            (Ok(dek), Ok(id)) => (dek, id),
            _ => return,
        }
    };

    match sync::load_sync_file(&state.paths, &dek, vault_id) {
        Ok(Some(file)) => *state.sync_config() = Some(file.config),
        // A sync config that will not decrypt must not block using the vault.
        Ok(None) | Err(_) => *state.sync_config() = None,
    }

    if let Some(bridge) = state.bridge().as_ref() {
        let _ = bridge.restore_pairing(&state.paths, &dek, vault_id);
    }

    let _ = app.emit(events::CHANGED, ());
}

/// Lock, clear secret-bearing memory outside the vault, and tell the UI.
pub fn lock_now(app: &AppHandle, state: &AppState, reason: LockReason) {
    state.vault().lock();
    // The S3 secret key lives here; it must not outlive the session.
    *state.sync_config() = None;
    let _ = app.emit(events::LOCKED, LockedEvent { reason });
}

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn vault_list_entries(state: State<'_, AppState>) -> Result<Vec<EntrySummary>> {
    state.vault().list_entries()
}

#[tauri::command]
pub fn vault_get_entry(state: State<'_, AppState>, id: Uuid) -> Result<EntryDetail> {
    state.vault().get_entry(id)
}

/// Return one secret field. The only command that hands a stored secret to the
/// webview, and only for the field the user explicitly revealed.
#[tauri::command]
pub fn vault_reveal_field(
    state: State<'_, AppState>,
    id: Uuid,
    selector: FieldSelector,
) -> Result<String> {
    let mut vault = state.vault();
    vault.touch();
    vault.reveal(id, &selector)
}

/// Copy a secret field to the clipboard **without** returning it.
///
/// The value goes vault → clipboard entirely inside Rust, so it never enters the
/// webview's heap. Returns the seconds until the clipboard is auto-cleared.
#[tauri::command]
pub fn vault_copy_field(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    selector: FieldSelector,
) -> Result<u64> {
    let value = {
        let mut vault = state.vault();
        vault.touch();
        vault.reveal(id, &selector)?
    };
    clipboard::copy_with_auto_clear(&app, value)
}

#[tauri::command]
pub fn vault_create_entry(
    app: AppHandle,
    state: State<'_, AppState>,
    input: EntryInput,
) -> Result<Uuid> {
    let id = {
        let mut vault = state.vault();
        vault.touch();
        vault.create_entry(input)?
    };
    maybe_sync_after_save(&app, &state);
    Ok(id)
}

#[tauri::command]
pub fn vault_update_entry(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    input: EntryInput,
) -> Result<()> {
    {
        let mut vault = state.vault();
        vault.touch();
        vault.update_entry(id, input)?;
    }
    maybe_sync_after_save(&app, &state);
    Ok(())
}

#[tauri::command]
pub fn vault_delete_entry(app: AppHandle, state: State<'_, AppState>, id: Uuid) -> Result<()> {
    {
        let mut vault = state.vault();
        vault.touch();
        vault.delete_entry(id)?;
    }
    maybe_sync_after_save(&app, &state);
    Ok(())
}

#[tauri::command]
pub fn vault_set_favorite(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    favorite: bool,
) -> Result<()> {
    {
        let mut vault = state.vault();
        vault.touch();
        vault.set_favorite(id, favorite)?;
    }
    maybe_sync_after_save(&app, &state);
    Ok(())
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn generator_capabilities() -> GeneratorCapabilities {
    generator::capabilities()
}

#[tauri::command]
pub fn generator_generate(options: GeneratorOptions) -> Result<GeneratedSecret> {
    generator::generate(&options)
}

#[tauri::command]
pub fn generator_list_presets(state: State<'_, AppState>) -> Result<Vec<GeneratorPreset>> {
    state.vault().list_presets()
}

#[tauri::command]
pub fn generator_save_preset(state: State<'_, AppState>, preset: GeneratorPreset) -> Result<Uuid> {
    state.vault().save_preset(preset)
}

#[tauri::command]
pub fn generator_delete_preset(state: State<'_, AppState>, id: Uuid) -> Result<()> {
    state.vault().delete_preset(id)
}

// ---------------------------------------------------------------------------
// Clipboard
// ---------------------------------------------------------------------------

/// Copy an arbitrary string, e.g. a freshly generated password the user has not
/// saved yet. Subject to the same auto-clear timer.
#[tauri::command]
pub fn clipboard_copy(app: AppHandle, text: String) -> Result<u64> {
    clipboard::copy_with_auto_clear(&app, text)
}

#[tauri::command]
pub fn clipboard_clear(app: AppHandle) -> Result<()> {
    clipboard::clear_now(&app)
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn settings_get(state: State<'_, AppState>) -> Settings {
    state.settings().clone()
}

#[tauri::command]
pub fn settings_update(
    app: AppHandle,
    state: State<'_, AppState>,
    settings: Settings,
) -> Result<Settings> {
    let bridge_was_enabled = state.settings().bridge_enabled;

    let saved = {
        let mut current = state.settings();
        *current = settings;
        current.save(&state.paths)?;
        current.clone()
    };

    // Starting and stopping the bridge follows the setting immediately, so
    // "disabled" really means "not listening".
    if saved.bridge_enabled != bridge_was_enabled {
        if saved.bridge_enabled {
            start_bridge(app);
        } else if let Some(handle) = state.bridge().take() {
            handle.stop();
        }
    }

    Ok(saved)
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn sync_get_config(state: State<'_, AppState>) -> Option<SyncConfigView> {
    state.sync_config().as_ref().map(|c| c.redacted())
}

#[tauri::command]
pub fn sync_set_config(state: State<'_, AppState>, config: SyncConfig) -> Result<SyncConfigView> {
    config.validate()?;

    let (dek, vault_id) = {
        let vault = state.vault();
        (vault.dek()?, vault.vault_id()?)
    };

    // Preserve existing bookkeeping when only the credentials changed; reset it
    // if the object location moved, since ETags are per-object.
    let previous = sync::load_sync_file(&state.paths, &dek, vault_id)
        .ok()
        .flatten();
    let state_to_keep = match previous {
        Some(ref file) if file.config.object_key() == config.object_key() => file.state.clone(),
        _ => sync::SyncState::default(),
    };

    let view = config.redacted();
    sync::save_sync_file(
        &state.paths,
        &dek,
        vault_id,
        &sync::SyncFile {
            config: config.clone(),
            state: state_to_keep,
        },
    )?;
    *state.sync_config() = Some(config);
    Ok(view)
}

#[tauri::command]
pub fn sync_clear_config(state: State<'_, AppState>) -> Result<()> {
    sync::delete_sync_file(&state.paths)?;
    *state.sync_config() = None;
    Ok(())
}

/// Check that an endpoint, bucket and credential set actually work, without
/// saving them.
#[tauri::command]
pub async fn sync_test_config(config: SyncConfig) -> Result<()> {
    config.validate()?;
    let store = sync::s3::S3Store::new(&config)?;
    store.test_connection().await.map_err(AppError::from)
}

#[tauri::command]
pub async fn sync_now(app: AppHandle) -> Result<SyncReport> {
    let _ = app.emit(events::SYNC_STATUS, SyncStatus::syncing());

    let result = {
        let state = app.state::<AppState>();
        sync::run_sync(&state).await
    };

    match &result {
        Ok(_) => {
            let _ = app.emit(events::SYNC_STATUS, SyncStatus::idle());
            let _ = app.emit(events::CHANGED, ());
        }
        Err(e) => {
            let _ = app.emit(events::SYNC_STATUS, SyncStatus::error(e.to_string()));
        }
    }
    result
}

/// Adopt an existing remote vault on this device.
#[tauri::command]
pub async fn sync_connect_existing(
    app: AppHandle,
    config: SyncConfig,
    master_password: String,
) -> Result<u64> {
    let revision = {
        let state = app.state::<AppState>();
        sync::connect_existing(&state, config, &master_password).await?
    };

    {
        let state = app.state::<AppState>();
        after_unlock(&app, &state);
    }
    Ok(revision)
}

/// Push after a local change, if the user has that enabled. Fire-and-forget:
/// a sync failure must never make a local save look like it failed.
fn maybe_sync_after_save(app: &AppHandle, state: &AppState) {
    let _ = app.emit(events::CHANGED, ());
    if state.settings().sync_on_save && state.sync_config().is_some() {
        spawn_background_sync(app.clone());
    }
}

fn spawn_background_sync(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let _ = app.emit(events::SYNC_STATUS, SyncStatus::syncing());
        let result = {
            let state = app.state::<AppState>();
            sync::run_sync(&state).await
        };
        match result {
            Ok(_) => {
                let _ = app.emit(events::SYNC_STATUS, SyncStatus::idle());
                let _ = app.emit(events::CHANGED, ());
            }
            Err(e) => {
                let _ = app.emit(events::SYNC_STATUS, SyncStatus::error(e.to_string()));
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Browser extension bridge
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct BridgeInfo {
    pub running: bool,
    pub port: Option<u16>,
    pub paired: bool,
    pub extension_id: Option<String>,
}

#[tauri::command]
pub fn bridge_info(state: State<'_, AppState>) -> BridgeInfo {
    let bridge = state.bridge();
    match bridge.as_ref() {
        Some(handle) => BridgeInfo {
            running: true,
            port: Some(handle.port()),
            paired: handle.is_paired(),
            extension_id: handle.paired_extension_id(),
        },
        None => BridgeInfo {
            running: false,
            port: None,
            paired: false,
            extension_id: None,
        },
    }
}

/// Open a pairing window and return the code to show the user.
#[tauri::command]
pub fn bridge_begin_pairing(state: State<'_, AppState>) -> Result<String> {
    let bridge = state.bridge();
    bridge
        .as_ref()
        .ok_or(AppError::BridgeNotRunning)?
        .begin_pairing()
}

#[tauri::command]
pub fn bridge_cancel_pairing(state: State<'_, AppState>) {
    if let Some(handle) = state.bridge().as_ref() {
        handle.cancel_pairing();
    }
}

#[tauri::command]
pub fn bridge_unpair(state: State<'_, AppState>) -> Result<()> {
    let bridge = state.bridge();
    bridge
        .as_ref()
        .ok_or(AppError::BridgeNotRunning)?
        .unpair(&state.paths)
}

/// Start the loopback listener. Idempotent.
pub fn start_bridge(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        {
            let state = app.state::<AppState>();
            if state.bridge().is_some() {
                return;
            }
        }

        match crate::bridge::start(app.clone()).await {
            Ok(handle) => {
                let state = app.state::<AppState>();

                // If the vault is already unlocked, restore any saved pairing now.
                let keys = {
                    let vault = state.vault();
                    match (vault.dek(), vault.vault_id()) {
                        (Ok(dek), Ok(id)) => Some((dek, id)),
                        _ => None,
                    }
                };
                if let Some((dek, vault_id)) = keys {
                    let _ = handle.restore_pairing(&state.paths, &dek, vault_id);
                }

                *state.bridge() = Some(handle);
                let _ = app.emit("bridge://started", ());
            }
            Err(e) => {
                let _ = app.emit("bridge://error", e.to_string());
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Import / export
// ---------------------------------------------------------------------------

/// # Why these three commands are `async`
///
/// They open a native file dialog via `blocking_pick_file` / `blocking_save_file`,
/// and the dialog plugin documents that those must **not** run on the main thread
/// — they dispatch the dialog to the main thread and block waiting for it, so
/// calling them *from* the main thread deadlocks. Tauri runs a synchronous
/// `#[tauri::command]` inline on the main thread; declaring these `async` moves
/// them onto the async runtime instead. Do not remove the `async`.
/// Import a CSV export from another password manager.
///
/// The file is chosen with a native dialog driven from Rust, so the webview needs
/// no filesystem permissions and the plaintext CSV is never handed to JS.
#[tauri::command]
pub async fn transfer_import_csv(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<ImportReport> {
    use tauri_plugin_dialog::DialogExt;

    let Some(path) = app
        .dialog()
        .file()
        .add_filter("CSV export", &["csv", "txt"])
        .blocking_pick_file()
    else {
        return Ok(ImportReport::default());
    };
    let path = path
        .into_path()
        .map_err(|_| AppError::Import("that file path is not readable".into()))?;

    let text = std::fs::read_to_string(&path)
        .map_err(|e| AppError::Import(format!("could not read the file: {e}")))?;

    let (entries, mut report) = transfer::parse_csv(&text)?;

    {
        let mut vault = state.vault();
        let mut payload = vault.payload_snapshot()?;
        transfer::merge_imported(&mut payload, entries, &mut report);
        vault.replace_payload(payload)?;
    }

    maybe_sync_after_save(&app, &state);
    Ok(report)
}

/// Import entries from an encrypted `.pmv` backup, merging them in.
#[tauri::command]
pub async fn transfer_import_backup(
    app: AppHandle,
    state: State<'_, AppState>,
    backup_password: String,
) -> Result<ImportReport> {
    use tauri_plugin_dialog::DialogExt;

    let Some(path) = app
        .dialog()
        .file()
        .add_filter("Vault backup", &["pmv"])
        .blocking_pick_file()
    else {
        return Ok(ImportReport::default());
    };
    let path = path
        .into_path()
        .map_err(|_| AppError::Import("that file path is not readable".into()))?;

    let bytes = std::fs::read(&path)
        .map_err(|e| AppError::Import(format!("could not read the file: {e}")))?;
    let entries = transfer::read_backup(&bytes, &backup_password)?;

    let mut report = ImportReport::default();
    {
        let mut vault = state.vault();
        let mut payload = vault.payload_snapshot()?;
        transfer::merge_imported(&mut payload, entries, &mut report);
        vault.replace_payload(payload)?;
    }

    maybe_sync_after_save(&app, &state);
    Ok(report)
}

/// Write an encrypted backup to a location the user chooses.
#[tauri::command]
pub async fn transfer_export_backup(
    app: AppHandle,
    state: State<'_, AppState>,
    backup_password: String,
) -> Result<Option<String>> {
    use tauri_plugin_dialog::DialogExt;

    let (payload, device_id) = {
        let vault = state.vault();
        (vault.payload_snapshot()?, vault.device_id())
    };

    // Enforce the policy before opening a dialog, so a weak password is reported
    // immediately rather than after the user picks a file.
    let bytes = transfer::export_backup(&payload, &backup_password, device_id)?;

    let Some(path) = app
        .dialog()
        .file()
        .set_file_name(transfer::suggested_backup_filename())
        .add_filter("Vault backup", &["pmv"])
        .blocking_save_file()
    else {
        return Ok(None);
    };
    let path = path
        .into_path()
        .map_err(|_| AppError::Other("that file path is not writable".into()))?;

    crate::storage::write_atomic(&path, &bytes)?;
    Ok(Some(path.to_string_lossy().to_string()))
}
