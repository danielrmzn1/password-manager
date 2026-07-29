//! Clipboard writes with an automatic timed clear.
//!
//! Driven entirely from Rust. That is deliberate: the frontend is never granted
//! clipboard permissions (see `src-tauri/capabilities/default.json`), and for
//! copying a stored secret the value never crosses the IPC boundary into the
//! webview at all — the backend reads it from the vault and writes it straight to
//! the clipboard.

use std::sync::atomic::Ordering;
use std::time::Duration;

use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_clipboard_manager::ClipboardExt;
use zeroize::Zeroizing;

use crate::error::{AppError, Result};
use crate::state::{events, AppState};

/// Copy `value`, then clear it after the configured timeout.
///
/// Returns the number of seconds until the clipboard will be cleared, or `0` if
/// clearing is disabled.
pub fn copy_with_auto_clear(app: &AppHandle, value: String) -> Result<u64> {
    let value = Zeroizing::new(value);
    let state = app.state::<AppState>();
    let clear_after = state.settings().clipboard_clear_secs;

    app.clipboard()
        .write_text(value.as_str())
        .map_err(|_| AppError::Other("could not write to the clipboard".into()))?;

    // Every copy invalidates any pending clear, so an older timer cannot wipe a
    // newer copy.
    let generation = state.clipboard_generation.fetch_add(1, Ordering::SeqCst) + 1;

    if clear_after == 0 {
        return Ok(0);
    }

    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(clear_after)).await;

        let state = app.state::<AppState>();
        if state.clipboard_generation.load(Ordering::SeqCst) != generation {
            // A newer copy happened; that copy owns the clipboard and its own
            // timer.
            return;
        }

        // Only clear if the clipboard still holds *our* value. Otherwise the user
        // copied something else in the meantime and wiping it would be
        // destructive and baffling.
        match app.clipboard().read_text() {
            Ok(current) if current == *value => {}
            Ok(_) => return,
            // Some platforms fail to read a clipboard holding non-text content,
            // which also means it is no longer ours.
            Err(_) => return,
        }

        if app.clipboard().clear().is_ok() {
            let _ = app.emit(events::CLIPBOARD_CLEARED, ());
        }
    });

    Ok(clear_after)
}

/// Clear the clipboard immediately, cancelling any pending timed clear.
pub fn clear_now(app: &AppHandle) -> Result<()> {
    let state = app.state::<AppState>();
    state.clipboard_generation.fetch_add(1, Ordering::SeqCst);
    app.clipboard()
        .clear()
        .map_err(|_| AppError::Other("could not clear the clipboard".into()))?;
    let _ = app.emit(events::CLIPBOARD_CLEARED, ());
    Ok(())
}
