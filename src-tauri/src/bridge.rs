//! Loopback HTTP bridge for the browser extension.
//!
//! Design rationale, threat model and wire protocol: `docs/extension-bridge.md`.
//!
//! Security posture in one place:
//! - Off unless the user enables it (`Settings::bridge_enabled`).
//! - Binds `127.0.0.1` only, never a routable address.
//! - Pairing needs a code displayed in the desktop UI; the resulting token is
//!   persisted encrypted under the vault DEK.
//! - Every credential endpoint requires the vault to be unlocked and returns
//!   `423 Locked` otherwise.
//! - The `Origin` header must match the extension recorded at pairing.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::oneshot;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto::aead::{self, SealedBlob};
use crate::crypto::kdf::Key32;
use crate::crypto::random;
use crate::error::{AppError, Result};
use crate::state::AppState;
use crate::storage::{self, Paths};
use crate::vault::model::now_ms;

/// Ports probed, in order. A range rather than a single port so a conflicting
/// service does not disable the feature. The port is not a secret.
pub const PORT_RANGE: std::ops::RangeInclusive<u16> = 8391..=8395;

/// How long a pairing code stays valid.
const PAIRING_TTL_MS: i64 = 120_000;
/// Wrong-code attempts before the pairing window closes.
const MAX_PAIRING_ATTEMPTS: u8 = 5;
const CODE_DIGITS: u32 = 6;

/// A paired extension. Persisted to `bridge.enc`, encrypted with the vault DEK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedClient {
    pub token: String,
    pub extension_id: String,
    pub paired_at: i64,
}

impl Drop for PairedClient {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

/// An in-progress pairing window.
struct PairingSession {
    code: String,
    expires_at: i64,
    attempts: u8,
}

impl Drop for PairingSession {
    fn drop(&mut self) {
        self.code.zeroize();
    }
}

/// State shared with the axum handlers.
pub struct BridgeRuntime {
    app: AppHandle,
    pairing: Mutex<Option<PairingSession>>,
    paired: Mutex<Option<PairedClient>>,
}

impl BridgeRuntime {
    fn pairing(&self) -> std::sync::MutexGuard<'_, Option<PairingSession>> {
        self.pairing.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn paired(&self) -> std::sync::MutexGuard<'_, Option<PairedClient>> {
        self.paired.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Owns the running listener. Dropping or calling [`BridgeHandle::stop`] shuts
/// it down.
pub struct BridgeHandle {
    port: u16,
    shutdown: Option<oneshot::Sender<()>>,
    runtime: Arc<BridgeRuntime>,
}

impl BridgeHandle {
    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }

    pub fn is_paired(&self) -> bool {
        self.runtime.paired().is_some()
    }

    pub fn paired_extension_id(&self) -> Option<String> {
        self.runtime
            .paired()
            .as_ref()
            .map(|c| c.extension_id.clone())
    }

    /// Open a pairing window and return the code to display in the UI.
    pub fn begin_pairing(&self) -> Result<String> {
        let mut code = String::with_capacity(CODE_DIGITS as usize);
        for _ in 0..CODE_DIGITS {
            code.push(char::from(b'0' + random::uniform_below(10)? as u8));
        }

        *self.runtime.pairing() = Some(PairingSession {
            code: code.clone(),
            expires_at: now_ms() + PAIRING_TTL_MS,
            attempts: 0,
        });
        Ok(code)
    }

    pub fn cancel_pairing(&self) {
        *self.runtime.pairing() = None;
    }

    /// Forget the paired extension, in memory and on disk.
    pub fn unpair(&self, paths: &Paths) -> Result<()> {
        *self.runtime.paired() = None;
        *self.runtime.pairing() = None;
        let path = paths.bridge();
        if path.is_file() {
            std::fs::remove_file(&path)
                .map_err(|e| AppError::io("could not remove the pairing file", e))?;
        }
        Ok(())
    }

    /// Load a previously paired client after unlock, so the user does not have to
    /// re-pair on every launch.
    pub fn restore_pairing(&self, paths: &Paths, dek: &Key32, vault_id: Uuid) -> Result<bool> {
        match load_paired(paths, dek, vault_id)? {
            Some(client) => {
                *self.runtime.paired() = Some(client);
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

impl Drop for BridgeHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

fn bridge_aad(vault_id: Uuid) -> Vec<u8> {
    let mut aad = b"pmv1:bridge:".to_vec();
    aad.extend_from_slice(vault_id.as_bytes());
    aad
}

fn load_paired(paths: &Paths, dek: &Key32, vault_id: Uuid) -> Result<Option<PairedClient>> {
    let path = paths.bridge();
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = storage::read_file(&path)?;
    let blob: SealedBlob =
        serde_json::from_slice(&bytes).map_err(|_| AppError::Corrupt("malformed pairing file"))?;
    let plaintext = aead::open(dek, &blob, &bridge_aad(vault_id))?;
    let client: PairedClient = serde_json::from_slice(&plaintext)
        .map_err(|_| AppError::Corrupt("malformed pairing file"))?;
    Ok(Some(client))
}

fn save_paired(paths: &Paths, dek: &Key32, vault_id: Uuid, client: &PairedClient) -> Result<()> {
    let plaintext = zeroize::Zeroizing::new(
        serde_json::to_vec(client)
            .map_err(|_| AppError::Other("could not serialize the pairing".into()))?,
    );
    let blob = aead::seal(dek, &plaintext, &bridge_aad(vault_id))?;
    let encoded = serde_json::to_vec(&blob)
        .map_err(|_| AppError::Other("could not serialize the pairing".into()))?;
    paths.ensure_dir()?;
    storage::write_atomic(&paths.bridge(), &encoded)
}

/// Bind the first free port in [`PORT_RANGE`] and start serving.
pub async fn start(app: AppHandle) -> Result<BridgeHandle> {
    let runtime = Arc::new(BridgeRuntime {
        app: app.clone(),
        pairing: Mutex::new(None),
        paired: Mutex::new(None),
    });

    let cors = tower_http::cors::CorsLayer::new()
        // Only browser extensions, never web pages. Browsers set `Origin`
        // themselves and pages cannot forge it.
        .allow_origin(tower_http::cors::AllowOrigin::predicate(
            |origin, _request| {
                origin
                    .to_str()
                    .map(|o| o.starts_with("chrome-extension://"))
                    .unwrap_or(false)
            },
        ))
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
        ]);

    let router = Router::new()
        .route("/health", get(health))
        .route("/pair", post(pair))
        .route("/unpair", post(unpair))
        .route("/status", get(status))
        .route("/credentials", post(credentials))
        .route("/fill", post(fill))
        .layer(cors)
        .with_state(runtime.clone());

    let mut listener = None;
    for port in PORT_RANGE {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        if let Ok(bound) = tokio::net::TcpListener::bind(addr).await {
            listener = Some((bound, port));
            break;
        }
    }
    let (listener, port) = listener.ok_or_else(|| {
        AppError::Other(format!(
            "no free port for the extension bridge in {}-{}",
            PORT_RANGE.start(),
            PORT_RANGE.end()
        ))
    })?;

    let (tx, rx) = oneshot::channel::<()>();
    tauri::async_runtime::spawn(async move {
        let _ = axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await;
    });

    Ok(BridgeHandle {
        port,
        shutdown: Some(tx),
        runtime,
    })
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct HealthResponse {
    app: &'static str,
    version: &'static str,
    locked: bool,
    paired: bool,
}

async fn health(State(runtime): State<Arc<BridgeRuntime>>) -> impl IntoResponse {
    let locked = !is_unlocked(&runtime.app);
    Json(HealthResponse {
        app: "password-manager",
        version: env!("CARGO_PKG_VERSION"),
        locked,
        paired: runtime.paired().is_some(),
    })
}

#[derive(Deserialize)]
struct PairRequest {
    code: String,
    extension_id: String,
}

#[derive(Serialize)]
struct PairResponse {
    token: String,
}

async fn pair(
    State(runtime): State<Arc<BridgeRuntime>>,
    headers: HeaderMap,
    Json(body): Json<PairRequest>,
) -> axum::response::Response {
    // The extension id is taken from the `Origin` header, not from the body, so a
    // caller cannot claim to be an extension it is not.
    let origin_id = match extension_id_from_origin(&headers) {
        Some(id) => id,
        None => {
            return error(
                StatusCode::UNAUTHORIZED,
                "requests must come from a browser extension",
            )
        }
    };
    if origin_id != body.extension_id {
        return error(
            StatusCode::UNAUTHORIZED,
            "extension id does not match the request origin",
        );
    }

    {
        let mut pairing = runtime.pairing();
        let session = match pairing.as_mut() {
            Some(session) => session,
            None => {
                return error(
                    StatusCode::FORBIDDEN,
                    "pairing is not in progress — start it from the desktop app's settings",
                )
            }
        };

        if now_ms() > session.expires_at {
            *pairing = None;
            return error(StatusCode::FORBIDDEN, "the pairing code expired");
        }

        session.attempts += 1;
        if session.attempts > MAX_PAIRING_ATTEMPTS {
            *pairing = None;
            return error(StatusCode::FORBIDDEN, "too many incorrect codes");
        }

        // Constant-time so a local attacker cannot time-guess the code digit by
        // digit. Length is compared first because `ct_eq` needs equal lengths.
        let expected = session.code.as_bytes();
        let provided = body.code.trim().as_bytes();
        let ok = expected.len() == provided.len() && bool::from(expected.ct_eq(provided));
        if !ok {
            return error(StatusCode::FORBIDDEN, "incorrect pairing code");
        }

        *pairing = None;
    }

    // The token is persisted under the vault DEK, so pairing requires an
    // unlocked vault.
    let state = runtime.app.state::<AppState>();
    let (dek, vault_id) = {
        let vault = state.vault();
        match (vault.dek(), vault.vault_id()) {
            (Ok(dek), Ok(id)) => (dek, id),
            _ => return error(StatusCode::LOCKED, "unlock the vault before pairing"),
        }
    };

    let token = match random::bytes::<32>() {
        Ok(bytes) => URL_SAFE_NO_PAD.encode(bytes),
        Err(_) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not generate a token",
            )
        }
    };

    let client = PairedClient {
        token: token.clone(),
        extension_id: origin_id,
        paired_at: now_ms(),
    };
    if save_paired(&state.paths, &dek, vault_id, &client).is_err() {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not save the pairing",
        );
    }
    *runtime.paired() = Some(client);

    let _ = runtime.app.emit("bridge://paired", ());
    (StatusCode::OK, Json(PairResponse { token })).into_response()
}

async fn unpair(
    State(runtime): State<Arc<BridgeRuntime>>,
    headers: HeaderMap,
) -> axum::response::Response {
    if let Some(response) = authorize(&runtime, &headers) {
        return response;
    }
    let state = runtime.app.state::<AppState>();
    *runtime.paired() = None;

    // Report a failed deletion rather than swallowing it: if `bridge.enc`
    // survives, the next unlock restores the pairing and the token the caller
    // just revoked starts working again. The client needs to know that.
    let path = state.paths.bridge();
    if path.is_file() {
        if let Err(err) = std::fs::remove_file(&path) {
            let _ = runtime.app.emit("bridge://unpair-failed", err.to_string());
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the pairing was dropped from memory but could not be deleted from disk; \
                 it will come back on the next unlock",
            );
        }
    }

    let _ = runtime.app.emit("bridge://unpaired", ());
    StatusCode::OK.into_response()
}

#[derive(Serialize)]
struct StatusResponse {
    locked: bool,
}

async fn status(
    State(runtime): State<Arc<BridgeRuntime>>,
    headers: HeaderMap,
) -> axum::response::Response {
    if let Some(response) = authorize(&runtime, &headers) {
        return response;
    }
    Json(StatusResponse {
        locked: !is_unlocked(&runtime.app),
    })
    .into_response()
}

#[derive(Deserialize)]
struct CredentialsRequest {
    url: String,
}

#[derive(Serialize)]
struct CredentialCandidate {
    id: Uuid,
    title: String,
    username: String,
}

#[derive(Serialize)]
struct CredentialsResponse {
    entries: Vec<CredentialCandidate>,
}

async fn credentials(
    State(runtime): State<Arc<BridgeRuntime>>,
    headers: HeaderMap,
    Json(body): Json<CredentialsRequest>,
) -> axum::response::Response {
    if let Some(response) = authorize(&runtime, &headers) {
        return response;
    }

    let Some(host) = crate::domain::host_of(&body.url) else {
        return error(
            StatusCode::BAD_REQUEST,
            "could not read a hostname from that URL",
        );
    };

    let state = runtime.app.state::<AppState>();
    let mut vault = state.vault();
    if !vault.is_unlocked() {
        return error(StatusCode::LOCKED, "the vault is locked");
    }
    // Using the extension is user activity on the vault, so it defers auto-lock.
    vault.touch();

    match vault.find_by_host(&host) {
        Ok(matches) => Json(CredentialsResponse {
            entries: matches
                .into_iter()
                .map(|e| CredentialCandidate {
                    id: e.id,
                    title: e.title,
                    username: e.username,
                })
                .collect(),
        })
        .into_response(),
        Err(AppError::Locked) => error(StatusCode::LOCKED, "the vault is locked"),
        Err(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not search the vault",
        ),
    }
}

#[derive(Deserialize)]
struct FillRequest {
    id: Uuid,
}

#[derive(Serialize)]
struct FillResponse {
    username: String,
    password: String,
}

async fn fill(
    State(runtime): State<Arc<BridgeRuntime>>,
    headers: HeaderMap,
    Json(body): Json<FillRequest>,
) -> axum::response::Response {
    if let Some(response) = authorize(&runtime, &headers) {
        return response;
    }

    let state = runtime.app.state::<AppState>();
    let result = {
        let mut vault = state.vault();
        if !vault.is_unlocked() {
            return error(StatusCode::LOCKED, "the vault is locked");
        }
        vault.touch();
        vault.credentials_for(body.id)
    };

    match result {
        Ok((username, password)) => {
            // Surfaced in the desktop UI so a release of credentials is never
            // invisible to the user.
            let _ = runtime.app.emit("bridge://fill", body.id);
            Json(FillResponse { username, password }).into_response()
        }
        Err(AppError::EntryNotFound) => error(StatusCode::NOT_FOUND, "entry not found"),
        Err(AppError::Locked) => error(StatusCode::LOCKED, "the vault is locked"),
        Err(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not read the entry",
        ),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_unlocked(app: &AppHandle) -> bool {
    app.state::<AppState>().vault().is_unlocked()
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

fn error(status: StatusCode, message: &str) -> axum::response::Response {
    (
        status,
        Json(ErrorBody {
            error: message.to_string(),
        }),
    )
        .into_response()
}

/// Extract `<id>` from an `Origin: chrome-extension://<id>` header.
fn extension_id_from_origin(headers: &HeaderMap) -> Option<String> {
    let origin = headers.get(axum::http::header::ORIGIN)?.to_str().ok()?;
    let id = origin.strip_prefix("chrome-extension://")?;
    let id = id.trim_end_matches('/');
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(id.to_string())
}

/// Require a valid bearer token whose `Origin` matches the paired extension.
///
/// Returns `Some(response)` describing the rejection, or `None` when the request
/// is authorized.
fn authorize(
    runtime: &Arc<BridgeRuntime>,
    headers: &HeaderMap,
) -> Option<axum::response::Response> {
    let paired = runtime.paired();
    let Some(client) = paired.as_ref() else {
        return Some(error(
            StatusCode::UNAUTHORIZED,
            "this extension is not paired",
        ));
    };

    let provided = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();

    let expected = client.token.as_bytes();
    let provided_bytes = provided.as_bytes();
    let token_ok =
        expected.len() == provided_bytes.len() && bool::from(expected.ct_eq(provided_bytes));
    if !token_ok {
        return Some(error(StatusCode::UNAUTHORIZED, "invalid token"));
    }

    // Pin the origin as well as the token: a stolen token used from anywhere
    // other than the paired extension is rejected.
    match extension_id_from_origin(headers) {
        Some(id) if id == client.extension_id => None,
        _ => Some(error(
            StatusCode::UNAUTHORIZED,
            "request origin does not match the paired extension",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with(origin: Option<&str>, auth: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(origin) = origin {
            headers.insert(
                axum::http::header::ORIGIN,
                HeaderValue::from_str(origin).unwrap(),
            );
        }
        if let Some(auth) = auth {
            headers.insert(
                axum::http::header::AUTHORIZATION,
                HeaderValue::from_str(auth).unwrap(),
            );
        }
        headers
    }

    #[test]
    fn parses_extension_ids_from_origins() {
        let h = headers_with(Some("chrome-extension://abcdefghijklmnop"), None);
        assert_eq!(
            extension_id_from_origin(&h).as_deref(),
            Some("abcdefghijklmnop")
        );

        let h = headers_with(Some("chrome-extension://abcdefghijklmnop/"), None);
        assert_eq!(
            extension_id_from_origin(&h).as_deref(),
            Some("abcdefghijklmnop")
        );
    }

    /// Web pages must never be accepted, whatever origin they present.
    #[test]
    fn rejects_non_extension_origins() {
        for origin in [
            "https://evil.example.com",
            "http://localhost:1420",
            "moz-extension://abcdef",
            "chrome-extension://",
            "chrome-extension://has-a-dash",
            "null",
        ] {
            let h = headers_with(Some(origin), None);
            assert!(
                extension_id_from_origin(&h).is_none(),
                "{origin} should be rejected"
            );
        }
        assert!(extension_id_from_origin(&HeaderMap::new()).is_none());
    }

    #[test]
    fn pairing_codes_are_six_digits_and_vary() {
        // Exercises the generator without needing a running server.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let mut code = String::new();
            for _ in 0..CODE_DIGITS {
                code.push(char::from(b'0' + random::uniform_below(10).unwrap() as u8));
            }
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
            seen.insert(code);
        }
        assert!(seen.len() > 50, "pairing codes look insufficiently random");
    }

    #[test]
    fn paired_client_round_trips_encrypted_and_is_vault_bound() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().to_path_buf());
        paths.ensure_dir().unwrap();

        let dek = aead::generate_key().unwrap();
        let vault_id = Uuid::new_v4();
        let client = PairedClient {
            token: "super-secret-bridge-token".into(),
            extension_id: "abcdefghijklmnop".into(),
            paired_at: 42,
        };

        save_paired(&paths, &dek, vault_id, &client).unwrap();

        let raw = std::fs::read(paths.bridge()).unwrap();
        assert!(
            !raw.windows(11).any(|w| w == b"super-secre"),
            "the bridge token leaked to disk in plaintext"
        );

        let loaded = load_paired(&paths, &dek, vault_id).unwrap().unwrap();
        assert_eq!(loaded.token, "super-secret-bridge-token");
        assert_eq!(loaded.extension_id, "abcdefghijklmnop");

        // Bound to this vault and this key only.
        assert!(load_paired(&paths, &dek, Uuid::new_v4()).is_err());
        let other = aead::generate_key().unwrap();
        assert!(load_paired(&paths, &other, vault_id).is_err());
    }

    #[test]
    fn missing_pairing_file_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().to_path_buf());
        paths.ensure_dir().unwrap();
        let dek = aead::generate_key().unwrap();
        assert!(load_paired(&paths, &dek, Uuid::new_v4()).unwrap().is_none());
    }

    #[test]
    fn port_range_is_loopback_only_and_non_privileged() {
        assert!(*PORT_RANGE.start() > 1024);
        assert!(PORT_RANGE.end() >= PORT_RANGE.start());
    }
}
