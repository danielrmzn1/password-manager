//! The error type shared by every module and surfaced to the frontend.
//!
//! # Security note
//!
//! Variants deliberately carry **no secret material**. In particular there is
//! intentionally *no* blanket `From<serde_json::Error>` conversion: serde's
//! messages embed the offending value (`invalid type: string "hunter2",
//! expected u64`), which for a decrypted vault payload would mean leaking
//! plaintext into an error string that may be logged or shown in the UI.
//! Payload parse failures must be mapped to [`AppError::Corrupt`] explicitly at
//! the call site — see [`crate::vault::container`].

use serde::ser::{Serialize, SerializeStruct, Serializer};

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("the vault is locked")]
    Locked,

    #[error("incorrect master password")]
    InvalidMasterPassword,

    #[error("the vault file is corrupt or is not a vault ({0})")]
    Corrupt(&'static str),

    #[error("unsupported vault format version {0}; this vault was written by a newer release")]
    UnsupportedFormat(u8),

    #[error("unsupported vault schema version {0}; this vault was written by a newer release")]
    UnsupportedSchema(u32),

    #[error("a vault already exists on this device")]
    VaultExists,

    #[error("no vault has been created on this device yet")]
    NoVault,

    #[error("entry not found")]
    EntryNotFound,

    #[error("the master password does not meet the minimum requirements: {0}")]
    WeakMasterPassword(String),

    #[error("cryptographic operation failed")]
    Crypto,

    #[error("the operating system random number generator is unavailable")]
    Random,

    #[error("invalid options: {0}")]
    InvalidOptions(String),

    #[error("filesystem error: {0}")]
    Io(String),

    #[error("sync is not configured")]
    SyncNotConfigured,

    #[error("sync failed: {0}")]
    Sync(String),

    #[error("the vault changed on the server while saving; sync again to merge")]
    SyncConflict,

    #[error("the remote vault belongs to a different vault ({0})")]
    SyncVaultMismatch(String),

    #[error("the extension bridge is not running")]
    BridgeNotRunning,

    #[error("import failed: {0}")]
    Import(String),

    #[error("{0}")]
    Other(String),
}

impl AppError {
    /// A stable machine-readable discriminant. The frontend switches on this
    /// rather than on the human-readable message, so wording can change freely.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::InvalidMasterPassword => "invalid_master_password",
            Self::Corrupt(_) => "corrupt",
            Self::UnsupportedFormat(_) => "unsupported_format",
            Self::UnsupportedSchema(_) => "unsupported_schema",
            Self::VaultExists => "vault_exists",
            Self::NoVault => "no_vault",
            Self::EntryNotFound => "entry_not_found",
            Self::WeakMasterPassword(_) => "weak_master_password",
            Self::Crypto => "crypto",
            Self::Random => "random",
            Self::InvalidOptions(_) => "invalid_options",
            Self::Io(_) => "io",
            Self::SyncNotConfigured => "sync_not_configured",
            Self::Sync(_) => "sync",
            Self::SyncConflict => "sync_conflict",
            Self::SyncVaultMismatch(_) => "sync_vault_mismatch",
            Self::BridgeNotRunning => "bridge_not_running",
            Self::Import(_) => "import",
            Self::Other(_) => "other",
        }
    }

    pub fn io(context: &str, err: std::io::Error) -> Self {
        Self::Io(format!("{context}: {err}"))
    }
}

/// Tauri requires command errors to be `Serialize`. We emit a tagged object so
/// the frontend can branch on `code` and display `message`.
impl Serialize for AppError {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut s = serializer.serialize_struct("AppError", 2)?;
        s.serialize_field("code", self.code())?;
        s.serialize_field("message", &self.to_string())?;
        s.end()
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

/// AEAD failures are always mapped to a single opaque variant: distinguishing
/// "wrong key" from "tampered ciphertext" would be an oracle.
impl From<chacha20poly1305::aead::Error> for AppError {
    fn from(_: chacha20poly1305::aead::Error) -> Self {
        Self::Crypto
    }
}

impl From<getrandom::Error> for AppError {
    fn from(_: getrandom::Error) -> Self {
        Self::Random
    }
}
