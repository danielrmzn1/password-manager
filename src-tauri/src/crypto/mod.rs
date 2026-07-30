//! All cryptography for the application lives here and **only** here.
//!
//! The frontend never performs crypto: it asks the backend to unlock, read or
//! write, and receives only what it must display. Primitives come from vetted
//! RustCrypto crates; nothing in this module implements a cipher, hash or KDF
//! by hand.
//!
//! - [`random`] — the single source of randomness (OS CSPRNG).
//! - [`kdf`] — Argon2id master-key derivation.
//! - [`aead`] — XChaCha20-Poly1305 sealing/opening.
//! - [`b64`] — serde helpers for byte fields in the vault header.

pub mod aead;
pub mod b64;
pub mod kdf;
pub mod random;
