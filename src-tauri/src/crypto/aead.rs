//! Authenticated encryption with XChaCha20-Poly1305.
//!
//! XChaCha20's 192-bit nonce is the reason this construction is used everywhere
//! in the app: a fresh nonce can be drawn at random on every single save with
//! negligible collision risk, so two devices never have to coordinate a nonce
//! counter. With AES-GCM's 96-bit nonce that would be an actual risk over a
//! vault's lifetime.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::kdf::Key32;
use crate::crypto::random;
use crate::error::{AppError, Result};

/// XChaCha20 nonce length, in bytes.
pub const NONCE_LEN: usize = 24;
/// Poly1305 authentication tag length, in bytes.
pub const TAG_LEN: usize = 16;

pub const CIPHER_NAME: &str = "xchacha20poly1305";

/// A nonce plus the ciphertext it produced, as stored in the vault header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBlob {
    pub cipher: String,
    #[serde(with = "crate::crypto::b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "crate::crypto::b64")]
    pub ciphertext: Vec<u8>,
}

/// A nonce with no attached ciphertext, for payloads stored out-of-band (the
/// vault body lives after the header rather than inside it).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceRef {
    pub cipher: String,
    #[serde(with = "crate::crypto::b64")]
    pub nonce: Vec<u8>,
}

fn cipher_for(key: &Key32) -> XChaCha20Poly1305 {
    // `Key::from` copies the 32 bytes into the cipher's own state. The source
    // buffer is still owned by the caller's `Zeroizing` wrapper.
    let key = Key::from(**key);
    XChaCha20Poly1305::new(&key)
}

fn check_cipher(name: &str) -> Result<()> {
    if name != CIPHER_NAME {
        return Err(AppError::Corrupt("unsupported cipher"));
    }
    Ok(())
}

fn nonce_from(bytes: &[u8]) -> Result<XNonce> {
    XNonce::try_from(bytes).map_err(|_| AppError::Corrupt("bad nonce length"))
}

/// Encrypt `plaintext` under `key`, authenticating `aad`, with a fresh nonce.
pub fn seal(key: &Key32, plaintext: &[u8], aad: &[u8]) -> Result<SealedBlob> {
    let nonce_bytes = random::bytes::<NONCE_LEN>()?;
    let nonce = XNonce::from(nonce_bytes);
    let ciphertext = cipher_for(key).encrypt(
        &nonce,
        Payload {
            msg: plaintext,
            aad,
        },
    )?;

    Ok(SealedBlob {
        cipher: CIPHER_NAME.to_string(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

/// Decrypt a [`SealedBlob`]. The plaintext is returned in a self-zeroizing
/// buffer because every caller of this function is handling key material or
/// vault contents.
pub fn open(key: &Key32, blob: &SealedBlob, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    check_cipher(&blob.cipher)?;
    let nonce = nonce_from(&blob.nonce)?;
    let plaintext = cipher_for(key).decrypt(
        &nonce,
        Payload {
            msg: &blob.ciphertext,
            aad,
        },
    )?;
    Ok(Zeroizing::new(plaintext))
}

/// Encrypt with a fresh nonce, returning the nonce and ciphertext separately so
/// the caller can store the ciphertext out-of-band.
pub fn seal_detached(key: &Key32, plaintext: &[u8], aad: &[u8]) -> Result<(NonceRef, Vec<u8>)> {
    let blob = seal(key, plaintext, aad)?;
    Ok((
        NonceRef {
            cipher: blob.cipher,
            nonce: blob.nonce,
        },
        blob.ciphertext,
    ))
}

/// Encrypt under a caller-chosen nonce.
///
/// Needed by the vault container, where the nonce is recorded *inside* the
/// header and the header bytes are themselves the AAD: the nonce therefore has
/// to be drawn before the AAD can be built. Callers are responsible for the
/// nonce being fresh — [`crate::crypto::random`] is the only acceptable source.
pub fn seal_with_nonce(
    key: &Key32,
    nonce_bytes: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let nonce = XNonce::from(*nonce_bytes);
    Ok(cipher_for(key).encrypt(
        &nonce,
        Payload {
            msg: plaintext,
            aad,
        },
    )?)
}

/// Counterpart to [`seal_detached`].
pub fn open_detached(
    key: &Key32,
    nonce_ref: &NonceRef,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    check_cipher(&nonce_ref.cipher)?;
    let nonce = nonce_from(&nonce_ref.nonce)?;
    let plaintext = cipher_for(key).decrypt(
        &nonce,
        Payload {
            msg: ciphertext,
            aad,
        },
    )?;
    Ok(Zeroizing::new(plaintext))
}

/// Generate a fresh random data encryption key.
pub fn generate_key() -> Result<Key32> {
    Ok(Zeroizing::new(random::bytes::<32>()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> Key32 {
        Zeroizing::new([b; 32])
    }

    #[test]
    fn round_trip_with_aad() {
        let k = key(1);
        let blob = seal(&k, b"top secret", b"header").unwrap();
        let out = open(&k, &blob, b"header").unwrap();
        assert_eq!(out.as_slice(), b"top secret");
    }

    #[test]
    fn ciphertext_is_not_plaintext_and_carries_a_tag() {
        let k = key(1);
        let blob = seal(&k, b"top secret", b"").unwrap();
        assert_eq!(blob.ciphertext.len(), b"top secret".len() + TAG_LEN);
        assert!(!blob.ciphertext.windows(6).any(|w| w == b"secret"));
        assert_eq!(blob.nonce.len(), NONCE_LEN);
    }

    #[test]
    fn wrong_key_fails() {
        let blob = seal(&key(1), b"msg", b"aad").unwrap();
        assert!(open(&key(2), &blob, b"aad").is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let k = key(1);
        let blob = seal(&k, b"msg", b"aad-a").unwrap();
        assert!(open(&k, &blob, b"aad-b").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let k = key(1);
        let mut blob = seal(&k, b"msg", b"aad").unwrap();
        blob.ciphertext[0] ^= 0x01;
        assert!(open(&k, &blob, b"aad").is_err());
    }

    #[test]
    fn tampered_nonce_fails() {
        let k = key(1);
        let mut blob = seal(&k, b"msg", b"aad").unwrap();
        blob.nonce[0] ^= 0x01;
        assert!(open(&k, &blob, b"aad").is_err());
    }

    #[test]
    fn truncated_ciphertext_fails() {
        let k = key(1);
        let mut blob = seal(&k, b"msg", b"aad").unwrap();
        blob.ciphertext.truncate(blob.ciphertext.len() - 1);
        assert!(open(&k, &blob, b"aad").is_err());
    }

    #[test]
    fn unknown_cipher_is_rejected() {
        let k = key(1);
        let mut blob = seal(&k, b"msg", b"").unwrap();
        blob.cipher = "aes-256-gcm".into();
        assert!(open(&k, &blob, b"").is_err());
    }

    #[test]
    fn bad_nonce_length_is_rejected_not_panicking() {
        let k = key(1);
        let mut blob = seal(&k, b"msg", b"").unwrap();
        blob.nonce.truncate(12);
        assert!(open(&k, &blob, b"").is_err());
    }

    /// Nonces must never repeat across saves — this is the property that makes
    /// random-nonce XChaCha20 safe.
    #[test]
    fn nonces_are_unique_per_seal() {
        let k = key(1);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            assert!(seen.insert(seal(&k, b"msg", b"").unwrap().nonce));
        }
    }

    #[test]
    fn detached_round_trip() {
        let k = key(3);
        let (nonce_ref, ct) = seal_detached(&k, b"body bytes", b"prefix").unwrap();
        let out = open_detached(&k, &nonce_ref, &ct, b"prefix").unwrap();
        assert_eq!(out.as_slice(), b"body bytes");
        assert!(open_detached(&k, &nonce_ref, &ct, b"other").is_err());
    }

    #[test]
    fn generated_keys_are_random() {
        let a = generate_key().unwrap();
        let b = generate_key().unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let k = key(4);
        let blob = seal(&k, b"", b"aad").unwrap();
        assert_eq!(blob.ciphertext.len(), TAG_LEN);
        assert!(open(&k, &blob, b"aad").unwrap().is_empty());
    }
}
