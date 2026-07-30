//! Reading and writing the `.pmv` container.
//!
//! The wire format is specified in `docs/vault-format.md`; this module is the
//! only place that knows its byte layout. The same bytes are used on disk and in
//! the S3 object, so [`parse`] must treat its input as fully untrusted:
//! attacker-controlled length prefixes get bounds-checked, and every failure
//! path returns an error rather than panicking.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::aead::{self, NonceRef, SealedBlob, NONCE_LEN, TAG_LEN};
use crate::crypto::kdf::{self, KdfParams, Key32, KEY_LEN};
use crate::crypto::random;
use crate::error::{AppError, Result};
use crate::vault::model::{now_ms, VaultPayload, SCHEMA_VERSION};

pub const MAGIC: &[u8; 8] = b"PMVAULT1";
pub const FORMAT_VERSION: u8 = 1;

const MAGIC_LEN: usize = 8;
const PREFIX_FIXED_LEN: usize = MAGIC_LEN + 1 + 4; // magic + version + header_len

/// A sane ceiling for the JSON header. The real one is a few hundred bytes; this
/// exists so a corrupt or hostile `header_len` cannot make us allocate wildly.
const MAX_HEADER_LEN: usize = 64 * 1024;

/// Ceiling on a whole container. Generous for a text vault, but bounded.
pub const MAX_CONTAINER_LEN: usize = 128 * 1024 * 1024;

/// The plaintext-but-authenticated header. Contains no secret material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHeader {
    pub vault_id: Uuid,
    pub kdf: KdfParams,
    pub wrapped_dek: SealedBlob,
    pub payload: NonceRef,
    pub revision: u64,
    pub updated_at: i64,
    pub device_id: Uuid,
}

/// A parsed but still-encrypted container.
pub struct ParsedContainer {
    pub header: VaultHeader,
    /// The exact file bytes preceding the ciphertext. Used verbatim as AEAD
    /// associated data, which sidesteps any JSON canonicalization concern.
    prefix: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// The result of a successful unlock.
pub struct UnlockedVault {
    pub header: VaultHeader,
    pub dek: Key32,
    pub payload: VaultPayload,
}

/// Hand-written so that `Debug` can never print the data key or the decrypted
/// entries. `#[derive(Debug)]` here would dump raw key bytes and every password
/// into any log line or panic message that formats this struct.
impl std::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("vault_id", &self.header.vault_id)
            .field("revision", &self.header.revision)
            .field("dek", &"<redacted>")
            .field("entries", &self.payload.entries.len())
            .finish()
    }
}

fn read_u32_be(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Parse a container without attempting to decrypt it.
pub fn parse(bytes: &[u8]) -> Result<ParsedContainer> {
    if bytes.len() > MAX_CONTAINER_LEN {
        return Err(AppError::Corrupt("container too large"));
    }
    if bytes.len() < PREFIX_FIXED_LEN {
        return Err(AppError::Corrupt("truncated container"));
    }
    if &bytes[..MAGIC_LEN] != MAGIC {
        return Err(AppError::Corrupt("bad magic"));
    }

    let version = bytes[MAGIC_LEN];
    if version != FORMAT_VERSION {
        return Err(AppError::UnsupportedFormat(version));
    }

    let header_len = read_u32_be(&bytes[MAGIC_LEN + 1..PREFIX_FIXED_LEN]) as usize;
    if header_len == 0 || header_len > MAX_HEADER_LEN {
        return Err(AppError::Corrupt("implausible header length"));
    }

    let header_end = PREFIX_FIXED_LEN
        .checked_add(header_len)
        .ok_or(AppError::Corrupt("header length overflow"))?;
    if bytes.len() < header_end {
        return Err(AppError::Corrupt("truncated header"));
    }

    let header: VaultHeader = serde_json::from_slice(&bytes[PREFIX_FIXED_LEN..header_end])
        // The header holds no secrets, but keep the message opaque anyway so a
        // malformed field value never lands in a log line.
        .map_err(|_| AppError::Corrupt("malformed header"))?;

    let ciphertext = &bytes[header_end..];
    if ciphertext.len() < TAG_LEN {
        return Err(AppError::Corrupt("payload shorter than its auth tag"));
    }

    Ok(ParsedContainer {
        header,
        prefix: bytes[..header_end].to_vec(),
        ciphertext: ciphertext.to_vec(),
    })
}

impl ParsedContainer {
    /// Derive the master key, unwrap the data key, and decrypt the payload.
    ///
    /// The master key is dropped (and zeroized) before this returns: an unlocked
    /// session only ever holds the DEK, because writing a new revision reuses
    /// the existing `wrapped_dek` untouched.
    pub fn unlock(&self, master_password: &str) -> Result<UnlockedVault> {
        let dek = self.unwrap_dek(master_password)?;
        let payload = self.decrypt_payload(&dek)?;
        Ok(UnlockedVault {
            header: self.header.clone(),
            dek,
            payload,
        })
    }

    /// Derive the master key and unwrap the DEK, without touching the payload.
    pub fn unwrap_dek(&self, master_password: &str) -> Result<Key32> {
        let master_key = kdf::derive_master_key(master_password, &self.header.kdf)?;
        let aad = self.header.kdf.aad();

        // An AEAD failure here is overwhelmingly "wrong password" in practice.
        // It is reported as such; a genuinely corrupt wrapped key is
        // indistinguishable by design and would be a strange thing to
        // distinguish for the user anyway.
        let unwrapped = aead::open(&master_key, &self.header.wrapped_dek, &aad)
            .map_err(|_| AppError::InvalidMasterPassword)?;

        if unwrapped.len() != KEY_LEN {
            return Err(AppError::Corrupt("wrapped key has the wrong length"));
        }
        let mut dek: Key32 = Zeroizing::new([0u8; KEY_LEN]);
        dek.copy_from_slice(&unwrapped);
        Ok(dek)
    }

    /// Decrypt the payload with an already-unwrapped DEK.
    pub fn decrypt_payload(&self, dek: &Key32) -> Result<VaultPayload> {
        let plaintext =
            aead::open_detached(dek, &self.header.payload, &self.ciphertext, &self.prefix)?;

        // NOTE: serde's error message can embed the offending value, which here
        // would be decrypted vault plaintext. It is deliberately discarded.
        let payload: VaultPayload = serde_json::from_slice(&plaintext)
            .map_err(|_| AppError::Corrupt("malformed payload"))?;

        if payload.schema > SCHEMA_VERSION {
            return Err(AppError::UnsupportedSchema(payload.schema));
        }
        Ok(payload)
    }

    pub fn revision(&self) -> u64 {
        self.header.revision
    }

    pub fn vault_id(&self) -> Uuid {
        self.header.vault_id
    }
}

/// Serialize a new revision of a container.
///
/// `kdf` and `wrapped_dek` are carried over unchanged from the existing header,
/// which is why saving does not need the master password.
pub fn write(
    vault_id: Uuid,
    kdf: &KdfParams,
    wrapped_dek: &SealedBlob,
    dek: &Key32,
    payload: &VaultPayload,
    revision: u64,
    device_id: Uuid,
) -> Result<Vec<u8>> {
    // The payload nonce is recorded in the header, and the header bytes are the
    // AAD, so the nonce has to be drawn first.
    let nonce_bytes = random::bytes::<NONCE_LEN>()?;

    let header = VaultHeader {
        vault_id,
        kdf: kdf.clone(),
        wrapped_dek: wrapped_dek.clone(),
        payload: NonceRef {
            cipher: aead::CIPHER_NAME.to_string(),
            nonce: nonce_bytes.to_vec(),
        },
        revision,
        updated_at: now_ms(),
        device_id,
    };

    let header_json = serde_json::to_vec(&header)
        .map_err(|_| AppError::Other("failed to serialize the vault header".into()))?;
    if header_json.len() > MAX_HEADER_LEN {
        return Err(AppError::Other("vault header too large".into()));
    }

    let mut prefix = Vec::with_capacity(PREFIX_FIXED_LEN + header_json.len());
    prefix.extend_from_slice(MAGIC);
    prefix.push(FORMAT_VERSION);
    prefix.extend_from_slice(&(header_json.len() as u32).to_be_bytes());
    prefix.extend_from_slice(&header_json);

    // The serialized plaintext is vault contents; keep it in a scrubbed buffer.
    let plaintext = Zeroizing::new(
        serde_json::to_vec(payload)
            .map_err(|_| AppError::Other("failed to serialize the vault payload".into()))?,
    );

    let ciphertext = aead::seal_with_nonce(dek, &nonce_bytes, &plaintext, &prefix)?;

    let mut out = prefix;
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Create a brand-new vault container protected by `master_password`.
///
/// Returns the serialized bytes plus the pieces an unlocked session needs, so
/// the caller does not have to immediately re-parse and re-derive.
pub fn create(
    master_password: &str,
    payload: &VaultPayload,
    device_id: Uuid,
) -> Result<(Vec<u8>, UnlockedVault)> {
    let kdf_params = KdfParams::generate()?;
    let master_key = kdf::derive_master_key(master_password, &kdf_params)?;

    let dek = aead::generate_key()?;
    let wrapped_dek = aead::seal(&master_key, dek.as_ref(), &kdf_params.aad())?;
    drop(master_key); // zeroized here; the session never keeps it

    let vault_id = Uuid::new_v4();
    let revision = 1;
    let bytes = write(
        vault_id,
        &kdf_params,
        &wrapped_dek,
        &dek,
        payload,
        revision,
        device_id,
    )?;

    // Re-parse so the returned header is byte-identical to what was written
    // (notably its `updated_at` and payload nonce).
    let header = parse(&bytes)?.header;

    Ok((
        bytes,
        UnlockedVault {
            header,
            dek,
            payload: payload.clone(),
        },
    ))
}

/// Re-wrap the DEK under a new master password, leaving the payload ciphertext
/// key unchanged. A fresh salt is generated, so the new wrap shares nothing with
/// the old one.
pub fn rewrap_dek(dek: &Key32, new_master_password: &str) -> Result<(KdfParams, SealedBlob)> {
    let kdf_params = KdfParams::generate()?;
    let master_key = kdf::derive_master_key(new_master_password, &kdf_params)?;
    let wrapped = aead::seal(&master_key, dek.as_ref(), &kdf_params.aad())?;
    Ok((kdf_params, wrapped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::model::{EntryKind, VaultEntry};

    fn sample_payload() -> VaultPayload {
        let mut payload = VaultPayload::default();
        let mut entry = VaultEntry::new(EntryKind::Login);
        entry.title = "GitHub".into();
        entry.username = "daniel".into();
        entry.password = "an-extremely-secret-value".into();
        payload.entries.push(entry);
        payload
    }

    /// Argon2id at production cost is slow on purpose; these tests use the real
    /// path anyway because the whole point is to exercise it end to end. Kept to
    /// a handful of derivations to keep the suite usable.
    #[test]
    fn create_then_unlock_round_trips() {
        let device = Uuid::new_v4();
        let (bytes, unlocked) = create("master-password", &sample_payload(), device).unwrap();

        assert_eq!(&bytes[..8], MAGIC);
        assert_eq!(bytes[8], FORMAT_VERSION);
        assert_eq!(unlocked.header.revision, 1);
        assert_eq!(unlocked.header.device_id, device);

        // The plaintext must not be recoverable from the file bytes.
        assert!(
            !bytes
                .windows(b"an-extremely-secret-value".len())
                .any(|w| w == b"an-extremely-secret-value"),
            "plaintext leaked into the container"
        );
        assert!(!bytes.windows(6).any(|w| w == b"GitHub"));

        let reopened = parse(&bytes).unwrap().unlock("master-password").unwrap();
        assert_eq!(reopened.payload.entries.len(), 1);
        assert_eq!(
            reopened.payload.entries[0].password,
            "an-extremely-secret-value"
        );
        assert_eq!(reopened.dek.as_ref(), unlocked.dek.as_ref());
        assert_eq!(reopened.header.vault_id, unlocked.header.vault_id);
    }

    #[test]
    fn wrong_password_is_reported_as_such() {
        let (bytes, _) = create("right-password", &sample_payload(), Uuid::new_v4()).unwrap();
        let err = parse(&bytes).unwrap().unlock("wrong-password").unwrap_err();
        assert!(
            matches!(err, AppError::InvalidMasterPassword),
            "got {err:?}"
        );
    }

    #[test]
    fn tampering_with_the_header_breaks_payload_decryption() {
        let (bytes, unlocked) = create("pw", &sample_payload(), Uuid::new_v4()).unwrap();

        // Bump the revision number inside the header JSON. It is plaintext, but
        // it is authenticated as AAD, so the payload must fail to open.
        let text = String::from_utf8_lossy(&bytes[13..]).to_string();
        assert!(text.contains("\"revision\":1"));
        let patched_text = text.replacen("\"revision\":1", "\"revision\":9", 1);

        let mut tampered = Vec::new();
        tampered.extend_from_slice(&bytes[..13]);
        tampered.extend_from_slice(patched_text.as_bytes());

        let parsed = parse(&tampered).unwrap();
        assert_eq!(parsed.header.revision, 9, "tamper did not land");
        assert!(
            parsed.decrypt_payload(&unlocked.dek).is_err(),
            "header tampering was not detected"
        );
    }

    /// Rebuild a container around a modified header, fixing up the length
    /// prefix so the result is a structurally valid file. Without this, tampering
    /// would be caught by the parser rather than by the cryptography, which is
    /// not what these tests are trying to prove.
    fn repack_with_header(original: &[u8], header: &VaultHeader) -> Vec<u8> {
        let header_len = read_u32_be(&original[9..13]) as usize;
        let ciphertext = &original[13 + header_len..];

        let json = serde_json::to_vec(header).unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        out.extend_from_slice(&(json.len() as u32).to_be_bytes());
        out.extend_from_slice(&json);
        out.extend_from_slice(ciphertext);
        out
    }

    #[test]
    fn kdf_cost_downgrade_below_the_floor_is_rejected() {
        let (bytes, _) = create("pw", &sample_payload(), Uuid::new_v4()).unwrap();
        let mut header = parse(&bytes).unwrap().header;
        header.kdf.m_cost_kib = 64; // far below the accepted minimum

        let tampered = repack_with_header(&bytes, &header);
        let parsed = parse(&tampered).unwrap();
        assert_eq!(parsed.header.kdf.m_cost_kib, 64, "tamper did not land");

        let err = parsed.unlock("pw").unwrap_err();
        assert!(matches!(err, AppError::Corrupt(_)), "got {err:?}");
    }

    /// A downgrade that still clears the parameter floor must be caught by the
    /// AAD binding instead: the wrapped key is bound to the exact parameters it
    /// was created with, so unwrapping fails.
    #[test]
    fn kdf_cost_downgrade_above_the_floor_is_caught_by_the_aad_binding() {
        let (bytes, _) = create("pw", &sample_payload(), Uuid::new_v4()).unwrap();
        let mut header = parse(&bytes).unwrap().header;
        assert_eq!(header.kdf.m_cost_kib, kdf::DEFAULT_M_COST_KIB);
        header.kdf.m_cost_kib = 8 * 1024; // legal, but not what was used
        header.kdf.t_cost = 1;

        let tampered = repack_with_header(&bytes, &header);
        let err = parse(&tampered).unwrap().unlock("pw").unwrap_err();
        assert!(
            matches!(err, AppError::InvalidMasterPassword),
            "got {err:?}"
        );
    }

    /// Swapping in a wrapped key from a *different* vault (whose password the
    /// attacker knows) must not yield a readable payload.
    #[test]
    fn substituting_another_vaults_wrapped_key_fails() {
        let (victim, _) = create("victim-password", &sample_payload(), Uuid::new_v4()).unwrap();
        let (attacker, _) = create("attacker-password", &sample_payload(), Uuid::new_v4()).unwrap();

        let attacker_header = parse(&attacker).unwrap().header;
        let mut header = parse(&victim).unwrap().header;
        header.kdf = attacker_header.kdf;
        header.wrapped_dek = attacker_header.wrapped_dek;

        let tampered = repack_with_header(&victim, &header);
        let parsed = parse(&tampered).unwrap();

        // The attacker can unwrap *their* DEK with their own password...
        let dek = parsed.unwrap_dek("attacker-password").unwrap();
        // ...but it does not decrypt the victim's payload.
        assert!(parsed.decrypt_payload(&dek).is_err());
    }

    #[test]
    fn password_change_preserves_the_data_key_and_payload() {
        let (bytes, unlocked) = create("old-password", &sample_payload(), Uuid::new_v4()).unwrap();
        let original_dek = unlocked.dek.clone();

        let (new_kdf, new_wrap) = rewrap_dek(&unlocked.dek, "new-password").unwrap();
        let rewritten = write(
            unlocked.header.vault_id,
            &new_kdf,
            &new_wrap,
            &unlocked.dek,
            &unlocked.payload,
            unlocked.header.revision + 1,
            unlocked.header.device_id,
        )
        .unwrap();

        let parsed = parse(&rewritten).unwrap();
        assert!(parsed.unlock("old-password").is_err());

        let reopened = parsed.unlock("new-password").unwrap();
        assert_eq!(reopened.dek.as_ref(), original_dek.as_ref());
        assert_eq!(
            reopened.payload.entries[0].password,
            "an-extremely-secret-value"
        );
        assert_eq!(reopened.header.revision, 2);
        assert_ne!(new_kdf.salt, parse(&bytes).unwrap().header.kdf.salt);
    }

    #[test]
    fn every_save_uses_a_fresh_payload_nonce() {
        let (_, unlocked) = create("pw", &sample_payload(), Uuid::new_v4()).unwrap();
        let mut seen = std::collections::HashSet::new();
        seen.insert(unlocked.header.payload.nonce.clone());

        for revision in 2..8 {
            let bytes = write(
                unlocked.header.vault_id,
                &unlocked.header.kdf,
                &unlocked.header.wrapped_dek,
                &unlocked.dek,
                &unlocked.payload,
                revision,
                unlocked.header.device_id,
            )
            .unwrap();
            assert!(seen.insert(parse(&bytes).unwrap().header.payload.nonce));
        }
    }

    #[test]
    fn malformed_input_never_panics() {
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            b"PM".to_vec(),
            b"PMVAULT1".to_vec(),
            b"NOTAVLT1\x01\x00\x00\x00\x10".to_vec(),
            // right magic, unsupported version
            {
                let mut v = MAGIC.to_vec();
                v.push(9);
                v.extend_from_slice(&16u32.to_be_bytes());
                v
            },
            // header_len beyond the cap
            {
                let mut v = MAGIC.to_vec();
                v.push(FORMAT_VERSION);
                v.extend_from_slice(&u32::MAX.to_be_bytes());
                v
            },
            // header_len of zero
            {
                let mut v = MAGIC.to_vec();
                v.push(FORMAT_VERSION);
                v.extend_from_slice(&0u32.to_be_bytes());
                v
            },
            // plausible header_len but no header bytes
            {
                let mut v = MAGIC.to_vec();
                v.push(FORMAT_VERSION);
                v.extend_from_slice(&200u32.to_be_bytes());
                v
            },
            // valid header, ciphertext too short to hold a tag
            {
                let (bytes, _) = create("pw", &VaultPayload::default(), Uuid::new_v4()).unwrap();
                let header_len = read_u32_be(&bytes[9..13]) as usize;
                bytes[..13 + header_len + 4].to_vec()
            },
        ];

        for (i, case) in cases.iter().enumerate() {
            assert!(parse(case).is_err(), "case {i} should not parse");
        }
    }

    #[test]
    fn truncating_the_ciphertext_is_detected() {
        let (bytes, _) = create("pw", &sample_payload(), Uuid::new_v4()).unwrap();
        let mut truncated = bytes.clone();
        truncated.truncate(truncated.len() - 8);
        assert!(parse(&truncated).unwrap().unlock("pw").is_err());
    }

    #[test]
    fn flipping_any_single_ciphertext_bit_is_detected() {
        let (bytes, _) = create("pw", &sample_payload(), Uuid::new_v4()).unwrap();
        let header_len = read_u32_be(&bytes[9..13]) as usize;
        let ct_start = 13 + header_len;

        for offset in [0, 1, 5, (bytes.len() - ct_start) / 2] {
            let mut corrupted = bytes.clone();
            corrupted[ct_start + offset] ^= 0x01;
            assert!(
                parse(&corrupted).unwrap().unlock("pw").is_err(),
                "bit flip at ciphertext offset {offset} went undetected"
            );
        }
    }

    #[test]
    fn a_newer_payload_schema_is_refused() {
        let payload = VaultPayload {
            schema: SCHEMA_VERSION + 1,
            ..Default::default()
        };
        let (bytes, _) = create("pw", &payload, Uuid::new_v4()).unwrap();
        let err = parse(&bytes).unwrap().unlock("pw").unwrap_err();
        assert!(matches!(err, AppError::UnsupportedSchema(_)), "got {err:?}");
    }

    #[test]
    fn dek_from_one_vault_cannot_open_another() {
        let (_, a) = create("pw", &sample_payload(), Uuid::new_v4()).unwrap();
        let (b_bytes, _) = create("pw", &sample_payload(), Uuid::new_v4()).unwrap();
        assert!(parse(&b_bytes).unwrap().decrypt_payload(&a.dek).is_err());
    }
}
