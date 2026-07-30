//! Argon2id key derivation.
//!
//! Parameters are stored *with* the vault (never the key) so that a vault
//! created today still opens after the defaults are raised, and so the cost can
//! be increased on a future re-encrypt. The parameters are authenticated as AEAD
//! associated data when the data key is unwrapped — see [`KdfParams::aad`] — so
//! an attacker cannot downgrade the cost of an existing vault.

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::random;
use crate::error::{AppError, Result};

/// Length of a derived key, in bytes (XChaCha20-Poly1305 key size).
pub const KEY_LEN: usize = 32;
/// Length of the KDF salt, in bytes.
pub const SALT_LEN: usize = 16;

/// 64 MiB. Comfortably above the OWASP Argon2id floor of 19 MiB and still
/// well under what a desktop machine can spare for a ~0.2s unlock.
pub const DEFAULT_M_COST_KIB: u32 = 64 * 1024;
pub const DEFAULT_T_COST: u32 = 3;
pub const DEFAULT_P_COST: u32 = 4;

/// Ceilings on parameters read from a vault header. Generous enough to allow a
/// future increase of the defaults by a wide margin, tight enough that a hostile
/// file cannot turn "open this vault" into an OOM abort or an unbounded hang.
/// 2 GiB of Argon2 memory, 64 passes, 64 lanes.
pub const MAX_M_COST_KIB: u32 = 2 * 1024 * 1024;
pub const MAX_T_COST: u32 = 64;
pub const MAX_P_COST: u32 = 64;

/// A 32-byte symmetric key that scrubs itself on drop.
pub type Key32 = Zeroizing<[u8; KEY_LEN]>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Only `"argon2id"` is accepted; present so the field can carry a future
    /// algorithm without another format bump.
    pub algorithm: String,
    /// Argon2 version number. `19` == `0x13`.
    pub version: u32,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    #[serde(with = "crate::crypto::b64")]
    pub salt: Vec<u8>,
}

impl KdfParams {
    /// Fresh parameters with the current defaults and a new random salt.
    pub fn generate() -> Result<Self> {
        Ok(Self {
            algorithm: "argon2id".to_string(),
            version: 0x13,
            m_cost_kib: DEFAULT_M_COST_KIB,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
            salt: random::bytes::<SALT_LEN>()?.to_vec(),
        })
    }

    /// The associated data that binds a wrapped key to these parameters.
    ///
    /// Deterministic and *not* JSON, so there is no canonicalization step that
    /// could disagree between writer and reader.
    pub fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(64 + self.salt.len());
        aad.extend_from_slice(b"pmv1:kdf:");
        aad.extend_from_slice(self.algorithm.as_bytes());
        aad.push(b':');
        aad.extend_from_slice(self.m_cost_kib.to_string().as_bytes());
        aad.push(b':');
        aad.extend_from_slice(self.t_cost.to_string().as_bytes());
        aad.push(b':');
        aad.extend_from_slice(self.p_cost.to_string().as_bytes());
        aad.push(b':');
        aad.extend_from_slice(&self.salt);
        aad
    }

    fn validate(&self) -> Result<()> {
        if self.algorithm != "argon2id" {
            return Err(AppError::Corrupt("unsupported kdf algorithm"));
        }
        if self.version != 0x13 {
            return Err(AppError::Corrupt("unsupported argon2 version"));
        }
        if self.salt.len() < 8 {
            return Err(AppError::Corrupt("kdf salt too short"));
        }
        // Refuse absurdly cheap parameters even though they are authenticated:
        // a vault written by a buggy or malicious client should not open at a
        // security level we would never choose ourselves.
        if self.m_cost_kib < 8 * 1024 || self.t_cost < 1 || self.p_cost < 1 {
            return Err(AppError::Corrupt(
                "kdf parameters below the accepted minimum",
            ));
        }
        // ...and refuse absurdly *expensive* ones. These values come from a file
        // that may be attacker-supplied (a hostile `.pmv`, or a tampered object in
        // a bucket someone else can write). Without a ceiling, `m_cost_kib` of
        // 4 TiB turns opening a vault into an out-of-memory abort and a large
        // `t_cost` into an unbounded hang.
        if self.m_cost_kib > MAX_M_COST_KIB || self.t_cost > MAX_T_COST || self.p_cost > MAX_P_COST
        {
            return Err(AppError::Corrupt(
                "kdf parameters above the accepted maximum",
            ));
        }
        Ok(())
    }
}

/// Derive the 32-byte master key from the master password.
///
/// The returned key is zeroized on drop. It is only needed long enough to
/// unwrap the data encryption key and is deliberately *not* retained for the
/// lifetime of an unlocked session.
pub fn derive_master_key(password: &str, params: &KdfParams) -> Result<Key32> {
    params.validate()?;

    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|_| AppError::Corrupt("invalid argon2 parameters"))?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut key: Key32 = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password.as_bytes(), &params.salt, key.as_mut())
        .map_err(|_| AppError::Crypto)?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap parameters so the test suite stays fast. Never used in production.
    fn test_params() -> KdfParams {
        KdfParams {
            algorithm: "argon2id".into(),
            version: 0x13,
            m_cost_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
            salt: vec![7u8; SALT_LEN],
        }
    }

    #[test]
    fn derivation_is_deterministic() {
        let p = test_params();
        let a = derive_master_key("correct horse battery staple", &p).unwrap();
        let b = derive_master_key("correct horse battery staple", &p).unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
        assert_ne!(a.as_ref(), &[0u8; KEY_LEN]);
    }

    #[test]
    fn different_password_yields_different_key() {
        let p = test_params();
        let a = derive_master_key("password-a", &p).unwrap();
        let b = derive_master_key("password-b", &p).unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn different_salt_yields_different_key() {
        let mut p1 = test_params();
        let mut p2 = test_params();
        p1.salt = vec![1u8; SALT_LEN];
        p2.salt = vec![2u8; SALT_LEN];
        let a = derive_master_key("same password", &p1).unwrap();
        let b = derive_master_key("same password", &p2).unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn generated_params_have_unique_salts() {
        let a = KdfParams::generate().unwrap();
        let b = KdfParams::generate().unwrap();
        assert_ne!(a.salt, b.salt);
        assert_eq!(a.salt.len(), SALT_LEN);
        assert_eq!(a.m_cost_kib, DEFAULT_M_COST_KIB);
    }

    #[test]
    fn aad_changes_with_every_parameter() {
        let base = test_params();
        let baseline = base.aad();

        let mut cheaper = base.clone();
        cheaper.m_cost_kib = 16 * 1024;
        assert_ne!(cheaper.aad(), baseline);

        let mut fewer_passes = base.clone();
        fewer_passes.t_cost = 2;
        assert_ne!(fewer_passes.aad(), baseline);

        let mut wider = base.clone();
        wider.p_cost = 2;
        assert_ne!(wider.aad(), baseline);

        let mut resalted = base.clone();
        resalted.salt = vec![9u8; SALT_LEN];
        assert_ne!(resalted.aad(), baseline);
    }

    /// The AAD must not be ambiguous under field concatenation: two different
    /// parameter sets must never serialize to the same byte string.
    #[test]
    fn aad_is_unambiguous() {
        let mut a = test_params();
        a.m_cost_kib = 11;
        a.t_cost = 111;
        let mut b = test_params();
        b.m_cost_kib = 111;
        b.t_cost = 11;
        assert_ne!(a.aad(), b.aad());
    }

    /// A hostile vault file must not be able to turn "open this vault" into an
    /// out-of-memory abort or an unbounded hang.
    #[test]
    fn rejects_absurdly_expensive_parameters() {
        let mut huge_memory = test_params();
        huge_memory.m_cost_kib = u32::MAX;
        assert!(derive_master_key("pw", &huge_memory).is_err());

        let mut many_passes = test_params();
        many_passes.t_cost = u32::MAX;
        assert!(derive_master_key("pw", &many_passes).is_err());

        let mut many_lanes = test_params();
        many_lanes.p_cost = 0xFF_FFFF;
        assert!(derive_master_key("pw", &many_lanes).is_err());

        // The production defaults must sit comfortably inside the ceilings.
        let defaults = KdfParams::generate().unwrap();
        assert!(defaults.m_cost_kib < MAX_M_COST_KIB);
        assert!(defaults.t_cost < MAX_T_COST);
        assert!(defaults.p_cost < MAX_P_COST);
    }

    #[test]
    fn rejects_downgraded_parameters() {
        let mut weak = test_params();
        weak.m_cost_kib = 64;
        assert!(derive_master_key("pw", &weak).is_err());

        let mut wrong_algo = test_params();
        wrong_algo.algorithm = "argon2i".into();
        assert!(derive_master_key("pw", &wrong_algo).is_err());

        let mut short_salt = test_params();
        short_salt.salt = vec![1, 2, 3];
        assert!(derive_master_key("pw", &short_salt).is_err());
    }
}
