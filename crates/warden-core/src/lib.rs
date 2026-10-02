//! warden-core
//!
//! The append-only, hash-chained, Ed25519-signed evidence ledger.
//!
//! DESIGN NOTE (read this before touching the wire format):
//! The signature and chain-link are computed over a hand-written canonical
//! byte encoding, NOT over serde_json output. JSON is not canonical across
//! implementations (field order, whitespace, number formatting all vary),
//! so signing JSON directly would make signatures unverifiable by any
//! third-party reimplementation. The `canonical_bytes()` function below is
//! the single source of truth for what gets hashed and signed. The
//! `warden-verify` crate reimplements this function independently (does
//! NOT depend on this crate) so that a skeptical auditor can compare the
//! two implementations by eye.

use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use uuid::Uuid;

pub const FORMAT_VERSION: u32 = 1;
pub const GENESIS_DOMAIN: &[u8] = b"WARDEN-GENESIS-v1";
pub const ENTRY_DOMAIN: &[u8] = b"WARDEN-ENTRY-v1";

/// One entry in the ledger. `entry_hash` and `signature` are computed over
/// `canonical_bytes()`, never over the JSON serialization of this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    pub timestamp_unix: i64,
    #[serde(with = "hex_32")]
    pub prev_hash: [u8; 32],
    #[serde(with = "hex_32")]
    pub payload_hash: [u8; 32],
    pub payload_len: u64,
    #[serde(with = "hex_32")]
    pub entry_hash: [u8; 32],
    #[serde(with = "hex_sig")]
    pub signature: [u8; 64],
    /// Relative path to the raw payload within the bundle, if one was stored.
    pub payload_ref: Option<String>,
    /// Free-text label supplied by the operator (e.g. "req#4821 /v1/complete").
    pub label: Option<String>,
}

/// The hash that anchors the first entry of a ledger. Binds the chain to a
/// specific regulator key and ledger id so entries from one ledger can
/// never be spliced into another.
pub fn genesis_hash(regulator_pubkey: &VerifyingKey, ledger_id: &Uuid) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(GENESIS_DOMAIN);
    hasher.update(regulator_pubkey.to_bytes());
    hasher.update(ledger_id.as_bytes());
    hasher.finalize().into()
}

/// Canonical byte encoding of an entry's signed fields, in fixed order,
/// with fixed-width little-endian integers. This is what gets hashed
/// (entry_hash) and what gets signed (signature).
pub fn canonical_bytes(
    seq: u64,
    timestamp_unix: i64,
    prev_hash: &[u8; 32],
    payload_hash: &[u8; 32],
    payload_len: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + 32 + 8 + 32 + 32 + 8);
    buf.extend_from_slice(ENTRY_DOMAIN);
    buf.extend_from_slice(&seq.to_le_bytes());
    buf.extend_from_slice(&timestamp_unix.to_le_bytes());
    buf.extend_from_slice(prev_hash);
    buf.extend_from_slice(payload_hash);
    buf.extend_from_slice(&payload_len.to_le_bytes());
    buf
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// An anchor: proof that the ledger's state at a given point existed no
/// later than a given time, established by a party outside the regulator's
/// own control (a timestamp authority, a transparency log, or a manually
/// recorded external publication). Without anchors, a regulator holding
/// the signing key could in principle rewrite history before ever
/// publishing a bundle; anchors close that gap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anchor {
    pub up_to_seq: u64,
    #[serde(with = "hex_32")]
    pub root_hash: [u8; 32],
    pub anchor_type: AnchorType,
    /// Opaque proof blob (e.g. an RFC 3161 timestamp token, a Rekor entry
    /// UUID + inclusion proof, or free text for a manual anchor).
    pub proof: String,
    pub anchored_at_unix: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnchorType {
    Rfc3161,
    Rekor,
    Manual,
}

/// The ledger. Holds the signing key only while actively ingesting;
/// exported bundles never contain the private key.
pub struct Ledger {
    pub ledger_id: Uuid,
    pub regulator_pubkey: VerifyingKey,
    pub entries: Vec<Entry>,
    pub anchors: Vec<Anchor>,
    signing_key: Option<SigningKey>,
}

#[derive(thiserror::Error, Debug)]
pub enum WardenError {
    #[error("chain broken at seq {seq}: prev_hash does not match preceding entry_hash")]
    ChainBroken { seq: u64 },
    #[error("signature invalid at seq {seq}")]
    BadSignature { seq: u64 },
    #[error("entry_hash mismatch at seq {seq}: stored hash does not match recomputed hash")]
    HashMismatch { seq: u64 },
    #[error("payload hash mismatch at seq {seq}: stored payload does not match payload_hash")]
    PayloadMismatch { seq: u64 },
    #[error("genesis mismatch: prev_hash of seq 0 does not derive from (pubkey, ledger_id)")]
    BadGenesis,
    #[error("ledger has no entries")]
    Empty,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("no signing key loaded; this ledger is read-only")]
    ReadOnly,
}

impl Ledger {
    /// Create a brand new ledger, generating a fresh keypair. The caller
    /// is responsible for persisting the returned signing key bytes
    /// somewhere safe — warden-core never writes private key material to
    /// disk on its own.
    pub fn new_with_generated_key() -> (Self, SigningKey) {
        let mut rng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let ledger = Self::new(signing_key.clone());
        (ledger, signing_key)
    }

    pub fn new(signing_key: SigningKey) -> Self {
        Ledger {
            ledger_id: Uuid::new_v4(),
            regulator_pubkey: signing_key.verifying_key(),
            entries: Vec::new(),
            anchors: Vec::new(),
            signing_key: Some(signing_key),
        }
    }

    /// Append a payload to the ledger, returning the new entry.
    /// `payload_ref` should be the relative path the payload will be
    /// written to inside the bundle (the CLI handles the actual file write).
    pub fn append(
        &mut self,
        payload: &[u8],
        payload_ref: Option<String>,
        label: Option<String>,
    ) -> Result<&Entry, WardenError> {
        let signing_key = self.signing_key.as_ref().ok_or(WardenError::ReadOnly)?;

        let seq = self.entries.len() as u64;
        let prev_hash = match self.entries.last() {
            Some(e) => e.entry_hash,
            None => genesis_hash(&self.regulator_pubkey, &self.ledger_id),
        };
        let timestamp_unix = Utc::now().timestamp();
        let payload_hash = sha256(payload);
        let payload_len = payload.len() as u64;

        let cbytes = canonical_bytes(seq, timestamp_unix, &prev_hash, &payload_hash, payload_len);
        let entry_hash = sha256(&cbytes);
        let signature: Signature = signing_key.sign(&cbytes);

        let entry = Entry {
            seq,
            timestamp_unix,
            prev_hash,
            payload_hash,
            payload_len,
            entry_hash,
            signature: signature.to_bytes(),
            payload_ref,
            label,
        };
        self.entries.push(entry);
        Ok(self.entries.last().unwrap())
    }

    /// Record an external anchor covering all entries up to `up_to_seq`.
    pub fn add_anchor(&mut self, anchor: Anchor) {
        self.anchors.push(anchor);
    }

    /// The root hash to submit for anchoring: the entry_hash of the most
    /// recent entry, which by construction commits to the entire chain.
    pub fn current_root(&self) -> Option<[u8; 32]> {
        self.entries.last().map(|e| e.entry_hash)
    }

    /// Self-check: recompute every hash and signature and verify the chain
    /// links. Use this after loading a ledger, and always run it before
    /// exporting a bundle. This is the same check `warden-verify` performs
    /// independently on an exported bundle.
    pub fn verify_chain(&self) -> Result<(), WardenError> {
        if self.entries.is_empty() {
            return Err(WardenError::Empty);
        }
        let expected_genesis = genesis_hash(&self.regulator_pubkey, &self.ledger_id);
        for (i, entry) in self.entries.iter().enumerate() {
            let expected_prev = if i == 0 {
                expected_genesis
            } else {
                self.entries[i - 1].entry_hash
            };
            if i == 0 && entry.prev_hash != expected_genesis {
                return Err(WardenError::BadGenesis);
            }
            if entry.prev_hash != expected_prev {
                return Err(WardenError::ChainBroken { seq: entry.seq });
            }
            let cbytes = canonical_bytes(
                entry.seq,
                entry.timestamp_unix,
                &entry.prev_hash,
                &entry.payload_hash,
                entry.payload_len,
            );
            let recomputed_hash = sha256(&cbytes);
            if recomputed_hash != entry.entry_hash {
                return Err(WardenError::HashMismatch { seq: entry.seq });
            }
            let sig = Signature::from_bytes(&entry.signature);
            if self
                .regulator_pubkey
                .verify(&cbytes, &sig)
                .is_err()
            {
                return Err(WardenError::BadSignature { seq: entry.seq });
            }
        }
        Ok(())
    }

    /// Rehydrate a Ledger from a previously-written manifest, so a CLI
    /// process can load existing state, append more entries, and persist
    /// again. `signing_key` is required to append; omit it (None) to load
    /// a ledger in read-only mode (e.g. just to call `verify_chain`).
    pub fn from_manifest(
        manifest: Manifest,
        signing_key: Option<SigningKey>,
    ) -> Result<Self, WardenError> {
        let pubkey_bytes: [u8; 32] = hex::decode(&manifest.regulator_pubkey)
            .map_err(|_| WardenError::BadGenesis)?
            .try_into()
            .map_err(|_| WardenError::BadGenesis)?;
        let regulator_pubkey =
            VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| WardenError::BadGenesis)?;

        if let Some(sk) = &signing_key {
            if sk.verifying_key() != regulator_pubkey {
                return Err(WardenError::BadGenesis);
            }
        }

        Ok(Ledger {
            ledger_id: manifest.ledger_id,
            regulator_pubkey,
            entries: manifest.entries,
            anchors: manifest.anchors,
            signing_key,
        })
    }

    pub fn to_manifest(&self) -> Manifest {
        Manifest {
            format_version: FORMAT_VERSION,
            ledger_id: self.ledger_id,
            regulator_pubkey: hex::encode(self.regulator_pubkey.to_bytes()),
            created_at_unix: self
                .entries
                .first()
                .map(|e| e.timestamp_unix)
                .unwrap_or_else(|| Utc::now().timestamp()),
            entries: self.entries.clone(),
            anchors: self.anchors.clone(),
        }
    }
}

/// The exported, self-contained manifest. Contains no private key
/// material. This is what gets written as `manifest.json` inside a
/// bundle directory, alongside a `payloads/` directory holding the raw
/// payload bytes referenced by `Entry::payload_ref`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub format_version: u32,
    pub ledger_id: Uuid,
    pub regulator_pubkey: String,
    pub created_at_unix: i64,
    pub entries: Vec<Entry>,
    pub anchors: Vec<Anchor>,
}

/// Write a bundle directory: `<dir>/manifest.json` plus `<dir>/payloads/*`.
/// Payload files must already exist at the paths given by `payload_ref`
/// relative to `dir` (the CLI writes these as it ingests).
pub fn write_manifest(dir: &Path, manifest: &Manifest) -> Result<(), WardenError> {
    fs::create_dir_all(dir)?;
    let path = dir.join("manifest.json");
    let json = serde_json::to_string_pretty(manifest)?;
    fs::write(path, json)?;
    Ok(())
}

pub fn read_manifest(dir: &Path) -> Result<Manifest, WardenError> {
    let path = dir.join("manifest.json");
    let data = fs::read(path)?;
    Ok(serde_json::from_slice(&data)?)
}

// --- hex (de)serialization helpers for fixed-size byte arrays ---

mod hex_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

mod hex_sig {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_of_three_verifies() {
        let (mut ledger, _sk) = Ledger::new_with_generated_key();
        ledger.append(b"first payload", None, Some("req 1".into())).unwrap();
        ledger.append(b"second payload", None, Some("req 2".into())).unwrap();
        ledger.append(b"third payload", None, Some("req 3".into())).unwrap();
        assert_eq!(ledger.entries.len(), 3);
        ledger.verify_chain().unwrap();
    }

    #[test]
    fn tampered_payload_hash_is_detected() {
        let (mut ledger, _sk) = Ledger::new_with_generated_key();
        ledger.append(b"original", None, None).unwrap();
        ledger.entries[0].payload_hash = sha256(b"forged");
        assert!(ledger.verify_chain().is_err());
    }

    #[test]
    fn tampered_prev_hash_breaks_chain() {
        let (mut ledger, _sk) = Ledger::new_with_generated_key();
        ledger.append(b"a", None, None).unwrap();
        ledger.append(b"b", None, None).unwrap();
        ledger.entries[1].prev_hash = [0xAB; 32];
        assert!(matches!(
            ledger.verify_chain(),
            Err(WardenError::ChainBroken { seq: 1 })
        ));
    }

    #[test]
    fn wrong_key_signature_rejected() {
        let (mut ledger, _sk) = Ledger::new_with_generated_key();
        ledger.append(b"a", None, None).unwrap();
        // Corrupt the signature bytes directly.
        ledger.entries[0].signature[0] ^= 0xFF;
        assert!(matches!(
            ledger.verify_chain(),
            Err(WardenError::BadSignature { seq: 0 })
        ));
    }
}
