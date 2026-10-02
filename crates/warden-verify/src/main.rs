//! warden-verify — an intentionally small, standalone bundle verifier.
//!
//! This binary does NOT depend on warden-core. Every rule it checks is
//! reimplemented here from scratch, in one file, so that a skeptical
//! auditor — a regulator, opposing counsel, a judge's clerk — can read
//! the entire trust boundary in one sitting without needing to trust
//! anything else in this repository.
//!
//! What it checks, given a bundle directory (manifest.json + payloads/):
//!   1. Every entry's payload file hashes to its declared payload_hash.
//!   2. Every entry's entry_hash is the SHA-256 of its own canonical
//!      encoding (recomputed here, not read from the file).
//!   3. Every entry's signature verifies against the manifest's
//!      regulator_pubkey, over that same recomputed canonical encoding.
//!   4. Every entry's prev_hash matches the previous entry's entry_hash,
//!      and entry 0's prev_hash matches the genesis formula bound to
//!      (regulator_pubkey, ledger_id) — so entries cannot be spliced in
//!      from a different ledger or a different key.
//!   5. If anchors are present, that each anchor's root_hash matches the
//!      entry_hash of the entry at its up_to_seq (anchor proof content
//!      itself, e.g. an RFC 3161 token, is printed for manual/external
//!      verification — this tool does not call out to a TSA).
//!
//! Usage: warden-verify <bundle-dir>
//! Exit code 0 = every check passed. Non-zero = at least one failed;
//! see stderr for exactly which entry and which rule.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const GENESIS_DOMAIN: &[u8] = b"WARDEN-GENESIS-v1";
const ENTRY_DOMAIN: &[u8] = b"WARDEN-ENTRY-v1";

#[derive(Debug, Deserialize)]
struct Manifest {
    format_version: u32,
    ledger_id: String,
    regulator_pubkey: String,
    entries: Vec<Entry>,
    #[serde(default)]
    anchors: Vec<Anchor>,
}

#[derive(Debug, Deserialize)]
struct Entry {
    seq: u64,
    timestamp_unix: i64,
    prev_hash: String,
    payload_hash: String,
    payload_len: u64,
    entry_hash: String,
    signature: String,
    payload_ref: Option<String>,
    #[allow(dead_code)]
    label: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Anchor {
    up_to_seq: u64,
    root_hash: String,
    anchor_type: String,
    proof: String,
    #[allow(dead_code)]
    anchored_at_unix: i64,
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s).map_err(|e| format!("{what}: bad hex: {e}"))?;
    v.try_into()
        .map_err(|_| format!("{what}: expected 32 bytes"))
}

fn hex64(s: &str, what: &str) -> Result<[u8; 64], String> {
    let v = hex::decode(s).map_err(|e| format!("{what}: bad hex: {e}"))?;
    v.try_into()
        .map_err(|_| format!("{what}: expected 64 bytes"))
}

/// Byte-for-byte the same encoding used to build and sign entries.
/// Must match warden-core::canonical_bytes exactly.
fn canonical_bytes(
    seq: u64,
    timestamp_unix: i64,
    prev_hash: &[u8; 32],
    payload_hash: &[u8; 32],
    payload_len: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ENTRY_DOMAIN.len() + 8 + 8 + 32 + 32 + 8);
    buf.extend_from_slice(ENTRY_DOMAIN);
    buf.extend_from_slice(&seq.to_le_bytes());
    buf.extend_from_slice(&timestamp_unix.to_le_bytes());
    buf.extend_from_slice(prev_hash);
    buf.extend_from_slice(payload_hash);
    buf.extend_from_slice(&payload_len.to_le_bytes());
    buf
}

fn genesis_hash(regulator_pubkey: &[u8; 32], ledger_id_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(GENESIS_DOMAIN);
    hasher.update(regulator_pubkey);
    hasher.update(ledger_id_bytes);
    hasher.finalize().into()
}

fn run(bundle_dir: &Path) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    let manifest_path = bundle_dir.join("manifest.json");
    let raw = fs::read(&manifest_path)
        .map_err(|e| vec![format!("cannot read {}: {e}", manifest_path.display())])?;
    let manifest: Manifest = serde_json::from_slice(&raw)
        .map_err(|e| vec![format!("cannot parse manifest.json: {e}")])?;

    if manifest.format_version != 1 {
        errors.push(format!(
            "unsupported format_version {} (this verifier understands version 1)",
            manifest.format_version
        ));
    }

    let pubkey_bytes = match hex32(&manifest.regulator_pubkey, "regulator_pubkey") {
        Ok(b) => b,
        Err(e) => return Err(vec![e]),
    };
    let verifying_key = match VerifyingKey::from_bytes(&pubkey_bytes) {
        Ok(k) => k,
        Err(e) => {
            return Err(vec![format!(
                "regulator_pubkey is not a valid Ed25519 key: {e}"
            )])
        }
    };

    // ledger_id is a UUID string in the manifest; warden-core hashes its
    // raw 16-byte form. Parse the canonical UUID text form ourselves
    // rather than pulling in a uuid crate dependency.
    let ledger_id_bytes = match parse_uuid(&manifest.ledger_id) {
        Ok(b) => b,
        Err(e) => return Err(vec![e]),
    };

    if manifest.entries.is_empty() {
        return Err(vec!["manifest has zero entries".into()]);
    }

    let mut prev_entry_hash: Option<[u8; 32]> = None;

    for entry in &manifest.entries {
        let label = format!("seq {}", entry.seq);

        let prev_hash = match hex32(&entry.prev_hash, &label) {
            Ok(v) => v,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };
        let payload_hash_declared = match hex32(&entry.payload_hash, &label) {
            Ok(v) => v,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };
        let entry_hash_declared = match hex32(&entry.entry_hash, &label) {
            Ok(v) => v,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };
        let sig_bytes = match hex64(&entry.signature, &label) {
            Ok(v) => v,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };

        // Rule 4a: chain linkage.
        let expected_prev = match prev_entry_hash {
            Some(h) => h,
            None => genesis_hash(&pubkey_bytes, &ledger_id_bytes),
        };
        if prev_hash != expected_prev {
            errors.push(format!(
                "{label}: prev_hash does not match {} — chain is broken or spliced",
                if prev_entry_hash.is_none() {
                    "genesis"
                } else {
                    "preceding entry"
                }
            ));
        }

        // Rule 1: payload integrity, if a payload file was included.
        if let Some(payload_ref) = &entry.payload_ref {
            let payload_path = bundle_dir.join(payload_ref);
            match fs::read(&payload_path) {
                Ok(bytes) => {
                    if bytes.len() as u64 != entry.payload_len {
                        errors.push(format!(
                            "{label}: payload_len mismatch (manifest says {}, file is {} bytes)",
                            entry.payload_len,
                            bytes.len()
                        ));
                    }
                    let actual = sha256(&bytes);
                    if actual != payload_hash_declared {
                        errors.push(format!(
                            "{label}: payload file does not hash to payload_hash — payload was altered"
                        ));
                    }
                }
                Err(e) => errors.push(format!(
                    "{label}: payload_ref {} unreadable: {e}",
                    payload_path.display()
                )),
            }
        }

        // Rule 2: entry_hash is the hash of the canonical encoding.
        let cbytes = canonical_bytes(
            entry.seq,
            entry.timestamp_unix,
            &prev_hash,
            &payload_hash_declared,
            entry.payload_len,
        );
        let recomputed_hash = sha256(&cbytes);
        if recomputed_hash != entry_hash_declared {
            errors.push(format!(
                "{label}: entry_hash does not match recomputed hash of its own fields — record was altered"
            ));
        }

        // Rule 3: signature verifies over the same canonical encoding.
        let sig = Signature::from_bytes(&sig_bytes);
        if verifying_key.verify(&cbytes, &sig).is_err() {
            errors.push(format!(
                "{label}: signature does not verify against regulator_pubkey"
            ));
        }

        prev_entry_hash = Some(entry_hash_declared);
    }

    // Rule 5: anchors, if present, reference a real entry hash.
    for anchor in &manifest.anchors {
        let entry = manifest.entries.iter().find(|e| e.seq == anchor.up_to_seq);
        match entry {
            None => errors.push(format!(
                "anchor for seq {} references an entry that does not exist in this bundle",
                anchor.up_to_seq
            )),
            Some(entry) => {
                if entry.entry_hash.to_lowercase() != anchor.root_hash.to_lowercase() {
                    errors.push(format!(
                        "anchor for seq {} has root_hash that does not match that entry's entry_hash",
                        anchor.up_to_seq
                    ));
                } else {
                    eprintln!(
                        "  [info] anchor up to seq {}: type={}, proof={} — verify this proof independently against its external authority",
                        anchor.up_to_seq, anchor.anchor_type, anchor.proof
                    );
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Parse a canonical hyphenated UUID string into its 16 raw bytes,
/// without pulling in the uuid crate.
fn parse_uuid(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s.chars().filter(|c| *c != '-').collect();
    if cleaned.len() != 32 {
        return Err(format!("ledger_id is not a valid UUID: {s}"));
    }
    hex::decode(&cleaned).map_err(|e| format!("ledger_id is not valid hex: {e}"))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: warden-verify <bundle-dir>");
        return ExitCode::FAILURE;
    }
    let bundle_dir = PathBuf::from(&args[1]);

    println!("warden-verify: checking bundle at {}", bundle_dir.display());
    match run(&bundle_dir) {
        Ok(()) => {
            println!("OK — all entries verified: hashes match, signatures valid, chain unbroken.");
            ExitCode::SUCCESS
        }
        Err(errors) => {
            eprintln!("FAILED — {} problem(s) found:", errors.len());
            for e in &errors {
                eprintln!("  - {e}");
            }
            ExitCode::FAILURE
        }
    }
}
