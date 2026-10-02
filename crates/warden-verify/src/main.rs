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
//!      entry_hash of the entry at its up_to_seq.
//!   6. For RFC 3161 anchors, that the stored token's `messageImprint` is
//!      SHA-256 of that root — so the token really does timestamp this
//!      bundle (the token's own signature is NOT checked here: verifying
//!      CMS certificates is beyond this file's intended scope, and
//!      `warden info` already does it; nothing here makes a network call).
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
        let Some(entry) = entry else {
            errors.push(format!(
                "anchor for seq {} references an entry that does not exist in this bundle",
                anchor.up_to_seq
            ));
            continue;
        };
        if entry.entry_hash.to_lowercase() != anchor.root_hash.to_lowercase() {
            errors.push(format!(
                "anchor for seq {} has root_hash that does not match that entry's entry_hash",
                anchor.up_to_seq
            ));
            continue;
        }

        if anchor.anchor_type != "Rfc3161" {
            eprintln!(
                "  [info] anchor up to seq {}: type={}, proof={} — verify this proof independently against its external authority",
                anchor.up_to_seq, anchor.anchor_type, anchor.proof
            );
            continue;
        }

        // Rule 6: an RFC 3161 token must actually timestamp this root.
        match rfc3161_report(&anchor.proof, &anchor.root_hash) {
            Ok(gen_time) => eprintln!(
                "  [ok] anchor up to seq {}: RFC 3161 token commits to this root (genTime={gen_time}; signature not checked here — run `warden info` for that)",
                anchor.up_to_seq
            ),
            Err(e) => errors.push(format!(
                "anchor for seq {}: RFC 3161 token does not check out: {e}",
                anchor.up_to_seq
            )),
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

/// Standard base64 (RFC 4648) with padding, hand-rolled the same way
/// `parse_uuid` is: this verifier stays free of dependencies it doesn't
/// need to re-implement a rule.
fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    fn sextet(c: u8) -> Result<u8, String> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            other => Err(format!("invalid base64 character {:?}", other as char)),
        }
    }

    let text: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if !text.len().is_multiple_of(4) {
        return Err("base64 length is not a multiple of 4".into());
    }
    let bytes = text.as_bytes();
    let pad = if text.ends_with("==") {
        2
    } else if text.ends_with('=') {
        1
    } else {
        0
    };
    let data_len = bytes.len() - pad;
    if data_len % 4 == 1 {
        return Err("base64 has a single leftover character".into());
    }

    let mut out = Vec::with_capacity(data_len * 3 / 4 + 2);
    let mut i = 0;
    while i < data_len {
        let remaining = data_len - i;
        let a = sextet(bytes[i])?;
        let b = sextet(bytes[i + 1])?;
        out.push((a << 2) | (b >> 4));
        if remaining == 2 {
            break;
        }
        let c = sextet(bytes[i + 2])?;
        out.push((b << 4) | (c >> 2));
        if remaining == 3 {
            break;
        }
        let d = sextet(bytes[i + 3])?;
        out.push((c << 6) | d);
        i += 4;
    }
    Ok(out)
}

/// DER contents of `id-ct-TSTInfo` (1.2.840.113549.1.9.16.1.4) and
/// `id-sha256` (2.16.840.1.101.3.4.2.1), without their tag/length bytes.
const OID_TST_INFO: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04,
];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// One DER tag/length/value triple, borrowed from its input slice.
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

/// Read one TLV at `offset`, returning it plus the offset just past it.
fn tlv_at<'a>(data: &'a [u8], offset: usize, what: &str) -> Result<(Tlv<'a>, usize), String> {
    if offset >= data.len() {
        return Err(format!("{what}: truncated"));
    }
    let tag = data[offset];
    let mut i = offset + 1;
    if tag & 0x1f == 0x1f {
        while i < data.len() && data[i] & 0x80 != 0 {
            i += 1;
        }
        if i >= data.len() {
            return Err(format!("{what}: truncated tag"));
        }
        i += 1;
    }
    if i >= data.len() {
        return Err(format!("{what}: truncated length"));
    }
    let first_len = data[i];
    i += 1;
    let len = if first_len & 0x80 == 0 {
        first_len as usize
    } else {
        let n = (first_len & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Err(format!("{what}: implausible length encoding"));
        }
        if i + n > data.len() {
            return Err(format!("{what}: truncated length"));
        }
        let mut l = 0usize;
        for _ in 0..n {
            l = (l << 8) | data[i] as usize;
            i += 1;
        }
        l
    };
    if i + len > data.len() {
        return Err(format!("{what}: value runs past the end of the data"));
    }
    Ok((
        Tlv {
            tag,
            value: &data[i..i + len],
        },
        i + len,
    ))
}

/// Split the contents of a DER SEQUENCE into its members.
fn tlv_children<'a>(data: &'a [u8], what: &str) -> Result<Vec<Tlv<'a>>, String> {
    let mut members = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let (member, next) = tlv_at(data, offset, what)?;
        members.push(member);
        offset = next;
    }
    Ok(members)
}

/// Pull `genTime` and the `messageImprint` out of a base64 RFC 3161
/// TimeStampToken, walking only the DER fields needed for Rule 6:
/// ContentInfo -> SignedData -> encapContentInfo -> TSTInfo.
fn token_imprint(proof_b64: &str) -> Result<(String, [u8; 32]), String> {
    let der = decode_base64(proof_b64)?;

    let (content_info, _) = tlv_at(&der, 0, "ContentInfo")?;
    if content_info.tag != 0x30 {
        return Err("token is not a DER SEQUENCE".into());
    }
    let ci_members = tlv_children(content_info.value, "ContentInfo")?;

    let signed = ci_members
        .iter()
        .find(|t| t.tag == 0xa0)
        .ok_or_else(|| "token carries no SignedData".to_string())?;
    let (signed_data, _) = tlv_at(signed.value, 0, "SignedData")?;
    let sd_members = tlv_children(signed_data.value, "SignedData")?;

    // encapContentInfo is the SEQUENCE whose first member is id-ct-TSTInfo.
    let mut encap_members = None;
    for member in sd_members.iter().filter(|t| t.tag == 0x30) {
        let members = tlv_children(member.value, "encapContentInfo")?;
        if matches!(
            members.first(),
            Some(m) if m.tag == 0x06 && m.value == OID_TST_INFO
        ) {
            encap_members = Some(members);
            break;
        }
    }
    let encap_members =
        encap_members.ok_or_else(|| "token's eContent is not id-ct-TSTInfo".to_string())?;

    let econtent = encap_members
        .iter()
        .find(|t| t.tag == 0xa0)
        .ok_or_else(|| "token's eContent is missing".to_string())?;
    let (octet, _) = tlv_at(econtent.value, 0, "eContent")?;
    if octet.tag != 0x04 {
        return Err("token's eContent is not an OCTET STRING".into());
    }

    // TSTInfo: version, policy, messageImprint, serial, genTime, ...
    let (tst_info, _) = tlv_at(octet.value, 0, "TSTInfo")?;
    if tst_info.tag != 0x30 {
        return Err("token's eContent does not hold a TSTInfo SEQUENCE".into());
    }
    let tst = tlv_children(tst_info.value, "TSTInfo")?;
    let imprint_seq = tst
        .iter()
        .find(|t| t.tag == 0x30)
        .ok_or_else(|| "TSTInfo has no messageImprint".to_string())?;
    let gen_time = tst
        .iter()
        .find(|t| t.tag == 0x18)
        .ok_or_else(|| "TSTInfo has no genTime".to_string())?;

    let imprint_members = tlv_children(imprint_seq.value, "messageImprint")?;
    let hash_alg = imprint_members
        .first()
        .filter(|t| t.tag == 0x30)
        .ok_or_else(|| "messageImprint has no hash algorithm".to_string())?;
    let alg_members = tlv_children(hash_alg.value, "hashAlgorithm")?;
    let oid = alg_members
        .first()
        .filter(|t| t.tag == 0x06)
        .ok_or_else(|| "hash algorithm has no OID".to_string())?;
    if oid.value != OID_SHA256 {
        return Err("messageImprint does not use SHA-256".into());
    }
    let hashed = imprint_members
        .get(1)
        .filter(|t| t.tag == 0x04)
        .ok_or_else(|| "messageImprint has no hashedMessage".to_string())?;
    if hashed.value.len() != 32 {
        return Err(format!(
            "messageImprint is {} bytes, expected 32",
            hashed.value.len()
        ));
    }
    let mut imprint = [0u8; 32];
    imprint.copy_from_slice(hashed.value);

    Ok((
        String::from_utf8_lossy(gen_time.value).into_owned(),
        imprint,
    ))
}

/// Rule 6: the stored RFC 3161 token must timestamp this bundle's root.
/// Returns the token's `genTime` when it does.
fn rfc3161_report(proof_b64: &str, root_hash_hex: &str) -> Result<String, String> {
    let root = hex32(root_hash_hex, "anchor root_hash")?;
    let (gen_time, imprint) = token_imprint(proof_b64)?;
    if imprint != sha256(&root) {
        return Err(
            "messageImprint is not SHA-256 of this bundle's root — it timestamps a different value"
                .into(),
        );
    }
    Ok(gen_time)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A real freetsa.org token, captured from `warden anchor --type rfc3161`.
    const PROOF: &str = include_str!("../tests/fixtures/rfc3161-proof.b64");
    const ROOT_HEX: &str = "cfd7e9e720f040bf65c8799157309aae3c2e7491b4e3ce31bac001276eb6cb70";

    #[test]
    fn base64_decoder_handles_padding_and_remainders() {
        assert_eq!(decode_base64("").unwrap(), Vec::<u8>::new());
        assert_eq!(decode_base64("TQ==").unwrap(), b"M");
        assert_eq!(decode_base64("TWE=").unwrap(), b"Ma");
        assert_eq!(decode_base64("SGVsbG8=").unwrap(), b"Hello");
        assert!(decode_base64("TQ=").is_err());
        assert!(decode_base64("QQ=#").is_err());
        assert!(decode_base64("A===").is_err());
    }

    #[test]
    fn captured_token_imprints_the_root_it_claims() {
        let (gen_time, imprint) = token_imprint(PROOF).unwrap();
        assert_eq!(gen_time, "20261002193814Z");
        let root: [u8; 32] = hex::decode(ROOT_HEX).unwrap().try_into().unwrap();
        assert_eq!(imprint, sha256(&root));
        assert_eq!(rfc3161_report(PROOF, ROOT_HEX).unwrap(), gen_time);
    }

    #[test]
    fn token_timestamping_another_root_is_rejected() {
        let err = rfc3161_report(PROOF, &hex::encode([0x11; 32])).unwrap_err();
        assert!(err.contains("timestamps a different value"), "{err}");
    }

    #[test]
    fn unreadable_proofs_are_rejected() {
        assert!(token_imprint("not base64!").is_err());
        assert!(token_imprint("AAAA").is_err());
        assert!(token_imprint(&PROOF[..100]).is_err());
    }
}
