//! warden — operator CLI for building an independent, regulator-held
//! evidence ledger.
//!
//! Typical session:
//!   warden keygen --key ./warden.key
//!   warden init   --dir ./ledger --key ./warden.key
//!   warden ingest --dir ./ledger --key ./warden.key --file req1.json --label "req#1"
//!   warden ingest --dir ./ledger --key ./warden.key --file req2.json --label "req#2"
//!   warden anchor --dir ./ledger --type manual --proof "published to <url> at <time>"
//!   warden info   --dir ./ledger
//!
//! Then hand the `./ledger` directory (manifest.json + payloads/) to
//! anyone — but NEVER `warden.key`, which must live outside `./ledger`
//! so it can't travel with the evidence. They verify it with
//! `warden-verify ./ledger`, a separate, deliberately tiny binary that
//! does not depend on this crate.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use warden_core::{Anchor, AnchorType, Ledger, Manifest};

mod tsa;

#[derive(Parser)]
#[command(name = "warden", about = "Independent, regulator-held evidence ledger")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new Ed25519 signing key and write it to a file.
    Keygen {
        #[arg(long)]
        key: PathBuf,
    },
    /// Create a new, empty ledger bound to a signing key.
    Init {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        key: PathBuf,
    },
    /// Append a payload (a captured request/response/artifact) to the ledger.
    Ingest {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        key: PathBuf,
        /// Read payload from this file. Omit to read from stdin.
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        label: Option<String>,
    },
    /// Record an external anchor (a timestamp/transparency-log proof)
    /// covering the ledger up to its current last entry.
    Anchor {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, value_enum)]
        r#type: AnchorTypeArg,
        /// The proof: a base64 RFC 3161 token (verified against this
        /// ledger's current root before it is recorded), a Rekor entry
        /// reference, or free text describing a manual publication.
        #[arg(long)]
        proof: Option<String>,
        /// RFC 3161 timestamp authority to ask when --proof is omitted
        /// (e.g. https://freetsa.org/tsr). Only for --type rfc3161.
        #[arg(long)]
        tsa_url: Option<String>,
        /// TSA certificate (PEM or DER) to pin: the token's signer must
        /// carry this exact public key. Only for --type rfc3161.
        #[arg(long)]
        tsa_cert: Option<PathBuf>,
    },
    /// Re-verify the ledger in place (same checks warden-verify runs on
    /// an exported bundle) and print a summary.
    Info {
        #[arg(long)]
        dir: PathBuf,
    },
}

#[derive(Clone, clap::ValueEnum)]
enum AnchorTypeArg {
    Rfc3161,
    Rekor,
    Manual,
}

impl From<AnchorTypeArg> for AnchorType {
    fn from(a: AnchorTypeArg) -> Self {
        match a {
            AnchorTypeArg::Rfc3161 => AnchorType::Rfc3161,
            AnchorTypeArg::Rekor => AnchorType::Rekor,
            AnchorTypeArg::Manual => AnchorType::Manual,
        }
    }
}

fn load_key(path: &Path) -> Result<SigningKey> {
    let hex_str =
        fs::read_to_string(path).with_context(|| format!("reading key file {}", path.display()))?;
    let bytes = hex::decode(hex_str.trim()).context("key file is not valid hex")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("key file must contain a 32-byte Ed25519 seed"))?;
    Ok(SigningKey::from_bytes(&arr))
}

fn write_key(path: &Path, key: &SigningKey) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, hex::encode(key.to_bytes()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen { key } => cmd_keygen(&key),
        Command::Init { dir, key } => cmd_init(&dir, &key),
        Command::Ingest {
            dir,
            key,
            file,
            label,
        } => cmd_ingest(&dir, &key, file.as_deref(), label),
        Command::Anchor {
            dir,
            r#type,
            proof,
            tsa_url,
            tsa_cert,
        } => cmd_anchor(&dir, r#type.into(), proof, tsa_url, tsa_cert),
        Command::Info { dir } => cmd_info(&dir),
    }
}

fn cmd_keygen(key_path: &Path) -> Result<()> {
    if key_path.exists() {
        bail!(
            "{} already exists — refusing to overwrite a key",
            key_path.display()
        );
    }
    let mut rng = rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    write_key(key_path, &signing_key)?;
    println!("wrote new signing key to {}", key_path.display());
    println!(
        "regulator public key: {}",
        hex::encode(signing_key.verifying_key().to_bytes())
    );
    println!(
        "IMPORTANT: this file is the ONLY thing that proves entries came from you. \
         Back it up somewhere the AI vendor cannot reach, e.g. offline or in a separate custody system."
    );
    Ok(())
}

fn cmd_init(dir: &Path, key_path: &Path) -> Result<()> {
    if dir.join("manifest.json").exists() {
        bail!(
            "{} already has a manifest.json — ledger already initialized",
            dir.display()
        );
    }
    let signing_key = load_key(key_path)?;
    let ledger = Ledger::new(signing_key);
    fs::create_dir_all(dir.join("payloads"))?;
    let manifest = ledger.to_manifest();
    warden_core::write_manifest(dir, &manifest)?;
    println!("initialized empty ledger at {}", dir.display());
    println!("ledger_id: {}", manifest.ledger_id);
    println!("regulator_pubkey: {}", manifest.regulator_pubkey);
    Ok(())
}

fn cmd_ingest(
    dir: &Path,
    key_path: &Path,
    file: Option<&Path>,
    label: Option<String>,
) -> Result<()> {
    let signing_key = load_key(key_path)?;
    let manifest = warden_core::read_manifest(dir).context("loading existing ledger")?;
    let mut ledger = Ledger::from_manifest(manifest, Some(signing_key))
        .context("signing key does not match this ledger's regulator_pubkey")?;

    let payload: Vec<u8> = match file {
        Some(path) => fs::read(path).with_context(|| format!("reading {}", path.display()))?,
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("reading payload from stdin")?;
            buf
        }
    };
    if payload.is_empty() {
        bail!("payload is empty — nothing to ingest");
    }

    let seq = ledger.entries.len() as u64;
    let payload_ref = format!("payloads/{seq:08}.bin");
    fs::write(dir.join(&payload_ref), &payload)?;

    let entry = ledger.append(&payload, Some(payload_ref), label)?.clone();

    ledger
        .verify_chain()
        .context("post-append self-check failed — refusing to persist")?;

    let manifest = ledger.to_manifest();
    warden_core::write_manifest(dir, &manifest)?;

    println!(
        "appended entry seq={} entry_hash={}",
        entry.seq,
        hex::encode(entry.entry_hash)
    );
    println!("ledger now has {} entries", ledger.entries.len());
    Ok(())
}

fn cmd_anchor(
    dir: &Path,
    anchor_type: AnchorType,
    proof: Option<String>,
    tsa_url: Option<String>,
    tsa_cert: Option<PathBuf>,
) -> Result<()> {
    if anchor_type != AnchorType::Rfc3161 && (tsa_url.is_some() || tsa_cert.is_some()) {
        bail!("--tsa-url and --tsa-cert only apply to --type rfc3161");
    }

    let manifest = warden_core::read_manifest(dir)?;
    let ledger = Ledger::from_manifest(manifest, None)?;
    let up_to_seq = match ledger.entries.last() {
        Some(e) => e.seq,
        None => bail!("ledger has no entries yet — nothing to anchor"),
    };
    let root_hash = ledger.current_root().unwrap();

    let pinned = match &tsa_cert {
        Some(path) => Some(tsa::load_pinned_spki(path)?),
        None => None,
    };

    let proof = match anchor_type {
        AnchorType::Rfc3161 => match proof {
            Some(text) => {
                let token = tsa::decode_token(&text)
                    .context("--proof is not a valid base64 TimeStampToken")?;
                let verified = tsa::verify_token(&token, &root_hash, None, pinned.as_deref())?;
                print_timestamp(&verified);
                text
            }
            None => {
                let url = tsa_url.as_deref().ok_or_else(|| {
                    anyhow!("--type rfc3161 needs either --tsa-url <url> (ask a TSA now) or --proof <base64 token>")
                })?;
                let (token, verified) = tsa::timestamp_root(url, &root_hash, pinned.as_deref())?;
                print_timestamp(&verified);
                tsa::encode_token(&token)
            }
        },
        _ => proof.ok_or_else(|| anyhow!("--proof is required for this anchor type"))?,
    };

    let mut ledger = ledger;
    ledger.add_anchor(Anchor {
        up_to_seq,
        root_hash,
        anchor_type,
        proof: proof.clone(),
        anchored_at_unix: chrono::Utc::now().timestamp(),
    });
    let manifest = ledger.to_manifest();
    warden_core::write_manifest(dir, &manifest)?;
    println!(
        "recorded anchor for seq 0..={} — root_hash={}",
        up_to_seq,
        hex::encode(root_hash)
    );
    if anchor_type == AnchorType::Rfc3161 {
        println!(
            "stored a {}-byte base64 RFC 3161 token as this anchor's proof",
            proof.len()
        );
    } else {
        println!("(this root_hash is what you should have submitted to your external timestamp authority / transparency log)");
    }
    Ok(())
}

fn print_timestamp(verified: &tsa::VerifiedTimestamp) {
    println!("RFC 3161 timestamp verified against this ledger's root hash:");
    println!("  {:<13} {}", "policy:", verified.policy);
    println!("  {:<13} {}", "genTime:", verified.gen_time);
    println!("  {:<13} {}", "tsa subject:", verified.tsa_subject);
    println!("  {:<13} {}", "tsa serial:", verified.serial_hex);
}

/// Re-verify one stored anchor's proof against the root hash it recorded.
///
/// This is the offline re-run of the checks `warden anchor` already applied
/// when the proof was accepted: for an RFC 3161 token that is the full path
/// in `tsa::verify_token` — messageImprint over *this* anchor's root, the
/// CMS signed attributes, the signature, and the signer certificate's
/// validity at `genTime`. (The request nonce is the one check that cannot
/// be repeated: the request is gone by the time anyone re-reads the bundle.)
///
/// Returns the one-line report, or `Err` with that same report when the
/// proof does not check out — `warden info` exits non-zero on any `Err`.
fn anchor_proof_status(anchor: &Anchor) -> Result<String, String> {
    let scope = format!("seq 0..={}", anchor.up_to_seq);
    match anchor.anchor_type {
        AnchorType::Rfc3161 => {
            let checked = tsa::decode_token(&anchor.proof)
                .context("proof is not base64")
                .and_then(|token| tsa::verify_token(&token, &anchor.root_hash, None, None));
            checked
                .map(|v| {
                    format!(
                        "rfc3161 {scope} OK — genTime {}, policy {}, TSA {}",
                        v.gen_time, v.policy, v.tsa_subject
                    )
                })
                .map_err(|e| format!("rfc3161 {scope} FAILED — {e:#}"))
        }
        other => Ok(format!(
            "{other:?} {scope} — proof stored; verify it against its external authority (not machine-checkable here)"
        )),
    }
}

/// Does this 64-hex-char blob decode to the seed of the key that signed
/// this ledger? If yes, it is *definitely* the regulator's private key —
/// not merely something that looks like one.
fn is_ledger_signing_key(file_text: &str, regulator_pubkey: &str) -> bool {
    let Ok(seed_bytes) = hex::decode(file_text.trim()) else {
        return false;
    };
    let Ok(seed) = <[u8; 32]>::try_from(seed_bytes) else {
        return false;
    };
    let key = SigningKey::from_bytes(&seed);
    hex::encode(key.verifying_key().to_bytes()).eq_ignore_ascii_case(regulator_pubkey)
}

fn cmd_info(dir: &Path) -> Result<()> {
    let manifest: Manifest = warden_core::read_manifest(dir)?;
    let entry_count = manifest.entries.len();
    let anchor_count = manifest.anchors.len();
    let ledger = Ledger::from_manifest(manifest.clone(), None)?;

    println!("ledger_id:        {}", manifest.ledger_id);
    println!("regulator_pubkey: {}", manifest.regulator_pubkey);
    println!("entries:          {entry_count}");
    println!("anchors:          {anchor_count}");
    match ledger.current_root() {
        Some(root) => println!("current root:     {}", hex::encode(root)),
        None => println!("current root:     (empty ledger)"),
    }

    let mut failures: Vec<String> = Vec::new();

    match ledger.verify_chain() {
        Ok(()) => println!("chain integrity:  OK"),
        Err(e) => {
            println!("chain integrity:  FAILED — {e}");
            failures.push(format!("chain integrity: {e}"));
        }
    }

    if !manifest.anchors.is_empty() {
        println!("anchor proofs:");
        for anchor in &manifest.anchors {
            match anchor_proof_status(anchor) {
                Ok(report) => println!("  - {report}"),
                Err(report) => {
                    println!("  - {report}");
                    failures.push(report);
                }
            }
        }
    }

    for item in fs::read_dir(dir)? {
        let item = item?;
        if !item.file_type()?.is_file() {
            continue;
        }
        let content = fs::read_to_string(item.path()).unwrap_or_default();
        let trimmed = content.trim();
        if !(trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit())) {
            continue;
        }

        let name = item.file_name().to_string_lossy().into_owned();
        if is_ledger_signing_key(trimmed, &manifest.regulator_pubkey) {
            println!();
            println!("ERROR: {name} IS this ledger's regulator signing key.");
            println!("Anyone who receives this bundle can forge regulator signatures for it.");
            println!("Move it out of the bundle directory before handing anything over.");
            failures.push(format!(
                "custody: {name} (this ledger's signing key) sits inside the bundle"
            ));
        } else {
            println!();
            println!("WARNING: {name} sits inside the bundle and looks like a private key.");
            println!("Hand over ONLY manifest.json + payloads/. Never share this file —");
            println!("whoever holds it can forge regulator signatures for this ledger.");
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        bail!(
            "ledger did not verify — {} problem(s): {}",
            failures.len(),
            failures.join("; ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Root hash the captured fixture token timestamps.
    const ROOT_HEX: &str = "cfd7e9e720f040bf65c8799157309aae3c2e7491b4e3ce31bac001276eb6cb70";
    const PROOF: &str = include_str!("../tests/fixtures/freetsa-proof.b64");

    fn anchor(root_hash: [u8; 32], anchor_type: AnchorType) -> Anchor {
        Anchor {
            up_to_seq: 0,
            root_hash,
            anchor_type,
            proof: PROOF.to_string(),
            anchored_at_unix: 0,
        }
    }

    #[test]
    fn stored_rfc3161_proof_reverifies() {
        let root: [u8; 32] = hex::decode(ROOT_HEX).unwrap().try_into().unwrap();
        let status = anchor_proof_status(&anchor(root, AnchorType::Rfc3161)).unwrap();
        assert!(status.contains("rfc3161 seq 0..=0 OK"), "{status}");
        assert!(status.contains("2026-10-02T19:38:14Z"), "{status}");
        assert!(status.contains("freetsa.org"), "{status}");
    }

    #[test]
    fn stored_proof_for_a_different_root_fails() {
        let status = anchor_proof_status(&anchor([0x11; 32], AnchorType::Rfc3161)).unwrap_err();
        assert!(status.contains("rfc3161 seq 0..=0 FAILED"), "{status}");
        assert!(status.contains("messageImprint"), "{status}");
    }

    #[test]
    fn unverifiable_anchor_types_say_so() {
        let status = anchor_proof_status(&anchor([0x11; 32], AnchorType::Manual)).unwrap();
        assert!(status.contains("external authority"), "{status}");
        assert!(status.contains("not machine-checkable"), "{status}");
    }

    #[test]
    fn only_the_ledgers_own_seed_is_recognized_as_its_key() {
        let pubkey = hex::encode(
            SigningKey::from_bytes(&[7u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        let seed = hex::encode([7u8; 32]);

        assert!(is_ledger_signing_key(&seed, &pubkey));
        assert!(is_ledger_signing_key(&format!("  {seed}\n"), &pubkey));
        // a different seed, a hash-shaped blob, and garbage: not the key
        assert!(!is_ledger_signing_key(&hex::encode([8u8; 32]), &pubkey));
        assert!(!is_ledger_signing_key(&hex::encode([0x11; 32]), &pubkey));
        assert!(!is_ledger_signing_key("not hex at all", &pubkey));
    }
}
