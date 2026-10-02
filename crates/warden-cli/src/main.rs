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

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use warden_core::{Anchor, AnchorType, Ledger, Manifest};

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
        /// The proof text: an RFC 3161 token (base64), a Rekor entry UUID,
        /// or a free-text description of where/how you published the root
        /// hash for a manual anchor.
        #[arg(long)]
        proof: String,
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
    let hex_str = fs::read_to_string(path)
        .with_context(|| format!("reading key file {}", path.display()))?;
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
        Command::Ingest { dir, key, file, label } => cmd_ingest(&dir, &key, file.as_deref(), label),
        Command::Anchor { dir, r#type, proof } => cmd_anchor(&dir, r#type.into(), proof),
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
        bail!("{} already has a manifest.json — ledger already initialized", dir.display());
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

fn cmd_ingest(dir: &Path, key_path: &Path, file: Option<&Path>, label: Option<String>) -> Result<()> {
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

    ledger.verify_chain().context("post-append self-check failed — refusing to persist")?;

    let manifest = ledger.to_manifest();
    warden_core::write_manifest(dir, &manifest)?;

    println!("appended entry seq={} entry_hash={}", entry.seq, hex::encode(entry.entry_hash));
    println!("ledger now has {} entries", ledger.entries.len());
    Ok(())
}

fn cmd_anchor(dir: &Path, anchor_type: AnchorType, proof: String) -> Result<()> {
    let manifest = warden_core::read_manifest(dir)?;
    let ledger = Ledger::from_manifest(manifest, None)?;
    let up_to_seq = match ledger.entries.last() {
        Some(e) => e.seq,
        None => bail!("ledger has no entries yet — nothing to anchor"),
    };
    let root_hash = ledger.current_root().unwrap();

    let mut ledger = ledger;
    ledger.add_anchor(Anchor {
        up_to_seq,
        root_hash,
        anchor_type,
        proof,
        anchored_at_unix: chrono::Utc::now().timestamp(),
    });
    let manifest = ledger.to_manifest();
    warden_core::write_manifest(dir, &manifest)?;
    println!(
        "recorded anchor for seq 0..={} — root_hash={}",
        up_to_seq,
        hex::encode(root_hash)
    );
    println!("(this root_hash is what you should have submitted to your external timestamp authority / transparency log)");
    Ok(())
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

    match ledger.verify_chain() {
        Ok(()) => println!("chain integrity:  OK"),
        Err(e) => println!("chain integrity:  FAILED — {e}"),
    }

    for item in fs::read_dir(dir)? {
        let item = item?;
        if !item.file_type()?.is_file() {
            continue;
        }
        let looks_like_key = fs::read_to_string(item.path())
            .map(|t| {
                let t = t.trim();
                t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit())
            })
            .unwrap_or(false);
        if looks_like_key {
            let name = item.file_name().to_string_lossy().into_owned();
            println!();
            println!("WARNING: {name} sits inside the bundle and looks like a private key.");
            println!("Hand over ONLY manifest.json + payloads/. Never share this file —");
            println!("whoever holds it can forge regulator signatures for this ledger.");
        }
    }
    Ok(())
}
