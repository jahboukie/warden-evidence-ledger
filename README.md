# Warden

An independent, regulator-held evidence ledger for AI systems.

## The problem this solves

"Don't take the vendor's word for what their AI system did. Run this
alongside it, and you have your own cryptographically provable copy of
the truth — one that survives even if the vendor's dashboard doesn't."

Vendor-side audit logs require trusting the party being audited to log
honestly, keep logging, and never edit the record. Warden flips that:
the regulator (or auditor) runs it, holds the signing key, and the AI
vendor never has write access to the chain.

## How it works

1. **Ingest** — every payload you feed in (a captured API request/response,
   a generated document, a decision record) is hashed, chained to the
   previous entry, and signed with a key **you** generate and hold.
2. **Chain** — each entry cryptographically commits to the one before it.
   Editing or deleting any entry breaks every hash after it.
3. **Anchor** — periodically, publish the current root hash somewhere
   outside your own control (an RFC 3161 timestamp authority, a
   transparency log like Rekor, or just a public bulletin board). This is
   what makes the ledger survive even a compromise of your own machine
   after the fact — an anchored root can't be quietly rewritten.
4. **Verify** — anyone, including someone who doesn't trust you, can
   check the whole chain with `warden-verify`, a ~250-line standalone
   binary that reimplements the crypto checks independently rather than
   trusting this repository's core library.

## Workspace layout

- `crates/warden-core` — the ledger: canonical encoding, hash chain,
  Ed25519 signing, bundle read/write. This is what `warden` (the CLI)
  is built on.
- `crates/warden-cli` (binary: `warden`) — operator tool: generate keys,
  create a ledger, ingest payloads, record anchors, inspect status.
- `crates/warden-verify` (binary: `warden-verify`) — standalone verifier.
  Does **not** depend on `warden-core`. Small enough to read end to end
  before trusting it with evidence that matters.

## Quick start

```sh
cargo build --release --workspace

# Generate a key OUTSIDE the ledger directory — the ledger dir gets
# handed to other people; the key never leaves your custody.
./target/release/warden keygen --key ./warden.key

# Start a new ledger bound to that key.
./target/release/warden init --dir ./ledger --key ./warden.key

# Feed it evidence, one artifact at a time.
./target/release/warden ingest --dir ./ledger --key ./warden.key \
    --file request_0001.json --label "req#1 /v1/complete"

# Periodically anchor the current state externally, then record it.
./target/release/warden anchor --dir ./ledger --type manual \
    --proof "root hash posted to <public URL> at <time>"

# Or ask an RFC 3161 timestamp authority to sign the current root hash.
# Any public TSA works; RSA and ECDSA over P-256/P-384/P-521 are supported.
./target/release/warden anchor --dir ./ledger --type rfc3161 \
    --tsa-url https://freetsa.org/tsr

# Pin the TSA certificate (PEM or DER) so the token must come from that key:
./target/release/warden anchor --dir ./ledger --type rfc3161 \
    --tsa-url https://freetsa.org/tsr --tsa-cert ./tsa-cert.pem

# Or hand it a token you already have (no network): it is re-verified
# against this ledger's current root before it is recorded.
./target/release/warden anchor --dir ./ledger --type rfc3161 \
    --proof '<base64 TimeStampToken>'

# Check status any time. (This also warns you if a private key file is
# sitting inside the bundle — it must never travel with the evidence.)
./target/release/warden info --dir ./ledger

# Hand ./ledger to anyone: manifest.json + payloads/ only, never warden.key.
# They verify it independently:
./target/release/warden-verify ./ledger
```

> **Key custody warning:** `manifest.json` contains only your *public*
> key. If `warden.key` (the *private* key) ends up inside `./ledger`,
> anyone who receives the bundle can forge regulator signatures and the
> whole trust model collapses. Keep the key in separate storage —
> ideally offline or in a different custody system than the evidence.

### What an RFC 3161 anchor proves

Every token — fetched with `--tsa-url` or supplied with `--proof` — is
verified locally before it is recorded: the `messageImprint` must be
SHA-256 over *this* ledger's current root hash (hashed as the raw 32
bytes, not the hex text `warden info` prints), the CMS signature must
verify against the certificate embedded in the token, that certificate
must have been valid at `genTime`, and the echoed nonce must match the
request we sent (when we sent it). With `--tsa-cert` the signer's public
key must additionally equal the pin. Without a pin, verification only
proves the token is internally consistent — anyone can mint such a token
with their own key — so pin the certificate, or at least check the
printed TSA subject. The full list of checks lives in the module docs of
`crates/warden-cli/src/tsa.rs`.

## What "unbreakable" actually means here

Being honest about the trust boundary, since that honesty is the whole
pitch:

- **What it protects against**: the AI vendor silently altering, deleting,
  or never having produced records of what their system did. Once an
  entry is in the chain and (ideally) anchored, it cannot be edited
  without detection.
- **What it does NOT protect against**: the regulator's own signing key
  being compromised before an anchor is published, or a captured payload
  being false at the moment of capture (garbage in, verifiably-preserved
  garbage out). Anchoring narrows the first risk to the gap between
  ingestion and anchor publication; it does not eliminate it. The tool
  proves *what was recorded and when it was committed to*, not that the
  recorded content was itself true when the AI system produced it — that
  latter guarantee depends on how tightly the capture layer (proxy vs.
  log-ingestion — see below) sits against the AI system itself.

## Capture modes (roadmap)

The MVP here is deliberately **log/artifact ingestion** — you hand
`warden ingest` a file or pipe it from stdin. Two stronger capture modes
are natural next steps, in increasing order of tamper-resistance and
integration effort:

1. *(built)* **Log ingestion** — regulator re-hashes and chains whatever
   the vendor already produced. Easiest to pilot; weakest guarantee,
   since the vendor could withhold or falsify what gets fed in.
2. **Output attestation** — the regulator, not the vendor, is the party
   who submits each output artifact for hashing at the moment it's
   received, closing the "vendor picks what gets logged" gap.
3. **Network tap / reverse proxy** — Warden sits in the request path
   between caller and AI system; it observes every request/response at
   the wire level, so the vendor cannot suppress an event without
   breaking the connection itself.

## Format notes for implementers / auditors

Signatures and hash-chain links are computed over a **hand-written
canonical byte encoding** (`canonical_bytes()` in both `warden-core` and,
independently, `warden-verify`), never over JSON. JSON is not canonical
across implementations, so signing serialized JSON directly would make
signatures effectively unverifiable by a third-party reimplementation —
which defeats the point of a regulator-owned verifier. See the doc
comment at the top of `crates/warden-core/src/lib.rs` for the full
rationale, and `crates/warden-verify/src/main.rs` for the independent
reimplementation.
