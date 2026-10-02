//! RFC 3161 timestamp authority support for `warden anchor --type rfc3161`.
//!
//! The timestamped message is the ledger's current root hash as its **raw
//! 32 bytes** (not the hex text `warden info` prints), imprinted with
//! SHA-256. Keep that in mind if you ever timestamp the same root with an
//! external tool: hash the 32 raw bytes.
//!
//! Every token we accept — whether we just fetched it or the operator handed
//! it to us with `--proof` — is verified locally before it is recorded:
//!
//!   * `messageImprint` is SHA-256 over *this* ledger's root hash,
//!   * the echoed `nonce` matches the one in the request we sent (when we
//!     sent the request ourselves),
//!   * the CMS `messageDigest` signed attribute commits to the token's
//!     TSTInfo, and `contentType` commits to `id-ct-TSTInfo`,
//!   * the signature over the DER-encoded `signedAttrs` verifies with the
//!     public key in the certificate the TSA embedded in the token — RSA
//!     (SHA-256/384/512) and ECDSA over P-256/P-384/P-521 are supported,
//!     which covers essentially every public TSA,
//!   * that certificate was valid at `genTime`, and — if `--tsa-cert` was
//!     given — its SubjectPublicKeyInfo equals the pinned one.
//!
//! Honest limitation: without `--tsa-cert`, verification only proves the
//! token is *internally consistent* — anyone can mint a self-consistent
//! token with their own key. Pin the TSA certificate (or check its subject
//! yourself) to make the timestamp mean something.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use const_oid::db::{rfc5911, rfc5912};
use const_oid::{AssociatedOid, ObjectIdentifier};
use der::asn1::{Any, AnyRef, GeneralizedTime, OctetString, OctetStringRef, Uint, UintRef};
use der::{Decode, DecodePem, Encode, Reader, SliceReader, Tag, TagNumber, Tagged};
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256, Sha384, Sha512};
use signature::hazmat::PrehashVerifier;
use signature::Verifier;
use spki::{AlgorithmIdentifierOwned, DecodePublicKey, SubjectPublicKeyInfoOwned};
use std::fs;
use std::path::Path;
use std::time::Duration;
use x509_cert::Certificate;

/// `id-ct-TSTInfo` — the content type of a `TimeStampToken`.
const OID_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// What a verified timestamp tells the caller, for printing.
#[derive(Debug, Clone)]
pub struct VerifiedTimestamp {
    /// The TSA's policy OID, as a dotted string.
    pub policy: String,
    /// TSTInfo serial number, hex.
    pub serial_hex: String,
    /// RFC 3161 `genTime`, RFC 3339-ish text.
    pub gen_time: String,
    /// Subject of the certificate that signed the token.
    pub tsa_subject: String,
}

/// ASN.1 shape of the request we build. See RFC 3161 §2.4.1.
#[derive(der::Sequence)]
struct MessageImprint {
    hash_algorithm: AlgorithmIdentifierOwned,
    hashed_message: OctetString,
}

#[derive(der::Sequence)]
struct TimeStampReq {
    version: u8,
    message_imprint: MessageImprint,
    #[asn1(optional = "true")]
    req_policy: Option<ObjectIdentifier>,
    #[asn1(optional = "true")]
    nonce: Option<Uint>,
    #[asn1(optional = "true")]
    cert_req: Option<bool>,
}

/// What we pulled out of a TSTInfo after parsing it.
struct ParsedTstInfo<'a> {
    policy: ObjectIdentifier,
    hashed_message: &'a [u8],
    serial_hex: String,
    gen_time: GeneralizedTime,
    nonce: Option<&'a [u8]>,
}

/// Ask the TSA at `url` to timestamp `root_hash`, then verify its answer.
///
/// Returns the raw `TimeStampToken` DER (what gets stored as the proof)
/// plus the verified metadata for display.
pub fn timestamp_root(
    url: &str,
    root_hash: &[u8; 32],
    pinned_spki: Option<&[u8]>,
) -> Result<(Vec<u8>, VerifiedTimestamp)> {
    let nonce = fresh_nonce();
    let request = build_request(root_hash, &nonce)?;
    let response = post_request(url, &request)?;
    let token = parse_response(&response)?;
    let verified = verify_token(&token, root_hash, Some(&nonce), pinned_spki)?;
    Ok((token, verified))
}

/// Verify a `TimeStampToken` against this ledger's root hash.
///
/// `expected_nonce` is `Some` when we just sent the request (the token must
/// echo it) and `None` when the token came from the operator's `--proof`.
/// `pinned_spki` is the DER SubjectPublicKeyInfo of a trusted TSA cert.
pub fn verify_token(
    token_der: &[u8],
    root_hash: &[u8; 32],
    expected_nonce: Option<&[u8]>,
    pinned_spki: Option<&[u8]>,
) -> Result<VerifiedTimestamp> {
    let mut reader = SliceReader::new(token_der)?;
    let content_info =
        ContentInfo::decode(&mut reader).context("token is not a CMS ContentInfo")?;
    reader
        .finish(())
        .context("trailing bytes after the token")?;

    // A TimeStampToken is a CMS ContentInfo carrying id-signedData, whose
    // eContent in turn carries id-ct-TSTInfo.
    if content_info.content_type != rfc5911::ID_SIGNED_DATA {
        bail!(
            "token content type is {}, expected id-signedData ({})",
            content_info.content_type,
            rfc5911::ID_SIGNED_DATA
        );
    }
    let signed_data: SignedData = content_info
        .content
        .decode_as()
        .context("token content is not CMS SignedData")?;

    // The eContent must be id-ct-TSTInfo carrying the TSTInfo structure.
    let encapsulated = &signed_data.encap_content_info;
    if encapsulated.econtent_type != OID_TST_INFO {
        bail!(
            "token eContent type is {}, expected id-ct-TSTInfo ({OID_TST_INFO})",
            encapsulated.econtent_type
        );
    }
    let econtent = encapsulated
        .econtent
        .as_ref()
        .ok_or_else(|| anyhow!("token carries no eContent"))?;
    // RFC 5652 encodes eContent as `[0] EXPLICIT OCTET STRING`, so the value
    // behind that tag is the DER of TSTInfo itself.
    if econtent.tag() != Tag::OctetString {
        bail!("unsupported token eContent encoding ({})", econtent.tag());
    }
    let tst_der = econtent.value();
    let tst = parse_tst_info(tst_der)?;

    let expected_imprint = Sha256::digest(root_hash);
    if tst.hashed_message != expected_imprint.as_slice() {
        bail!("token's messageImprint is not SHA-256 of this ledger's root hash — it timestamps a different value");
    }

    if let Some(want) = expected_nonce {
        match tst.nonce {
            Some(got) if got == want => {}
            Some(_) => bail!("token nonce does not match the request we sent"),
            None => bail!("token has no nonce although the request supplied one"),
        }
    }

    let signer = signed_data
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or_else(|| anyhow!("token has no SignerInfo"))?;
    let attrs = check_signed_attrs(signer, tst_der)?;

    let cert = find_signer_cert(&signed_data, signer)?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .context("encoding the signer certificate's SubjectPublicKeyInfo")?;

    if let Some(pinned) = pinned_spki {
        if spki_der != pinned {
            bail!("token's signer certificate does not match the pinned --tsa-cert public key");
        }
    }

    let gen_unix = tst.gen_time.to_unix_duration().as_secs();
    let not_before = cert
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs();
    let not_after = cert
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs();
    if gen_unix < not_before || gen_unix > not_after {
        bail!(
            "token genTime ({}) falls outside the TSA certificate's validity ({} .. {})",
            tst.gen_time.to_date_time(),
            cert.tbs_certificate.validity.not_before,
            cert.tbs_certificate.validity.not_after
        );
    }

    let attrs_der = attrs
        .to_der()
        .context("re-encoding the token's signedAttrs")?;
    verify_signature(
        &cert.tbs_certificate.subject_public_key_info,
        &spki_der,
        signer,
        &attrs_der,
    )?;

    Ok(VerifiedTimestamp {
        policy: tst.policy.to_string(),
        serial_hex: tst.serial_hex,
        gen_time: tst.gen_time.to_date_time().to_string(),
        tsa_subject: cert.tbs_certificate.subject.to_string(),
    })
}

/// Check the attributes the CMS signature covers: `messageDigest` must be
/// the digest of the TSTInfo we just parsed, and `contentType` must name
/// `id-ct-TSTInfo`. Returns the `signedAttrs` to verify the signature over.
fn check_signed_attrs<'a>(
    signer: &'a SignerInfo,
    tst_der: &[u8],
) -> Result<&'a x509_cert::attr::Attributes> {
    let attrs = signer
        .signed_attrs
        .as_ref()
        .ok_or_else(|| anyhow!("token's SignerInfo has no signedAttrs — cannot verify"))?;

    let content_type = attrs
        .iter()
        .find(|a| a.oid == rfc5911::ID_CONTENT_TYPE)
        .ok_or_else(|| anyhow!("signedAttrs missing the contentType attribute"))?;
    let ct_value = content_type
        .values
        .iter()
        .next()
        .ok_or_else(|| anyhow!("contentType attribute is empty"))?;
    let ct_oid = AnyRef::from(ct_value)
        .decode_as::<ObjectIdentifier>()
        .context("contentType attribute is not an OID")?;
    if ct_oid != OID_TST_INFO {
        bail!("contentType attribute is {ct_oid}, expected id-ct-TSTInfo");
    }

    let message_digest = attrs
        .iter()
        .find(|a| a.oid == rfc5911::ID_MESSAGE_DIGEST)
        .ok_or_else(|| anyhow!("signedAttrs missing the messageDigest attribute"))?;
    let md_value = message_digest
        .values
        .iter()
        .next()
        .ok_or_else(|| anyhow!("messageDigest attribute is empty"))?;
    // The digest algorithm lives in the SignerInfo, not in TSTInfo.
    let expected: Vec<u8> = match signer.digest_alg.oid {
        rfc5912::ID_SHA_256 => Sha256::digest(tst_der).to_vec(),
        rfc5912::ID_SHA_384 => Sha384::digest(tst_der).to_vec(),
        rfc5912::ID_SHA_512 => Sha512::digest(tst_der).to_vec(),
        other => bail!("unsupported token digest algorithm {other}"),
    };
    if md_value.tag() != Tag::OctetString || md_value.value() != expected.as_slice() {
        bail!("messageDigest attribute does not commit to the token's TSTInfo");
    }

    Ok(attrs)
}

/// Pick the certificate named by the SignerInfo out of the token.
fn find_signer_cert<'a>(
    signed_data: &'a SignedData,
    signer: &SignerInfo,
) -> Result<&'a Certificate> {
    let certificates = signed_data
        .certificates
        .as_ref()
        .ok_or_else(|| anyhow!("token embeds no certificates — cannot verify it offline"))?;

    match &signer.sid {
        SignerIdentifier::IssuerAndSerialNumber(iasn) => {
            for choice in certificates.0.iter() {
                if let CertificateChoices::Certificate(cert) = choice {
                    if cert.tbs_certificate.issuer == iasn.issuer
                        && cert.tbs_certificate.serial_number == iasn.serial_number
                    {
                        return Ok(cert);
                    }
                }
            }
            bail!("no certificate in the token matches the signer's issuer/serial")
        }
        SignerIdentifier::SubjectKeyIdentifier(_) => {
            bail!("token identifies its signer by SubjectKeyIdentifier — unsupported")
        }
    }
}

/// Verify an ECDSA signature with curve-specific types from `$krate`.
macro_rules! ec_verify {
    ($krate:ident, $sec1:expr, $hash:expr, $sig:expr) => {{
        use $krate::ecdsa::{Signature as EcSignature, VerifyingKey as EcVerifyingKey};
        let key = EcVerifyingKey::from_sec1_bytes($sec1)
            .map_err(|e| anyhow!("TSA signer certificate has no usable EC public key: {e}"))?;
        let signature = EcSignature::from_der($sig)
            .map_err(|e| anyhow!("token carries a malformed ECDSA signature: {e}"))?;
        key.verify_prehash($hash.as_slice(), &signature)
            .map_err(|_| anyhow!("ECDSA signature over the signedAttrs does not verify"))
    }};
}

/// Verify the CMS signature over `signed_attrs`, dispatching on the signer
/// certificate's key algorithm and the SignerInfo's signature algorithm.
///
/// `spki_der` is the DER encoding of `spki`, which the caller already needed
/// for pinning.
fn verify_signature(
    spki: &SubjectPublicKeyInfoOwned,
    spki_der: &[u8],
    signer: &SignerInfo,
    attrs_der: &[u8],
) -> Result<()> {
    let sig_alg = signer.signature_algorithm.oid;
    let sig = signer.signature.as_bytes();

    match spki.algorithm.oid {
        rfc5912::RSA_ENCRYPTION => {
            let key = RsaPublicKey::from_public_key_der(spki_der)
                .map_err(|e| anyhow!("TSA signer certificate has no usable RSA public key: {e}"))?;
            // `rsaEncryption` as the signature algorithm is the CMS default and
            // means "hash comes from digestAlgorithm"; the sha*WithRSAEncryption
            // OIDs say it themselves.
            let digest = match sig_alg {
                rfc5912::RSA_ENCRYPTION => signer.digest_alg.oid,
                other => other,
            };
            match digest {
                rfc5912::SHA_256_WITH_RSA_ENCRYPTION | rfc5912::ID_SHA_256 => {
                    rsa_verify::<Sha256>(key, attrs_der, sig)
                }
                rfc5912::SHA_384_WITH_RSA_ENCRYPTION | rfc5912::ID_SHA_384 => {
                    rsa_verify::<Sha384>(key, attrs_der, sig)
                }
                rfc5912::SHA_512_WITH_RSA_ENCRYPTION | rfc5912::ID_SHA_512 => {
                    rsa_verify::<Sha512>(key, attrs_der, sig)
                }
                other => bail!("unsupported RSA signature algorithm {other}"),
            }
        }
        rfc5912::ID_EC_PUBLIC_KEY => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .ok_or_else(|| anyhow!("TSA EC public key names no curve"))?
                .decode_as::<ObjectIdentifier>()
                .context("TSA EC public key parameters are not a named curve")?;
            let sec1 = spki.subject_public_key.raw_bytes();
            let hash = prehash(sig_alg, attrs_der)?;
            match curve {
                rfc5912::SECP_256_R_1 => ec_verify!(p256, sec1, hash, sig),
                rfc5912::SECP_384_R_1 => ec_verify!(p384, sec1, hash, sig),
                rfc5912::SECP_521_R_1 => ec_verify!(p521, sec1, hash, sig),
                other => bail!("unsupported elliptic curve in the TSA certificate ({other})"),
            }
        }
        other => bail!("TSA signer certificate uses an unsupported key algorithm ({other})"),
    }
}

/// RSASSA-PKCS1-v1_5 verification for one digest at a time.
fn rsa_verify<D>(key: RsaPublicKey, attrs_der: &[u8], sig: &[u8]) -> Result<()>
where
    D: Digest + AssociatedOid,
{
    let signature = RsaSignature::try_from(sig)
        .map_err(|e| anyhow!("token carries a malformed RSA signature: {e}"))?;
    RsaVerifyingKey::<D>::new(key)
        .verify(attrs_der, &signature)
        .map_err(|_| anyhow!("RSA signature over the signedAttrs does not verify"))
}

/// The digest an ECDSA signature algorithm applies to `signed_attrs`.
///
/// This is independent of the SignerInfo digest algorithm, which only
/// governs the `messageDigest` attribute.
fn prehash(sig_alg: ObjectIdentifier, attrs_der: &[u8]) -> Result<Vec<u8>> {
    Ok(match sig_alg {
        rfc5912::ECDSA_WITH_SHA_256 => Sha256::digest(attrs_der).to_vec(),
        rfc5912::ECDSA_WITH_SHA_384 => Sha384::digest(attrs_der).to_vec(),
        rfc5912::ECDSA_WITH_SHA_512 => Sha512::digest(attrs_der).to_vec(),
        other => bail!("unsupported ECDSA signature algorithm {other}"),
    })
}

/// Decode a TSTInfo SEQUENCE, taking only what we need (RFC 3161 §2.4.2).
/// Trailing optional fields (accuracy/nonce/tsa/extensions) are skipped.
fn parse_tst_info(tst_der: &[u8]) -> Result<ParsedTstInfo<'_>> {
    let mut outer = SliceReader::new(tst_der)?;
    let sequence = AnyRef::decode(&mut outer).context("TSTInfo is not DER")?;
    outer.finish(()).context("trailing bytes after TSTInfo")?;
    if sequence.tag() != Tag::Sequence {
        bail!("TSTInfo is not a SEQUENCE (got {})", sequence.tag());
    }
    let mut reader = SliceReader::new(sequence.value())?;

    let version = u8::decode(&mut reader).context("TSTInfo: version")?;
    if version != 1 {
        bail!("unsupported TSTInfo version {version}");
    }
    let policy = ObjectIdentifier::decode(&mut reader).context("TSTInfo: policy")?;

    // MessageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage }.
    let imprint = AnyRef::decode(&mut reader).context("TSTInfo: messageImprint")?;
    if imprint.tag() != Tag::Sequence {
        bail!(
            "TSTInfo messageImprint is not a SEQUENCE (got {})",
            imprint.tag()
        );
    }
    let mut imprint_reader = SliceReader::new(imprint.value())?;
    let hash_algorithm = AlgorithmIdentifierOwned::decode(&mut imprint_reader)
        .context("TSTInfo: messageImprint hash algorithm")?;
    if hash_algorithm.oid != rfc5912::ID_SHA_256 {
        bail!(
            "unsupported messageImprint hash algorithm {}",
            hash_algorithm.oid
        );
    }
    let hashed_message =
        OctetStringRef::decode(&mut imprint_reader).context("TSTInfo: hashedMessage")?;
    imprint_reader
        .finish(())
        .context("trailing bytes in messageImprint")?;

    let serial = UintRef::decode(&mut reader).context("TSTInfo: serial")?;
    let gen_time = GeneralizedTime::decode(&mut reader).context("TSTInfo: genTime")?;

    let mut nonce = None;
    while !reader.is_finished() {
        match reader.peek_tag()? {
            // accuracy SEQUENCE
            Tag::Sequence => {
                reader.tlv_bytes()?;
            }
            // ordering BOOLEAN
            Tag::Boolean => {
                bool::decode(&mut reader).context("TSTInfo: ordering")?;
            }
            // nonce INTEGER
            Tag::Integer => {
                nonce = Some(
                    UintRef::decode(&mut reader)
                        .context("TSTInfo: nonce")?
                        .as_bytes(),
                );
            }
            // tsa [0] and extensions [1] — nothing we need
            _ => break,
        }
    }

    Ok(ParsedTstInfo {
        policy,
        hashed_message: hashed_message.as_bytes(),
        serial_hex: hex::encode(serial.as_bytes()),
        gen_time,
        nonce,
    })
}

/// Build the DER `TimeStampRequest` for `root_hash`.
fn build_request(root_hash: &[u8; 32], nonce: &[u8; 8]) -> Result<Vec<u8>> {
    let null: &[u8] = &[];
    let request = TimeStampReq {
        version: 1,
        message_imprint: MessageImprint {
            hash_algorithm: AlgorithmIdentifierOwned {
                oid: rfc5912::ID_SHA_256,
                parameters: Some(Any::new(Tag::Null, null)?),
            },
            hashed_message: OctetString::new(Sha256::digest(root_hash).to_vec())?,
        },
        req_policy: None,
        nonce: Some(Uint::new(nonce)?),
        cert_req: Some(true),
    };
    Ok(request.to_der()?)
}

/// A nonce that survives DER round-tripping: top bit clear (no sign byte),
/// bottom bit set (never zero).
fn fresh_nonce() -> [u8; 8] {
    let mut nonce = rand::random::<u64>().to_be_bytes();
    nonce[0] = (nonce[0] & 0x7f) | 0x01;
    nonce
}

/// POST the request as `application/timestamp-query`, return the raw body.
fn post_request(url: &str, request: &[u8]) -> Result<Vec<u8>> {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .build();
    let agent: ureq::Agent = config.into();

    let mut response = agent
        .post(url)
        .header("Content-Type", "application/timestamp-query")
        .header("Accept", "application/timestamp-reply")
        .send(request)
        .with_context(|| format!("sending timestamp request to {url}"))?;

    let status = response.status();
    if !status.is_success() {
        bail!("TSA at {url} answered with HTTP {}", status.as_u16());
    }
    response
        .body_mut()
        .read_to_vec()
        .with_context(|| format!("reading the response from {url}"))
}

/// Split a `TimeStampResp` (RFC 3161 §2.4.2) into its status and token.
fn parse_response(response_der: &[u8]) -> Result<Vec<u8>> {
    let mut outer = SliceReader::new(response_der)?;
    let sequence = AnyRef::decode(&mut outer).context("TSA response is not DER")?;
    outer
        .finish(())
        .context("trailing bytes after the response")?;
    if sequence.tag() != Tag::Sequence {
        bail!("TSA response is not a SEQUENCE (got {})", sequence.tag());
    }
    let body = sequence.value();
    let mut reader = SliceReader::new(body)?;

    // `status` is a whole PKIStatusInfo SEQUENCE, not a bare INTEGER.
    let status_info = AnyRef::decode(&mut reader).context("TSA response carries no status")?;
    if status_info.tag() != Tag::Sequence {
        bail!(
            "TSA response status is not a PKIStatusInfo SEQUENCE (got {})",
            status_info.tag()
        );
    }
    let mut status_reader = SliceReader::new(status_info.value())?;
    let status = u8::decode(&mut status_reader).context("TSA response status is not an INTEGER")?;
    if status != 0 {
        let reason = status_string(status_info.value())
            .map(|s| format!(" — {s}"))
            .unwrap_or_default();
        bail!("TSA rejected the request (PKIStatus {status}){reason}");
    }
    // timeStampToken TimeStampToken OPTIONAL — untagged (RFC 3161 §2.4.2),
    // so whatever bytes remain are the CMS ContentInfo itself.
    if reader.is_finished() {
        bail!("TSA replied 'granted' but returned no timeStampToken");
    }
    let start = usize::try_from(reader.position())?;
    let token_der = &body[start..];
    let mut token_reader = SliceReader::new(token_der)?;
    ContentInfo::decode(&mut token_reader).context("response token is not a CMS ContentInfo")?;
    token_reader
        .finish(())
        .context("trailing bytes after the token")?;
    Ok(token_der.to_vec())
}

/// Best-effort `statusString` out of a `PKIStatusInfo`, for rejection errors.
fn status_string(status_info: &[u8]) -> Option<String> {
    let mut reader = SliceReader::new(status_info).ok()?;
    u8::decode(&mut reader).ok()?;
    if reader.is_finished() {
        return None;
    }
    let tagged = AnyRef::decode(&mut reader).ok()?;
    if !matches!(
        tagged.tag(),
        Tag::ContextSpecific { number, .. } if number == TagNumber::N0
    ) {
        return None;
    }
    // PKIFreeText ::= SEQUENCE OF DirectoryString, and the [0] tag wraps it,
    // so strings can sit one SEQUENCE down (or directly under [0]).
    let mut parts = Vec::new();
    collect_status_strings(tagged.value(), &mut parts);
    (!parts.is_empty()).then(|| parts.join(" "))
}

/// Gather the `DirectoryString`s out of a (possibly nested) PKIFreeText.
fn collect_status_strings(data: &[u8], parts: &mut Vec<String>) {
    let Ok(mut reader) = SliceReader::new(data) else {
        return;
    };
    while let Ok(item) = AnyRef::decode(&mut reader) {
        match item.tag() {
            Tag::Sequence | Tag::Set => collect_status_strings(item.value(), parts),
            Tag::PrintableString | Tag::Utf8String | Tag::Ia5String => {
                parts.push(String::from_utf8_lossy(item.value()).into_owned());
            }
            _ => {}
        }
    }
}

/// Load a TSA certificate (PEM or DER) and return its SubjectPublicKeyInfo
/// DER, for pinning during verification.
pub fn load_pinned_spki(path: &Path) -> Result<Vec<u8>> {
    let data =
        fs::read(path).with_context(|| format!("reading TSA certificate {}", path.display()))?;
    let cert = if data.windows(11).any(|w| w == b"-----BEGIN ") {
        Certificate::from_pem(&data)
            .with_context(|| format!("parsing {} as PEM", path.display()))?
    } else {
        Certificate::from_der(&data)
            .with_context(|| format!("parsing {} as DER", path.display()))?
    };
    cert.tbs_certificate
        .subject_public_key_info
        .to_der()
        .context("encoding the pinned certificate's SubjectPublicKeyInfo")
}

/// Store-ready representation of a token: base64 of its DER.
pub fn encode_token(token_der: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(token_der)
}

/// Inverse of [`encode_token`], for `--proof` round-trips.
pub fn decode_token(text: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .context("proof is not valid base64")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The proof a real `warden anchor --type rfc3161 --tsa-url
    /// https://freetsa.org/tsr` run stored for `root()`.
    const PROOF: &str = include_str!("../tests/fixtures/freetsa-proof.b64");
    /// A full `TimeStampResp` off the same TSA, for the status/token split.
    const RESPONSE: &[u8] = include_bytes!("../tests/fixtures/freetsa-response.bin");

    /// Root hash the captured token timestamps (SHA-256 of the raw 32 bytes).
    fn root() -> [u8; 32] {
        let decoded = hex::decode(concat!(
            "cfd7e9e720f040bf65c8799157309aae",
            "3c2e7491b4e3ce31bac001276eb6cb70"
        ))
        .unwrap();
        decoded.try_into().unwrap()
    }

    #[test]
    fn captured_token_verifies_against_its_root() {
        let token = decode_token(PROOF).unwrap();
        let verified = verify_token(&token, &root(), None, None).unwrap();
        assert_eq!(verified.policy, "1.2.3.4.1");
        assert_eq!(verified.gen_time, "2026-10-02T19:38:14Z");
        assert!(
            verified.tsa_subject.contains("freetsa.org"),
            "{}",
            verified.tsa_subject
        );
        assert!(!verified.serial_hex.is_empty());
    }

    #[test]
    fn token_for_a_different_root_is_rejected() {
        let token = decode_token(PROOF).unwrap();
        let err = verify_token(&token, &[0x11; 32], None, None).unwrap_err();
        assert!(err.to_string().contains("messageImprint"), "{err:#}");
    }

    #[test]
    fn missing_expected_nonce_is_rejected() {
        let token = decode_token(PROOF).unwrap();
        let err = verify_token(&token, &root(), Some(&[0x07; 8]), None).unwrap_err();
        assert!(err.to_string().contains("nonce"), "{err:#}");
    }

    #[test]
    fn pinned_key_mismatch_is_rejected() {
        let token = decode_token(PROOF).unwrap();
        let err = verify_token(&token, &root(), None, Some(&[0u8; 8])).unwrap_err();
        assert!(err.to_string().contains("pinned"), "{err:#}");
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let mut token = decode_token(PROOF).unwrap();
        let last = token.len() - 1;
        token[last] ^= 0xff;
        let err = verify_token(&token, &root(), None, None).unwrap_err();
        assert!(err.to_string().contains("signature"), "{err:#}");
    }

    #[test]
    fn response_splits_status_and_token() {
        let token = parse_response(RESPONSE).unwrap();
        let mut reader = SliceReader::new(&token).unwrap();
        let content_info = ContentInfo::decode(&mut reader).unwrap();
        reader.finish(()).unwrap();
        assert_eq!(content_info.content_type, rfc5911::ID_SIGNED_DATA);
    }

    #[test]
    fn rejection_response_reports_status_and_reason() {
        // TimeStampResp with PKIStatus rejected(1) and a statusString.
        let der = hex::decode("300f300d020101a008300613046e6f7065").unwrap();
        let err = parse_response(&der).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("PKIStatus 1"), "{text}");
        assert!(text.contains("nope"), "{text}");
    }

    #[test]
    fn request_imprints_the_sha256_of_the_root() {
        let request = build_request(&root(), &[0x07; 8]).unwrap();
        let imprint = Sha256::digest(root());
        assert!(request.windows(32).any(|w| w == imprint.as_slice()));
        // the raw root must not appear verbatim (it is only ever hashed)
        assert!(!request.windows(32).any(|w| w == root()));
    }
}
