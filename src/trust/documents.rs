// Ported from TrackAI apps/api/src/features/attesta/trust-documents.ts @
// 67af03726a86c94ff1de766059bebd1a7147add9 (Task15l, trust.md); behaviour fixed
// by tests/fixtures/trust vectors.
// Provenance: those files were themselves ported from SushiCorp B4
// core/trust/{revocation,verdict}.py @ 0bd67a5 (catalog TR-1).
//
// Bounded parsing and strict validation of root documents and key sets, the
// forward-only rule between versions, and the per-key validity rule. Pure: no
// database, no network, no clock.
//
// The envelope's closed shape (no unknown `payload`/`payloadType`/`signatures`
// keys, and no unknown keys on signature entries) is enforced here from the
// fields `DsseEnvelope` captures at deserialization, because the artifact path
// (`checkInput`) deliberately ignores those same extras, exactly like the
// TypeScript.

use std::collections::BTreeMap;

use base64::engine::{GeneralPurpose, GeneralPurposeConfig};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey as _;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use super::dsse::{self, DsseEnvelope};
use super::{
    ArtifactPurpose, CustomerPinnedKey, KEYSET_PAYLOAD_TYPE, KEYSET_TYPE, KeyPurpose, KeyStatus,
    PLATFORM_SCOPE, RevocationReason, TRUST_MAX_DOCUMENT_BYTES, TRUST_MAX_KEYS_PER_DOCUMENT,
    TRUST_MAX_KEYSET_LIFETIME_MS, TRUST_MAX_ROOT_LIFETIME_MS, TRUST_MAX_SIGNATURES_PER_DOCUMENT,
    TRUST_ROOT_PAYLOAD_TYPE, TRUST_ROOT_TYPE, TrustCode, TrustDocumentBody, TrustKeyEntry,
};

/// Integers the JCS snapshot refuses: beyond ±(2^53 − 1) but below 1e21.
const MAX_SAFE_INT: i64 = 9_007_199_254_740_991;

/// A trust code with a short reason for logs (never raw values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustDocumentError {
    pub code: TrustCode,
}

impl TrustDocumentError {
    pub fn new(code: TrustCode) -> Self {
        Self { code }
    }
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

/// `DIGEST_RE`: `sha256:` + 64 lowercase hex chars.
pub fn is_digest(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 71 && value.starts_with("sha256:") && bytes[7..].iter().all(|b| is_lower_hex(*b))
}

/// `UUID_RE`: lowercase tenant UUID.
pub fn is_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, b) in bytes.iter().enumerate() {
        let is_dash = i == 8 || i == 13 || i == 18 || i == 23;
        if is_dash {
            if *b != b'-' {
                return false;
            }
        } else if !is_lower_hex(*b) {
            return false;
        }
    }
    true
}

fn two_digits(bytes: &[u8], range: std::ops::RangeInclusive<u8>) -> bool {
    bytes.len() == 2 && bytes[0].is_ascii_digit() && bytes[1].is_ascii_digit() && {
        let value = (bytes[0] - b'0') * 10 + (bytes[1] - b'0');
        range.contains(&value)
    }
}

/// `TS_RE`: RFC 3339 UTC with milliseconds and a century of 19xx-21xx.
fn valid_timestamp_format(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 24 {
        return false;
    }
    let century_ok = matches!(&bytes[0..2], b"19" | b"20" | b"21");
    century_ok
        && bytes[2].is_ascii_digit()
        && bytes[3].is_ascii_digit()
        && bytes[4] == b'-'
        && two_digits(&bytes[5..7], 1..=12)
        && bytes[7] == b'-'
        && two_digits(&bytes[8..10], 1..=31)
        && bytes[10] == b'T'
        && two_digits(&bytes[11..13], 0..=23)
        && bytes[13] == b':'
        && two_digits(&bytes[14..16], 0..=59)
        && bytes[16] == b':'
        && two_digits(&bytes[17..19], 0..=59)
        && bytes[19] == b'.'
        && bytes[20].is_ascii_digit()
        && bytes[21].is_ascii_digit()
        && bytes[22].is_ascii_digit()
        && bytes[23] == b'Z'
}

/// RFC 3339 UTC with milliseconds and a real instant; returns epoch ms or None.
/// The format-then-round-trip shape mirrors `Date.parse` + `toISOString` equality.
pub fn parse_timestamp(value: &str) -> Option<i64> {
    if !valid_timestamp_format(value) {
        return None;
    }
    let parsed = chrono::DateTime::parse_from_rfc3339(value).ok()?;
    let utc = parsed.to_utc();
    if utc.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string() != value {
        return None;
    }
    Some(utc.timestamp_millis())
}

fn is_b64_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/'
}

/// `BASE64_RE`: canonical padding, no whitespace or URL-safe alphabet.
fn is_canonical_base64(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return false;
    }
    if bytes[..bytes.len() - 4].iter().any(|b| !is_b64_char(*b)) {
        return false;
    }
    let tail = &bytes[bytes.len() - 4..];
    if !is_b64_char(tail[0]) || !is_b64_char(tail[1]) {
        return false;
    }
    // Last quantum: XXXX, XXX= or XX==.
    let middle_data = is_b64_char(tail[2]);
    let last_data = is_b64_char(tail[3]);
    (middle_data && last_data)
        || (middle_data && tail[3] == b'=')
        || (tail[2] == b'=' && tail[3] == b'=')
}

/// Strict base64 like `decodeBase64Strict`: canonical alphabet and padding, bounded
/// length. Non-zero trailing pad bits decode like Node does (they are dropped:
/// `AR==` decodes exactly like `AQ==`), so every regex-valid encoding the
/// TypeScript accepts decodes to the same bytes here.
pub fn decode_base64_strict(value: &str, max_bytes: usize) -> Option<Vec<u8>> {
    use base64::Engine;
    static ENGINE: GeneralPurpose = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    );
    if value.len() > max_bytes.div_ceil(3) * 4 || !is_canonical_base64(value) {
        return None;
    }
    ENGINE.decode(value).ok()
}

/// `sha256:` plus the lowercase hex SHA-256 of `data`.
pub fn sha256_prefixed(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for byte in digest {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 15), 16).unwrap_or('0'));
    }
    out
}

pub fn keyid_of(spki_der: &[u8]) -> String {
    sha256_prefixed(spki_der)
}

fn is_record(value: &Value) -> bool {
    value.is_object()
}

/// The JCS snapshot refusal: integers beyond ±(2^53 − 1) below 1e21.
/// (NaN, Infinity, bigint and friends cannot occur in parsed JSON.)
fn check_canonical_number(number: &serde_json::Number) -> bool {
    const SAFE: f64 = MAX_SAFE_INT as f64;
    if let Some(i) = number.as_i64() {
        (i as f64).abs() <= SAFE || (i as f64).abs() >= 1e21
    } else if let Some(u) = number.as_u64() {
        (u as f64) <= SAFE || (u as f64) >= 1e21
    } else if let Some(f) = number.as_f64() {
        !(f.fract() == 0.0 && f.abs() > SAFE && f.abs() < 1e21)
    } else {
        false
    }
}

fn check_canonical_value(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => true,
        Value::Number(n) => check_canonical_number(n),
        Value::Array(items) => items.iter().all(check_canonical_value),
        Value::Object(map) => map.values().all(check_canonical_value),
    }
}

/// RFC 8785 canonical JSON text of `value`, or None when it cannot be canonicalized.
fn canonicalize(value: &Value) -> Option<String> {
    if !check_canonical_value(value) {
        return None;
    }
    serde_json_canonicalizer::to_string(value).ok()
}

/// A JSON number that is an integer in the JCS safe range.
fn as_safe_int(value: &Value) -> Option<i64> {
    match value {
        Value::Number(n) => {
            if let Some(i) = n.as_i64()
                && (-MAX_SAFE_INT..=MAX_SAFE_INT).contains(&i)
            {
                return Some(i);
            }
            if let Some(u) = n.as_u64()
                && u <= MAX_SAFE_INT as u64
            {
                return Some(u as i64);
            }
            if let Some(f) = n.as_f64()
                && f.fract() == 0.0
                && f.abs() <= MAX_SAFE_INT as f64
            {
                return Some(f as i64);
            }
            None
        }
        _ => None,
    }
}

fn parse_key_purpose(value: &Value) -> Option<KeyPurpose> {
    match value.as_str()? {
        "root" => Some(KeyPurpose::Root),
        "anchor" => Some(KeyPurpose::Anchor),
        "activation_lease" => Some(KeyPurpose::ActivationLease),
        "fleet_config" => Some(KeyPurpose::FleetConfig),
        "policy_bundle" => Some(KeyPurpose::PolicyBundle),
        "release" => Some(KeyPurpose::Release),
        "tenant_keyset" => Some(KeyPurpose::TenantKeyset),
        "statement" => Some(KeyPurpose::Statement),
        _ => None,
    }
}

fn parse_key_status(value: &Value) -> Option<KeyStatus> {
    match value.as_str()? {
        "active" => Some(KeyStatus::Active),
        "retired" => Some(KeyStatus::Retired),
        "revoked" => Some(KeyStatus::Revoked),
        _ => None,
    }
}

fn parse_revocation_reason(value: &Value) -> Option<RevocationReason> {
    match value.as_str()? {
        "superseded" => Some(RevocationReason::Superseded),
        "compromised" => Some(RevocationReason::Compromised),
        _ => None,
    }
}

/// `SPKI_B64_RE`: exactly a 91-byte uncompressed P-256 SPKI in standard base64.
fn valid_spki_b64(value: &str) -> bool {
    const PREFIX: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE";
    const TAIL_OK: &[u8] = b"AQgw";
    let bytes = value.as_bytes();
    bytes.len() == 124
        && value.starts_with(PREFIX)
        && bytes[36..121].iter().all(|b| is_b64_char(*b))
        && TAIL_OK.contains(&bytes[121])
        && bytes[122] == b'='
        && bytes[123] == b'='
}

/// A key entry with its parsed times and public key.
#[derive(Debug, Clone)]
pub struct ParsedKey {
    pub entry: TrustKeyEntry,
    pub key: VerifyingKey,
    pub not_before: i64,
    pub not_after: i64,
    pub revoked_at: Option<i64>,
    pub compromised_since: Option<i64>,
}

/// Validate one key entry (document or customer pin). Err is DOCUMENT_MALFORMED.
pub fn parse_key_entry(
    raw: &Value,
    allowed: &[KeyPurpose],
) -> Result<ParsedKey, TrustDocumentError> {
    let bad = || TrustDocumentError::new(TrustCode::DocumentMalformed);
    let obj = raw.as_object().ok_or_else(bad)?;
    const KEY_FIELDS: [&str; 9] = [
        "keyid",
        "purpose",
        "spki_der_b64",
        "not_before",
        "not_after",
        "status",
        "revoked_at",
        "revocation_reason",
        "compromised_since",
    ];
    if obj.keys().any(|k| !KEY_FIELDS.contains(&k.as_str())) {
        return Err(bad());
    }
    let keyid = obj.get("keyid").and_then(Value::as_str).ok_or_else(bad)?;
    if !is_digest(keyid) {
        return Err(bad());
    }
    let purpose = obj
        .get("purpose")
        .and_then(parse_key_purpose)
        .ok_or_else(bad)?;
    if !allowed.contains(&purpose) {
        return Err(bad());
    }
    let spki_b64 = obj
        .get("spki_der_b64")
        .and_then(Value::as_str)
        .ok_or_else(bad)?;
    if !valid_spki_b64(spki_b64) {
        return Err(bad());
    }
    let spki = decode_base64_strict(spki_b64, 256).ok_or_else(bad)?;
    if keyid_of(&spki) != keyid {
        return Err(bad());
    }
    let public_key = p256::PublicKey::from_public_key_der(&spki).map_err(|_| bad())?;
    let not_before = obj
        .get("not_before")
        .and_then(Value::as_str)
        .and_then(parse_timestamp)
        .ok_or_else(bad)?;
    let not_after = obj
        .get("not_after")
        .and_then(Value::as_str)
        .and_then(parse_timestamp)
        .ok_or_else(bad)?;
    if not_before >= not_after {
        return Err(bad());
    }
    let status = obj
        .get("status")
        .and_then(parse_key_status)
        .ok_or_else(bad)?;
    let has = |field: &str| obj.contains_key(field);
    let mut revoked_at: Option<i64> = None;
    let mut compromised_since: Option<i64> = None;
    match status {
        KeyStatus::Active => {
            if has("revoked_at") || has("revocation_reason") || has("compromised_since") {
                return Err(bad());
            }
        }
        KeyStatus::Retired => {
            revoked_at = Some(
                obj.get("revoked_at")
                    .and_then(Value::as_str)
                    .and_then(parse_timestamp)
                    .ok_or_else(bad)?,
            );
            if has("revocation_reason") || has("compromised_since") {
                return Err(bad());
            }
        }
        KeyStatus::Revoked => {
            revoked_at = Some(
                obj.get("revoked_at")
                    .and_then(Value::as_str)
                    .and_then(parse_timestamp)
                    .ok_or_else(bad)?,
            );
            match obj
                .get("revocation_reason")
                .and_then(parse_revocation_reason)
            {
                Some(RevocationReason::Superseded) => {
                    if has("compromised_since") {
                        return Err(bad());
                    }
                }
                Some(RevocationReason::Compromised) => {
                    let since = obj
                        .get("compromised_since")
                        .and_then(Value::as_str)
                        .and_then(parse_timestamp)
                        .ok_or_else(bad)?;
                    if since > revoked_at.unwrap_or(0) {
                        return Err(bad());
                    }
                    compromised_since = Some(since);
                }
                None => return Err(bad()),
            }
        }
    }
    let reason = match status {
        KeyStatus::Revoked => obj
            .get("revocation_reason")
            .and_then(parse_revocation_reason),
        _ => None,
    };
    Ok(ParsedKey {
        entry: TrustKeyEntry {
            keyid: keyid.to_string(),
            purpose,
            spki_der_b64: spki_b64.to_string(),
            not_before: obj
                .get("not_before")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            not_after: obj
                .get("not_after")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            status,
            revoked_at: obj
                .get("revoked_at")
                .and_then(Value::as_str)
                .map(str::to_string),
            revocation_reason: reason,
            compromised_since: obj
                .get("compromised_since")
                .and_then(Value::as_str)
                .map(str::to_string),
        },
        key: VerifyingKey::from(&public_key),
        not_before,
        not_after,
        revoked_at,
        compromised_since,
    })
}

/// Validate one customer pin as a `statement` key entry. Err is INPUT_INVALID.
pub fn parse_customer_pin(raw: &CustomerPinnedKey) -> Result<ParsedKey, TrustCode> {
    let value = serde_json::to_value(raw).map_err(|_| TrustCode::InputInvalid)?;
    parse_key_entry(&value, &[KeyPurpose::Statement]).map_err(|_| TrustCode::InputInvalid)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentKind {
    Root,
    Keyset,
}

/// A trust document that passed bounded parsing and validation (not yet its signatures).
#[derive(Debug, Clone)]
pub struct ParsedDocument {
    pub kind: DocumentKind,
    pub envelope: DsseEnvelope,
    pub payload: Vec<u8>,
    /// `sha256:` of the payload bytes: what the next version's `previous` names.
    pub digest: String,
    pub body: TrustDocumentBody,
    pub issued_at: i64,
    pub expires: i64,
    pub keys: BTreeMap<String, ParsedKey>,
    /// Signatures in the envelope, shape-checked, keyids distinct.
    pub signatures: Vec<ParsedSignature>,
}

#[derive(Debug, Clone)]
pub struct ParsedSignature {
    pub keyid: String,
    pub sig: Vec<u8>,
}

/// Parse a trust document envelope: bounds first, then base64, JSON, its RFC 8785
/// form, the closed shape, every key entry (keyid recomputed, P-256), time order.
/// Signatures are only shape-checked here. Err is TrustDocumentError (MALFORMED).
pub fn parse_trust_document(envelope: &DsseEnvelope) -> Result<ParsedDocument, TrustDocumentError> {
    let bad = || TrustDocumentError::new(TrustCode::DocumentMalformed);
    if envelope.has_unknown_fields() {
        return Err(bad());
    }
    let kind = match envelope.payload_type.as_str() {
        x if x == TRUST_ROOT_PAYLOAD_TYPE => DocumentKind::Root,
        x if x == KEYSET_PAYLOAD_TYPE => DocumentKind::Keyset,
        _ => return Err(bad()),
    };
    let payload = decode_base64_strict(&envelope.payload, TRUST_MAX_DOCUMENT_BYTES)
        .filter(|p| !p.is_empty() && p.len() <= TRUST_MAX_DOCUMENT_BYTES)
        .ok_or_else(bad)?;
    if envelope.signatures.is_empty()
        || envelope.signatures.len() > TRUST_MAX_SIGNATURES_PER_DOCUMENT
    {
        return Err(bad());
    }
    let mut signatures = Vec::with_capacity(envelope.signatures.len());
    let mut seen: Vec<&str> = Vec::with_capacity(envelope.signatures.len());
    for entry in &envelope.signatures {
        if entry.has_unknown_fields() {
            return Err(bad());
        }
        let sig = decode_base64_strict(&entry.sig, 256)
            .filter(|s| !s.is_empty())
            .ok_or_else(bad)?;
        if !is_digest(&entry.keyid) || seen.contains(&entry.keyid.as_str()) {
            return Err(bad());
        }
        seen.push(entry.keyid.as_str());
        signatures.push(ParsedSignature {
            keyid: entry.keyid.clone(),
            sig,
        });
    }
    let text = std::str::from_utf8(&payload).map_err(|_| bad())?;
    let parsed: Value = serde_json::from_str(text).map_err(|_| bad())?;
    if canonicalize(&parsed).as_deref() != Some(text) {
        return Err(bad());
    }
    if !is_record(&parsed) {
        return Err(bad());
    }
    let body = parsed.as_object().ok_or_else(bad)?;
    const DOC_FIELDS: [&str; 8] = [
        "_type",
        "scope",
        "version",
        "issued_at",
        "expires",
        "previous",
        "threshold",
        "keys",
    ];
    if body.keys().any(|k| !DOC_FIELDS.contains(&k.as_str())) {
        return Err(bad());
    }
    let expected_type = match kind {
        DocumentKind::Root => TRUST_ROOT_TYPE,
        DocumentKind::Keyset => KEYSET_TYPE,
    };
    if body.get("_type").and_then(Value::as_str) != Some(expected_type) {
        return Err(bad());
    }
    let scope = body.get("scope").and_then(Value::as_str).ok_or_else(bad)?;
    match kind {
        DocumentKind::Root => {
            if scope != PLATFORM_SCOPE {
                return Err(bad());
            }
        }
        DocumentKind::Keyset => {
            if !is_uuid(scope) {
                return Err(bad());
            }
        }
    }
    let version = body.get("version").and_then(as_safe_int).ok_or_else(bad)?;
    if version < 1 {
        return Err(bad());
    }
    let previous = body.get("previous").ok_or_else(bad)?;
    if version == 1 {
        if !previous.is_null() {
            return Err(bad());
        }
    } else if previous.as_str().is_none_or(|p| !is_digest(p)) {
        return Err(bad());
    }
    let issued_at = body
        .get("issued_at")
        .and_then(Value::as_str)
        .and_then(parse_timestamp)
        .ok_or_else(bad)?;
    let expires = body
        .get("expires")
        .and_then(Value::as_str)
        .and_then(parse_timestamp)
        .ok_or_else(bad)?;
    if issued_at >= expires {
        return Err(bad());
    }
    // A bounded lifetime: issued_at is the signer's own claim, so without this a
    // retired signing key could back-date a document that never expires.
    let max_lifetime = match kind {
        DocumentKind::Root => TRUST_MAX_ROOT_LIFETIME_MS,
        DocumentKind::Keyset => TRUST_MAX_KEYSET_LIFETIME_MS,
    };
    if expires - issued_at > max_lifetime {
        return Err(bad());
    }
    let keys_raw = body.get("keys").and_then(Value::as_array).ok_or_else(bad)?;
    if keys_raw.is_empty() || keys_raw.len() > TRUST_MAX_KEYS_PER_DOCUMENT {
        return Err(bad());
    }
    let allowed: &[KeyPurpose] = match kind {
        DocumentKind::Root => &[
            KeyPurpose::Root,
            KeyPurpose::Anchor,
            KeyPurpose::ActivationLease,
            KeyPurpose::FleetConfig,
            KeyPurpose::PolicyBundle,
            KeyPurpose::Release,
            KeyPurpose::TenantKeyset,
        ],
        DocumentKind::Keyset => &[KeyPurpose::Statement],
    };
    let mut keys = BTreeMap::new();
    for raw in keys_raw {
        let parsed_key = parse_key_entry(raw, allowed)?;
        if keys.contains_key(&parsed_key.entry.keyid) {
            return Err(bad());
        }
        if parsed_key.revoked_at.is_some_and(|t| t > issued_at)
            || parsed_key.compromised_since.is_some_and(|t| t > issued_at)
        {
            return Err(bad());
        }
        keys.insert(parsed_key.entry.keyid.clone(), parsed_key);
    }
    match kind {
        DocumentKind::Root => {
            let active_roots = keys
                .values()
                .filter(|k| {
                    k.entry.purpose == KeyPurpose::Root && k.entry.status == KeyStatus::Active
                })
                .count() as i64;
            let value = body
                .get("threshold")
                .and_then(as_safe_int)
                .ok_or_else(bad)?;
            if !(1..=16).contains(&value) || value > active_roots {
                return Err(bad());
            }
        }
        DocumentKind::Keyset => {
            if body.contains_key("threshold") {
                return Err(bad());
            }
        }
    };
    let typed: TrustDocumentBody = serde_json::from_value(parsed.clone()).map_err(|_| bad())?;
    Ok(ParsedDocument {
        kind,
        envelope: envelope.clone(),
        digest: sha256_prefixed(&payload),
        payload,
        body: typed,
        issued_at,
        expires,
        keys,
        signatures,
    })
}

fn status_order(status: KeyStatus) -> u8 {
    match status {
        KeyStatus::Active => 0,
        KeyStatus::Retired => 1,
        KeyStatus::Revoked => 2,
    }
}

/// True when `sig` is a valid ES256 DER signature by `key` over the document's PAE.
pub fn document_signed_by(doc: &ParsedDocument, key: &VerifyingKey, sig: &[u8]) -> bool {
    verify_signature(
        key,
        &dsse::pae(&doc.envelope.payload_type, &doc.payload),
        sig,
    )
}

pub fn verify_signature(key: &VerifyingKey, data: &[u8], sig: &[u8]) -> bool {
    let Ok(signature) = Signature::from_der(sig) else {
        return false;
    };
    key.verify(data, &signature).is_ok()
}

/// Distinct keyids among `candidates` (active keys of `purpose`, valid at the
/// document's issued_at) whose signature on `doc` verifies. Unknown or failing
/// signatures are ignored, not fatal.
pub fn valid_document_signers(
    doc: &ParsedDocument,
    candidates: &BTreeMap<String, ParsedKey>,
    purpose: KeyPurpose,
) -> Vec<String> {
    let mut ok = Vec::new();
    for entry in &doc.signatures {
        let Some(candidate) = candidates.get(&entry.keyid) else {
            continue;
        };
        if candidate.entry.purpose != purpose || candidate.entry.status != KeyStatus::Active {
            continue;
        }
        if doc.issued_at < candidate.not_before || doc.issued_at > candidate.not_after {
            continue;
        }
        if document_signed_by(doc, &candidate.key, &entry.sig) && !ok.contains(&entry.keyid) {
            ok.push(entry.keyid.clone());
        }
    }
    ok
}

/// Forward-only rule between consecutive documents of one scope (trust.md "Key sets
/// only move forward"). Root keys of a root document may be dropped; every other key
/// must stay. Returns None or KEYSET_REGRESSION.
pub fn forward_only_violation(prev: &ParsedDocument, next: &ParsedDocument) -> Option<TrustCode> {
    for (keyid, old) in &prev.keys {
        if old.entry.purpose == KeyPurpose::Root {
            continue;
        }
        let Some(new) = next.keys.get(keyid) else {
            return Some(TrustCode::KeysetRegression);
        };
        if new.entry.purpose != old.entry.purpose
            || new.entry.spki_der_b64 != old.entry.spki_der_b64
            || new.not_before != old.not_before
            || new.not_after > old.not_after
        {
            return Some(TrustCode::KeysetRegression);
        }
        if status_order(new.entry.status) < status_order(old.entry.status) {
            return Some(TrustCode::KeysetRegression);
        }
        if old.entry.revocation_reason == Some(RevocationReason::Compromised)
            && new.entry.revocation_reason != Some(RevocationReason::Compromised)
        {
            return Some(TrustCode::KeysetRegression);
        }
        if old.revoked_at.is_some()
            && (new.revoked_at.is_none()
                || new.revoked_at.unwrap_or(0) > old.revoked_at.unwrap_or(0))
        {
            return Some(TrustCode::KeysetRegression);
        }
        if old.compromised_since.is_some()
            && (new.compromised_since.is_none()
                || new.compromised_since.unwrap_or(0) > old.compromised_since.unwrap_or(0))
        {
            return Some(TrustCode::KeysetRegression);
        }
    }
    if next.issued_at < prev.issued_at {
        return Some(TrustCode::KeysetRegression);
    }
    None
}

/// What a signature's time evidence may be checked against (trust.md step 8).
pub struct SignatureFacts {
    pub purpose: KeyPurpose,
    /// `sha256:` of the DER signature bytes.
    pub signature_digest: String,
    /// `sha256:` of the signed payload.
    pub payload_digest: String,
}

impl SignatureFacts {
    pub fn for_artifact(purpose: ArtifactPurpose, signature: &[u8], payload: &[u8]) -> Self {
        let purpose = match purpose {
            ArtifactPurpose::Anchor => KeyPurpose::Anchor,
            ArtifactPurpose::ActivationLease => KeyPurpose::ActivationLease,
            ArtifactPurpose::FleetConfig => KeyPurpose::FleetConfig,
            ArtifactPurpose::PolicyBundle => KeyPurpose::PolicyBundle,
            ArtifactPurpose::Release => KeyPurpose::Release,
            ArtifactPurpose::Statement => KeyPurpose::Statement,
        };
        Self {
            purpose,
            signature_digest: sha256_prefixed(signature),
            payload_digest: sha256_prefixed(payload),
        }
    }
}

/// Time from evidence that is bound to this signature (or, for statements, this ledger statement); else None.
fn bound_evidence_time(
    evidence: Option<&super::TimeEvidence>,
    facts: Option<&SignatureFacts>,
) -> Option<i64> {
    use super::{TimeEvidenceBinds, TimeEvidenceKind};
    let evidence = evidence?;
    let facts = facts?;
    match evidence.kind {
        TimeEvidenceKind::TsaGenTime | TimeEvidenceKind::RekorIntegratedTime => {}
    }
    let bound = (evidence.binds == TimeEvidenceBinds::Signature
        && evidence.digest == facts.signature_digest)
        || (evidence.binds == TimeEvidenceBinds::LedgerStatement
            && facts.purpose == KeyPurpose::Statement
            && evidence.digest == facts.payload_digest);
    if bound {
        parse_timestamp(&evidence.time)
    } else {
        None
    }
}

/// Was `key` valid for this signature? (trust.md step 8.)
pub fn key_validity_violation(
    key: &ParsedKey,
    signed_at: i64,
    now_ms: i64,
    skew_ms: i64,
    time_evidence: Option<&super::TimeEvidence>,
    facts: Option<&SignatureFacts>,
) -> Option<TrustCode> {
    if signed_at < key.not_before || signed_at > key.not_after || signed_at > now_ms + skew_ms {
        return Some(TrustCode::KeyNotValidAt);
    }
    let entry = &key.entry;
    let superseded = entry.status == KeyStatus::Revoked
        && entry.revocation_reason == Some(RevocationReason::Superseded);
    let compromised = entry.status == KeyStatus::Revoked
        && entry.revocation_reason == Some(RevocationReason::Compromised);
    if facts.is_none() {
        // Documents carry no time evidence: a compromised keyset key never vouches.
        if entry.status == KeyStatus::Retired {
            return if signed_at < key.revoked_at.unwrap_or(0) {
                None
            } else {
                Some(TrustCode::KeyNotValidAt)
            };
        }
        if superseded {
            return if signed_at < key.revoked_at.unwrap_or(0) {
                None
            } else {
                Some(TrustCode::KeyRevoked)
            };
        }
        if compromised {
            return Some(TrustCode::KeyRevoked);
        }
        return None;
    }
    let usable_now = entry.status == KeyStatus::Active
        && now_ms + skew_ms >= key.not_before
        && now_ms - skew_ms <= key.not_after;
    if usable_now {
        return None;
    }
    let evidence_time = bound_evidence_time(time_evidence, facts);
    let before = |limit: i64| {
        evidence_time.is_some_and(|t| {
            t <= now_ms + skew_ms && t >= key.not_before && t <= key.not_after && t < limit
        })
    };
    if entry.status == KeyStatus::Active || entry.status == KeyStatus::Retired {
        let limit = if entry.status == KeyStatus::Retired {
            key.revoked_at.unwrap_or(0)
        } else {
            i64::MAX
        };
        return if before(limit) {
            None
        } else {
            Some(TrustCode::KeyNotValidAt)
        };
    }
    if superseded {
        return if before(key.revoked_at.unwrap_or(0)) {
            None
        } else {
            Some(TrustCode::KeyRevoked)
        };
    }
    if before(key.compromised_since.unwrap_or(0)) {
        None
    } else {
        Some(TrustCode::KeyRevoked)
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_base64_strict, is_canonical_base64, is_digest, is_uuid, parse_timestamp};

    #[test]
    fn timestamp_shape_matches_typescript() {
        assert_eq!(
            parse_timestamp("2026-10-20T12:00:00.000Z"),
            Some(1_792_497_600_000)
        );
        assert_eq!(parse_timestamp("not-a-time"), None);
        assert_eq!(parse_timestamp("2026-10-20T12:00:00Z"), None);
        assert_eq!(parse_timestamp("2026-13-01T00:00:00.000Z"), None);
        assert_eq!(parse_timestamp("2026-02-30T00:00:00.000Z"), None);
        assert_eq!(parse_timestamp("1800-01-01T00:00:00.000Z"), None);
    }

    #[test]
    fn base64_trailing_bits_match_node() {
        // Ground truth from Node's Buffer.from(x, 'base64'): non-zero trailing
        // pad bits are dropped, so these pairs decode identically.
        let pairs = [
            ("AQ==", vec![0x01]),
            ("AR==", vec![0x01]),
            ("Ag==", vec![0x02]),
            ("Ah==", vec![0x02]),
            ("AB==", vec![0x00]),
            ("AZ==", vec![0x01]),
            ("/w==", vec![0xff]),
            ("/x==", vec![0xff]),
            ("//8=", vec![0xff, 0xff]),
            ("//9=", vec![0xff, 0xff]),
            ("e30=", vec![0x7b, 0x7d]),
            ("QQ==", vec![0x41]),
        ];
        for (text, bytes) in pairs {
            assert_eq!(
                decode_base64_strict(text, 256),
                Some(bytes),
                "{text} must decode like Node"
            );
        }
        // Rejected exactly where the TypeScript regex rejects.
        for text in ["AQ=", "A===", "====", "AQ== ", "AQ-_", "eyJub3"] {
            assert!(
                decode_base64_strict(text, 256).is_none(),
                "{text} must be refused like the TypeScript"
            );
        }
        // The byte bound mirrors Math.ceil(maxBytes / 3) * 4 on the text length.
        assert!(decode_base64_strict("AQ==", 0).is_none());
        assert!(decode_base64_strict("AQ==", 1).is_some());
        assert!(!is_canonical_base64("AQ="));
        assert!(is_canonical_base64(""));
    }

    #[test]
    fn digest_and_uuid_shapes() {
        assert!(is_digest(&format!("sha256:{}", "a".repeat(64))));
        assert!(!is_digest("sha256:ABC"));
        assert!(is_uuid("0a0a0a0a-0000-4000-8000-00000000000a"));
        assert!(!is_uuid("platform"));
        assert!(!is_uuid("0A0A0A0A-0000-4000-8000-00000000000A"));
    }
}
