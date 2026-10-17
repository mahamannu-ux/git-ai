// Ported from TrackAI apps/api/src/features/attesta/trust-verify.ts @
// 67af03726a86c94ff1de766059bebd1a7147add9 (Task15l, trust.md); behaviour fixed
// by tests/fixtures/trust vectors.
// Provenance: those files were themselves ported from SushiCorp B4
// core/trust/{revocation,verdict}.py @ 0bd67a5 (catalog TR-1).
//
// Implements trust.md "Verification" step by step. Pure: no database, no
// network, no clock (`state.now`), never throws.
// Status rule: tampering evidence -> `rejected`; absent trust information ->
// `unavailable`, never `verified`.

use std::collections::{BTreeMap, BTreeSet};

use super::documents::{
    DocumentKind, ParsedDocument, ParsedKey, SignatureFacts, TrustDocumentError,
    decode_base64_strict, document_signed_by, forward_only_violation, is_digest, is_uuid,
    key_validity_violation, parse_customer_pin, parse_timestamp, parse_trust_document,
    valid_document_signers, verify_signature,
};
use super::dsse::{self, DsseEnvelope};
use super::{
    ArtifactPurpose, KeyPurpose, KeyStatus, PLATFORM_SCOPE, TRUST_DEFAULT_CLOCK_SKEW_MS,
    TRUST_MAX_DOCUMENTS_PER_SCOPE, TRUST_MAX_SCOPES, TRUST_MAX_SIGNED_BYTES,
    TRUST_MAX_TOTAL_DOCUMENT_BYTES, TimeEvidence, TrustCode, TrustState, TrustVerdict,
    TrustedDocumentRef, VerifyTrustedInput,
};

const MAX_SKEW_MS: i64 = 3_600_000;
const MAX_PINS: usize = 16;
const MAX_SAFE_INT: i64 = 9_007_199_254_740_991;

impl From<TrustDocumentError> for TrustCode {
    fn from(err: TrustDocumentError) -> Self {
        err.code
    }
}

fn is_safe_int(value: i64) -> bool {
    (-MAX_SAFE_INT..=MAX_SAFE_INT).contains(&value)
}

struct Checked<'a> {
    payload: &'a [u8],
    payload_type: &'a str,
    keyid: &'a str,
    sig: Vec<u8>,
    purpose: ArtifactPurpose,
    audience: &'a str,
    signed_at: i64,
    now: i64,
    skew: i64,
    time_evidence: Option<&'a TimeEvidence>,
    state: &'a TrustState,
    floor: Option<i64>,
}

/// Step 1: the call itself, bounded. Any breach -> INPUT_INVALID.
fn check_input(input: &VerifyTrustedInput) -> Result<Checked<'_>, TrustCode> {
    const INVALID: TrustCode = TrustCode::InputInvalid;
    if input.payload.len() > TRUST_MAX_SIGNED_BYTES {
        return Err(INVALID);
    }
    if input.payload_type.is_empty() || input.payload_type.len() > 256 {
        return Err(INVALID);
    }
    if input.envelope.payload_type != input.payload_type {
        return Err(INVALID);
    }
    let decoded =
        decode_base64_strict(&input.envelope.payload, TRUST_MAX_SIGNED_BYTES).ok_or(INVALID)?;
    if decoded.as_slice() != input.payload.as_slice() {
        return Err(INVALID);
    }
    if input.envelope.signatures.len() != 1 {
        return Err(INVALID);
    }
    let Some(entry) = input.envelope.signatures.first() else {
        return Err(INVALID);
    };
    let sig = decode_base64_strict(&entry.sig, 256)
        .filter(|s| !s.is_empty())
        .ok_or(INVALID)?;
    if !is_digest(&entry.keyid) {
        return Err(INVALID);
    }
    match input.purpose {
        ArtifactPurpose::Statement => {
            if !is_uuid(&input.audience) {
                return Err(INVALID);
            }
        }
        _ => {
            if input.audience != PLATFORM_SCOPE {
                return Err(INVALID);
            }
        }
    }
    let signed_at = parse_timestamp(&input.signed_at).ok_or(INVALID)?;
    let state = &input.state;
    let now = parse_timestamp(&state.now).ok_or(INVALID)?;
    let skew = state.clock_skew_ms.unwrap_or(TRUST_DEFAULT_CLOCK_SKEW_MS);
    if !is_safe_int(skew) || !(0..=MAX_SKEW_MS).contains(&skew) {
        return Err(INVALID);
    }
    if let Some(evidence) = &input.time_evidence {
        // Exact shape: a malformed object is a caller error, never silently ignored.
        // (Unknown keys are refused by serde at the boundary; values are checked here.)
        if evidence.binds == super::TimeEvidenceBinds::LedgerStatement
            && input.purpose != ArtifactPurpose::Statement
        {
            return Err(INVALID);
        }
        if parse_timestamp(&evidence.time).is_none() || !is_digest(&evidence.digest) {
            return Err(INVALID);
        }
    }
    let floor = match &state.trusted_time_floor {
        Some(value) => Some(parse_timestamp(value).ok_or(INVALID)?),
        None => None,
    };
    if state.pinned_root_keyids.len() > MAX_PINS
        || state.pinned_root_keyids.iter().any(|k| !is_digest(k))
    {
        return Err(INVALID);
    }
    let pin_threshold = state.pinned_root_threshold.unwrap_or(1);
    if !is_safe_int(pin_threshold) || pin_threshold < 1 || pin_threshold > MAX_PINS as i64 {
        return Err(INVALID);
    }
    if state.root_documents.len() > TRUST_MAX_DOCUMENTS_PER_SCOPE {
        return Err(INVALID);
    }
    if state.keyset_documents.len() > TRUST_MAX_SCOPES {
        return Err(INVALID);
    }
    // Total work bound before any parsing: the sum of every held payload's base64 length.
    let mut total: usize = 0;
    total = total.saturating_add(
        state
            .root_documents
            .iter()
            .map(|env| env.payload.len())
            .sum::<usize>(),
    );
    for docs in state.keyset_documents.values() {
        if docs.len() > TRUST_MAX_DOCUMENTS_PER_SCOPE {
            return Err(INVALID);
        }
        total = total.saturating_add(docs.iter().map(|env| env.payload.len()).sum::<usize>());
    }
    if total > TRUST_MAX_TOTAL_DOCUMENT_BYTES {
        return Err(INVALID);
    }
    if state.last_trusted.len() > TRUST_MAX_SCOPES + 1 {
        return Err(INVALID);
    }
    for reference in state.last_trusted.values() {
        if !is_safe_int(reference.version) || reference.version < 1 || !is_digest(&reference.digest)
        {
            return Err(INVALID);
        }
    }
    if state
        .customer_pins
        .as_ref()
        .is_some_and(|pins| pins.len() > TRUST_MAX_SCOPES)
    {
        return Err(INVALID);
    }
    Ok(Checked {
        payload: &input.payload,
        payload_type: &input.payload_type,
        keyid: &entry.keyid,
        sig,
        purpose: input.purpose,
        audience: &input.audience,
        signed_at,
        now,
        skew,
        time_evidence: input.time_evidence.as_ref(),
        state,
        floor,
    })
}

fn parse_all(
    envelopes: &[DsseEnvelope],
    kind: DocumentKind,
    scope: &str,
) -> Result<Vec<ParsedDocument>, TrustCode> {
    let mut out = Vec::with_capacity(envelopes.len());
    for envelope in envelopes {
        let doc = parse_trust_document(envelope)?;
        if doc.kind != kind || doc.body.scope != scope {
            return Err(TrustCode::DocumentMalformed);
        }
        out.push(doc);
    }
    Ok(out)
}

/// One document per version (byte-identical duplicates collapse); two different ones conflict.
fn by_version(docs: Vec<ParsedDocument>) -> Result<BTreeMap<i64, ParsedDocument>, TrustCode> {
    let mut out: BTreeMap<i64, ParsedDocument> = BTreeMap::new();
    for doc in docs {
        if let Some(seen) = out.get(&doc.body.version)
            && seen.digest != doc.digest
        {
            return Err(TrustCode::DocumentConflict);
        }
        out.insert(doc.body.version, doc);
    }
    Ok(out)
}

/// The document this verifier accepted before for `scope`, if any.
fn last_trusted_ref<'a>(c: &Checked<'a>, scope: &str) -> Option<&'a TrustedDocumentRef> {
    c.state.last_trusted.get(scope)
}

/// Where a chain must start when the verifier accepted a document of this scope
/// before: at exactly that document. Older held versions are ignored; a different
/// document at that version is a fork; nothing at or above it is a rollback.
fn anchored_start(
    versions: &BTreeMap<i64, ParsedDocument>,
    reference: &TrustedDocumentRef,
) -> Result<ParsedDocument, TrustCode> {
    if let Some(found) = versions.get(&reference.version) {
        if found.digest != reference.digest {
            return Err(TrustCode::DocumentConflict);
        }
        return Ok(found.clone());
    }
    match versions.keys().max() {
        Some(max) if *max >= reference.version => Err(TrustCode::DocumentUnavailable),
        _ => Err(TrustCode::Rollback),
    }
}

fn check_not_expired(doc: &ParsedDocument, c: &Checked<'_>) -> Result<(), TrustCode> {
    if c.now > doc.expires.saturating_add(c.skew) {
        return Err(TrustCode::DocumentExpired);
    }
    Ok(())
}

fn check_not_from_future(docs: &[ParsedDocument], c: &Checked<'_>) -> Result<(), TrustCode> {
    for doc in docs {
        if doc.issued_at > c.now.saturating_add(c.skew) {
            return Err(TrustCode::DocumentFromFuture);
        }
    }
    Ok(())
}

fn active_root_keys(doc: &ParsedDocument) -> BTreeMap<String, ParsedKey> {
    doc.keys
        .iter()
        .filter(|(_, k)| k.entry.purpose == KeyPurpose::Root && k.entry.status == KeyStatus::Active)
        .map(|(id, k)| (id.clone(), k.clone()))
        .collect()
}

fn artifact_purpose_key(purpose: ArtifactPurpose) -> KeyPurpose {
    match purpose {
        ArtifactPurpose::Anchor => KeyPurpose::Anchor,
        ArtifactPurpose::ActivationLease => KeyPurpose::ActivationLease,
        ArtifactPurpose::FleetConfig => KeyPurpose::FleetConfig,
        ArtifactPurpose::PolicyBundle => KeyPurpose::PolicyBundle,
        ArtifactPurpose::Release => KeyPurpose::Release,
        ArtifactPurpose::Statement => KeyPurpose::Statement,
    }
}

/// Steps 3-4: the root chain from the pin to the newest root document.
fn verify_root_chain(c: &Checked<'_>) -> Result<ParsedDocument, TrustCode> {
    let state = c.state;
    let pinned = &state.pinned_root_keyids;
    if pinned.is_empty() && (state.production || state.allow_unpinned_root != Some(true)) {
        return Err(TrustCode::RootNotPinned);
    }
    let docs = parse_all(&state.root_documents, DocumentKind::Root, PLATFORM_SCOPE)?;
    if docs.is_empty() {
        return Err(TrustCode::DocumentUnavailable);
    }
    let versions = by_version(docs)?;
    let ordered: Vec<ParsedDocument> = versions.values().cloned().collect();
    check_not_from_future(&ordered, c)?;
    let start: ParsedDocument;
    if let Some(reference) = last_trusted_ref(c, PLATFORM_SCOPE) {
        // Accepted before (after its own chain check): start there, so a root key
        // rotated out since then can no longer fork from an older version.
        start = anchored_start(&versions, reference)?;
    } else if !pinned.is_empty() {
        let pin_set: BTreeSet<&str> = pinned.iter().map(String::as_str).collect();
        let found = ordered.iter().find(|d| {
            active_root_keys(d)
                .keys()
                .any(|k| pin_set.contains(k.as_str()))
        });
        let Some(candidate) = found else {
            return Err(TrustCode::DocumentUnavailable);
        };
        let pinned_keys: BTreeMap<String, ParsedKey> = active_root_keys(candidate)
            .into_iter()
            .filter(|(k, _)| pin_set.contains(k.as_str()))
            .collect();
        let need = candidate
            .body
            .threshold
            .unwrap_or(1)
            .max(state.pinned_root_threshold.unwrap_or(1));
        let signers =
            valid_document_signers(candidate, &pinned_keys, KeyPurpose::Root).len() as i64;
        if signers < need {
            return Err(TrustCode::ThresholdNotMet);
        }
        start = candidate.clone();
    } else {
        // Development only (checked above): trust the lowest held root on first use.
        let Some(candidate) = ordered.first() else {
            return Err(TrustCode::DocumentUnavailable);
        };
        let need = candidate.body.threshold.unwrap_or(1);
        let signers =
            valid_document_signers(candidate, &active_root_keys(candidate), KeyPurpose::Root).len()
                as i64;
        if signers < need {
            return Err(TrustCode::ThresholdNotMet);
        }
        start = candidate.clone();
    }
    let mut current = start;
    let Some(max) = ordered.last().map(|d| d.body.version) else {
        return Err(TrustCode::DocumentUnavailable);
    };
    let mut version = current.body.version.saturating_add(1);
    while version <= max {
        let Some(next) = versions.get(&version) else {
            return Err(TrustCode::DocumentUnavailable);
        };
        if next.body.previous.as_deref() != Some(current.digest.as_str()) {
            return Err(TrustCode::DocumentConflict);
        }
        // TUF root rotation: k of the previous root AND k' of its own root keys.
        let need_prev = current.body.threshold.unwrap_or(1);
        let need_next = next.body.threshold.unwrap_or(1);
        let prev_signers =
            valid_document_signers(next, &active_root_keys(&current), KeyPurpose::Root).len()
                as i64;
        let next_signers =
            valid_document_signers(next, &active_root_keys(next), KeyPurpose::Root).len() as i64;
        if prev_signers < need_prev || next_signers < need_next {
            return Err(TrustCode::ThresholdNotMet);
        }
        if let Some(regression) = forward_only_violation(&current, next) {
            return Err(regression);
        }
        current = next.clone();
        version = version.saturating_add(1);
    }
    check_not_expired(&current, c)?;
    Ok(current)
}

/// A key set is signed by a `tenant_keyset` key of the current root, valid at its issued_at.
fn check_keyset_signature(
    doc: &ParsedDocument,
    root: &ParsedDocument,
    c: &Checked<'_>,
) -> Result<(), TrustCode> {
    let mut first_violation: Option<TrustCode> = None;
    for entry in &doc.signatures {
        let Some(candidate) = root.keys.get(&entry.keyid) else {
            continue;
        };
        if candidate.entry.purpose != KeyPurpose::TenantKeyset
            || !document_signed_by(doc, &candidate.key, &entry.sig)
        {
            continue;
        }
        // Documents carry no time evidence: a compromised keyset key never vouches.
        match key_validity_violation(candidate, doc.issued_at, c.now, c.skew, None, None) {
            None => return Ok(()),
            Some(violation) => {
                if first_violation.is_none() {
                    first_violation = Some(violation);
                }
            }
        }
    }
    Err(first_violation.unwrap_or(TrustCode::DocumentSignatureInvalid))
}

/// Step 5: the audience's key sets, contiguous, signed, forward-only, fresh.
fn verify_keysets(c: &Checked<'_>, root: &ParsedDocument) -> Result<ParsedDocument, TrustCode> {
    let empty: Vec<DsseEnvelope> = Vec::new();
    let held = c.state.keyset_documents.get(c.audience).unwrap_or(&empty);
    if held.is_empty() {
        return Err(TrustCode::RevocationUnknown);
    }
    let docs = parse_all(held, DocumentKind::Keyset, c.audience)?;
    let versions = by_version(docs)?;
    let all: Vec<ParsedDocument> = versions.values().cloned().collect();
    check_not_from_future(&all, c)?;
    let mut ordered = all;
    if let Some(reference) = last_trusted_ref(c, c.audience) {
        let start = anchored_start(&versions, reference)?;
        ordered.retain(|d| d.body.version >= start.body.version);
        ordered.sort_by_key(|d| d.body.version);
    } else if ordered.first().is_none_or(|d| d.body.version != 1) {
        // First use: the full history from version 1, so a lone forged document
        // (a stolen tenant_keyset key) cannot hide an earlier revocation.
        return Err(TrustCode::DocumentUnavailable);
    }
    for window in ordered.windows(2) {
        let (previous, current) = (&window[0], &window[1]);
        if current.body.version != previous.body.version.saturating_add(1) {
            return Err(TrustCode::DocumentUnavailable);
        }
        if current.body.previous.as_deref() != Some(previous.digest.as_str()) {
            return Err(TrustCode::DocumentConflict);
        }
        if let Some(regression) = forward_only_violation(previous, current) {
            return Err(regression);
        }
    }
    // Only the newest needs a signer valid under the current root: each `previous`
    // digest authenticates the one before, so older history stays valid after its
    // tenant_keyset key is retired or compromised (and forged history still needs a
    // currently valid key to sign the newest).
    let Some(newest) = ordered.last() else {
        return Err(TrustCode::DocumentUnavailable);
    };
    check_keyset_signature(newest, root, c)?;
    check_not_expired(newest, c)?;
    Ok(newest.clone())
}

/// Step 2: customer pins for the audience (statement only), validated as key entries.
fn pinned_keys(c: &Checked<'_>) -> Result<Option<BTreeMap<String, ParsedKey>>, TrustCode> {
    if c.purpose != ArtifactPurpose::Statement {
        return Ok(None);
    }
    let Some(pins) = c.state.customer_pins.as_ref() else {
        return Ok(None);
    };
    let Some(list) = pins.get(c.audience) else {
        return Ok(None);
    };
    if list.len() > TRUST_MAX_DOCUMENTS_PER_SCOPE.saturating_mul(16) {
        return Err(TrustCode::InputInvalid);
    }
    let mut out = BTreeMap::new();
    for raw in list {
        let parsed = parse_customer_pin(raw).map_err(|_| TrustCode::InputInvalid)?;
        if out.contains_key(&parsed.entry.keyid) {
            return Err(TrustCode::InputInvalid);
        }
        out.insert(parsed.entry.keyid.clone(), parsed);
    }
    Ok(Some(out))
}

/// For the rejection code only: is this keyid listed in another tenant's key set?
fn listed_for_other_tenant(c: &Checked<'_>) -> bool {
    for (tenant, envelopes) in &c.state.keyset_documents {
        if tenant == c.audience {
            continue;
        }
        for envelope in envelopes {
            match parse_trust_document(envelope) {
                Ok(doc) => {
                    if doc.keys.contains_key(c.keyid) {
                        return true;
                    }
                }
                Err(_) => {
                    // Unparseable documents of other tenants say nothing about this key.
                }
            }
        }
    }
    false
}

/// Format epoch ms as RFC 3339 UTC with milliseconds (`Date.toISOString` shape).
fn format_iso_millis(ms: i64) -> Result<String, TrustCode> {
    let instant = chrono::DateTime::from_timestamp_millis(ms).ok_or(TrustCode::InputInvalid)?;
    Ok(instant
        .to_utc()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string())
}

fn run(input: &VerifyTrustedInput) -> Result<TrustVerdict, TrustCode> {
    let c = check_input(input)?;
    // Step 1b: a clock behind the persisted floor (beyond skew) cannot judge expiry or validity.
    if c.floor
        .is_some_and(|floor| c.now < floor.saturating_sub(c.skew))
    {
        return Err(TrustCode::ClockBehind);
    }
    let keys: BTreeMap<String, ParsedKey>;
    let mut trusted: BTreeMap<String, TrustedDocumentRef> = BTreeMap::new();
    let mut root: Option<ParsedDocument> = None;
    if let Some(pins) = pinned_keys(&c)? {
        // Step 2: customer pins replace the platform key set and the root for this tenant.
        keys = pins;
    } else {
        // Steps 3-4: the root chain.
        let current = verify_root_chain(&c)?;
        trusted.insert(
            PLATFORM_SCOPE.to_string(),
            TrustedDocumentRef {
                version: current.body.version,
                digest: current.digest.clone(),
            },
        );
        if c.purpose == ArtifactPurpose::Statement {
            // Step 5: the audience's key sets.
            let keyset = verify_keysets(&c, &current)?;
            trusted.insert(
                c.audience.to_string(),
                TrustedDocumentRef {
                    version: keyset.body.version,
                    digest: keyset.digest.clone(),
                },
            );
            keys = keyset.keys.clone();
        } else {
            keys = current
                .keys
                .iter()
                .filter(|(_, k)| k.entry.purpose != KeyPurpose::Root)
                .map(|(id, k)| (id.clone(), k.clone()))
                .collect();
        }
        root = Some(current);
    }
    // Step 6: the key list.
    let key = match keys.get(c.keyid) {
        Some(key) => key.clone(),
        None => {
            if root.is_none() {
                return Err(TrustCode::KeyUnknown);
            }
            let Some(root) = root.as_ref() else {
                return Err(TrustCode::KeyUnknown);
            };
            if root.keys.contains_key(c.keyid) {
                return Err(TrustCode::PurposeMismatch);
            }
            if listed_for_other_tenant(&c) {
                if c.purpose == ArtifactPurpose::Statement {
                    return Err(TrustCode::AudienceMismatch);
                }
                return Err(TrustCode::PurposeMismatch);
            }
            return Err(TrustCode::KeyUnknown);
        }
    };
    if key.entry.purpose != artifact_purpose_key(c.purpose) {
        return Err(TrustCode::PurposeMismatch);
    }
    // Step 7: the signature verifies over PAE(payloadType, payload) with the listed SPKI.
    if !verify_signature(&key.key, &dsse::pae(c.payload_type, c.payload), &c.sig) {
        return Err(TrustCode::SignatureInvalid);
    }
    // Step 8: the key was valid for this signature.
    let facts = SignatureFacts::for_artifact(c.purpose, &c.sig, c.payload);
    if let Some(violation) = key_validity_violation(
        &key,
        c.signed_at,
        c.now,
        c.skew,
        c.time_evidence,
        Some(&facts),
    ) {
        return Err(violation);
    }
    // Step 9: all passed.
    let floor_or_now = c.floor.unwrap_or(c.now);
    let trusted_time = format_iso_millis(c.now.max(floor_or_now))?;
    Ok(TrustVerdict {
        status: TrustCode::Verified.status(),
        code: TrustCode::Verified,
        keyid: Some(c.keyid.to_string()),
        trusted: Some(trusted),
        trusted_time: Some(trusted_time),
    })
}

/// trust-contract.ts `VerifyTrusted`.
pub fn verify_trusted_impl(input: &VerifyTrustedInput) -> TrustVerdict {
    match run(input) {
        Ok(verdict) => verdict,
        Err(code) => TrustVerdict::of(code),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::{
        ArtifactPurpose, DsseEnvelope, DsseSignature, TrustCode, TrustState, TrustStatus,
        VerifyTrustedInput, verify_trusted,
    };
    use super::verify_trusted_impl;

    fn minimal_state() -> TrustState {
        TrustState {
            pinned_root_keyids: Vec::new(),
            pinned_root_threshold: None,
            root_documents: Vec::new(),
            keyset_documents: BTreeMap::new(),
            customer_pins: None,
            last_trusted: BTreeMap::new(),
            now: "2026-10-20T12:00:00.000Z".to_string(),
            trusted_time_floor: None,
            clock_skew_ms: None,
            production: false,
            allow_unpinned_root: None,
        }
    }

    fn input_with_envelope(payload: Vec<u8>, envelope: DsseEnvelope) -> VerifyTrustedInput {
        VerifyTrustedInput {
            payload_type: "application/vnd.in-toto+json".to_string(),
            payload,
            envelope,
            purpose: ArtifactPurpose::Release,
            audience: "platform".to_string(),
            signed_at: "2026-10-16T00:00:00.000Z".to_string(),
            time_evidence: None,
            state: minimal_state(),
        }
    }

    #[test]
    fn garbage_envelope_is_input_invalid() {
        let input = input_with_envelope(
            b"{}".to_vec(),
            DsseEnvelope {
                payload: "%%%not-base64%%%".to_string(),
                payload_type: "application/vnd.in-toto+json".to_string(),
                signatures: Vec::new(),
            },
        );
        assert_eq!(verify_trusted(&input).code, TrustCode::InputInvalid);
    }

    #[test]
    fn truncated_envelope_payload_is_input_invalid() {
        // Valid base64, but decodes to bytes that are not the artifact payload.
        let input = input_with_envelope(
            b"{\"note\":\"full\"}".to_vec(),
            DsseEnvelope {
                payload: "eyJub3".to_string(),
                payload_type: "application/vnd.in-toto+json".to_string(),
                signatures: vec![DsseSignature {
                    keyid: format!("sha256:{}", "0".repeat(64)),
                    sig: "AA==".to_string(),
                }],
            },
        );
        assert_eq!(verify_trusted(&input).code, TrustCode::InputInvalid);
    }

    #[test]
    fn empty_signature_list_is_input_invalid() {
        let input = input_with_envelope(
            b"{}".to_vec(),
            DsseEnvelope {
                payload: "e30=".to_string(),
                payload_type: "application/vnd.in-toto+json".to_string(),
                signatures: Vec::new(),
            },
        );
        assert_eq!(verify_trusted(&input).code, TrustCode::InputInvalid);
    }

    #[test]
    fn oversized_payload_is_input_invalid() {
        let big = vec![0u8; super::super::TRUST_MAX_SIGNED_BYTES + 1];
        let input = input_with_envelope(
            big,
            DsseEnvelope {
                payload: String::new(),
                payload_type: "application/vnd.in-toto+json".to_string(),
                signatures: Vec::new(),
            },
        );
        assert_eq!(verify_trusted(&input).code, TrustCode::InputInvalid);
    }

    #[test]
    fn unknown_purposes_are_rejected_at_the_boundary() {
        // `root` and `tenant_keyset` sign documents only: they are not artifact
        // purposes, so they never deserialize and can never reach the verifier.
        for purpose in ["root", "tenant_keyset", "policy"] {
            let parsed: Result<ArtifactPurpose, _> =
                serde_json::from_value(serde_json::Value::String(purpose.to_string()));
            assert!(
                parsed.is_err(),
                "{purpose} must not parse as an artifact purpose"
            );
        }
    }

    #[test]
    fn verdict_is_deterministic() {
        // Positive path: vector 01 verifies, and the same input verifies identically twice.
        let text = include_str!("../../tests/fixtures/trust/01-good-statement.json");
        let raw: serde_json::Value = serde_json::from_str(text).expect("fixture parses");
        let input_value = raw.get("input").expect("fixture has input");
        let payload_b64 = input_value
            .get("payload_b64")
            .and_then(serde_json::Value::as_str)
            .expect("fixture has payload_b64");
        let payload = super::super::documents::decode_base64_strict(
            payload_b64,
            super::super::TRUST_MAX_SIGNED_BYTES,
        )
        .expect("fixture payload is base64");
        let input = VerifyTrustedInput {
            payload_type: serde_json::from_value(
                input_value
                    .get("payload_type")
                    .cloned()
                    .expect("payload_type"),
            )
            .expect("payload_type parses"),
            payload,
            envelope: serde_json::from_value(
                input_value.get("envelope").cloned().expect("envelope"),
            )
            .expect("envelope parses"),
            purpose: serde_json::from_value(input_value.get("purpose").cloned().expect("purpose"))
                .expect("purpose parses"),
            audience: serde_json::from_value(
                input_value.get("audience").cloned().expect("audience"),
            )
            .expect("audience parses"),
            signed_at: serde_json::from_value(
                input_value.get("signed_at").cloned().expect("signed_at"),
            )
            .expect("signed_at parses"),
            time_evidence: None,
            state: serde_json::from_value(input_value.get("state").cloned().expect("state"))
                .expect("state parses"),
        };
        let first = verify_trusted_impl(&input);
        let second = verify_trusted(&input);
        assert_eq!(first.code, TrustCode::Verified);
        assert_eq!(first.status, TrustStatus::Verified);
        assert_eq!(first, second);

        // Negative path is deterministic too.
        let bad = input_with_envelope(
            b"{}".to_vec(),
            DsseEnvelope {
                payload: "e30=".to_string(),
                payload_type: "application/vnd.in-toto+json".to_string(),
                signatures: Vec::new(),
            },
        );
        assert_eq!(verify_trusted(&bad), verify_trusted(&bad));
    }
}
