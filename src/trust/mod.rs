// Ported from TrackAI apps/api/src/features/attesta/trust-contract.ts @
// 67af03726a86c94ff1de766059bebd1a7147add9 (Task15l, trust.md); behaviour fixed
// by tests/fixtures/trust vectors.
// Provenance: those files were themselves ported from SushiCorp B4
// core/trust/{revocation,verdict}.py @ 0bd67a5 (catalog TR-1).

pub mod documents;
pub mod dsse;
pub mod verify;

pub use dsse::{DsseEnvelope, DsseSignature};

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// `scope` of the root document; every other scope is a tenant UUID.
pub const PLATFORM_SCOPE: &str = "platform";

pub const TRUST_ROOT_PAYLOAD_TYPE: &str = "application/vnd.trackai.trust-root+json";
pub const KEYSET_PAYLOAD_TYPE: &str = "application/vnd.trackai.keyset+json";
pub const TRUST_ROOT_TYPE: &str = "https://trackai.dev/attesta/trust-root/v1";
pub const KEYSET_TYPE: &str = "https://trackai.dev/attesta/keyset/v1";

/// Bounds checked before any parsing or signature work (trust.md "Bounds").
pub const TRUST_MAX_DOCUMENT_BYTES: usize = 262_144;
/// About 700 key entries fit in TRUST_MAX_DOCUMENT_BYTES; this is the separate count bound.
pub const TRUST_MAX_KEYS_PER_DOCUMENT: usize = 1_000;
pub const TRUST_MAX_SIGNATURES_PER_DOCUMENT: usize = 16;
/// Key sets keep full history (weekly publish), so a scope may hold many versions.
pub const TRUST_MAX_DOCUMENTS_PER_SCOPE: usize = 1_024;
/// Tenant scopes in `keyset_documents`, `customer_pins` and `last_trusted`.
pub const TRUST_MAX_SCOPES: usize = 256;
/// Sum of all held documents' base64 payload lengths.
pub const TRUST_MAX_TOTAL_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
pub const TRUST_MAX_SIGNED_BYTES: usize = 16 * 1024 * 1024;
pub const TRUST_DEFAULT_CLOCK_SKEW_MS: i64 = 300_000;
/// `expires` - `issued_at` bounds (key sets 30 days + 1 day margin, roots 1 year + 1 day).
pub const TRUST_MAX_KEYSET_LIFETIME_MS: i64 = 31 * 86_400_000;
pub const TRUST_MAX_ROOT_LIFETIME_MS: i64 = 366 * 86_400_000;

/// What a key may sign. A key has exactly one purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPurpose {
    Root,
    Anchor,
    ActivationLease,
    FleetConfig,
    PolicyBundle,
    Release,
    TenantKeyset,
    Statement,
}

/// Purposes a consumer may pass to `verify_trusted` (root and tenant_keyset sign documents only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactPurpose {
    Anchor,
    ActivationLease,
    FleetConfig,
    PolicyBundle,
    Release,
    Statement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    Active,
    Retired,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    Superseded,
    Compromised,
}

/// One key in a document. RFC 3339 UTC timestamps with milliseconds (`...T00:00:00.000Z`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TrustKeyEntry {
    /// `sha256:` + hex(SHA-256(SPKI DER)); the verifier recomputes it.
    pub keyid: String,
    pub purpose: KeyPurpose,
    /// Standard base64 of the SPKI DER (ECDSA P-256). Public material only.
    pub spki_der_b64: String,
    pub not_before: String,
    pub not_after: String,
    pub status: KeyStatus,
    /// `retired` and `revoked`: the instant the key stopped being valid for new signatures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    /// `revoked` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<RevocationReason>,
    /// `revoked` + `compromised` only: signatures from then on are never trusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compromised_since: Option<String>,
}

/// The JSON payload of a trust document (RFC 8785 bytes inside a DSSE envelope).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TrustDocumentBody {
    #[serde(rename = "_type")]
    pub doc_type: String,
    /// `platform` (root document) or a tenant UUID (key set).
    pub scope: String,
    /// Strictly increasing per scope, starting at 1.
    pub version: i64,
    pub issued_at: String,
    pub expires: String,
    /// `sha256:` digest of the previous version's payload bytes; null exactly at version 1.
    pub previous: Option<String>,
    /// Root documents only: root signatures required (k of n).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<i64>,
    pub keys: Vec<TrustKeyEntry>,
}

/// A key the auditor or customer pins for their own tenant (founder decision 2026-10-13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CustomerPinnedKey {
    pub keyid: String,
    pub purpose: KeyPurpose,
    pub spki_der_b64: String,
    pub not_before: String,
    pub not_after: String,
    pub status: KeyStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<RevocationReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compromised_since: Option<String>,
}

/// A document a verifier accepted: its scope's version and payload digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TrustedDocumentRef {
    pub version: i64,
    pub digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeEvidenceKind {
    #[serde(rename = "tsa_gen_time")]
    TsaGenTime,
    #[serde(rename = "rekor_integrated_time")]
    RekorIntegratedTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeEvidenceBinds {
    #[serde(rename = "signature")]
    Signature,
    #[serde(rename = "ledger_statement")]
    LedgerStatement,
}

/// Independent proof that the signed payload existed at `time`.
/// Closed shape: a malformed object is a caller error, never silently ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct TimeEvidence {
    pub kind: TimeEvidenceKind,
    pub time: String,
    pub binds: TimeEvidenceBinds,
    /// `sha256:` + hex(SHA-256(bytes)) of the signature (`signature`) or the payload (`ledger_statement`).
    pub digest: String,
}

/// Everything the verifier trusts or holds. No database, no network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TrustState {
    /// Keyids of the root keys pinned at install or enrollment.
    pub pinned_root_keyids: Vec<String>,
    /// Root signatures from pinned keys required on the start document (default 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_root_threshold: Option<i64>,
    /// Every root document held, any order.
    pub root_documents: Vec<DsseEnvelope>,
    /// Key-set documents held, by tenant UUID: the latest and optionally its predecessors.
    pub keyset_documents: BTreeMap<String, Vec<DsseEnvelope>>,
    /// Customer pins by tenant UUID; when present for a tenant they replace its platform key set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer_pins: Option<BTreeMap<String, Vec<CustomerPinnedKey>>>,
    /// The newest document this verifier accepted before, by scope (`platform` = root).
    pub last_trusted: BTreeMap<String, TrustedDocumentRef>,
    /// The verifier's clock, RFC 3339 UTC.
    pub now: String,
    /// The latest trusted time this verifier has seen, persisted from `TrustVerdict.trusted_time`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_time_floor: Option<String>,
    /// Allowed clock skew in ms (default 300000 = 5 minutes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_skew_ms: Option<i64>,
    /// Production: a pinned root is mandatory and `allow_unpinned_root` is ignored.
    pub production: bool,
    /// Outside production only: trust the lowest held root document on first use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_unpinned_root: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VerifyTrustedInput {
    /// DSSE payload type of the artifact (e.g. `application/vnd.in-toto+json`).
    pub payload_type: String,
    /// The signed payload bytes; must equal the envelope's decoded payload.
    pub payload: Vec<u8>,
    /// Exactly one signature.
    pub envelope: DsseEnvelope,
    pub purpose: ArtifactPurpose,
    /// Tenant UUID for `statement`; `platform` for every other purpose.
    pub audience: String,
    /// When the artifact claims it was signed (RFC 3339 UTC). Not covered by the signature.
    pub signed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_evidence: Option<TimeEvidence>,
    pub state: TrustState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustStatus {
    Verified,
    Rejected,
    Unavailable,
}

/// Stable codes (errors.md "Trust (A15.12)"). Each maps to exactly one status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustCode {
    #[serde(rename = "ATTESTA_TRUST_VERIFIED")]
    Verified,
    #[serde(rename = "ATTESTA_TRUST_ROOT_NOT_PINNED")]
    RootNotPinned,
    #[serde(rename = "ATTESTA_TRUST_DOCUMENT_UNAVAILABLE")]
    DocumentUnavailable,
    #[serde(rename = "ATTESTA_TRUST_DOCUMENT_EXPIRED")]
    DocumentExpired,
    #[serde(rename = "ATTESTA_TRUST_DOCUMENT_FROM_FUTURE")]
    DocumentFromFuture,
    #[serde(rename = "ATTESTA_TRUST_REVOCATION_UNKNOWN")]
    RevocationUnknown,
    #[serde(rename = "ATTESTA_TRUST_CLOCK_BEHIND")]
    ClockBehind,
    #[serde(rename = "ATTESTA_TRUST_DOCUMENT_MALFORMED")]
    DocumentMalformed,
    #[serde(rename = "ATTESTA_TRUST_DOCUMENT_SIGNATURE_INVALID")]
    DocumentSignatureInvalid,
    #[serde(rename = "ATTESTA_TRUST_THRESHOLD_NOT_MET")]
    ThresholdNotMet,
    #[serde(rename = "ATTESTA_TRUST_DOCUMENT_CONFLICT")]
    DocumentConflict,
    #[serde(rename = "ATTESTA_TRUST_ROLLBACK")]
    Rollback,
    #[serde(rename = "ATTESTA_TRUST_KEYSET_REGRESSION")]
    KeysetRegression,
    #[serde(rename = "ATTESTA_TRUST_KEY_UNKNOWN")]
    KeyUnknown,
    #[serde(rename = "ATTESTA_TRUST_PURPOSE_MISMATCH")]
    PurposeMismatch,
    #[serde(rename = "ATTESTA_TRUST_AUDIENCE_MISMATCH")]
    AudienceMismatch,
    #[serde(rename = "ATTESTA_TRUST_KEY_NOT_VALID_AT")]
    KeyNotValidAt,
    #[serde(rename = "ATTESTA_TRUST_KEY_REVOKED")]
    KeyRevoked,
    #[serde(rename = "ATTESTA_TRUST_SIGNATURE_INVALID")]
    SignatureInvalid,
    #[serde(rename = "ATTESTA_TRUST_INPUT_INVALID")]
    InputInvalid,
}

impl TrustCode {
    /// The one status this code maps to (`TRUST_CODE_STATUS`).
    pub fn status(self) -> TrustStatus {
        match self {
            TrustCode::Verified => TrustStatus::Verified,
            TrustCode::RootNotPinned
            | TrustCode::DocumentUnavailable
            | TrustCode::DocumentExpired
            | TrustCode::DocumentFromFuture
            | TrustCode::RevocationUnknown
            | TrustCode::ClockBehind => TrustStatus::Unavailable,
            _ => TrustStatus::Rejected,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TrustVerdict {
    pub status: TrustStatus,
    pub code: TrustCode,
    /// On `verified`: the keyid that signed the artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyid: Option<String>,
    /// On `verified`: the newest document accepted per scope in this call (empty with customer pins).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted: Option<BTreeMap<String, TrustedDocumentRef>>,
    /// On `verified`: max(`trusted_time_floor`, `now`), for consumers to persist as the next floor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_time: Option<String>,
}

impl TrustVerdict {
    pub fn of(code: TrustCode) -> Self {
        let status = code.status();
        Self {
            status,
            code,
            keyid: None,
            trusted: None,
            trusted_time: None,
        }
    }
}

/// The verifier (trust-verify.rs). Pure: never panics on malformed input, never reads
/// a clock, a file or the network. `production` comes only from `state.production`;
/// shipped consumers hard-code `true` (trust.md "Consumers").
pub fn verify_trusted(input: &VerifyTrustedInput) -> TrustVerdict {
    verify::verify_trusted_impl(input)
}
