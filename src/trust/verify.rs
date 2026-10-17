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

use super::{TrustCode, TrustVerdict, VerifyTrustedInput};

/// trust-contract.ts `VerifyTrusted`. Stage 1 stub: everything is `INPUT_INVALID`.
pub fn verify_trusted_impl(_input: &VerifyTrustedInput) -> TrustVerdict {
    TrustVerdict::of(TrustCode::InputInvalid)
}
