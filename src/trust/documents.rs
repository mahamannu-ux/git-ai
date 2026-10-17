// Ported from TrackAI apps/api/src/features/attesta/trust-documents.ts @
// 67af03726a86c94ff1de766059bebd1a7147add9 (Task15l, trust.md); behaviour fixed
// by tests/fixtures/trust vectors.
// Provenance: those files were themselves ported from SushiCorp B4
// core/trust/{revocation,verdict}.py @ 0bd67a5 (catalog TR-1).

use super::TrustCode;

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
