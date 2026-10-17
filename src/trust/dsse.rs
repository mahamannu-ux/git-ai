// Ported from TrackAI apps/api/src/features/attesta/dsse.ts @
// 67af03726a86c94ff1de766059bebd1a7147add9 (Task15l, trust.md); behaviour fixed
// by tests/fixtures/trust vectors.
// Provenance: those files were themselves ported from SushiCorp B4
// core/trust/{revocation,verdict}.py @ 0bd67a5 (catalog TR-1).
//
// DSSE (Dead Simple Signing Envelope) v1, after
// https://github.com/secure-systems-lab/dsse. Signatures are ECDSA P-256 over
// SHA-256, DER-encoded.

use serde::{Deserialize, Serialize};

/// One signature entry of an envelope: base64-encoded DER signature by `keyid`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsseSignature {
    pub keyid: String,
    /// Base64-encoded DER signature.
    pub sig: String,
}

/// A DSSE envelope: base64-encoded payload bytes plus signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsseEnvelope {
    /// Base64-encoded payload bytes.
    pub payload: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub signatures: Vec<DsseSignature>,
}

/// Pre-Authentication Encoding: `"DSSEv1" SP LEN(type) SP type SP LEN(body)
/// SP body`, where lengths are ASCII decimal counts of *bytes*.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let type_bytes = payload_type.as_bytes();
    let header = format!("DSSEv1 {} {} {} ", type_bytes.len(), payload_type, payload.len());
    let mut out = Vec::with_capacity(header.len() + payload.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::pae;

    #[test]
    fn pae_layout_matches_spec() {
        let bytes = pae("application/vnd.in-toto+json", b"{}");
        assert_eq!(bytes, b"DSSEv1 28 application/vnd.in-toto+json 2 {}");
    }
}
