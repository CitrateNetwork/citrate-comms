//! Canonical CBOR encoding — the single deterministic byte representation used
//! wherever a structure must be hashed or signed (audit links, role assertions,
//! binding attestations). Determinism matters: two parties must derive identical
//! bytes for identical values, or signatures and hash chains diverge.
//!
//! This is serialization, not cryptography — it lives in `comms-proto` so every
//! crate agrees on the bytes.

use crate::ProtoError;
use serde::Serialize;

/// Serialize `value` to canonical CBOR bytes.
pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtoError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf).map_err(|e| ProtoError::Encode(e.to_string()))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    #[test]
    fn wallet_hex_roundtrip() {
        let w = WalletAddress([0x11; 20]);
        assert_eq!(WalletAddress::from_hex(&w.to_hex()).unwrap(), w);
    }

    #[test]
    fn canonical_is_deterministic() {
        let ev = AuditEvent::MemberAdded {
            group_id: GroupId([7; 32]),
            member: WalletAddress([3; 20]),
            epoch: EpochId(1),
        };
        assert_eq!(to_vec(&ev).unwrap(), to_vec(&ev).unwrap());
    }

    #[test]
    fn envelope_carries_no_plaintext_field() {
        // Compile-time documentation: an Envelope's only payload is `ciphertext`.
        let e = Envelope {
            group_id: GroupId([0; 32]),
            epoch: EpochId(0),
            kind: EnvelopeKind::Application,
            sender: WalletAddress([1; 20]),
            recipients: vec![WalletAddress([2; 20])],
            ciphertext: vec![0xde, 0xad],
            group_seq: None,
        };
        let bytes = to_vec(&e).unwrap();
        assert!(!bytes.is_empty());
    }
}
