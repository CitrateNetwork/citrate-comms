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

/// Deserialize a value from canonical CBOR bytes (the inverse of [`to_vec`]).
pub fn from_slice<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtoError> {
    ciborium::de::from_reader(bytes).map_err(|e| ProtoError::Encode(e.to_string()))
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

    /// WP-4.5 (`PLANSET/07` §4): the decode path the relay and clients run on **every**
    /// message must never panic, over-read, or escape its frame on malformed, truncated,
    /// hostile, or oversized CBOR — it returns `Err`, fail-closed. (ciborium is a
    /// memory-safe decoder; this pins the contract as a regression test and is the seed
    /// corpus for the `cargo-fuzz` target.)
    #[test]
    fn hostile_cbor_never_panics_only_errors() {
        let good = to_vec(&Envelope {
            group_id: GroupId([9; 32]),
            epoch: EpochId(3),
            kind: EnvelopeKind::Application,
            sender: WalletAddress([1; 20]),
            recipients: vec![WalletAddress([2; 20])],
            ciphertext: vec![0xab; 64],
            group_seq: Some(7),
        })
        .unwrap();

        let mut corpus: Vec<Vec<u8>> = vec![
            vec![],                              // empty
            vec![0x00],                          // single byte
            vec![0xff; 8],                       // garbage
            good[..good.len() / 2].to_vec(),     // truncated mid-value
            good[1..].to_vec(),                  // dropped leading byte (frame shift)
            {
                let mut g = good.clone();
                g.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // trailing garbage
                g
            },
            vec![0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // array with a giant declared length
            vec![0xbf; 4096],                    // many indefinite-length map openers (nesting bomb)
        ];
        // Every single-byte flip of the valid encoding.
        for i in 0..good.len() {
            let mut m = good.clone();
            m[i] ^= 0xff;
            corpus.push(m);
        }

        // The contract is "no panic". Decoding may succeed or error; if it succeeds,
        // re-encoding must also not panic.
        for bytes in &corpus {
            if let Ok(env) = from_slice::<Envelope>(bytes) {
                let _ = to_vec(&env);
            }
        }
        // The valid bytes still round-trip exactly (decode did not regress).
        let back: Envelope = from_slice(&good).unwrap();
        assert_eq!(to_vec(&back).unwrap(), good);
    }
}
