//! `audit` — the BLAKE3 hash-chained, append-only metadata log.
//!
//! Mirrors `citrate-agent-runtime`'s `AuditChain`: a monotone `sequence`, contiguous
//! `previous_hash` links, an all-zero genesis prev-hash, and an offline
//! [`AuditChain::verify_integrity`] walk. It records metadata events only — never
//! plaintext content (`PLANSET/02_ARCHITECTURE.md` §7). Time is **caller-supplied**
//! (the chain reads no clock), so the structure is fully deterministic and airgap-verifiable.

use comms_proto::{canonical, AuditEvent, AuditRecord};
use serde::Serialize;

const DOMAIN: &[u8] = b"citrate-comms/audit/v1";
const ZERO: [u8; 32] = [0u8; 32];

/// The hash pre-image for one link: everything in the record except `record_hash`.
#[derive(Serialize)]
struct LinkInput<'a> {
    sequence: u64,
    timestamp_ms: u64,
    previous_hash: [u8; 32],
    event: &'a AuditEvent,
}

fn link_hash(seq: u64, ts: u64, prev: [u8; 32], event: &AuditEvent) -> Result<[u8; 32], AuditError> {
    let input = LinkInput { sequence: seq, timestamp_ms: ts, previous_hash: prev, event };
    let body = canonical::to_vec(&input).map_err(|e| AuditError::Encode(e.to_string()))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN);
    hasher.update(&body);
    Ok(*hasher.finalize().as_bytes())
}

/// An append-only BLAKE3 hash chain of [`AuditRecord`]s.
#[derive(Clone, Debug, Default)]
pub struct AuditChain {
    records: Vec<AuditRecord>,
}

impl AuditChain {
    /// Start a fresh chain with a genesis record (`previous_hash == 0`).
    pub fn new(genesis_ts_ms: u64) -> Result<Self, AuditError> {
        let event = AuditEvent::Genesis;
        let record_hash = link_hash(0, genesis_ts_ms, ZERO, &event)?;
        let genesis = AuditRecord {
            sequence: 0,
            timestamp_ms: genesis_ts_ms,
            previous_hash: ZERO,
            event,
            record_hash,
        };
        Ok(Self { records: vec![genesis] })
    }

    /// Append an event, linking it to the current head. Returns the new record.
    pub fn append(&mut self, event: AuditEvent, timestamp_ms: u64) -> Result<&AuditRecord, AuditError> {
        let head = self.records.last().ok_or(AuditError::Empty)?;
        let sequence = head.sequence + 1;
        let previous_hash = head.record_hash;
        let record_hash = link_hash(sequence, timestamp_ms, previous_hash, &event)?;
        self.records.push(AuditRecord { sequence, timestamp_ms, previous_hash, event, record_hash });
        Ok(self.records.last().expect("just pushed"))
    }

    /// The current head hash — bind this to chain 40204 when anchoring (`PLANSET/02` §7).
    pub fn head_hash(&self) -> [u8; 32] {
        self.records.last().map(|r| r.record_hash).unwrap_or(ZERO)
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    /// Walk the whole chain offline and prove it has not been tampered with:
    /// genesis prev-hash is zero, sequence increases by exactly 1, each
    /// `previous_hash` equals the prior `record_hash`, and every `record_hash`
    /// recomputes from its contents.
    pub fn verify_integrity(&self) -> Result<(), AuditError> {
        let mut prev_hash = ZERO;
        for (i, r) in self.records.iter().enumerate() {
            let expected_seq = i as u64;
            if r.sequence != expected_seq {
                return Err(AuditError::SequenceBreak { at: i, expected: expected_seq, found: r.sequence });
            }
            if i == 0 && r.previous_hash != ZERO {
                return Err(AuditError::GenesisNotZero);
            }
            if r.previous_hash != prev_hash {
                return Err(AuditError::PrevHashMismatch { at: i });
            }
            let recomputed = link_hash(r.sequence, r.timestamp_ms, r.previous_hash, &r.event)?;
            if recomputed != r.record_hash {
                return Err(AuditError::RecordHashMismatch { at: i });
            }
            prev_hash = r.record_hash;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuditError {
    #[error("chain is empty")]
    Empty,
    #[error("canonical encode failed: {0}")]
    Encode(String),
    #[error("sequence break at index {at}: expected {expected}, found {found}")]
    SequenceBreak { at: usize, expected: u64, found: u64 },
    #[error("genesis previous_hash is not zero")]
    GenesisNotZero,
    #[error("previous_hash mismatch at index {at}")]
    PrevHashMismatch { at: usize },
    #[error("record_hash does not recompute at index {at}")]
    RecordHashMismatch { at: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use comms_proto::{EpochId, EnvelopeKind, GroupId, WalletAddress};

    fn sample_chain() -> AuditChain {
        let mut c = AuditChain::new(1_000).unwrap();
        c.append(
            AuditEvent::GroupCreated { group_id: GroupId([1; 32]), creator: WalletAddress([9; 20]) },
            1_001,
        ).unwrap();
        c.append(
            AuditEvent::MemberAdded { group_id: GroupId([1; 32]), member: WalletAddress([8; 20]), epoch: EpochId(1) },
            1_002,
        ).unwrap();
        c.append(
            AuditEvent::EnvelopeReceipt {
                group_id: GroupId([1; 32]),
                group_seq: 0,
                epoch: EpochId(1),
                sender: WalletAddress([9; 20]),
                kind: EnvelopeKind::Application,
                ciphertext_hash: [0xab; 32],
                size: 128,
            },
            1_003,
        ).unwrap();
        c
    }

    #[test]
    fn fresh_chain_verifies() {
        let c = sample_chain();
        assert_eq!(c.len(), 4);
        c.verify_integrity().unwrap();
    }

    #[test]
    fn genesis_prev_hash_is_zero() {
        let c = AuditChain::new(0).unwrap();
        assert_eq!(c.records()[0].previous_hash, [0u8; 32]);
        c.verify_integrity().unwrap();
    }

    #[test]
    fn tamper_with_event_is_detected() {
        let mut c = sample_chain();
        // Flip a logged event field WITHOUT recomputing the hash → integrity fails.
        if let AuditEvent::MemberAdded { member, .. } = &mut c.records[2].event {
            *member = WalletAddress([0xff; 20]);
        }
        assert!(matches!(c.verify_integrity(), Err(AuditError::RecordHashMismatch { at: 2 })));
    }

    #[test]
    fn tamper_with_link_is_detected() {
        let mut c = sample_chain();
        c.records[2].previous_hash = [0x00; 32];
        let err = c.verify_integrity().unwrap_err();
        assert!(matches!(err, AuditError::PrevHashMismatch { at: 2 } | AuditError::RecordHashMismatch { at: 2 }));
    }

    #[test]
    fn head_hash_changes_on_append() {
        let mut c = AuditChain::new(0).unwrap();
        let h0 = c.head_hash();
        c.append(AuditEvent::RoleRevoked { subject: WalletAddress([1; 20]), scope: None }, 1).unwrap();
        assert_ne!(h0, c.head_hash());
    }
}
