//! Domain events — the mutations replicated over MLS and folded by every client.

use super::{EntityId, Lamport, SpaceId};
use comms_proto::WalletAddress;
use serde::{Deserialize, Serialize};

/// The kind of record an event targets.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum EntityType {
    Conversation,
    Thread,
    Contact,
    Account,
    Deal,
    Project,
    Task,
    Board,
    BoardColumn,
}

/// A typed field value. The common currency of the event-sourced store.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum FieldValue {
    Null,
    Text(String),
    Int(i64),
    Bool(bool),
    /// Minor units (e.g. cents) to avoid float drift in deal values.
    Money(i64),
    /// Unix milliseconds.
    Timestamp(u64),
    /// A reference to another entity (contact→account, task→thread, …).
    Ref(EntityId),
    /// A member reference (owner, assignee, author).
    Wallet(WalletAddress),
    /// A short categorical label (stage, status, kind, tag).
    Tag(String),
}

/// What an event does to its entity.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum Op {
    /// Set the named fields (each resolved by per-field LWW on the event clock).
    Upsert { fields: Vec<(String, FieldValue)> },
    /// Tombstone the entity (LWW on the clock).
    Delete,
}

/// One replicated mutation. Rides inside an MLS application message; the relay sees
/// only its ciphertext.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct DomainEvent {
    pub space_id: SpaceId,
    pub entity_type: EntityType,
    pub entity_id: EntityId,
    pub op: Op,
    pub clock: Lamport,
}

impl DomainEvent {
    /// Build an upsert event.
    pub fn upsert(
        space_id: SpaceId,
        entity_type: EntityType,
        entity_id: EntityId,
        fields: Vec<(String, FieldValue)>,
        clock: Lamport,
    ) -> Self {
        Self { space_id, entity_type, entity_id, op: Op::Upsert { fields }, clock }
    }

    /// Build a delete (tombstone) event.
    pub fn delete(space_id: SpaceId, entity_type: EntityType, entity_id: EntityId, clock: Lamport) -> Self {
        Self { space_id, entity_type, entity_id, op: Op::Delete, clock }
    }

    /// Serialize to the bytes that get MLS-encrypted (canonical CBOR).
    pub fn encode(&self) -> Result<Vec<u8>, comms_proto::ProtoError> {
        comms_proto::canonical::to_vec(self)
    }
    /// Decode a received event from decrypted MLS plaintext.
    pub fn decode(bytes: &[u8]) -> Result<Self, comms_proto::ProtoError> {
        comms_proto::canonical::from_slice(bytes)
    }
}

/// Canonical field names (one source of truth — avoids typos across emit/fold/project).
pub mod fields {
    // conversation / thread
    pub const KIND: &str = "kind";
    pub const NAME: &str = "name";
    pub const TOPIC: &str = "topic";
    pub const TITLE: &str = "title";
    pub const AUTHOR: &str = "author";
    // crm
    pub const EMAIL: &str = "email";
    pub const ACCOUNT: &str = "account";
    pub const OWNER: &str = "owner";
    pub const ACCOUNT_DOMAIN: &str = "account_domain";
    pub const VALUE: &str = "value";
    pub const STAGE: &str = "stage";
    pub const PRIORITY: &str = "priority";
    pub const CLOSE_DATE: &str = "close_date";
    // pm
    pub const STATUS: &str = "status";
    pub const ASSIGNEE: &str = "assignee";
    pub const DUE: &str = "due";
    pub const DESCRIPTION: &str = "description";
    pub const PROJECT: &str = "project";
    pub const BOARD: &str = "board";
    pub const COLUMN: &str = "column";
    pub const ORDER: &str = "order";
    // linkage (entity ↔ conversation)
    pub const LINKED_THREAD: &str = "linked_thread";
}
