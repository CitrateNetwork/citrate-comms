//! `domain` — the unified, event-sourced CRM + PM + conversation model (`PLANSET/02` §5).
//!
//! Every structured record (a contact, a deal, a task, a forum thread, a channel's
//! metadata) lives inside an **MLS-protected space** and is replicated as an
//! [`event::DomainEvent`] riding inside an MLS application message. There is no
//! server-side database of these objects — clients fold the relay's totally-ordered
//! event stream into materialized state in [`store::DomainStore`]. Conflicts resolve
//! by **per-field last-writer-wins** keyed on a [`Lamport`] clock (actor tiebreak),
//! which is commutative + idempotent → all members converge.
//!
//! This module is pure logic: no sockets, no MLS, no storage. It operates on the
//! plaintext that the `mls` layer encrypts and the relay never sees.

pub mod event;
pub mod store;

#[cfg(test)]
mod tests;

use comms_proto::{GroupId, WalletAddress};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;

pub use event::{fields, DomainEvent, EntityType, FieldValue, Op};
pub use store::{
    Account, Board, BoardColumn, Contact, Conversation, Deal, DealStage, DomainSnapshot, DomainStore,
    Project, Task, TaskStatus, Thread,
};

/// A space is an MLS group; CRM/PM records + conversations live inside one.
pub type SpaceId = GroupId;

/// 16-byte entity identifier (client-generated, UUID-like).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EntityId(pub [u8; 16]);

impl EntityId {
    /// A fresh random id (OS RNG).
    pub fn random() -> Self {
        let mut b = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut b);
        Self(b)
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for EntityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EntityId({})", &self.to_hex()[..8])
    }
}

/// A Lamport timestamp with an actor tiebreak. Deriving `Ord` orders by
/// `(counter, actor)` — exactly the total order LWW needs.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub struct Lamport {
    pub counter: u64,
    pub actor: WalletAddress,
}

/// A per-actor logical clock. Each client owns one and stamps its events.
#[derive(Clone, Debug)]
pub struct LamportClock {
    counter: u64,
    actor: WalletAddress,
}

impl LamportClock {
    pub fn new(actor: WalletAddress) -> Self {
        Self { counter: 0, actor }
    }
    /// Advance and return the next timestamp (for an event this actor emits).
    pub fn tick(&mut self) -> Lamport {
        self.counter += 1;
        Lamport { counter: self.counter, actor: self.actor }
    }
    /// Observe a remote timestamp, keeping the clock ahead (causal consistency).
    pub fn observe(&mut self, other: Lamport) {
        if other.counter > self.counter {
            self.counter = other.counter;
        }
    }
}

/// The kind of a conversation space.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ConversationKind {
    Channel,
    Forum,
    Dm,
}

impl ConversationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConversationKind::Channel => "channel",
            ConversationKind::Forum => "forum",
            ConversationKind::Dm => "dm",
        }
    }
    pub fn from_tag(s: &str) -> Self {
        match s {
            "forum" => ConversationKind::Forum,
            "dm" => ConversationKind::Dm,
            _ => ConversationKind::Channel,
        }
    }
}

/// The plaintext payload of a chat message — what the `mls` layer encrypts as an
/// Application envelope. The relay only ever sees its ciphertext. Threading metadata
/// (`thread_id`/`parent_id`) lives here, *inside* the ciphertext.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ChatMessage {
    /// `None` for a top-level channel/DM message; `Some` to post into a forum thread.
    pub thread_id: Option<EntityId>,
    /// `Some` to reply to a specific message (threaded replies).
    pub parent_id: Option<EntityId>,
    pub body: String,
    pub sent: Lamport,
}

impl ChatMessage {
    /// Serialize to the bytes that get MLS-encrypted (canonical CBOR).
    pub fn encode(&self) -> Result<Vec<u8>, comms_proto::ProtoError> {
        comms_proto::canonical::to_vec(self)
    }
    /// Decode a received chat message from decrypted MLS plaintext.
    pub fn decode(bytes: &[u8]) -> Result<Self, comms_proto::ProtoError> {
        comms_proto::canonical::from_slice(bytes)
    }
}
