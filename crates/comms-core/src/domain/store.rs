//! `DomainStore` — folds the ordered event stream into materialized, typed records.

use std::collections::HashMap;

use comms_proto::WalletAddress;
use serde::{Deserialize, Serialize};

use super::event::{fields as f, DomainEvent, EntityType, FieldValue, Op};
use super::{ConversationKind, EntityId, Lamport, SpaceId};

/// One entity's materialized state: a per-field (value, clock) map + a delete tombstone.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct EntityRecord {
    space_id: SpaceId,
    fields: HashMap<String, (FieldValue, Lamport)>,
    deleted: Option<Lamport>,
}

impl EntityRecord {
    fn get(&self, k: &str) -> Option<&FieldValue> {
        self.fields.get(k).map(|(v, _)| v)
    }
    fn text(&self, k: &str) -> String {
        match self.get(k) {
            Some(FieldValue::Text(s)) | Some(FieldValue::Tag(s)) => s.clone(),
            _ => String::new(),
        }
    }
    fn money_or_int(&self, k: &str) -> i64 {
        match self.get(k) {
            Some(FieldValue::Money(i)) | Some(FieldValue::Int(i)) => *i,
            _ => 0,
        }
    }
    fn timestamp(&self, k: &str) -> Option<u64> {
        match self.get(k) {
            Some(FieldValue::Timestamp(t)) => Some(*t),
            _ => None,
        }
    }
    fn ref_(&self, k: &str) -> Option<EntityId> {
        match self.get(k) {
            Some(FieldValue::Ref(id)) => Some(*id),
            _ => None,
        }
    }
    fn wallet(&self, k: &str) -> Option<WalletAddress> {
        match self.get(k) {
            Some(FieldValue::Wallet(w)) => Some(*w),
            _ => None,
        }
    }
    fn tag(&self, k: &str) -> Option<String> {
        match self.get(k) {
            Some(FieldValue::Tag(s)) | Some(FieldValue::Text(s)) => Some(s.clone()),
            _ => None,
        }
    }
}

/// The materialized view of a space's records, built by folding domain events.
/// Conflict-free: per-field LWW makes `apply` commutative + idempotent, so every
/// member that has seen the same set of events holds the same state.
#[derive(Clone, Debug, Default)]
pub struct DomainStore {
    records: HashMap<(EntityType, EntityId), EntityRecord>,
}

impl DomainStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one event into the store (per-field / tombstone LWW on the Lamport clock).
    pub fn apply(&mut self, e: &DomainEvent) {
        let rec = self
            .records
            .entry((e.entity_type, e.entity_id))
            .or_insert_with(|| EntityRecord { space_id: e.space_id, ..Default::default() });
        match &e.op {
            Op::Upsert { fields } => {
                for (name, value) in fields {
                    let newer = match rec.fields.get(name) {
                        Some((_, c)) => e.clock > *c,
                        None => true,
                    };
                    if newer {
                        rec.fields.insert(name.clone(), (value.clone(), e.clock));
                    }
                }
            }
            Op::Delete => {
                if rec.deleted.map(|c| e.clock > c).unwrap_or(true) {
                    rec.deleted = Some(e.clock);
                }
            }
        }
    }

    /// Fold a batch (any order — the result converges).
    pub fn apply_all(&mut self, events: &[DomainEvent]) {
        for e in events {
            self.apply(e);
        }
    }

    fn live(&self, t: EntityType, id: EntityId) -> Option<&EntityRecord> {
        self.records.get(&(t, id)).filter(|r| r.deleted.is_none())
    }

    fn ids_in(&self, t: EntityType, space: SpaceId) -> Vec<EntityId> {
        let mut ids: Vec<EntityId> = self
            .records
            .iter()
            .filter(|((et, _), r)| *et == t && r.space_id == space && r.deleted.is_none())
            .map(|((_, id), _)| *id)
            .collect();
        ids.sort();
        ids
    }

    // ─────────────────────────── conversations ───────────────────────────

    pub fn conversation(&self, id: EntityId) -> Option<Conversation> {
        let r = self.live(EntityType::Conversation, id)?;
        Some(Conversation {
            id,
            space_id: r.space_id,
            kind: ConversationKind::from_tag(&r.tag(f::KIND).unwrap_or_default()),
            name: r.text(f::NAME),
            topic: r.text(f::TOPIC),
        })
    }

    pub fn threads_in(&self, space: SpaceId) -> Vec<Thread> {
        self.ids_in(EntityType::Thread, space)
            .into_iter()
            .filter_map(|id| {
                let r = self.live(EntityType::Thread, id)?;
                Some(Thread { id, space_id: r.space_id, title: r.text(f::TITLE), author: r.wallet(f::AUTHOR) })
            })
            .collect()
    }

    // ─────────────────────────── CRM ───────────────────────────

    pub fn contact(&self, id: EntityId) -> Option<Contact> {
        let r = self.live(EntityType::Contact, id)?;
        Some(Contact {
            id,
            space_id: r.space_id,
            name: r.text(f::NAME),
            email: r.text(f::EMAIL),
            title: r.text(f::TITLE),
            account: r.ref_(f::ACCOUNT),
            owner: r.wallet(f::OWNER),
        })
    }

    pub fn contacts_in(&self, space: SpaceId) -> Vec<Contact> {
        self.ids_in(EntityType::Contact, space).into_iter().filter_map(|id| self.contact(id)).collect()
    }

    pub fn account(&self, id: EntityId) -> Option<Account> {
        let r = self.live(EntityType::Account, id)?;
        Some(Account { id, space_id: r.space_id, name: r.text(f::NAME), domain: r.text(f::ACCOUNT_DOMAIN), owner: r.wallet(f::OWNER) })
    }

    pub fn deal(&self, id: EntityId) -> Option<Deal> {
        let r = self.live(EntityType::Deal, id)?;
        Some(Deal {
            id,
            space_id: r.space_id,
            name: r.text(f::NAME),
            account: r.ref_(f::ACCOUNT),
            value: r.money_or_int(f::VALUE),
            stage: DealStage::from_tag(&r.tag(f::STAGE).unwrap_or_default()),
            owner: r.wallet(f::OWNER),
            close_date: r.timestamp(f::CLOSE_DATE),
            linked_thread: r.ref_(f::LINKED_THREAD),
        })
    }

    pub fn deals_in(&self, space: SpaceId) -> Vec<Deal> {
        self.ids_in(EntityType::Deal, space).into_iter().filter_map(|id| self.deal(id)).collect()
    }

    /// The deal pipeline grouped by stage, in canonical stage order.
    pub fn pipeline(&self, space: SpaceId) -> Vec<(DealStage, Vec<Deal>)> {
        let deals = self.deals_in(space);
        DealStage::ALL
            .iter()
            .map(|stage| (*stage, deals.iter().filter(|d| d.stage == *stage).cloned().collect()))
            .collect()
    }

    // ─────────────────────────── PM ───────────────────────────

    pub fn project(&self, id: EntityId) -> Option<Project> {
        let r = self.live(EntityType::Project, id)?;
        Some(Project { id, space_id: r.space_id, name: r.text(f::NAME), status: r.tag(f::STATUS).unwrap_or_else(|| "active".into()) })
    }

    pub fn projects_in(&self, space: SpaceId) -> Vec<Project> {
        self.ids_in(EntityType::Project, space).into_iter().filter_map(|id| self.project(id)).collect()
    }

    pub fn task(&self, id: EntityId) -> Option<Task> {
        let r = self.live(EntityType::Task, id)?;
        Some(Task {
            id,
            space_id: r.space_id,
            title: r.text(f::TITLE),
            description: r.text(f::DESCRIPTION),
            assignee: r.wallet(f::ASSIGNEE),
            status: TaskStatus::from_tag(&r.tag(f::STATUS).unwrap_or_default()),
            due: r.timestamp(f::DUE),
            project: r.ref_(f::PROJECT),
            board: r.ref_(f::BOARD),
            column: r.ref_(f::COLUMN),
            order: r.money_or_int(f::ORDER),
            linked_thread: r.ref_(f::LINKED_THREAD),
        })
    }

    /// Tasks in a board column, ordered by their `order` field then id (deterministic).
    pub fn tasks_in_column(&self, board: EntityId, column: EntityId) -> Vec<Task> {
        let mut tasks: Vec<Task> = self
            .records
            .iter()
            .filter(|((et, _), _)| *et == EntityType::Task)
            .filter_map(|((_, id), _)| self.task(*id))
            .filter(|t| t.board == Some(board) && t.column == Some(column))
            .collect();
        tasks.sort_by(|a, b| a.order.cmp(&b.order).then(a.id.cmp(&b.id)));
        tasks
    }

    pub fn board(&self, id: EntityId) -> Option<Board> {
        let r = self.live(EntityType::Board, id)?;
        // Columns are BoardColumn entities referencing this board, ordered by `order`.
        let mut columns: Vec<BoardColumn> = self
            .records
            .iter()
            .filter(|((et, _), _)| *et == EntityType::BoardColumn)
            .filter_map(|((_, cid), _)| {
                let cr = self.live(EntityType::BoardColumn, *cid)?;
                if cr.ref_(f::BOARD) != Some(id) {
                    return None;
                }
                Some(BoardColumn { id: *cid, name: cr.text(f::NAME), order: cr.money_or_int(f::ORDER) })
            })
            .collect();
        columns.sort_by(|a, b| a.order.cmp(&b.order).then(a.id.cmp(&b.id)));
        Some(Board { id, space_id: r.space_id, name: r.text(f::NAME), columns })
    }

    // ─────────────────────────── state-sync snapshot ───────────────────────────

    /// Compact the store to a snapshot a new member receives (MLS-encrypted) so it
    /// doesn't have to replay history from epoch 0 (`PLANSET/02` §5.3).
    pub fn snapshot(&self) -> DomainSnapshot {
        DomainSnapshot {
            entries: self.records.iter().map(|((t, id), r)| (*t, *id, r.clone())).collect(),
        }
    }

    /// Rebuild a store from a snapshot. Subsequent events fold on top normally.
    pub fn from_snapshot(snap: DomainSnapshot) -> Self {
        let mut records = HashMap::new();
        for (t, id, r) in snap.entries {
            records.insert((t, id), r);
        }
        Self { records }
    }
}

/// The serializable, transferable form of a [`DomainStore`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DomainSnapshot {
    entries: Vec<(EntityType, EntityId, EntityRecord)>,
}

impl DomainSnapshot {
    pub fn encode(&self) -> Result<Vec<u8>, comms_proto::ProtoError> {
        comms_proto::canonical::to_vec(self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, comms_proto::ProtoError> {
        comms_proto::canonical::from_slice(bytes)
    }
}

// ─────────────────────────── typed views ───────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct Conversation {
    pub id: EntityId,
    pub space_id: SpaceId,
    pub kind: ConversationKind,
    pub name: String,
    pub topic: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Thread {
    pub id: EntityId,
    pub space_id: SpaceId,
    pub title: String,
    pub author: Option<WalletAddress>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Contact {
    pub id: EntityId,
    pub space_id: SpaceId,
    pub name: String,
    pub email: String,
    pub title: String,
    pub account: Option<EntityId>,
    pub owner: Option<WalletAddress>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Account {
    pub id: EntityId,
    pub space_id: SpaceId,
    pub name: String,
    pub domain: String,
    pub owner: Option<WalletAddress>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DealStage {
    Lead,
    Qualified,
    Proposal,
    Won,
    Lost,
}

impl DealStage {
    pub const ALL: [DealStage; 5] =
        [DealStage::Lead, DealStage::Qualified, DealStage::Proposal, DealStage::Won, DealStage::Lost];
    pub fn as_str(&self) -> &'static str {
        match self {
            DealStage::Lead => "Lead",
            DealStage::Qualified => "Qualified",
            DealStage::Proposal => "Proposal",
            DealStage::Won => "Won",
            DealStage::Lost => "Lost",
        }
    }
    pub fn from_tag(s: &str) -> Self {
        match s {
            "Qualified" => DealStage::Qualified,
            "Proposal" => DealStage::Proposal,
            "Won" => DealStage::Won,
            "Lost" => DealStage::Lost,
            _ => DealStage::Lead,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Deal {
    pub id: EntityId,
    pub space_id: SpaceId,
    pub name: String,
    pub account: Option<EntityId>,
    /// Minor units (cents).
    pub value: i64,
    pub stage: DealStage,
    pub owner: Option<WalletAddress>,
    pub close_date: Option<u64>,
    /// The conversation thread this deal is linked to (entity ↔ conversation).
    pub linked_thread: Option<EntityId>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Project {
    pub id: EntityId,
    pub space_id: SpaceId,
    pub name: String,
    pub status: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TaskStatus {
    Todo,
    Doing,
    Review,
    Done,
}

impl TaskStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskStatus::Todo => "Todo",
            TaskStatus::Doing => "Doing",
            TaskStatus::Review => "Review",
            TaskStatus::Done => "Done",
        }
    }
    pub fn from_tag(s: &str) -> Self {
        match s {
            "Doing" => TaskStatus::Doing,
            "Review" => TaskStatus::Review,
            "Done" => TaskStatus::Done,
            _ => TaskStatus::Todo,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Task {
    pub id: EntityId,
    pub space_id: SpaceId,
    pub title: String,
    pub description: String,
    pub assignee: Option<WalletAddress>,
    pub status: TaskStatus,
    pub due: Option<u64>,
    pub project: Option<EntityId>,
    pub board: Option<EntityId>,
    pub column: Option<EntityId>,
    pub order: i64,
    pub linked_thread: Option<EntityId>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BoardColumn {
    pub id: EntityId,
    pub name: String,
    pub order: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Board {
    pub id: EntityId,
    pub space_id: SpaceId,
    pub name: String,
    pub columns: Vec<BoardColumn>,
}
