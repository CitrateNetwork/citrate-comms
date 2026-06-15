//! Domain-model tests: event-sourced fold (commutative + idempotent), per-field LWW,
//! CRM pipeline, PM board ordering, deletion tombstones, entity↔conversation linking,
//! state-sync snapshot round-trip, and the chat/event codecs.

use super::event::fields as f;
use super::*;
use comms_proto::{GroupId, WalletAddress};

fn space(n: u8) -> GroupId {
    GroupId([n; 32])
}
fn eid(n: u8) -> EntityId {
    EntityId([n; 16])
}
fn wallet(n: u8) -> WalletAddress {
    WalletAddress([n; 20])
}
fn clk(counter: u64, actor: u8) -> Lamport {
    Lamport { counter, actor: wallet(actor) }
}
fn text(s: &str) -> FieldValue {
    FieldValue::Text(s.into())
}
fn tag(s: &str) -> FieldValue {
    FieldValue::Tag(s.into())
}

#[test]
fn fold_is_commutative_and_idempotent() {
    let s = space(1);
    let id = eid(1);
    let e_name = DomainEvent::upsert(s, EntityType::Deal, id, vec![(f::NAME.into(), text("Acme"))], clk(1, 1));
    let e_stage = DomainEvent::upsert(s, EntityType::Deal, id, vec![(f::STAGE.into(), tag("Proposal"))], clk(2, 1));

    let mut a = DomainStore::new();
    a.apply_all(&[e_name.clone(), e_stage.clone()]);
    // Reversed order + a duplicate must yield identical state.
    let mut b = DomainStore::new();
    b.apply_all(&[e_stage.clone(), e_name.clone(), e_name.clone()]);

    assert_eq!(a.deal(id), b.deal(id));
    let d = a.deal(id).unwrap();
    assert_eq!(d.name, "Acme");
    assert_eq!(d.stage, DealStage::Proposal);
}

#[test]
fn per_field_lww_picks_the_higher_clock_either_order() {
    let s = space(1);
    let id = eid(2);
    let older = DomainEvent::upsert(s, EntityType::Contact, id, vec![(f::NAME.into(), text("old"))], clk(1, 1));
    let newer = DomainEvent::upsert(s, EntityType::Contact, id, vec![(f::NAME.into(), text("new"))], clk(3, 2));

    let mut a = DomainStore::new();
    a.apply(&newer);
    a.apply(&older); // older arrives last but must NOT overwrite
    assert_eq!(a.contact(id).unwrap().name, "new");

    let mut b = DomainStore::new();
    b.apply(&older);
    b.apply(&newer);
    assert_eq!(b.contact(id).unwrap().name, "new");
}

#[test]
fn deal_pipeline_groups_by_stage() {
    let s = space(7);
    let mut store = DomainStore::new();
    for (n, stage) in [(10u8, "Lead"), (11, "Proposal"), (12, "Proposal")] {
        store.apply(&DomainEvent::upsert(
            s,
            EntityType::Deal,
            eid(n),
            vec![(f::NAME.into(), text("d")), (f::STAGE.into(), tag(stage)), (f::VALUE.into(), FieldValue::Money(50_000))],
            clk(1, 1),
        ));
    }
    let pipeline = store.pipeline(s);
    let counts: Vec<(DealStage, usize)> = pipeline.iter().map(|(st, ds)| (*st, ds.len())).collect();
    assert_eq!(counts[0], (DealStage::Lead, 1));
    assert_eq!(counts[1], (DealStage::Qualified, 0));
    assert_eq!(counts[2], (DealStage::Proposal, 2));
    assert_eq!(store.deals_in(s).len(), 3);
}

#[test]
fn board_columns_and_tasks_are_ordered() {
    let s = space(3);
    let board = eid(1);
    let col_a = eid(2);
    let col_b = eid(3);
    let mut store = DomainStore::new();
    store.apply(&DomainEvent::upsert(s, EntityType::Board, board, vec![(f::NAME.into(), text("Sprint"))], clk(1, 1)));
    // Columns with gap-spaced order values (insert-between friendly).
    store.apply(&DomainEvent::upsert(s, EntityType::BoardColumn, col_b, vec![(f::BOARD.into(), FieldValue::Ref(board)), (f::NAME.into(), text("Doing")), (f::ORDER.into(), FieldValue::Int(2000))], clk(1, 1)));
    store.apply(&DomainEvent::upsert(s, EntityType::BoardColumn, col_a, vec![(f::BOARD.into(), FieldValue::Ref(board)), (f::NAME.into(), text("Todo")), (f::ORDER.into(), FieldValue::Int(1000))], clk(1, 1)));
    // Tasks in col_a, out of order.
    store.apply(&DomainEvent::upsert(s, EntityType::Task, eid(20), vec![(f::TITLE.into(), text("second")), (f::BOARD.into(), FieldValue::Ref(board)), (f::COLUMN.into(), FieldValue::Ref(col_a)), (f::ORDER.into(), FieldValue::Int(200))], clk(1, 1)));
    store.apply(&DomainEvent::upsert(s, EntityType::Task, eid(21), vec![(f::TITLE.into(), text("first")), (f::BOARD.into(), FieldValue::Ref(board)), (f::COLUMN.into(), FieldValue::Ref(col_a)), (f::ORDER.into(), FieldValue::Int(100))], clk(1, 1)));

    let b = store.board(board).unwrap();
    assert_eq!(b.columns.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), vec!["Todo", "Doing"]);
    let tasks = store.tasks_in_column(board, col_a);
    assert_eq!(tasks.iter().map(|t| t.title.as_str()).collect::<Vec<_>>(), vec!["first", "second"]);

    // Move "second" before "first" by lowering its order (LWW with a newer clock).
    store.apply(&DomainEvent::upsert(s, EntityType::Task, eid(20), vec![(f::ORDER.into(), FieldValue::Int(50))], clk(2, 1)));
    let tasks = store.tasks_in_column(board, col_a);
    assert_eq!(tasks.iter().map(|t| t.title.as_str()).collect::<Vec<_>>(), vec!["second", "first"]);
}

#[test]
fn delete_tombstone_hides_entity_and_is_idempotent() {
    let s = space(4);
    let id = eid(9);
    let mut store = DomainStore::new();
    store.apply(&DomainEvent::upsert(s, EntityType::Deal, id, vec![(f::NAME.into(), text("Doomed"))], clk(1, 1)));
    assert!(store.deal(id).is_some());
    store.apply(&DomainEvent::delete(s, EntityType::Deal, id, clk(2, 1)));
    assert!(store.deal(id).is_none());
    assert!(store.deals_in(s).is_empty());
    // Re-applying the delete is a no-op (idempotent).
    store.apply(&DomainEvent::delete(s, EntityType::Deal, id, clk(2, 1)));
    assert!(store.deal(id).is_none());
}

#[test]
fn entity_links_to_a_conversation_thread() {
    let s = space(5);
    let thread = eid(1);
    let deal = eid(2);
    let mut store = DomainStore::new();
    // A forum conversation + a thread + a deal linked to that thread, all in one space.
    store.apply(&DomainEvent::upsert(s, EntityType::Conversation, eid(99), vec![(f::KIND.into(), tag("forum")), (f::NAME.into(), text("#acme"))], clk(1, 1)));
    store.apply(&DomainEvent::upsert(s, EntityType::Thread, thread, vec![(f::TITLE.into(), text("Acme negotiation")), (f::AUTHOR.into(), FieldValue::Wallet(wallet(1)))], clk(1, 1)));
    store.apply(&DomainEvent::upsert(s, EntityType::Deal, deal, vec![(f::NAME.into(), text("Acme")), (f::STAGE.into(), tag("Proposal")), (f::LINKED_THREAD.into(), FieldValue::Ref(thread))], clk(1, 1)));

    let d = store.deal(deal).unwrap();
    assert_eq!(d.linked_thread, Some(thread));
    let threads = store.threads_in(s);
    assert_eq!(threads.len(), 1);
    assert_eq!(threads[0].id, d.linked_thread.unwrap());
    assert_eq!(store.conversation(eid(99)).unwrap().kind, ConversationKind::Forum);
}

#[test]
fn state_sync_snapshot_roundtrips() {
    let s = space(6);
    let mut store = DomainStore::new();
    store.apply(&DomainEvent::upsert(s, EntityType::Contact, eid(1), vec![(f::NAME.into(), text("Priya")), (f::EMAIL.into(), text("p@acme.co"))], clk(1, 1)));
    store.apply(&DomainEvent::upsert(s, EntityType::Project, eid(2), vec![(f::NAME.into(), text("Launch")), (f::STATUS.into(), tag("active"))], clk(1, 1)));

    // Snapshot → bytes → snapshot → store (the new-member catch-up path).
    let snap = store.snapshot();
    let bytes = snap.encode().unwrap();
    let restored = DomainStore::from_snapshot(DomainSnapshot::decode(&bytes).unwrap());

    assert_eq!(restored.contact(eid(1)), store.contact(eid(1)));
    assert_eq!(restored.projects_in(s), store.projects_in(s));

    // Events fold normally on top of a restored snapshot.
    let mut restored = restored;
    restored.apply(&DomainEvent::upsert(s, EntityType::Contact, eid(1), vec![(f::TITLE.into(), text("VP Eng"))], clk(2, 1)));
    assert_eq!(restored.contact(eid(1)).unwrap().title, "VP Eng");
}

#[test]
fn chat_message_and_event_codecs_roundtrip() {
    let msg = ChatMessage {
        thread_id: Some(eid(5)),
        parent_id: None,
        body: "loop in @crm-agent".into(),
        sent: clk(4, 2),
    };
    let bytes = msg.encode().unwrap();
    assert_eq!(ChatMessage::decode(&bytes).unwrap(), msg);

    let ev = DomainEvent::upsert(space(1), EntityType::Task, eid(1), vec![(f::STATUS.into(), tag("Done"))], clk(1, 1));
    assert_eq!(DomainEvent::decode(&ev.encode().unwrap()).unwrap(), ev);
}

#[test]
fn lamport_clock_advances_and_observes() {
    let mut c = LamportClock::new(wallet(1));
    assert_eq!(c.tick().counter, 1);
    assert_eq!(c.tick().counter, 2);
    c.observe(Lamport { counter: 10, actor: wallet(2) });
    assert_eq!(c.tick().counter, 11);
}
