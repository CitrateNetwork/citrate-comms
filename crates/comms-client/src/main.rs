//! citrate-comms desktop client (COMMS-S2).
//!
//! The native Slint UI translated from the Claude Design handoff (`design/handoff/`),
//! wired to the LIVE backend (`src/backend.rs`): an in-process server-blind relay + a
//! real 4-member MLS group + the event-sourced domain store. The channel stream,
//! members, CRM/PM records, and audit trail are produced by the real crypto stack;
//! the composer's Send performs a real MLS encrypt → relay submit.

mod backend;

use std::cell::RefCell;
use std::rc::Rc;

use backend::Workspace;
use slint::{Color, ModelRc, SharedString, VecModel};

slint::include_modules!();

fn rgb(c: (u8, u8, u8)) -> Color {
    Color::from_rgb_u8(c.0, c.1, c.2)
}
fn s(text: &str) -> SharedString {
    text.into()
}

fn messages_model(ws: &Workspace) -> ModelRc<Msg> {
    let v: Vec<Msg> = ws
        .messages()
        .iter()
        .map(|m| Msg {
            author: s(&m.author),
            initials: s(&m.initials),
            tint: rgb(m.rgb),
            role: s(&m.role),
            ts: s(&m.ts),
            text: s(&m.text),
            is_agent: m.is_agent,
            system: m.system,
            boundary: m.boundary,
            has_link: m.has_link,
            link_kind: s(&m.link_kind),
            link_name: s(&m.link_name),
            link_id: s(&m.link_id),
            state: SharedString::new(),
        })
        .collect();
    ModelRc::new(VecModel::from(v))
}

fn roster_model(ws: &Workspace) -> ModelRc<Person> {
    let v: Vec<Person> = ws
        .members()
        .iter()
        .map(|m| Person {
            name: s(&m.name),
            initials: s(&m.initials),
            tint: rgb(m.rgb),
            role: s(&m.role),
            addr: s(&m.addr),
            is_agent: m.is_agent,
            external: false,
        })
        .collect();
    ModelRc::new(VecModel::from(v))
}

fn member_rows_model(ws: &Workspace) -> ModelRc<MemberRow> {
    let v: Vec<MemberRow> = ws
        .members()
        .iter()
        .map(|m| MemberRow {
            name: s(&m.name),
            initials: s(&m.initials),
            tint: rgb(m.rgb),
            role: s(&m.role),
            addr: s(&m.addr),
            status: s("active"),
            external: false,
            devices: 1,
        })
        .collect();
    ModelRc::new(VecModel::from(v))
}

fn deals_model(ws: &Workspace) -> ModelRc<Deal> {
    let v: Vec<Deal> = ws
        .deals()
        .iter()
        .map(|d| Deal {
            id: SharedString::new(),
            name: s(&d.name),
            account: s(&d.account),
            value: s(&d.value),
            stage: s(&d.stage),
            priority: s(&d.priority),
            owner: s(&d.owner),
            close: SharedString::new(),
            has_channel: d.name.contains("Northwind"),
        })
        .collect();
    ModelRc::new(VecModel::from(v))
}

fn tasks_model(ws: &Workspace) -> ModelRc<Task> {
    let v: Vec<Task> = ws
        .tasks()
        .iter()
        .map(|t| Task {
            id: SharedString::new(),
            title: s(&t.title),
            assignee: s(&t.assignee),
            status: s(&t.status),
            priority: s(&t.priority),
            due: s(&t.due),
        })
        .collect();
    ModelRc::new(VecModel::from(v))
}

fn audit_model(ws: &Workspace) -> ModelRc<AuditRow> {
    let v: Vec<AuditRow> = ws
        .audit()
        .iter()
        .map(|a| AuditRow {
            seq: s(&a.seq),
            ts: SharedString::new(),
            event: s(&a.event),
            summary: s(&a.summary),
            actor: s(&a.actor),
            hash: s(&a.hash),
        })
        .collect();
    ModelRc::new(VecModel::from(v))
}

fn populate(app: &AppWindow, ws: &Workspace) {
    app.set_ws_messages(messages_model(ws));
    app.set_ws_members(roster_model(ws));
    app.set_ws_member_rows(member_rows_model(ws));
    app.set_ws_deals(deals_model(ws));
    app.set_ws_tasks(tasks_model(ws));
    app.set_ws_audit(audit_model(ws));
}

/// Register the embedded brand fonts (Geist / Geist Mono / Space Grotesk / Cormorant)
/// into Slint's shared font collection so type renders on-brand. Must run after the
/// platform is initialized (i.e. after `AppWindow::new`).
fn register_brand_fonts() {
    use slint::fontique_08::fontique;
    for bytes in [
        include_bytes!("../ui/fonts/Geist.ttf").as_slice(),
        include_bytes!("../ui/fonts/GeistMono.ttf").as_slice(),
        include_bytes!("../ui/fonts/SpaceGrotesk.ttf").as_slice(),
        include_bytes!("../ui/fonts/Cormorant.ttf").as_slice(),
    ] {
        let blob = fontique::Blob::new(std::sync::Arc::new(bytes.to_vec()));
        let _ = slint::fontique_08::shared_collection().register_fonts(blob, None);
    }
}

fn main() -> Result<(), slint::PlatformError> {
    let app = AppWindow::new()?;
    register_brand_fonts();

    match Workspace::bootstrap() {
        Ok(workspace) => {
            let ws = Rc::new(RefCell::new(workspace));
            populate(&app, &ws.borrow());

            // Live send: real MLS encrypt → relay submit → re-render the stream + audit.
            let app_weak = app.as_weak();
            let ws_send = ws.clone();
            app.on_send_message(move |text| {
                ws_send.borrow_mut().send(&text);
                if let Some(app) = app_weak.upgrade() {
                    let ws = ws_send.borrow();
                    app.set_ws_messages(messages_model(&ws));
                    app.set_ws_audit(audit_model(&ws));
                }
            });
        }
        Err(e) => {
            // Fall back to the screens' built-in static data if the backend can't start.
            eprintln!("citrate-comms: backend bootstrap failed ({e}); showing static fixtures");
        }
    }

    app.run()
}
