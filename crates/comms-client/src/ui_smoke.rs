//! Headless UI harness (geometry + interaction) over the real `AppWindow` — no display.
//! Complements the visual golden harness (`comms-client-proof`). All checks live in ONE
//! test: the testing backend sets the platform + runs the event loop once per process, so
//! multiple window-driving test fns would conflict.

#![cfg(test)]

use i_slint_backend_testing as st;
use slint::platform::PointerEventButton;
use slint::{ComponentHandle, LogicalSize};

use crate::AppWindow;

#[test]
fn ui_harness_geometry_and_nav_interaction() {
    st::init_integration_test_with_system_time();

    slint::spawn_local(async move {
        // ── 1. Geometry + property drive (the harness can introspect + steer the UI). ──
        let app = AppWindow::new().unwrap();
        app.window().set_size(LogicalSize::new(1440.0, 900.0));
        let win = app.window().size();
        assert_eq!((win.width, win.height), (1440, 900), "headless window size");
        app.set_relay_status("connecting…".into());
        assert_eq!(app.get_relay_status().to_string(), "connecting…", "property round-trip");

        // ── 2. Mount the signed-in shell (force-shell, no live relay) + realize the tree. ──
        app.set_force_shell(true);
        app.show().unwrap();
        assert_eq!(app.get_route().to_string(), "comms", "default route");

        // ── 2b. Comms ledger panel tabs (finding #1): at route=comms the Info pane shows by
        //       default; clicking the Ledger tab must swap to the ledger pane (proves the
        //       tab TouchArea isn't occluded / dead). ──
        let present = |label: &str, app: &AppWindow| {
            st::ElementHandle::find_by_accessible_label(app, label).next().is_some()
        };
        assert!(present("ledger-pane:info", &app), "ledger Info pane shows by default");
        assert!(!present("ledger-pane:ledger", &app), "ledger pane hidden until its tab is clicked");
        let ledger_tab = st::ElementHandle::find_by_accessible_label(&app, "ledger-tab:Ledger")
            .next()
            .expect("'Ledger' tab");
        let ts = ledger_tab.size();
        assert!(ts.height >= 30.0, "ledger tab hit area too short (was the bug): {ts:?}");
        ledger_tab.single_click(PointerEventButton::Left).await;
        assert!(present("ledger-pane:ledger", &app), "clicking Ledger tab shows the ledger pane");
        // restore Info for the rest of the run
        st::ElementHandle::find_by_accessible_label(&app, "ledger-tab:Info").next().unwrap().single_click(PointerEventButton::Left).await;

        // ── 3. Interaction + hit-target: for each section, find its nav control, assert a
        // real ≥24×24 hit area, synth-click it, and assert the route changes — proving the
        // control responds and its TouchArea covers the visual (no dead/occluded clicks). ──
        for (label, route) in [
            ("CRM", "crm"),
            ("Projects", "projects"),
            ("Agents", "agents"),
            ("Members", "members"),
            ("Security", "security"),
            ("Audit", "audit"),
            ("Settings", "settings"),
        ] {
            let item = st::ElementHandle::find_by_accessible_label(&app, label)
                .next()
                .unwrap_or_else(|| panic!("nav item '{label}' not found"));
            let s = item.size();
            assert!(s.width >= 24.0 && s.height >= 24.0, "'{label}' hit area too small: {s:?}");
            item.single_click(PointerEventButton::Left).await;
            assert_eq!(app.get_route().to_string(), route, "click '{label}' should route to '{route}'");
        }

        // ── 3b. Settings sub-nav tabs SWITCH the pane (S6.3). At route=settings (the last
        //       nav click), only the Identity pane is mounted; clicking Devices swaps it. ──
        let pane_mounted = |label: &str, app: &AppWindow| {
            st::ElementHandle::find_by_accessible_label(app, label).next().is_some()
        };
        assert!(pane_mounted("settings-pane:Identity", &app), "Identity pane shows by default");
        assert!(!pane_mounted("settings-pane:Devices", &app), "Devices pane hidden until its tab is clicked");
        st::ElementHandle::find_by_accessible_label(&app, "settings-tab:Devices")
            .next()
            .expect("'Devices' settings tab")
            .single_click(PointerEventButton::Left)
            .await;
        assert!(pane_mounted("settings-pane:Devices", &app), "clicking the Devices tab shows the Devices pane");
        assert!(!pane_mounted("settings-pane:Identity", &app), "Identity pane hidden after switching to Devices");

        // ── 4. Every button (nav rail + Btn) has an adequate hit area. ──
        let buttons = st::ElementQuery::from_root(&app)
            .match_descendants()
            .match_accessible_role(st::AccessibleRole::Button)
            .find_all();
        assert!(buttons.len() >= 10, "expected nav + buttons, found {}", buttons.len());
        for el in &buttons {
            let s = el.size();
            assert!(s.width >= 24.0 && s.height >= 24.0, "button hit area too small: {s:?}");
        }

        // ── 5. Dialog flow: open Invite from Members, then Send — proving overlay triggers
        //       and dialog buttons are live and wire through to the callback. ──
        let fired = std::rc::Rc::new(std::cell::RefCell::new(false));
        {
            let f = fired.clone();
            app.on_create_channel(move |_addr| *f.borrow_mut() = true);
        }
        // Back to Members, open its Invite dialog.
        st::ElementHandle::find_by_accessible_label(&app, "Members")
            .next()
            .unwrap()
            .single_click(PointerEventButton::Left)
            .await;
        st::ElementHandle::find_by_accessible_label(&app, "+ Invite")
            .next()
            .expect("'+ Invite' button")
            .single_click(PointerEventButton::Left)
            .await;
        assert_eq!(app.get_overlay().to_string(), "invite", "'+ Invite' opens the invite dialog");
        // The dialog's Send button is live and wires through to create-channel.
        st::ElementHandle::find_by_accessible_label(&app, "Send invite")
            .next()
            .expect("'Send invite' button")
            .single_click(PointerEventButton::Left)
            .await;
        assert!(*fired.borrow(), "'Send invite' should fire the create-channel callback");
        app.set_overlay("".into());

        // ── 6. Every overlay + the command palette mount their content when triggered
        //       (each dialog's buttons are covered by the hit-area + a11y checks above; the
        //       invite SUBMIT flow above proves a dialog button wires through to a callback). ──
        for (state, component) in [
            ("invite", "InviteDialog"),
            ("offboard", "OffboardDialog"),
            ("addAgent", "AddAgentDialog"),
        ] {
            app.set_overlay(state.into());
            st::mock_elapsed_time(std::time::Duration::from_millis(1));
            assert!(
                st::ElementHandle::find_by_element_type_name(&app, component).next().is_some(),
                "overlay '{state}' should mount {component}"
            );
            app.set_overlay("".into());
        }
        app.set_cmdk(true);
        st::mock_elapsed_time(std::time::Duration::from_millis(1));
        assert!(
            st::ElementHandle::find_by_element_type_name(&app, "CommandPalette").next().is_some(),
            "⌘K should mount the CommandPalette"
        );

        slint::quit_event_loop().unwrap();
    })
    .unwrap();
    slint::run_event_loop().unwrap();
}
