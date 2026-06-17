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

        slint::quit_event_loop().unwrap();
    })
    .unwrap();
    slint::run_event_loop().unwrap();
}
