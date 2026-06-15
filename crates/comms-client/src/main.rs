//! citrate-comms desktop client (COMMS-S2).
//!
//! The native Slint UI, translated from the Claude Design handoff (`design/handoff/`).
//! Shell + the full screen set (channel, CRM, projects, agents, members, sealed audit,
//! security, settings), the Info/Ledger right panel (the Witness differentiator), and
//! the add-agent / offboard / invite overlays. Data is the design's static scenario;
//! wiring the screens to `comms-core` (MLS/domain) over `comms-relay::ws` is COMMS-S2 WP-2.9.
//!
//! Brand fonts (Geist / Geist Mono / Space Grotesk / Cormorant) are staged in `ui/fonts/`;
//! the theme references them by family name. Embedding them at runtime uses Slint 1.16's
//! `fontique` collection API (an unstable feature) — wired in a follow-up; until then the
//! families fall back to close system equivalents.

slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    let app = AppWindow::new()?;
    app.run()
}
