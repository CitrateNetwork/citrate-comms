//! citrate-comms desktop client (COMMS-S2).
//!
//! The native Slint UI, translated from the Claude Design handoff (`design/handoff/`).
//! This first pass renders the app shell + the primary **channel screen** with the brand
//! tokens. The data is the design's static `#deals` scenario; wiring the screens to the
//! `comms-core` MLS/domain layer and the relay (`comms-relay::ws`) is the next S2 step.

slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    let app = AppWindow::new()?;
    app.run()
}
