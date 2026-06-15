//! `comms-client` — the native desktop client (Slint).
//!
//! Drives the full member experience: SIWE/OIDC login handshake, MLS group membership,
//! channels / forums / DMs, the CRM and PM surfaces, and onboarding/offboarding actions
//! for admins. All plaintext and all group secrets live here, never on the relay.
//!
//! UI is built in Slint against `@citrate-ui-kit` (`citrate-studio/ui-kit`) — the same
//! brand Theme + primitives used across the federation. The screens are hand-translated
//! 1:1 from the Claude design team's HTML/CSS package (COMMS-S2). See `PLANSET/02` §UI and
//! `PLANSET/07` for the build/airgap/signing pipeline.

#![forbid(unsafe_code)]
