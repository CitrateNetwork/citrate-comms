//! `admin` — the loopback-only, bearer-gated control surface (COMMS-S1 WP-1.7).
//!
//! Mirrors the `citrate-node-agent` supervision pattern: two fail-closed layers.
//!   1. **Loopback bind** — [`serve_admin`] refuses any non-loopback address.
//!   2. **Per-instance bearer token** — every state-changing endpoint requires
//!      `Authorization: Bearer <token>`, compared in constant time.
//!
//! Endpoints:
//!   - `GET  /health` — JSON snapshot (no auth; loopback-only already limits exposure).
//!   - `GET  /status` — bare `"running"` | `"paused"` string.
//!   - `POST /pause`  — stop accepting new mutations (bearer).
//!   - `POST /resume` — resume (bearer).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::ws::RelayServer;

#[derive(Clone)]
struct AdminState {
    server: Arc<RelayServer>,
    token: Arc<String>,
}

/// The health snapshot returned by `GET /health`.
#[derive(Serialize)]
pub struct Health {
    pub domain: String,
    pub paused: bool,
    pub connected: usize,
    pub groups: usize,
    pub audit_records: usize,
}

/// Bind the admin surface (loopback-only) and start serving. `bind` must resolve to a
/// loopback address; anything else is refused (fail-closed). Use port 0 for an
/// OS-assigned port. Returns the bound address and the serve task handle.
pub async fn serve_admin(
    server: Arc<RelayServer>,
    bind: &str,
    token: String,
) -> Result<(SocketAddr, JoinHandle<()>), AdminError> {
    let requested: SocketAddr = bind.parse().map_err(|_| AdminError::BadAddr)?;
    if !requested.ip().is_loopback() {
        return Err(AdminError::NotLoopback);
    }
    let listener = TcpListener::bind(requested).await.map_err(|e| AdminError::Io(e.to_string()))?;
    let addr = listener.local_addr().map_err(|e| AdminError::Io(e.to_string()))?;

    let state = AdminState { server, token: Arc::new(token) };
    let app = Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/pause", post(pause))
        .route("/resume", post(resume))
        .with_state(state);

    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((addr, handle))
}

async fn health(State(st): State<AdminState>) -> Json<Health> {
    let (groups, audit_records) = st.server.snapshot().await;
    Json(Health {
        domain: st.server.domain().await,
        paused: st.server.is_paused(),
        connected: st.server.connected().await,
        groups,
        audit_records,
    })
}

async fn status(State(st): State<AdminState>) -> &'static str {
    if st.server.is_paused() {
        "paused"
    } else {
        "running"
    }
}

async fn pause(State(st): State<AdminState>, headers: HeaderMap) -> StatusCode {
    if !authorized(&headers, &st.token) {
        return StatusCode::UNAUTHORIZED;
    }
    st.server.set_paused(true);
    StatusCode::OK
}

async fn resume(State(st): State<AdminState>, headers: HeaderMap) -> StatusCode {
    if !authorized(&headers, &st.token) {
        return StatusCode::UNAUTHORIZED;
    }
    st.server.set_paused(false);
    StatusCode::OK
}

/// Constant-time bearer-token check (fail-closed: missing/garbled header → false).
fn authorized(headers: &HeaderMap, token: &str) -> bool {
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let expected = format!("Bearer {token}");
    // Audited constant-time comparator (`subtle`) — never `==` on the secret bearer.
    presented.as_bytes().ct_eq(expected.as_bytes()).into()
}

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("invalid bind address")]
    BadAddr,
    #[error("admin surface refuses to bind a non-loopback address")]
    NotLoopback,
    #[error("io error: {0}")]
    Io(String),
}
