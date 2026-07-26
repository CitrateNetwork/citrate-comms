//! Connection-hardening guard for the client→relay endpoint (COMMS-S4 WP-4.6,
//! `PLANSET/07` §3).
//!
//! MLS already makes message *content* opaque end to end, but the transport still
//! carries routing metadata (who-talks-to-whom, timing, sizes) and the SIWE handshake.
//! Across the internet that transport MUST be TLS: we **refuse plaintext WebSocket to a
//! remote host**, fail-closed. `wss://` is always allowed; `ws://` is allowed only to a
//! loopback host (local dev / on-prem / airgap-on-one-box). A non-loopback `ws://` is
//! refused unless the operator explicitly opts in for a trusted private network
//! (`RelayClient::connect_insecure` / `CITRATE_COMMS_ALLOW_INSECURE_WS`).

/// How a relay endpoint is classified by [`classify_endpoint`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointClass {
    /// `wss://…` — WebSocket over TLS. Safe for the public internet.
    Tls,
    /// `ws://` to a loopback host — fine for local dev / on-prem / single-box airgap.
    LoopbackPlaintext,
    /// `ws://` to a non-loopback host — plaintext over a network. Refused by default.
    RemotePlaintext,
}

/// Classify a relay URL by transport security. Pure; does not perform any I/O.
pub fn classify_endpoint(url: &str) -> Result<EndpointClass, EndpointError> {
    let (scheme, rest) = url.split_once("://").ok_or(EndpointError::Malformed)?;
    let scheme = scheme.to_ascii_lowercase();
    // Authority is everything up to the first '/', '?' or '#'.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let host = host_of(authority);
    if host.is_empty() {
        return Err(EndpointError::Malformed);
    }
    match scheme.as_str() {
        "wss" => Ok(EndpointClass::Tls),
        "ws" => {
            if is_loopback_host(&host) {
                Ok(EndpointClass::LoopbackPlaintext)
            } else {
                Ok(EndpointClass::RemotePlaintext)
            }
        }
        other => Err(EndpointError::UnsupportedScheme(other.to_string())),
    }
}

/// Enforce the connection policy: TLS and loopback-plaintext always pass; remote
/// plaintext passes only when `allow_insecure` is set (trusted private network).
pub fn enforce_endpoint_policy(
    url: &str,
    allow_insecure: bool,
) -> Result<EndpointClass, EndpointError> {
    let class = classify_endpoint(url)?;
    match class {
        EndpointClass::RemotePlaintext if !allow_insecure => {
            Err(EndpointError::RemotePlaintextRefused)
        }
        _ => Ok(class),
    }
}

/// Extract the host from an `authority` (`host`, `host:port`, `[v6]`, `[v6]:port`).
fn host_of(authority: &str) -> String {
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: take up to the closing bracket.
        if let Some((inside, _)) = rest.split_once(']') {
            return inside.to_ascii_lowercase();
        }
        return String::new();
    }
    authority
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// Loopback hosts: `localhost`, `127.0.0.0/8`, IPv6 `::1`.
fn is_loopback_host(host: &str) -> bool {
    if host == "localhost" || host == "::1" {
        return true;
    }
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        return v4.is_loopback();
    }
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        return v6.is_loopback();
    }
    false
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EndpointError {
    #[error("malformed relay url (expected scheme://host[:port])")]
    Malformed,
    #[error("unsupported url scheme `{0}` (use wss:// or ws://)")]
    UnsupportedScheme(String),
    #[error("refusing plaintext ws:// to a remote host — use wss:// (TLS), or opt in for a trusted private network")]
    RemotePlaintextRefused,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_is_always_allowed() {
        assert_eq!(
            classify_endpoint("wss://relay.citrate.ai").unwrap(),
            EndpointClass::Tls
        );
        assert_eq!(
            classify_endpoint("wss://relay.citrate.ai:443/ws").unwrap(),
            EndpointClass::Tls
        );
        assert_eq!(
            enforce_endpoint_policy("wss://relay.citrate.ai", false).unwrap(),
            EndpointClass::Tls
        );
    }

    #[test]
    fn loopback_plaintext_is_allowed() {
        for u in [
            "ws://127.0.0.1:8787",
            "ws://localhost:8787",
            "ws://[::1]:8787",
            "ws://127.0.0.5",
        ] {
            assert_eq!(
                classify_endpoint(u).unwrap(),
                EndpointClass::LoopbackPlaintext,
                "{u}"
            );
            assert!(enforce_endpoint_policy(u, false).is_ok(), "{u}");
        }
    }

    #[test]
    fn remote_plaintext_is_refused_by_default_but_opt_in_works() {
        for u in [
            "ws://relay.citrate.ai:8787",
            "ws://10.0.0.4:8787",
            "ws://192.168.1.9",
        ] {
            assert_eq!(
                classify_endpoint(u).unwrap(),
                EndpointClass::RemotePlaintext,
                "{u}"
            );
            assert_eq!(
                enforce_endpoint_policy(u, false),
                Err(EndpointError::RemotePlaintextRefused),
                "{u}"
            );
            // Operator opt-in for a trusted private network.
            assert_eq!(
                enforce_endpoint_policy(u, true).unwrap(),
                EndpointClass::RemotePlaintext,
                "{u}"
            );
        }
    }

    #[test]
    fn malformed_and_unsupported_are_rejected() {
        assert_eq!(
            classify_endpoint("relay.citrate.ai:8787"),
            Err(EndpointError::Malformed)
        );
        assert_eq!(classify_endpoint("ws://"), Err(EndpointError::Malformed));
        assert!(matches!(
            classify_endpoint("http://relay.citrate.ai"),
            Err(EndpointError::UnsupportedScheme(_))
        ));
        assert!(matches!(
            classify_endpoint("tcp://1.2.3.4"),
            Err(EndpointError::UnsupportedScheme(_))
        ));
    }
}
