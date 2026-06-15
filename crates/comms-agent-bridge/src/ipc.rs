//! JSON-per-line IPC framing — mirrors `nist-agent/crates/nist-agent-daemon/src/ipc.rs`.
//! Each message is a single JSON object terminated by a newline; the bridge writes
//! [`AgentInbound`](crate::AgentInbound) lines to the agent runtime and reads
//! [`AgentOutbound`](crate::AgentOutbound) lines back over the Unix-domain socket.

use serde::de::DeserializeOwned;
use serde::Serialize;

/// Encode a value as one newline-terminated JSON line.
pub fn to_line<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let mut s = serde_json::to_string(value)?;
    s.push('\n');
    Ok(s)
}

/// Decode a value from one JSON line (trailing newline tolerated).
pub fn from_line<T: DeserializeOwned>(line: &str) -> Result<T, serde_json::Error> {
    serde_json::from_str(line.trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentInbound, AgentOutbound};

    #[test]
    fn line_roundtrip_and_tagging() {
        let ev = AgentInbound::Message { group: "0x4cd1".into(), sender: "0x1f2e".into(), text: "hi".into() };
        let line = to_line(&ev).unwrap();
        assert!(line.ends_with('\n'));
        assert!(line.contains("\"type\":\"message\""));
        assert_eq!(from_line::<AgentInbound>(&line).unwrap(), ev);

        // A command the runtime sends back parses by its tag.
        let cmd: AgentOutbound = from_line("{\"type\":\"send\",\"group\":\"deals\",\"text\":\"ok\"}\n").unwrap();
        assert_eq!(cmd, AgentOutbound::Send { group: "deals".into(), text: "ok".into() });
    }
}
