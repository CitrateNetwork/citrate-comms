//! GC-2: role grants as MLS application messages.
//!
//! A grant travels inside an ordinary encrypted group message whose UTF-8 body is
//! [`GRANT_PREFIX`] followed by the lowercase hex of the canonical encoding of a signed
//! [`RoleAssertion`]. ASCII on purpose: a daemon from before this change decodes it as
//! text instead of failing the poll.

use comms_proto::RoleAssertion;

/// Body prefix of a role-grant message. Starts with NUL so no typed chat text matches it.
pub const GRANT_PREFIX: &str = "\u{0}citrate:role-grant:v1:";

/// Encode a signed grant as a message body.
pub fn encode_grant_message(a: &RoleAssertion) -> String {
    let _ = a;
    String::new()
}

/// `None`: not a grant message. `Some(Err)`: has the prefix but does not decode.
pub fn decode_grant_message(body: &str) -> Option<Result<RoleAssertion, String>> {
    let _ = body;
    None
}
