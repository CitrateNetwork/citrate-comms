/**
 * At-rest field encryption + one-way hashing for the trusted-tier web app.
 *
 * - `encryptField` / `decryptField`: AES-256-GCM with a **per-workspace** key
 *   derived from the master key via HKDF-SHA256. Used for content columns we DO
 *   store (message bodies, ledger text, CRM free-text) so a raw DB read never
 *   yields plaintext, and so per-workspace key rotation/destruction is possible.
 *   This is the honest trust boundary: the web tier CAN decrypt (it holds the
 *   master key) — unlike the server-blind native MLS relay — but storage
 *   compromise alone does not yield content.
 * - `hashId`: salted SHA-256 of an identifier (IP/UA) — audit attribution without
 *   retaining the raw value.
 * - `hashToken`: SHA-256 of an invite token; we persist only the hash.
 *
 * Master key in COMMS_ENC_KEY (32-byte base64). Fail-closed if unset.
 */
import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";

function masterKey(): Buffer {
  const b64 = process.env.COMMS_ENC_KEY;
  if (!b64) throw new Error("COMMS_ENC_KEY is not set (32-byte base64 key)");
  const key = Buffer.from(b64, "base64");
  if (key.length !== 32) throw new Error("COMMS_ENC_KEY must decode to 32 bytes");
  return key;
}

/** Per-workspace AES key = HKDF(master, salt=workspaceId, info="comms-field-v1"). */
function workspaceKey(workspaceId: string): Buffer {
  const derived = hkdfSync("sha256", masterKey(), Buffer.from(workspaceId, "utf8"), "comms-field-v1", 32);
  return Buffer.from(derived);
}

/** Encrypt a field for a workspace. Returns `v1:<iv b64>:<tag b64>:<ct b64>`. */
export function encryptField(workspaceId: string, plaintext: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", workspaceKey(workspaceId), iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1:${iv.toString("base64")}:${tag.toString("base64")}:${ct.toString("base64")}`;
}

/** Decrypt a field encrypted by `encryptField`. */
export function decryptField(workspaceId: string, packed: string): string {
  const [v, ivb, tagb, ctb] = packed.split(":");
  if (v !== "v1" || !ivb || !tagb || !ctb) throw new Error("bad ciphertext envelope");
  const decipher = createDecipheriv("aes-256-gcm", workspaceKey(workspaceId), Buffer.from(ivb, "base64"));
  decipher.setAuthTag(Buffer.from(tagb, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(ctb, "base64")), decipher.final()]).toString("utf8");
}

/**
 * Domain-separated per-workspace HMAC signature (hex). Used to SIGN agent-asserted
 * knowledge-graph nodes/edges (the Asserted plane) with a workspace key derived from
 * the master via HKDF — distinct from the field-encryption key. A future hardening
 * step swaps this for the persona's runner-keyring secp256k1 key; the call sites and
 * stored shape stay the same.
 */
function signKey(workspaceId: string): Buffer {
  return Buffer.from(hkdfSync("sha256", masterKey(), Buffer.from(workspaceId, "utf8"), "comms-assert-sig-v1", 32));
}

export function signWorkspace(workspaceId: string, message: string): string {
  return createHmac("sha256", signKey(workspaceId)).update(message).digest("hex");
}

export function verifyWorkspaceSig(workspaceId: string, message: string, signature: string): boolean {
  const expected = signWorkspace(workspaceId, message);
  const a = Buffer.from(expected, "hex");
  let b: Buffer;
  try {
    b = Buffer.from(signature, "hex");
  } catch {
    return false;
  }
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Salted one-way hash for audit attribution (IP/UA). Not reversible. */
export function hashId(value: string): string {
  const salt = process.env.COMMS_ENC_KEY ?? "citrate-comms";
  return createHash("sha256").update(`${salt}:${value}`).digest("hex").slice(0, 32);
}

/** SHA-256 of an invite token — we persist only this, never the raw token. */
export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

// --- Unsubscribe tokens (HMAC-signed, self-verifying — no DB token storage) ---

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromB64url(s: string): Buffer {
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

/** Key for unsubscribe-token HMACs, domain-separated from the field-encryption key. */
function unsubKey(): Buffer {
  return Buffer.from(hkdfSync("sha256", masterKey(), Buffer.from("unsubscribe", "utf8"), "comms-unsub-v1", 32));
}

/**
 * A stateless unsubscribe token = `b64url(email).b64url(HMAC(email))`. The link in
 * every email carries this; the unsubscribe endpoint verifies the HMAC and extracts
 * the email — no stored token to leak or brute-force, and the link can't be forged.
 */
export function unsubscribeToken(email: string): string {
  const e = email.trim().toLowerCase();
  const mac = createHmac("sha256", unsubKey()).update(e).digest();
  return `${b64url(Buffer.from(e, "utf8"))}.${b64url(mac)}`;
}

/** Verify an unsubscribe token and return the email it authorizes, or null. */
export function verifyUnsubscribeToken(token: string): string | null {
  const [ePart, macPart] = token.split(".");
  if (!ePart || !macPart) return null;
  let email: string;
  try {
    email = fromB64url(ePart).toString("utf8");
  } catch {
    return null;
  }
  const expected = createHmac("sha256", unsubKey()).update(email).digest();
  let provided: Buffer;
  try {
    provided = fromB64url(macPart);
  } catch {
    return null;
  }
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) return null;
  return email;
}
