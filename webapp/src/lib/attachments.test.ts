import { describe, it, expect } from "vitest";
import { ATTACHMENT_ACCESS, workspaceBlobPrefix } from "./attachments";

describe("attachment storage policy (ATT-HARDEN)", () => {
  it("pins the store access to private — attachments are never written public", () => {
    // Guards against a regression flipping the value the server `put` and client `upload` pass.
    expect(ATTACHMENT_ACCESS).toBe("private");
    const access: "private" = ATTACHMENT_ACCESS; // also pinned at the type level
    expect(access).toBe("private");
  });

  it("binds objects to their workspace via the comms/<id>/ prefix", () => {
    const ws = "11111111-2222-3333-4444-555555555555";
    expect(workspaceBlobPrefix(ws)).toBe(`comms/${ws}/`);
    // A UUID has no slash, so the prefix uniquely identifies the owning workspace.
    expect(workspaceBlobPrefix(ws).endsWith("/")).toBe(true);
    expect(workspaceBlobPrefix("a").startsWith("comms/")).toBe(true);
  });
});
