/**
 * Client-upload token issuer: a token is only minted for a pathname under the requesting
 * workspace's `comms/<id>/` prefix, so a client can't write into another workspace's namespace.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const requireCapability = vi.fn<(...a: unknown[]) => unknown>();
type BeforeToken = (pathname: string, clientPayload: string | null) => Promise<Record<string, unknown>>;
let issued: Record<string, unknown> | null = null;

vi.mock("@/lib/tenant/guard", async (orig) => ({
  ...(await orig<Record<string, unknown>>()),
  requireCapability: (...a: unknown[]) => requireCapability(...a),
}));
vi.mock("@vercel/blob/client", () => ({
  handleUpload: async ({ body, onBeforeGenerateToken }: { body: { payload: { pathname: string } }; onBeforeGenerateToken: BeforeToken }) => {
    issued = await onBeforeGenerateToken(body.payload.pathname, null);
    return { type: "blob.generate-client-token", clientToken: "tok" };
  },
}));

import { POST } from "./route";

const WS = "11111111-1111-1111-1111-111111111111";
const OTHER = "22222222-2222-2222-2222-222222222222";

function ask(pathname: string) {
  const body = { type: "blob.generate-client-token", payload: { pathname, callbackUrl: "", clientPayload: null, multipart: false } };
  return POST(new Request(`http://localhost/api/workspaces/${WS}/documents/upload-token`, { method: "POST", body: JSON.stringify(body) }), {
    params: Promise.resolve({ id: WS }),
  });
}

beforeEach(() => {
  requireCapability.mockReset();
  requireCapability.mockResolvedValue({ sub: "alice", role: "Member" });
  issued = null;
});

describe("upload token is bound to the workspace prefix", () => {
  it("issues a token for a pathname under comms/<workspaceId>/", async () => {
    const res = await ask(`comms/${WS}/deck.pdf`);
    expect(res.status).toBe(200);
    expect(issued).toMatchObject({ addRandomSuffix: true });
  });

  it.each([
    ["another workspace", `comms/${OTHER}/deck.pdf`],
    ["no prefix", "deck.pdf"],
    ["bare comms/", "comms/deck.pdf"],
    ["prefix without the trailing slash", `comms/${WS}deck.pdf`],
  ])("refuses %s (400, no token)", async (_label, pathname) => {
    const res = await ask(pathname);
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "upload_denied" });
    expect(issued).toBeNull();
  });
});
