import { NextResponse } from "next/server";
import { handleUpload, type HandleUploadBody } from "@vercel/blob/client";
import { Capability, requireCapability, GuardError } from "@/lib/tenant/guard";
import { ALLOWED_CONTENT_TYPES, MAX_BYTES, workspaceBlobPrefix } from "@/lib/attachments";

export const runtime = "nodejs";

/**
 * Issues a short-lived client-upload token so the browser streams the file straight to
 * Vercel Blob (bypassing the 4.5 MB serverless body limit — needed for video). Auth is
 * checked here (Member+ via CreateRecord) before any token is granted; the token is
 * scoped to the allowed content types + a hard size cap. Ingest happens in /finalize.
 */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  try {
    const body = (await req.json()) as HandleUploadBody;
    // Authorize a token request BEFORE handing it to the SDK (fail-closed, and the
    // route x role matrix test can see the role gate). Vercel's upload-completed
    // callback carries no user session; handleUpload verifies its signature instead.
    if (body?.type !== "blob.upload-completed") await requireCapability(req, id, Capability.CreateRecord);
    const json = await handleUpload({
      body,
      request: req,
      onBeforeGenerateToken: async (pathname, clientPayload) => {
        await requireCapability(req, id, Capability.CreateRecord); // fail-closed: no auth ⇒ throws
        // ATT-HARDEN: the token may only mint objects under THIS workspace's prefix, so a
        // client can't plant into (or overwrite within) another workspace's namespace. This
        // is an input validation (400 via the catch), not an RBAC denial.
        if (!pathname.startsWith(workspaceBlobPrefix(id))) throw new Error("bad_prefix");
        return {
          allowedContentTypes: ALLOWED_CONTENT_TYPES,
          addRandomSuffix: true,
          maximumSizeInBytes: MAX_BYTES.video, // hard ceiling (largest kind)
          tokenPayload: clientPayload ?? null,
        };
      },
      // Ingest is done by the client → /finalize (works in all envs); nothing to do here.
      onUploadCompleted: async () => {},
    });
    return NextResponse.json(json);
  } catch (e) {
    // PBA-L3c-024: never echo raw error text (driver/SQL/upstream) to the client.
    if (e instanceof GuardError) return NextResponse.json({ error: e.message }, { status: e.status });
    console.error("[upload-token] denied", e);
    return NextResponse.json({ error: "upload_denied" }, { status: 400 });
  }
}
