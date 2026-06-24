import { NextResponse } from "next/server";
import { handleUpload, type HandleUploadBody } from "@vercel/blob/client";
import { Capability, requireCapability } from "@/lib/tenant/guard";
import { ALLOWED_CONTENT_TYPES, MAX_BYTES } from "@/lib/attachments";

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
    const json = await handleUpload({
      body,
      request: req,
      onBeforeGenerateToken: async (_pathname, clientPayload) => {
        await requireCapability(req, id, Capability.CreateRecord); // fail-closed: no auth ⇒ throws
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
    return NextResponse.json({ error: (e as Error)?.message ?? "upload_denied" }, { status: 400 });
  }
}
