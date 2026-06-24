/**
 * Attachment policy (ATT) — client + server safe (no imports). The single source of
 * truth for which file types are allowed, how they're classified (image/video/doc), and
 * the per-kind size caps. Used by the DropZone (client), the Blob upload-token route, and
 * the finalize/ingest route.
 */
export type AttachKind = "image" | "video" | "doc";

const DOC_EXT = ["pdf", "txt", "md", "markdown", "csv", "tsv", "json", "log", "xlsx", "xls", "docx"];
const IMAGE_EXT = ["png", "jpg", "jpeg", "webp", "svg", "gif"];
const VIDEO_EXT = ["mp4", "webm", "mov", "m4v"];

export const ALLOWED_EXT = [...DOC_EXT, ...IMAGE_EXT, ...VIDEO_EXT];

/** Content types we let the Blob client-upload token accept. */
export const ALLOWED_CONTENT_TYPES = [
  "application/pdf",
  "text/plain",
  "text/markdown",
  "text/csv",
  "text/tab-separated-values",
  "application/json",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/vnd.ms-excel",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "image/png",
  "image/jpeg",
  "image/webp",
  "image/svg+xml",
  "image/gif",
  "video/mp4",
  "video/webm",
  "video/quicktime",
];

const MB = 1024 * 1024;
export const MAX_BYTES: Record<AttachKind, number> = { image: 25 * MB, video: 200 * MB, doc: 25 * MB };
/** Max size we'll fetch server-side to parse for RAG (bigger docs are stored, not parsed). */
export const MAX_PARSE_BYTES = 25 * MB;

export function extOf(name: string): string {
  const i = name.lastIndexOf(".");
  return i === -1 ? "" : name.slice(i + 1).toLowerCase();
}

export function kindOf(name: string, mime?: string | null): AttachKind {
  const ext = extOf(name);
  if (IMAGE_EXT.includes(ext) || (mime ?? "").startsWith("image/")) return "image";
  if (VIDEO_EXT.includes(ext) || (mime ?? "").startsWith("video/")) return "video";
  return "doc";
}

export function isAllowed(name: string, mime?: string | null): boolean {
  const ext = extOf(name);
  if (ALLOWED_EXT.includes(ext)) return true;
  return Boolean(mime && (mime.startsWith("image/") || mime.startsWith("video/") || mime.startsWith("text/")));
}

/** Doc types we extract text from for RAG (images/video are never parsed). */
export function isParseable(name: string, mime?: string | null): boolean {
  return kindOf(name, mime) === "doc";
}

export function maxBytesFor(name: string, mime?: string | null): number {
  return MAX_BYTES[kindOf(name, mime)];
}

/** `accept` attribute for the file picker. */
export const ACCEPT_ATTR = ALLOWED_EXT.map((e) => `.${e}`).join(",");
