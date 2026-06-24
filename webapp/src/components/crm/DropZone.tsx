"use client";

/**
 * Drag-and-drop + browse uploader (ATT). Streams files straight to Vercel Blob via a
 * short-lived client token (handles large/video files), then calls /finalize to record +
 * index them. Validates type + size on the client before uploading. Multi-file.
 */
import { useRef, useState } from "react";
import { upload } from "@vercel/blob/client";
import { Icon } from "@/components/primitives";
import { ACCEPT_ATTR, isAllowed, maxBytesFor, kindOf } from "@/lib/attachments";
import styles from "./DropZone.module.css";

interface Scope {
  accountId?: string;
  dealId?: string;
  channelId?: string;
}
interface FileState {
  name: string;
  status: "uploading" | "done" | "error";
  error?: string;
}

function humanSize(n: number): string {
  return n > 1024 * 1024 ? `${Math.round(n / (1024 * 1024))} MB` : `${Math.round(n / 1024)} KB`;
}

export function DropZone({ workspaceId, scope, onDone }: { workspaceId: string; scope: Scope; onDone: () => void }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [files, setFiles] = useState<FileState[]>([]);

  function setFile(name: string, patch: Partial<FileState>) {
    setFiles((prev) => prev.map((f) => (f.name === name ? { ...f, ...patch } : f)));
  }

  async function handleFiles(list: FileList | File[]) {
    const arr = Array.from(list);
    if (arr.length === 0) return;
    setFiles((prev) => [...prev, ...arr.map((f) => ({ name: f.name, status: "uploading" as const }))]);
    let anyDone = false;
    for (const file of arr) {
      if (!isAllowed(file.name, file.type)) {
        setFile(file.name, { status: "error", error: "Unsupported type" });
        continue;
      }
      if (file.size > maxBytesFor(file.name, file.type)) {
        setFile(file.name, { status: "error", error: `Too large (max ${humanSize(maxBytesFor(file.name, file.type))})` });
        continue;
      }
      let blobUrl: string;
      try {
        const blob = await upload(file.name, file, {
          access: "public",
          handleUploadUrl: `/api/workspaces/${workspaceId}/documents/upload-token`,
          clientPayload: JSON.stringify(scope),
        });
        blobUrl = blob.url;
      } catch (e) {
        const msg = (e as Error)?.message ?? "";
        setFile(file.name, { status: "error", error: /token|blob|store|not\s*found/i.test(msg) ? "Storage not configured (link a Vercel Blob store)" : "Storage upload failed" });
        continue;
      }
      try {
        const r = await fetch(`/api/workspaces/${workspaceId}/documents/finalize`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ blobUrl, name: file.name, mime: file.type, ...scope }),
        });
        if (!r.ok) {
          const body = (await r.json().catch(() => ({}))) as { error?: string };
          setFile(file.name, { status: "error", error: `Finalize failed (${r.status}${body.error ? `: ${body.error}` : ""})` });
          continue;
        }
        setFile(file.name, { status: "done" });
        anyDone = true;
      } catch {
        setFile(file.name, { status: "error", error: "Finalize error" });
      }
    }
    if (anyDone) onDone();
  }

  return (
    <div className={styles.wrap}>
      <div
        className={`${styles.zone} ${dragging ? styles.dragging : ""}`}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          void handleFiles(e.dataTransfer.files);
        }}
        onClick={() => inputRef.current?.click()}
        role="button"
        tabIndex={0}
      >
        <Icon name="download" size={18} />
        <div className={styles.zoneText}>
          <strong>Drag files here</strong> or <span className={styles.browse}>browse</span>
        </div>
        <div className={styles.hint}>xlsx, csv, docx, pdf, txt, md · png, svg, jpg, webp · mp4 — stored, displayed, and indexed</div>
        <input
          ref={inputRef}
          type="file"
          multiple
          accept={ACCEPT_ATTR}
          hidden
          onChange={(e) => {
            if (e.target.files) void handleFiles(e.target.files);
            e.target.value = "";
          }}
        />
      </div>

      {files.length > 0 && (
        <div className={styles.list}>
          {files.map((f, i) => (
            <div key={`${f.name}-${i}`} className={styles.row}>
              <Icon name={kindOf(f.name) === "image" ? "globe" : kindOf(f.name) === "video" ? "play" : "paperclip"} size={13} />
              <span className={styles.fname}>{f.name}</span>
              <span className={`${styles.status} ${f.status === "error" ? styles.err : ""}`}>
                {f.status === "uploading" ? "uploading…" : f.status === "done" ? "added" : f.error ?? "failed"}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
