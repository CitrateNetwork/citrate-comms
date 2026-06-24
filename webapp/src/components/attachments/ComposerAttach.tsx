"use client";

/**
 * Composer attach control (ATT-3) — a paperclip button that uploads files (browse) and
 * reports each finalized document via onAttached, so a composer can collect attachments
 * before sending. Reused by the channel composer and the agent chat composer.
 */
import { useRef, useState } from "react";
import { Icon } from "@/components/primitives";
import { ACCEPT_ATTR } from "@/lib/attachments";
import { uploadAttachment, type UploadedDoc } from "./uploadAttachment";
import styles from "./ComposerAttach.module.css";

interface Scope {
  accountId?: string;
  dealId?: string;
  channelId?: string;
}

export function ComposerAttach({
  workspaceId,
  scope,
  onAttached,
  onError,
}: {
  workspaceId: string;
  scope: Scope;
  onAttached: (doc: UploadedDoc) => void;
  onError?: (msg: string) => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);

  async function pick(e: React.ChangeEvent<HTMLInputElement>) {
    const files = e.target.files;
    if (!files || files.length === 0) return;
    setBusy(true);
    for (const f of Array.from(files)) {
      const r = await uploadAttachment(workspaceId, scope, f);
      if (r.ok) onAttached(r.doc);
      else onError?.(`${f.name}: ${r.error}`);
    }
    setBusy(false);
    e.target.value = "";
  }

  return (
    <>
      <button type="button" className={styles.btn} title="Attach files" aria-label="Attach files" onClick={() => inputRef.current?.click()} disabled={busy}>
        <Icon name="paperclip" size={16} />
      </button>
      <input ref={inputRef} type="file" multiple hidden accept={ACCEPT_ATTR} onChange={pick} />
    </>
  );
}
