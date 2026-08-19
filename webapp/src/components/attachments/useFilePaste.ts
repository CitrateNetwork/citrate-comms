"use client";

/**
 * useFilePaste — make a composer accept pasted files/images the same way useFileDrop
 * handles drag-and-drop. When the clipboard carries a file (a copied image, a
 * screenshot, a file copied from the OS/file manager), we upload it instead of letting
 * the browser paste the filename/title as plain text. Pure-text pastes fall through
 * untouched (we only preventDefault when there are actual files).
 */
import type { ClipboardEvent } from "react";

/** Extract File objects from a clipboard event (items first — covers screenshot blobs
 *  that never appear in `.files` on some browsers — then fall back to `.files`). */
export function filesFromClipboard(e: ClipboardEvent): File[] {
  const dt = e.clipboardData;
  if (!dt) return [];
  const out: File[] = [];
  if (dt.items && dt.items.length) {
    for (const it of Array.from(dt.items)) {
      if (it.kind === "file") {
        const f = it.getAsFile();
        if (f) out.push(f);
      }
    }
  }
  if (out.length === 0 && dt.files && dt.files.length) {
    out.push(...Array.from(dt.files));
  }
  return out;
}

export function useFilePaste(onFiles: (files: File[]) => void) {
  return {
    onPaste: (e: ClipboardEvent) => {
      const files = filesFromClipboard(e);
      if (files.length === 0) return; // plain text — let the paste happen normally
      e.preventDefault();
      onFiles(files);
    },
  };
}
