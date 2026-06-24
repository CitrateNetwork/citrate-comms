"use client";

/**
 * App-wide drag-and-drop guard. Without this, dropping a file anywhere the app doesn't
 * explicitly handle (between zones, on the chat, just off a dropzone) makes the BROWSER
 * navigate to the file — it "downloads"/opens instead of uploading. We preventDefault on
 * window dragover/drop so the browser never does that. Elements that DO want the drop
 * (DropZone, the composers) still receive their own onDrop and read the files — this only
 * suppresses the browser's default navigation, not the React handlers.
 */
import { useEffect } from "react";

export function DragDropGuard() {
  useEffect(() => {
    const prevent = (e: DragEvent) => {
      // Only guard actual file drags (not text/element drags within the app).
      if (e.dataTransfer && Array.from(e.dataTransfer.types).includes("Files")) {
        e.preventDefault();
      }
    };
    window.addEventListener("dragover", prevent);
    window.addEventListener("drop", prevent);
    return () => {
      window.removeEventListener("dragover", prevent);
      window.removeEventListener("drop", prevent);
    };
  }, []);
  return null;
}
