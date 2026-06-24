"use client";

/**
 * useFileDrop — make any element a file drop target. Returns a `dragging` flag (for a visual
 * cue) and `dropProps` to spread onto the element. Only reacts to actual file drags, and
 * always preventDefaults so the browser never navigates to / opens the dropped file.
 */
import { useState, type DragEvent } from "react";

function hasFiles(e: DragEvent): boolean {
  return Boolean(e.dataTransfer) && Array.from(e.dataTransfer.types).includes("Files");
}

export function useFileDrop(onFiles: (files: File[]) => void) {
  const [dragging, setDragging] = useState(false);
  return {
    dragging,
    dropProps: {
      onDragOver: (e: DragEvent) => {
        if (!hasFiles(e)) return;
        e.preventDefault();
        setDragging(true);
      },
      onDragLeave: (e: DragEvent) => {
        // Ignore leaves that bubble from children still inside the element.
        if (e.currentTarget instanceof Node && e.relatedTarget instanceof Node && (e.currentTarget as Node).contains(e.relatedTarget as Node)) return;
        setDragging(false);
      },
      onDrop: (e: DragEvent) => {
        if (!hasFiles(e)) return;
        e.preventDefault();
        setDragging(false);
        const files = Array.from(e.dataTransfer.files);
        if (files.length) onFiles(files);
      },
    },
  };
}
