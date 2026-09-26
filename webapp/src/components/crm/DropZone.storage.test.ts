/**
 * DropZone is a client component (not renderable in the node test environment), so pin its
 * storage call at the source level: the upload must use the shared private-access constant
 * and the workspace prefix, like uploadAttachment (which is tested behaviourally).
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const src = readFileSync(fileURLToPath(new URL("./DropZone.tsx", import.meta.url)), "utf8");

describe("DropZone storage call", () => {
  it("uploads with ATTACHMENT_ACCESS under the workspace prefix, never a literal access", () => {
    const calls = src.match(/upload\(([\s\S]*?)\}\);/g) ?? [];
    expect(calls).toHaveLength(1);
    expect(calls[0]).toContain("upload(`${workspaceBlobPrefix(workspaceId)}${file.name}`");
    expect(calls[0]).toMatch(/access:\s*ATTACHMENT_ACCESS\s*,/);
    expect(src).not.toMatch(/access:\s*["'](public|private)["']/);
  });
});
