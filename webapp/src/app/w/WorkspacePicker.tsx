"use client";

/**
 * Workspace switcher + first-run create (design brief §6-A2). Lists the user's
 * workspaces; an empty state offers "Create a workspace". Real data only — no mocks.
 */
import { useState } from "react";
import { useRouter } from "next/navigation";
import { Btn, Card } from "@/components/primitives";
import styles from "./w.module.css";

export interface WorkspaceRow {
  id: string;
  slug: string;
  name: string;
  role: string;
}

export function WorkspacePicker({ workspaces }: { workspaces: WorkspaceRow[] }) {
  const router = useRouter();
  const [creating, setCreating] = useState(workspaces.length === 0);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (name.trim().length < 2) return;
    setBusy(true);
    setError(null);
    try {
      const r = await fetch("/api/workspaces", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: name.trim() }),
      });
      if (!r.ok) {
        setError(r.status === 429 ? "Too many attempts — wait a moment." : "Couldn't create the workspace.");
        return;
      }
      const { workspace } = (await r.json()) as { workspace: WorkspaceRow };
      router.push(`/w/${workspace.slug}/comms`);
    } catch {
      setError("Network error — please retry.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className={styles.screen}>
      <div className={styles.inner}>
        <div className={styles.mark}>◐ citrate-comms</div>

        {workspaces.length > 0 && !creating && (
          <>
            <h1 className={styles.title}>Your workspaces</h1>
            <div className={styles.list}>
              {workspaces.map((w) => (
                <button key={w.id} className={styles.wsRow} onClick={() => router.push(`/w/${w.slug}/comms`)}>
                  <span className={styles.wsName}>{w.name}</span>
                  <span className={styles.wsRole}>{w.role}</span>
                </button>
              ))}
            </div>
            <Btn variant="ghost" icon="plus" onClick={() => setCreating(true)}>
              Create a workspace
            </Btn>
          </>
        )}

        {creating && (
          <Card className={styles.createCard}>
            <h1 className={styles.title}>{workspaces.length === 0 ? "Create your workspace" : "New workspace"}</h1>
            <p className={styles.sub}>Name your team&apos;s private workspace. You&apos;ll be the owner.</p>
            <form onSubmit={create} className={styles.form}>
              <input
                className={styles.input}
                placeholder="e.g. Citrate Core"
                value={name}
                onChange={(e) => setName(e.target.value)}
                autoFocus
                maxLength={60}
              />
              {error && <div className={styles.error}>{error}</div>}
              <div className={styles.actions}>
                {workspaces.length > 0 && (
                  <Btn type="button" variant="quiet" onClick={() => setCreating(false)}>
                    Cancel
                  </Btn>
                )}
                <Btn type="submit" variant="primary" disabled={busy || name.trim().length < 2}>
                  {busy ? "Creating…" : "Create workspace"}
                </Btn>
              </div>
            </form>
          </Card>
        )}
      </div>
    </main>
  );
}
