"use client";

/**
 * CRM — accounts and the deals pipeline (kanban by stage). Deals are children of an
 * account: you create an account first, then add deals under it. Drag a deal between
 * stages to advance it (persisted + audited).
 */
import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Btn, DataChip } from "@/components/primitives";
import { Kanban, type KanbanColumn } from "@/components/board/Kanban";
import { CrmTable } from "./CrmTable";
import type { DealStage } from "@/lib/domain/enums";
import s from "@/components/common/screen.module.css";
import styles from "./CrmScreen.module.css";

export interface UiAccount {
  id: string;
  name: string;
  domain: string | null;
}
export interface UiDeal {
  id: string;
  column: string; // stage
  accountId: string | null;
  accountName: string | null;
  name: string;
  valueMinor: number;
}
export interface UiContact {
  id: string;
  name: string;
  title: string | null;
  accountName: string | null;
}

type CrmView = "pipeline" | "accounts" | "deals" | "contacts";

const COLUMNS: KanbanColumn[] = [
  { key: "Lead", label: "Lead", accent: "var(--stone-400)" },
  { key: "Qualified", label: "Qualified", accent: "var(--info)" },
  { key: "Proposal", label: "Proposal", accent: "var(--citrate-yellow-deep)" },
  { key: "Won", label: "Won", accent: "var(--success)" },
  { key: "Lost", label: "Lost", accent: "var(--danger)" },
];

function money(minor: number): string {
  return `$${(minor / 100).toLocaleString(undefined, { maximumFractionDigits: 0 })}`;
}

export function CrmScreen({
  workspaceId,
  workspaceSlug,
  canEdit,
  accounts,
  deals,
  contacts = [],
}: {
  workspaceId: string;
  workspaceSlug: string;
  canEdit: boolean;
  accounts: UiAccount[];
  deals: UiDeal[];
  contacts?: UiContact[];
}) {
  const router = useRouter();
  const [dealList, setDealList] = useState<UiDeal[]>(deals);
  const [newAccount, setNewAccount] = useState(false);
  const [newDeal, setNewDeal] = useState(false);
  const [view, setView] = useState<CrmView>("pipeline");

  async function move(dealId: string, toStage: string) {
    setDealList((prev) => prev.map((d) => (d.id === dealId ? { ...d, column: toStage } : d)));
    await fetch(`/api/workspaces/${workspaceId}/deals`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ dealId, stage: toStage as DealStage }),
    }).catch(() => router.refresh());
  }

  const VIEWS: { key: CrmView; label: string; count: number }[] = [
    { key: "pipeline", label: "Pipeline", count: dealList.length },
    { key: "accounts", label: "Accounts", count: accounts.length },
    { key: "deals", label: "Deals", count: dealList.length },
    { key: "contacts", label: "Contacts", count: contacts.length },
  ];

  return (
    <div className={s.wrap}>
      <header className={s.head}>
        <div>
          <div className={s.eyebrow}>Workspace</div>
          <h1 className={s.title}>CRM</h1>
        </div>
        {canEdit && (
          <div className={s.headActions}>
            <Btn variant="ghost" icon="plus" onClick={() => setNewAccount(true)}>
              New account
            </Btn>
            <Btn variant="primary" icon="plus" onClick={() => setNewDeal(true)} disabled={accounts.length === 0}>
              New deal
            </Btn>
          </div>
        )}
      </header>

      <div className={styles.viewTabs}>
        {VIEWS.map((v) => (
          <button key={v.key} className={`${styles.viewTab} ${view === v.key ? styles.viewActive : ""}`} onClick={() => setView(v.key)}>
            {v.label} <span className={styles.viewCount}>{v.count}</span>
          </button>
        ))}
      </div>

      {accounts.length === 0 ? (
        <div className={s.empty}>
          No accounts yet. {canEdit ? "Create an account, then add deals under it." : "An admin will add accounts."}
        </div>
      ) : view === "pipeline" ? (
        <Kanban
          columns={COLUMNS}
          items={dealList}
          emptyHint="No deals"
          onMove={canEdit ? move : () => {}}
          renderCard={(d) => (
            <Link href={`/w/${workspaceSlug}/crm/deals/${d.id}`} className={styles.dealCard}>
              <div className={styles.dealName}>{d.name}</div>
              {d.accountName && <DataChip>{d.accountName}</DataChip>}
              <div className={styles.dealValue}>{money(d.valueMinor)}</div>
            </Link>
          )}
        />
      ) : (
        <CrmTable
          workspaceId={workspaceId}
          slug={workspaceSlug}
          entity={view === "accounts" ? "account" : view === "deals" ? "deal" : "contact"}
          canEdit={canEdit}
        />
      )}

      {newAccount && (
        <AccountDialog workspaceId={workspaceId} onClose={() => setNewAccount(false)} onDone={() => router.refresh()} />
      )}
      {newDeal && (
        <DealDialog
          workspaceId={workspaceId}
          accounts={accounts}
          onClose={() => setNewDeal(false)}
          onCreated={(d) => {
            setDealList((prev) => [...prev, d]);
            setNewDeal(false);
          }}
        />
      )}
    </div>
  );
}

function AccountDialog({ workspaceId, onClose, onDone }: { workspaceId: string; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [busy, setBusy] = useState(false);
  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim() || busy) return;
    setBusy(true);
    const r = await fetch(`/api/workspaces/${workspaceId}/accounts`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: name.trim(), domain: domain.trim() || undefined }),
    });
    setBusy(false);
    if (r.ok) {
      onDone();
      onClose();
    }
  }
  return (
    <div className={s.scrim} onClick={onClose}>
      <div className={s.dialog} onClick={(e) => e.stopPropagation()}>
        <div className={s.dialogHead}>New account</div>
        <form className={s.form} onSubmit={create}>
          <label className={s.field}>
            <span className={s.fieldLabel}>Name</span>
            <input className={s.input} value={name} onChange={(e) => setName(e.target.value)} autoFocus />
          </label>
          <label className={s.field}>
            <span className={s.fieldLabel}>Domain (optional)</span>
            <input className={s.input} value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="acme.com" />
          </label>
          <div className={s.dialogFoot}>
            <Btn variant="quiet" type="button" onClick={onClose}>
              Cancel
            </Btn>
            <Btn variant="primary" type="submit" disabled={busy || !name.trim()}>
              Create
            </Btn>
          </div>
        </form>
      </div>
    </div>
  );
}

function DealDialog({
  workspaceId,
  accounts,
  onClose,
  onCreated,
}: {
  workspaceId: string;
  accounts: UiAccount[];
  onClose: () => void;
  onCreated: (d: UiDeal) => void;
}) {
  const [accountId, setAccountId] = useState(accounts[0]?.id ?? "");
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim() || !accountId || busy) return;
    setBusy(true);
    const valueMinor = Math.round((Number(value) || 0) * 100);
    const r = await fetch(`/api/workspaces/${workspaceId}/deals`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ accountId, name: name.trim(), valueMinor }),
    });
    setBusy(false);
    if (r.ok) {
      const { deal } = (await r.json()) as { deal: { id: string; accountId: string | null; accountName: string | null; name: string; valueMinor: number } };
      onCreated({ id: deal.id, column: "Lead", accountId: deal.accountId, accountName: deal.accountName, name: deal.name, valueMinor: deal.valueMinor });
    }
  }
  return (
    <div className={s.scrim} onClick={onClose}>
      <div className={s.dialog} onClick={(e) => e.stopPropagation()}>
        <div className={s.dialogHead}>New deal</div>
        <form className={s.form} onSubmit={create}>
          <label className={s.field}>
            <span className={s.fieldLabel}>Account</span>
            <select className={s.input} value={accountId} onChange={(e) => setAccountId(e.target.value)}>
              {accounts.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
          </label>
          <label className={s.field}>
            <span className={s.fieldLabel}>Deal name</span>
            <input className={s.input} value={name} onChange={(e) => setName(e.target.value)} autoFocus />
          </label>
          <label className={s.field}>
            <span className={s.fieldLabel}>Value (USD)</span>
            <input className={s.input} type="number" min="0" value={value} onChange={(e) => setValue(e.target.value)} placeholder="50000" />
          </label>
          <div className={s.dialogFoot}>
            <Btn variant="quiet" type="button" onClick={onClose}>
              Cancel
            </Btn>
            <Btn variant="primary" type="submit" disabled={busy || !name.trim()}>
              Create deal
            </Btn>
          </div>
        </form>
      </div>
    </div>
  );
}
