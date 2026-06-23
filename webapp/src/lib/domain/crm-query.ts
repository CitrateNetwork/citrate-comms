/**
 * CRM table query (COMMS-CRM-DEPTH D4). Assembles a flat, sortable table for an entity:
 * standard columns + every custom field column, with a display string and a sort key per
 * cell. Custom values are decrypted for display; queryable forms (value_key/value_num)
 * drive sorting. Bounded fetch (the workspace's CRM is small); the cap is surfaced.
 */
import { and, asc, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { crmFieldValues } from "@/lib/db/schema";
import { decryptField } from "@/lib/security/crypto";
import { listAccounts, listDeals, listContacts } from "./crm";
import { listFieldDefs, formatFieldDisplay } from "./crm-fields";
import type { CrmEntity } from "./crm-enums";

const ROW_CAP = 2000;

export interface TableColumn {
  key: string;
  label: string;
  kind: "standard" | "custom";
  numeric?: boolean;
}
export interface TableCell {
  display: string;
  sort: string | number;
}
export interface TableRow {
  id: string;
  cells: Record<string, TableCell>;
}
export interface RecordsTable {
  entity: CrmEntity;
  columns: TableColumn[]; // standard first, then custom (all enabled fields)
  rows: TableRow[];
  truncated: boolean;
}

function money(minor: number): string {
  return `$${(minor / 100).toLocaleString(undefined, { maximumFractionDigits: 0 })}`;
}
function cell(display: string, sort?: string | number): TableCell {
  return { display, sort: sort ?? display.toLowerCase() };
}

function standardColumns(entity: CrmEntity): TableColumn[] {
  if (entity === "account") return [
    { key: "name", label: "Name", kind: "standard" },
    { key: "domain", label: "Domain", kind: "standard" },
  ];
  if (entity === "deal") return [
    { key: "name", label: "Name", kind: "standard" },
    { key: "value", label: "Value", kind: "standard", numeric: true },
    { key: "stage", label: "Stage", kind: "standard" },
    { key: "account", label: "Account", kind: "standard" },
  ];
  return [
    { key: "name", label: "Name", kind: "standard" },
    { key: "title", label: "Title", kind: "standard" },
    { key: "account", label: "Account", kind: "standard" },
  ];
}

interface BaseRow {
  id: string;
  cells: Record<string, TableCell>;
}

async function baseRows(workspaceId: string, entity: CrmEntity): Promise<BaseRow[]> {
  if (entity === "account") {
    const rows = await listAccounts(workspaceId);
    return rows.map((a) => ({ id: a.id, cells: { name: cell(a.name), domain: cell(a.domain ?? "") } }));
  }
  if (entity === "deal") {
    const rows = await listDeals(workspaceId);
    return rows.map((d) => ({
      id: d.id,
      cells: {
        name: cell(d.name),
        value: cell(money(d.valueMinor), d.valueMinor),
        stage: cell(d.stage),
        account: cell(d.accountName ?? ""),
      },
    }));
  }
  const rows = await listContacts(workspaceId);
  return rows.map((c) => ({
    id: c.id,
    cells: { name: cell(c.name), title: cell(c.title ?? ""), account: cell(c.accountName ?? "") },
  }));
}

export async function queryRecords(workspaceId: string, entity: CrmEntity): Promise<RecordsTable> {
  const [defs, rows] = await Promise.all([listFieldDefs(workspaceId, entity), baseRows(workspaceId, entity)]);
  const truncated = rows.length > ROW_CAP;
  const capped = rows.slice(0, ROW_CAP);

  // One pass over all custom values for this entity, grouped by record → field.
  const valueRows = await db()
    .select({ recordId: crmFieldValues.recordId, fieldId: crmFieldValues.fieldId, valueEnc: crmFieldValues.valueEnc, valueKey: crmFieldValues.valueKey, valueNum: crmFieldValues.valueNum })
    .from(crmFieldValues)
    .where(and(eq(crmFieldValues.workspaceId, workspaceId), eq(crmFieldValues.entity, entity)))
    .orderBy(asc(crmFieldValues.recordId));
  const byRecord = new Map<string, Map<string, { valueEnc: string | null; valueKey: string | null; valueNum: number | null }>>();
  for (const v of valueRows) {
    if (!byRecord.has(v.recordId)) byRecord.set(v.recordId, new Map());
    byRecord.get(v.recordId)!.set(v.fieldId, { valueEnc: v.valueEnc, valueKey: v.valueKey, valueNum: v.valueNum });
  }
  for (const row of capped) {
    const fields = byRecord.get(row.id);
    for (const def of defs) {
      const v = fields?.get(def.id);
      const raw = v?.valueEnc ? safeDecrypt(workspaceId, v.valueEnc) : null;
      const display = formatFieldDisplay(def, raw);
      const sort = v?.valueNum != null ? v.valueNum : (v?.valueKey ?? display).toLowerCase();
      row.cells[def.key] = { display, sort };
    }
  }

  const columns: TableColumn[] = [
    ...standardColumns(entity),
    ...defs.map((d) => ({ key: d.key, label: d.label, kind: "custom" as const, numeric: d.type === "number" || d.type === "currency" || d.type === "date" })),
  ];
  return { entity, columns, rows: capped, truncated };
}

function safeDecrypt(workspaceId: string, enc: string): string | null {
  try {
    return decryptField(workspaceId, enc);
  } catch {
    return null;
  }
}
