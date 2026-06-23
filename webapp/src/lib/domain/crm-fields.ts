/**
 * CRM custom-field ENGINE (COMMS-CRM-DEPTH §4). Admin-defined fields per workspace +
 * entity drive the dynamic forms, the L0 column chooser, and the agents' dynamic tool
 * schemas. Values are encrypted at rest (`value_enc`, the canonical display source);
 * controlled/numeric/date forms are mirrored to `value_key`/`value_num` so filtering
 * and sorting work WITHOUT decrypting PII.
 */
import { and, asc, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { crmFieldDefs, crmFieldValues } from "@/lib/db/schema";
import { encryptField, decryptField } from "@/lib/security/crypto";
import { appendAudit } from "@/lib/audit/chain";
import { recordActivity } from "./crm-activity";
import { CRM_ENTITIES, type CrmEntity, type CrmFieldType, defaultSensitive } from "./crm-enums";

export interface FieldOption {
  key: string;
  label: string;
}
export interface FieldDef {
  id: string;
  entity: CrmEntity;
  key: string;
  label: string;
  type: CrmFieldType;
  options: FieldOption[];
  required: boolean;
  sensitive: boolean;
  ord: number;
  enabled: boolean;
}
export interface FieldWithValue {
  def: FieldDef;
  /** Decrypted canonical value (display source), or null if unset. */
  value: string | null;
}

function toDef(r: typeof crmFieldDefs.$inferSelect): FieldDef {
  return {
    id: r.id,
    entity: r.entity as CrmEntity,
    key: r.key,
    label: r.label,
    type: r.type as CrmFieldType,
    options: (r.optionsJson as FieldOption[] | null) ?? [],
    required: r.required,
    sensitive: r.sensitive,
    ord: r.ord,
    enabled: r.enabled,
  };
}

export async function listFieldDefs(
  workspaceId: string,
  entity: CrmEntity,
  opts: { includeDisabled?: boolean } = {},
): Promise<FieldDef[]> {
  const rows = await db()
    .select()
    .from(crmFieldDefs)
    .where(and(eq(crmFieldDefs.workspaceId, workspaceId), eq(crmFieldDefs.entity, entity)))
    .orderBy(asc(crmFieldDefs.ord), asc(crmFieldDefs.createdAt));
  return rows.map(toDef).filter((d) => opts.includeDisabled || d.enabled);
}

export interface CreateFieldDefInput {
  workspaceId: string;
  entity: CrmEntity;
  key: string;
  label: string;
  type: CrmFieldType;
  options?: FieldOption[];
  required?: boolean;
  sensitive?: boolean;
  ord?: number;
  createdBy: string;
}

export async function createFieldDef(input: CreateFieldDefInput): Promise<FieldDef> {
  const [row] = await db()
    .insert(crmFieldDefs)
    .values({
      workspaceId: input.workspaceId,
      entity: input.entity,
      key: input.key,
      label: input.label,
      type: input.type,
      optionsJson: input.options ?? null,
      required: input.required ?? false,
      sensitive: input.sensitive ?? defaultSensitive(input.type),
      ord: input.ord ?? 0,
      createdBy: input.createdBy,
    })
    .returning();
  await appendAudit({ workspaceId: input.workspaceId, actorSub: input.createdBy, event: "crm_field_defined", target: `${input.entity}.${input.key}` });
  return toDef(row!);
}

export interface UpdateFieldDefPatch {
  label?: string;
  options?: FieldOption[];
  required?: boolean;
  sensitive?: boolean;
  ord?: number;
  enabled?: boolean;
}

export async function updateFieldDef(workspaceId: string, fieldId: string, patch: UpdateFieldDefPatch, by: string): Promise<void> {
  const set: Record<string, unknown> = {};
  if (patch.label !== undefined) set.label = patch.label;
  if (patch.options !== undefined) set.optionsJson = patch.options;
  if (patch.required !== undefined) set.required = patch.required;
  if (patch.sensitive !== undefined) set.sensitive = patch.sensitive;
  if (patch.ord !== undefined) set.ord = patch.ord;
  if (patch.enabled !== undefined) set.enabled = patch.enabled;
  if (Object.keys(set).length === 0) return;
  await db().update(crmFieldDefs).set(set).where(and(eq(crmFieldDefs.workspaceId, workspaceId), eq(crmFieldDefs.id, fieldId)));
  await appendAudit({ workspaceId, actorSub: by, event: "crm_field_updated", target: fieldId });
}

/** Hard-delete a field def AND its stored values (the explicit "drop values" path). */
export async function deleteFieldDef(workspaceId: string, fieldId: string, by: string): Promise<void> {
  await db().delete(crmFieldValues).where(and(eq(crmFieldValues.workspaceId, workspaceId), eq(crmFieldValues.fieldId, fieldId)));
  await db().delete(crmFieldDefs).where(and(eq(crmFieldDefs.workspaceId, workspaceId), eq(crmFieldDefs.id, fieldId)));
  await appendAudit({ workspaceId, actorSub: by, event: "crm_field_deleted", target: fieldId });
}

// ── value encode / decode ────────────────────────────────────────────────────

interface EncodedValue {
  valueEnc: string | null;
  valueKey: string | null;
  valueNum: number | null;
}

/** Encode a raw string value per the field type. `value_enc` is the canonical (encrypted)
 *  form; `value_key`/`value_num` are derived indexes for non-PII query/sort. */
export function encodeValue(workspaceId: string, def: FieldDef, raw: string): EncodedValue {
  const trimmed = raw.trim();
  if (trimmed === "") return { valueEnc: null, valueKey: null, valueNum: null };
  const valueEnc = encryptField(workspaceId, trimmed);
  let valueKey: string | null = null;
  let valueNum: number | null = null;
  switch (def.type) {
    case "select":
    case "boolean":
      valueKey = trimmed;
      break;
    case "multiselect":
      valueKey = trimmed
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
        .join(",");
      break;
    case "number": {
      const n = Number(trimmed);
      if (Number.isFinite(n)) valueNum = Math.round(n);
      break;
    }
    case "currency": {
      const n = Number(trimmed.replace(/[^0-9.-]/g, ""));
      if (Number.isFinite(n)) valueNum = Math.round(n * 100); // minor units
      break;
    }
    case "date": {
      const ms = Date.parse(trimmed);
      if (Number.isFinite(ms)) valueNum = ms;
      break;
    }
    default:
      break; // text/longtext/url/email/phone/user → enc only
  }
  return { valueEnc, valueKey, valueNum };
}

function decodeValue(workspaceId: string, enc: string | null): string | null {
  if (!enc) return null;
  try {
    return decryptField(workspaceId, enc);
  } catch {
    return null;
  }
}

/** Human display for a decrypted canonical value, per field type (option keys→labels,
 *  booleans→Yes/No, dates formatted). Used by record files + table cells. */
export function formatFieldDisplay(def: FieldDef, raw: string | null): string {
  if (raw == null || raw === "") return "";
  if (def.type === "boolean") return raw === "true" ? "Yes" : "No";
  if (def.type === "select") return def.options.find((o) => o.key === raw)?.label ?? raw;
  if (def.type === "multiselect") {
    return raw.split(",").map((k) => def.options.find((o) => o.key === k.trim())?.label ?? k.trim()).join(", ");
  }
  if (def.type === "date") {
    const ms = Date.parse(raw);
    return Number.isFinite(ms) ? new Date(ms).toISOString().slice(0, 10) : raw;
  }
  return raw;
}

/** Enabled custom field keys per entity — for the agents' dynamic crm.write schema. */
export async function loadFieldDefsByEntity(
  workspaceId: string,
): Promise<Partial<Record<CrmEntity, { key: string; label: string; type: string }[]>>> {
  const out: Partial<Record<CrmEntity, { key: string; label: string; type: string }[]>> = {};
  for (const e of CRM_ENTITIES) {
    const defs = await listFieldDefs(workspaceId, e);
    out[e] = defs.map((d) => ({ key: d.key, label: d.label, type: d.type }));
  }
  return out;
}

/** All enabled fields for a record, joined with their (decrypted) values, ordered. */
export async function getFieldsForRecord(
  workspaceId: string,
  entity: CrmEntity,
  recordId: string,
): Promise<FieldWithValue[]> {
  const defs = await listFieldDefs(workspaceId, entity);
  if (defs.length === 0) return [];
  const valueRows = await db()
    .select({ fieldId: crmFieldValues.fieldId, valueEnc: crmFieldValues.valueEnc })
    .from(crmFieldValues)
    .where(and(eq(crmFieldValues.workspaceId, workspaceId), eq(crmFieldValues.recordId, recordId)));
  const byField = new Map(valueRows.map((v) => [v.fieldId, v.valueEnc]));
  return defs.map((def) => ({ def, value: decodeValue(workspaceId, byField.get(def.id) ?? null) }));
}

/** Upsert one field value (encode + index), audited + value-free activity. */
export async function setFieldValue(args: {
  workspaceId: string;
  entity: CrmEntity;
  recordId: string;
  fieldId: string;
  raw: string;
  bySub: string;
  byAgent?: boolean;
}): Promise<void> {
  const [defRow] = await db()
    .select()
    .from(crmFieldDefs)
    .where(and(eq(crmFieldDefs.workspaceId, args.workspaceId), eq(crmFieldDefs.id, args.fieldId)))
    .limit(1);
  if (!defRow) throw new Error("unknown field");
  const def = toDef(defRow);
  const enc = encodeValue(args.workspaceId, def, args.raw);
  await db()
    .insert(crmFieldValues)
    .values({
      workspaceId: args.workspaceId,
      entity: args.entity,
      recordId: args.recordId,
      fieldId: args.fieldId,
      valueEnc: enc.valueEnc,
      valueKey: enc.valueKey,
      valueNum: enc.valueNum,
      updatedBySub: args.bySub,
    })
    .onConflictDoUpdate({
      target: [crmFieldValues.workspaceId, crmFieldValues.recordId, crmFieldValues.fieldId],
      set: { valueEnc: enc.valueEnc, valueKey: enc.valueKey, valueNum: enc.valueNum, updatedBySub: args.bySub, updatedAt: new Date() },
    });
  await recordActivity({
    workspaceId: args.workspaceId,
    entity: args.entity,
    recordId: args.recordId,
    actorSub: args.bySub,
    byAgent: args.byAgent ?? false,
    input: { kind: "field_changed", fieldLabel: def.label }, // LABEL only, never the value
    meta: { fieldId: args.fieldId },
  });
}

// ── default field-def seeding (rich out of the box) ──────────────────────────

interface DefaultDef {
  entity: CrmEntity;
  key: string;
  label: string;
  type: CrmFieldType;
  options?: FieldOption[];
}

const opt = (...labels: string[]): FieldOption[] => labels.map((l) => ({ key: l.toLowerCase().replace(/\s+/g, "_"), label: l }));

/** Sensible defaults that DON'T duplicate the standard columns (accounts.domain,
 *  contacts.email/title, deals.value/stage/priority/closeDate already exist). */
const DEFAULTS: DefaultDef[] = [
  { entity: "account", key: "industry", label: "Industry", type: "select", options: opt("Technology", "Finance", "Healthcare", "Retail", "Manufacturing", "Energy", "Government", "Education", "Other") },
  { entity: "account", key: "employees", label: "Employees", type: "number" },
  { entity: "account", key: "lifecycle", label: "Lifecycle", type: "select", options: opt("Lead", "Prospect", "Customer", "Churned") },
  { entity: "account", key: "phone", label: "Phone", type: "phone" },
  { entity: "account", key: "location", label: "Location", type: "text" },
  { entity: "account", key: "description", label: "Description", type: "longtext" },
  { entity: "deal", key: "probability", label: "Probability (%)", type: "number" },
  { entity: "deal", key: "source", label: "Source", type: "select", options: opt("Inbound", "Outbound", "Referral", "Partner", "Event", "Other") },
  { entity: "deal", key: "forecast", label: "Forecast", type: "select", options: opt("Pipeline", "Best case", "Commit", "Closed") },
  { entity: "deal", key: "next_step", label: "Next step", type: "text" },
  { entity: "deal", key: "description", label: "Description", type: "longtext" },
  { entity: "contact", key: "phone", label: "Phone", type: "phone" },
  { entity: "contact", key: "linkedin", label: "LinkedIn", type: "url" },
  { entity: "contact", key: "department", label: "Department", type: "text" },
  { entity: "contact", key: "description", label: "Notes", type: "longtext" },
];

/** Seed the default field defs for a workspace (idempotent on (entity,key)). */
export async function seedDefaultCrmFields(workspaceId: string, by: string): Promise<number> {
  const existing = await db()
    .select({ entity: crmFieldDefs.entity, key: crmFieldDefs.key })
    .from(crmFieldDefs)
    .where(eq(crmFieldDefs.workspaceId, workspaceId));
  const have = new Set(existing.map((e) => `${e.entity}.${e.key}`));
  let seeded = 0;
  for (let i = 0; i < DEFAULTS.length; i++) {
    const d = DEFAULTS[i]!;
    if (have.has(`${d.entity}.${d.key}`)) continue;
    await db()
      .insert(crmFieldDefs)
      .values({
        workspaceId,
        entity: d.entity,
        key: d.key,
        label: d.label,
        type: d.type,
        optionsJson: d.options ?? null,
        required: false,
        sensitive: defaultSensitive(d.type),
        ord: i,
        createdBy: by,
      })
      .onConflictDoNothing();
    seeded++;
  }
  return seeded;
}
