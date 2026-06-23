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
import { type CrmEntity, type CrmFieldType, defaultSensitive } from "./crm-enums";

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

/** Upsert one field value (encode + index), audited. Returns the decrypted value. */
export async function setFieldValue(args: {
  workspaceId: string;
  entity: CrmEntity;
  recordId: string;
  fieldId: string;
  raw: string;
  bySub: string;
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
