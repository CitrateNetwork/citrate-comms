/**
 * Column → CRM mapping for the import engine (AGENTS_03). A `MappingSpec` says how a
 * sheet's columns become accounts / contacts / deals / tasks + custom fields, and how
 * to dedupe. `suggestMapping` produces a sensible default from the parsed column
 * profile that a human (or the agent) reviews and edits before approval.
 */
import type { ColType, ParsedColumn } from "./import-parse";

export type StdTarget =
  | "account.name"
  | "account.domain"
  | "contact.name"
  | "contact.firstName"
  | "contact.lastName"
  | "contact.email"
  | "contact.title"
  | "contact.phone"
  | "deal.name"
  | "deal.value"
  | "task.title"
  | "task.priority"
  | "ignore";

export type ColMap =
  | { kind: "std"; target: StdTarget }
  | { kind: "custom"; entity: "account" | "contact" | "deal"; key: string; label: string; type: string };

export interface MappingColumn {
  column: string;
  map: ColMap;
}

export interface MappingSpec {
  primaryEntity: "contact" | "account" | "deal" | "task";
  columns: MappingColumn[];
  dedupe: { account: "domain" | "name" | "none"; contact: "email" | "name" | "none" };
  /** Create one task per row (for prioritized action lists like "Priority 150"). */
  createTasks?: { projectName?: string };
}

const SINGULAR: StdTarget[] = [
  "account.name", "account.domain", "contact.name", "contact.firstName",
  "contact.lastName", "contact.email", "contact.title", "contact.phone", "deal.name", "deal.value",
];

export function slugKey(name: string): string {
  return (
    name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "_")
      .replace(/^_+|_+$/g, "")
      .slice(0, 60) || "field"
  );
}

function crmTypeFor(t: ColType): string {
  switch (t) {
    case "email": return "email";
    case "phone": return "phone";
    case "url": return "url";
    case "currency": return "currency";
    case "number": return "number";
    case "date": return "date";
    case "boolean": return "boolean";
    case "select": return "select";
    default: return "text";
  }
}

/** Best-guess standard target for a single column by name + inferred type. */
function guessStd(name: string, type: ColType): StdTarget | null {
  const n = name.toLowerCase().trim();
  if (/^(company|account|organi[sz]ation|employer|firm)(\s*name)?$/.test(n) || /\bcompany name\b/.test(n)) return "account.name";
  if (type === "url" || /\b(website|web site|company url|domain|url)\b/.test(n)) return "account.domain";
  if (type === "email" || /\be[-\s]?mail\b/.test(n)) return "contact.email";
  if (/^first\s*name$/.test(n)) return "contact.firstName";
  if (/^last\s*name$/.test(n)) return "contact.lastName";
  if (/^(full\s*)?name$/.test(n) || /\b(contact|person|prospect|investor|lead)\s*name\b/.test(n)) return "contact.name";
  if (/\b(job\s*title|title|role|position|seniority|management level)\b/.test(n)) return "contact.title";
  if (type === "phone" || /\b(phone|mobile|cell|direct phone)\b/.test(n)) return "contact.phone";
  if (/\bdeal\b|\bopportunity\b/.test(n)) return "deal.name";
  if (/\b(deal\s*(value|size)|amount|revenue|arr|mrr|value in usd)\b/.test(n)) return "deal.value";
  return null;
}

/** Produce a default mapping from a sheet's column profile. Singular standard targets
 *  are claimed first-come; later columns wanting a taken target become custom fields. */
export function suggestMapping(columns: ParsedColumn[]): MappingSpec {
  const taken = new Set<StdTarget>();
  const hasEmail = columns.some((c) => c.type === "email" || /email/i.test(c.name));
  const hasPersonName = columns.some((c) => /name/i.test(c.name));
  const primaryEntity: MappingSpec["primaryEntity"] = hasEmail || hasPersonName ? "contact" : "account";

  const cols: MappingColumn[] = columns.map((c) => {
    const std = guessStd(c.name, c.type);
    if (std && (!SINGULAR.includes(std) || !taken.has(std))) {
      if (SINGULAR.includes(std)) taken.add(std);
      return { column: c.name, map: { kind: "std", target: std } };
    }
    // Fall through to a custom field on the primary entity (suggestMapping only ever
    // picks "contact" or "account" as the primary).
    const entity: "account" | "contact" | "deal" = primaryEntity === "account" ? "account" : "contact";
    return {
      column: c.name,
      map: { kind: "custom", entity, key: slugKey(c.name), label: c.name, type: crmTypeFor(c.type) },
    };
  });

  return {
    primaryEntity,
    columns: cols,
    dedupe: {
      account: taken.has("account.domain") ? "domain" : taken.has("account.name") ? "name" : "none",
      contact: taken.has("contact.email") ? "email" : "name",
    },
  };
}

/** All column names a spec maps to a given standard target (0 or 1 for singular targets). */
export function columnsFor(spec: MappingSpec, target: StdTarget): string[] {
  return spec.columns.filter((c) => c.map.kind === "std" && c.map.target === target).map((c) => c.column);
}
