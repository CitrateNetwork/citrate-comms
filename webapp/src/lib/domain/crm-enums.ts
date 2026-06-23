/**
 * Pure CRM-depth enums/constants — safe to import from BOTH client and server (no DB
 * or node imports). Mirrors the enums.ts pattern so client components avoid pulling the
 * server-only DB client into the browser bundle.
 */
export const CRM_ENTITIES = ["account", "deal", "contact"] as const;
export type CrmEntity = (typeof CRM_ENTITIES)[number];

export const CRM_FIELD_TYPES = [
  "text",
  "longtext",
  "number",
  "currency",
  "date",
  "select",
  "multiselect",
  "boolean",
  "url",
  "email",
  "phone",
  "user",
] as const;
export type CrmFieldType = (typeof CRM_FIELD_TYPES)[number];

export const CRM_NOTE_TYPES = ["note", "journal", "call", "meeting", "email"] as const;
export type CrmNoteType = (typeof CRM_NOTE_TYPES)[number];

/** Types whose values are controlled/numeric/date → safe to index (value_key/value_num)
 *  and NOT sensitive by default. Everything else is free-text/PII → encrypt-only. */
export const NON_SENSITIVE_TYPES: ReadonlySet<CrmFieldType> = new Set<CrmFieldType>([
  "number",
  "currency",
  "date",
  "select",
  "multiselect",
  "boolean",
  "url",
]);

export function defaultSensitive(type: CrmFieldType): boolean {
  return !NON_SENSITIVE_TYPES.has(type);
}
