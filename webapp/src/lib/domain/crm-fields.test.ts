import { beforeAll, describe, expect, it } from "vitest";
import { encodeValue, formatFieldDisplay, type FieldDef } from "./crm-fields";
import { decryptField } from "@/lib/security/crypto";
import { defaultSensitive } from "./crm-enums";

const WS = "11111111-1111-1111-1111-111111111111";

beforeAll(() => {
  process.env.COMMS_ENC_KEY = Buffer.alloc(32, 9).toString("base64");
});

function def(partial: Partial<FieldDef> & Pick<FieldDef, "type">): FieldDef {
  return {
    id: "f1",
    entity: "account",
    key: "k",
    label: "K",
    options: [],
    required: false,
    sensitive: defaultSensitive(partial.type),
    ord: 0,
    enabled: true,
    ...partial,
  };
}

describe("custom-field value encoding (encrypt canonical, index controlled forms)", () => {
  it("text/PII → encrypted only, no index columns", () => {
    const enc = encodeValue(WS, def({ type: "text" }), "123 Main St, Springfield");
    expect(enc.valueEnc).toBeTruthy();
    expect(enc.valueKey).toBeNull();
    expect(enc.valueNum).toBeNull();
    expect(decryptField(WS, enc.valueEnc!)).toBe("123 Main St, Springfield"); // canonical round-trips
  });

  it("select → value_key holds the option key (queryable)", () => {
    const enc = encodeValue(WS, def({ type: "select" }), "customer");
    expect(enc.valueKey).toBe("customer");
    expect(enc.valueNum).toBeNull();
  });

  it("multiselect → comma-joined keys", () => {
    const enc = encodeValue(WS, def({ type: "multiselect" }), "a, b ,c");
    expect(enc.valueKey).toBe("a,b,c");
  });

  it("number → value_num (rounded int)", () => {
    expect(encodeValue(WS, def({ type: "number" }), "250").valueNum).toBe(250);
  });

  it("currency → value_num in minor units (×100)", () => {
    expect(encodeValue(WS, def({ type: "currency" }), "$1,250.50").valueNum).toBe(125050);
  });

  it("date → value_num epoch ms", () => {
    expect(encodeValue(WS, def({ type: "date" }), "2026-01-01T00:00:00Z").valueNum).toBe(Date.parse("2026-01-01T00:00:00Z"));
  });

  it("empty input clears all forms", () => {
    expect(encodeValue(WS, def({ type: "text" }), "   ")).toEqual({ valueEnc: null, valueKey: null, valueNum: null });
  });

  it("default sensitivity: free-text sensitive, controlled types not", () => {
    expect(defaultSensitive("email")).toBe(true);
    expect(defaultSensitive("phone")).toBe(true);
    expect(defaultSensitive("longtext")).toBe(true);
    expect(defaultSensitive("select")).toBe(false);
    expect(defaultSensitive("number")).toBe(false);
    expect(defaultSensitive("url")).toBe(false);
  });
});

describe("formatFieldDisplay (table + record cells)", () => {
  const withOptions = (type: FieldDef["type"], options: { key: string; label: string }[] = []) => def({ type, options });
  it("maps select/multiselect keys to labels", () => {
    const d = withOptions("select", [{ key: "customer", label: "Customer" }]);
    expect(formatFieldDisplay(d, "customer")).toBe("Customer");
    const m = withOptions("multiselect", [{ key: "a", label: "Alpha" }, { key: "b", label: "Beta" }]);
    expect(formatFieldDisplay(m, "a,b")).toBe("Alpha, Beta");
  });
  it("formats booleans and dates, passes through text, blanks empty", () => {
    expect(formatFieldDisplay(withOptions("boolean"), "true")).toBe("Yes");
    expect(formatFieldDisplay(withOptions("date"), "2026-01-02T00:00:00Z")).toBe("2026-01-02");
    expect(formatFieldDisplay(withOptions("text"), "hello")).toBe("hello");
    expect(formatFieldDisplay(withOptions("text"), null)).toBe("");
  });
});
