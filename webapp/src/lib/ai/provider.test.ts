import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resolveMode, getInferenceModel, defaultModelId } from "./provider";

const SAVE = { ...process.env };

function clearInferenceEnv() {
  delete process.env.CITRATE_INFERENCE_MODE;
  delete process.env.CITRATE_GATEWAY_URL;
  delete process.env.CITRATE_GATEWAY_API_KEY;
  delete process.env.CITRATE_INFERENCE_API_KEY;
  delete process.env.CITRATE_MODEL_NAME;
  delete process.env.COMMS_FRONTIER_ENABLED;
  delete process.env.COMMS_FRONTIER_MODEL;
}

beforeEach(clearInferenceEnv);
afterEach(() => {
  process.env = { ...SAVE };
});

describe("inference provider", () => {
  it("defaults to gateway mode and rejects unknown modes", () => {
    expect(resolveMode()).toBe("gateway");
    process.env.CITRATE_INFERENCE_MODE = "nonsense";
    expect(() => resolveMode()).toThrow();
  });

  it("FAILS CLOSED in gateway mode without a cgk_ key", () => {
    process.env.CITRATE_INFERENCE_MODE = "gateway";
    expect(() => getInferenceModel({ model: { gateway: "m" } })).toThrow(/cgk_/i);
  });

  it("builds a model in gateway mode once a key is set", () => {
    process.env.CITRATE_INFERENCE_MODE = "gateway";
    process.env.CITRATE_GATEWAY_API_KEY = "cgk_test";
    const m = getInferenceModel({ model: { gateway: "my-model" } });
    expect(m).toBeTruthy();
  });

  it("local mode does not require a key", () => {
    process.env.CITRATE_INFERENCE_MODE = "local";
    expect(() => getInferenceModel({ model: { gateway: "" } })).not.toThrow();
  });

  it("uses the deployment default model id when the persona pins none", () => {
    expect(defaultModelId()).toBeTruthy();
    process.env.CITRATE_MODEL_NAME = "pinned-model";
    expect(defaultModelId()).toBe("pinned-model");
  });
});
