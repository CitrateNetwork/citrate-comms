import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { embed, embeddingsConfigured, embedModel } from "./embeddings";

const SAVE = { ...process.env };
function clearEnv() {
  delete process.env.CITRATE_INFERENCE_MODE;
  delete process.env.CITRATE_GATEWAY_URL;
  delete process.env.CITRATE_GATEWAY_API_KEY;
  delete process.env.CITRATE_INFERENCE_API_KEY;
  delete process.env.CITRATE_INFERENCE_URL;
  delete process.env.CITRATE_EMBED_MODEL;
}
beforeEach(clearEnv);
afterEach(() => {
  process.env = { ...SAVE };
});

describe("embeddings client (best-effort)", () => {
  it("FAILS CLOSED in gateway mode without a key — no network, returns null", async () => {
    process.env.CITRATE_INFERENCE_MODE = "gateway";
    expect(embeddingsConfigured()).toBe(false);
    expect(await embed(["hello"])).toBeNull();
  });

  it("local mode is configured without a key", () => {
    process.env.CITRATE_INFERENCE_MODE = "local";
    expect(embeddingsConfigured()).toBe(true);
  });

  it("empty input short-circuits to null (no network)", async () => {
    process.env.CITRATE_INFERENCE_MODE = "local";
    expect(await embed([])).toBeNull();
  });

  it("embed model: default + override", () => {
    expect(embedModel()).toBeTruthy();
    process.env.CITRATE_EMBED_MODEL = "bge-custom";
    expect(embedModel()).toBe("bge-custom");
  });
});
