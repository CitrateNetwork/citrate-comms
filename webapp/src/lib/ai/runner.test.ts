import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runnerConfigured, webSearch, RunnerUnavailableError } from "./runner";

const SAVE = { ...process.env };
beforeEach(() => {
  delete process.env.COMMS_RUNNER_URL;
  delete process.env.COMMS_RUNNER_BEARER;
});
afterEach(() => {
  process.env = { ...SAVE };
});

describe("comms-agent-runner client (fail-closed)", () => {
  it("unconfigured → not configured, and delegating calls throw without hitting the network", async () => {
    expect(runnerConfigured()).toBe(false);
    await expect(webSearch("anything")).rejects.toBeInstanceOf(RunnerUnavailableError);
  });

  it("requires BOTH url and bearer", () => {
    process.env.COMMS_RUNNER_URL = "http://127.0.0.1:8791";
    expect(runnerConfigured()).toBe(false); // bearer missing
    process.env.COMMS_RUNNER_BEARER = "secret";
    expect(runnerConfigured()).toBe(true);
  });
});
