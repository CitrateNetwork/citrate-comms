/**
 * Inference adapter for the comms agentic CRM — every persona's inference flows
 * through ONE keyed, audited, budgeted entry point: the citrate-inference-gateway's
 * OpenAI-compatible `/v1`. Cloned from `citrate-explorer/src/lib/ai/provider.ts`
 * and `citrate-chatbot/src/lib/inference/*`, extended for COMMS-AGENTS decision #5:
 * per-persona model selection + an optional admin-configured frontier fallback.
 *
 * Posture (fail-closed): in `gateway` mode a `cgk_` key is REQUIRED — a Tier-1 app
 * must not silently call an unauthenticated/unbudgeted endpoint. `local` mode (a
 * loopback llama.cpp/vLLM) is dev-only and may run keyless.
 *
 * The frontier model (e.g. a heavier writing/analysis model) is selected per-persona
 * and routed through the SAME audited key layer — preferring the gateway proxying it
 * (one budget, one audit). A dedicated direct-provider seam is intentionally NOT
 * added here: keeping a single egress keeps key custody and budgeting in one place.
 */
import type { LanguageModel } from "ai";
import { createOpenAICompatible } from "@ai-sdk/openai-compatible";

export type InferenceMode = "local" | "gateway";

/** Per-persona model ids: the default gateway model and an optional heavier route. */
export interface PersonaModel {
  gateway: string;
  frontier?: string;
}

export function resolveMode(): InferenceMode {
  const m = (process.env.CITRATE_INFERENCE_MODE ?? "gateway").toLowerCase();
  if (m === "local" || m === "gateway") return m;
  throw new Error(`Invalid CITRATE_INFERENCE_MODE="${m}" (expected local | gateway)`);
}

function gatewayClient(mode: InferenceMode) {
  const baseURL =
    mode === "gateway"
      ? (process.env.CITRATE_GATEWAY_URL ?? "https://infer.citrate.ai/v1")
      : (process.env.CITRATE_INFERENCE_URL ?? "http://127.0.0.1:8080/v1");
  const apiKey = process.env.CITRATE_GATEWAY_API_KEY ?? process.env.CITRATE_INFERENCE_API_KEY;
  // Fail-closed: the keyed/budgeted gateway must not be called without a cgk_ key.
  if (mode === "gateway" && !apiKey) {
    throw new Error(
      "CITRATE_GATEWAY_API_KEY (cgk_…) is required in gateway mode — refusing to call " +
        "the inference gateway unauthenticated (fail closed).",
    );
  }
  return createOpenAICompatible({ name: "citrate-comms", baseURL, apiKey: apiKey ?? "not-needed" });
}

/** The default model id when a persona does not pin one. */
export function defaultModelId(): string {
  return process.env.CITRATE_MODEL_NAME ?? "gemma-4-E4B-it-Q4_K_M";
}

/**
 * Resolve the LanguageModel for a persona turn. `useFrontier` is honored only when
 * the persona declares a frontier model AND the deployment enables it
 * (`COMMS_FRONTIER_ENABLED=1`) — otherwise it degrades to the gateway model so the
 * feature ships either way. Either path goes through the same audited gateway client.
 */
export function getInferenceModel(opts: { model: PersonaModel; useFrontier?: boolean }): LanguageModel {
  const mode = resolveMode();
  const client = gatewayClient(mode);
  const frontierEnabled = process.env.COMMS_FRONTIER_ENABLED === "1";
  // A template may leave `frontier` blank to mean "the deployment's frontier model".
  const frontierId = opts.model.frontier || process.env.COMMS_FRONTIER_MODEL || "";
  const modelId =
    opts.useFrontier && frontierEnabled && frontierId
      ? frontierId
      : (opts.model.gateway || defaultModelId());
  return client(modelId);
}
