/**
 * MemoryStore factory — picks the gateway when configured + healthy, else the Neon
 * fallback (decision #4). The health decision is cached briefly so we don't probe on
 * every tool call; a failed gateway in a later call still degrades safely because the
 * caller (the memory.* tools) treats a thrown gateway error as "fall back to Neon".
 */
import type { MemoryStore } from "./store";
import { NeonMemoryStore } from "./neon";
import { GatewayMemoryStore, gatewayHealthy } from "./gateway";

export * from "./store";

let cached: { store: MemoryStore; at: number } | null = null;
const TTL_MS = 60_000;

/** Resolve the active MemoryStore. Use this everywhere; never `new` a store directly. */
export async function getMemoryStore(now = Date.now()): Promise<MemoryStore> {
  if (cached && now - cached.at < TTL_MS) return cached.store;
  let store: MemoryStore;
  if (process.env.MEM_GATEWAY_URL && (await gatewayHealthy())) {
    store = new GatewayMemoryStore();
  } else {
    store = new NeonMemoryStore();
  }
  cached = { store, at: now };
  return store;
}

/** The Neon fallback, always available — used when a gateway call throws mid-flight. */
export function neonMemoryStore(): MemoryStore {
  return new NeonMemoryStore();
}
