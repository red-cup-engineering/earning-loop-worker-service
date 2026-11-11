// The on-chain engine's live scans hang off this loop's clock. When a scan URL is configured (the operation's
// onchainScanUrl, or the ONCHAIN_SCAN_URL Worker variable), each pass POSTs
// { at, cron } to it (with ONCHAIN_SCAN_TOKEN as a bearer when set) and keeps its JSON answer, expected to be
// { scanned, opportunities, fills: [{ transactionHash, mechanism, netAtomic, asset }] }. Unset, it records that
// no engine is attached, so the scorecard shows the gap instead of silence.
import { register, put } from "./registers.mjs";

export async function runOnchainHook(env, { now = new Date(), cron = null, url = env.ONCHAIN_SCAN_URL, fetchImpl = fetch } = {}) {
  const at = now.toISOString();
  if (!url) { await put(env.STATE, register("onchain"), { at, status: "no-engine-attached" }); return { status: "no-engine-attached" }; }
  try {
    const response = await fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/json", ...(env.ONCHAIN_SCAN_TOKEN ? { authorization: `Bearer ${env.ONCHAIN_SCAN_TOKEN}` } : {}) },
      body: JSON.stringify({ at, cron }),
    });
    const answer = response.headers.get("content-type")?.includes("json") ? await response.json() : null;
    const result = { at, status: response.ok ? "ran" : `http-${response.status}`, answer };
    await put(env.STATE, register("onchain"), result);
    return { status: result.status };
  } catch (error) {
    await put(env.STATE, register("onchain"), { at, status: "unreachable", error: error.message });
    return { status: "unreachable" };
  }
}
