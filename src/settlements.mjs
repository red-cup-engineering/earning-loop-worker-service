// Receive market.561.group's x402 sales without a house machine: list the seller's settlement witnesses in R2,
// corroborate each against two independent public Base providers, and classify the payer as outside or Group.
// The rule is Red Cup's confirmSellerWitness (x402-services-section, settlement-derivation): both receipts agree,
// the transaction succeeded, and it holds exactly one USDC transfer from the payer to the seller for the amount.
// A corroborated transfer is cash received; it is not delivery, acceptance or recognized revenue.
import { register, read, put } from "./registers.mjs";

export const BASE_USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
export const BASE_PROVIDERS = [
  "https://mainnet.base.org",
  "https://base-rpc.publicnode.com",
  "https://base.llamarpc.com",
  "https://1rpc.io/base",
];
const TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const PREFIX = "settlements/eip155:8453/";
const TX = /^0x[\da-f]{64}$/i, ADDRESS = /^0x[\da-f]{40}$/i;
const topic = (address) => `0x${"0".repeat(24)}${address.slice(2).toLowerCase()}`;

export function matchingTransfers(receipt, witness) {
  return (receipt?.logs ?? []).filter((log) => log.address?.toLowerCase() === BASE_USDC
    && log.topics?.[0]?.toLowerCase() === TRANSFER
    && log.topics?.[1]?.toLowerCase() === topic(witness.payer)
    && log.topics?.[2]?.toLowerCase() === topic(witness.payTo)
    && /^0x[\da-f]{1,64}$/i.test(log.data ?? "") && BigInt(log.data).toString() === witness.amount);
}

export function witnessProblem(witness) {
  if (witness?.network !== "eip155:8453" || !TX.test(witness.transaction ?? "")) return "invalid-transaction";
  if (!ADDRESS.test(witness.payer ?? "") || !ADDRESS.test(witness.payTo ?? "")) return "invalid-address";
  if (witness.asset?.toLowerCase() !== BASE_USDC) return "not-base-usdc";
  if (!/^[1-9]\d*$/.test(witness.amount ?? "")) return "invalid-amount";
  return null;
}

export function corroborate(witness, receipts) {
  const problem = witnessProblem(witness);
  if (problem) return { ok: false, reason: problem };
  if (receipts.length < 2) return { ok: false, reason: "two-provider-receipts-required", retry: true };
  const [a, b] = receipts;
  if (a.status !== "0x1") return { ok: false, reason: "failed-transaction" };
  if (a.blockHash?.toLowerCase() !== b.blockHash?.toLowerCase() || a.transactionHash?.toLowerCase() !== witness.transaction.toLowerCase()
    || matchingTransfers(a, witness).length !== matchingTransfers(b, witness).length) return { ok: false, reason: "provider-disagreement", retry: true };
  const transfers = matchingTransfers(a, witness);
  if (transfers.length !== 1) return { ok: false, reason: "exactly-one-matching-usdc-transfer-required" };
  return { ok: true, receipt: a, transfer: transfers[0] };
}

export const usdc = (atomic) => Number(BigInt(atomic)) / 1e6;

async function receiptsFor(hash, fetchImpl) {
  const read = async (url) => {
    try {
      const response = await fetchImpl(url, { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getTransactionReceipt", params: [hash] }) });
      const body = await response.json();
      return response.ok && body.result ? body.result : null;
    } catch { return null; }
  };
  const found = [];
  for (const url of BASE_PROVIDERS) {
    if (found.length === 2) break;
    const receipt = await read(url);
    if (receipt) found.push(receipt);
  }
  return found;
}

/** One receiving pass: at most `limit` new witnesses, two provider reads each. */
export async function receiveSettlements(env, { now = new Date(), limit = 8, groupPayers = new Set(), fetchImpl = fetch } = {}) {
  const key = register("settlements");
  const state = (await read(env.STATE, key)) ?? { settlements: {}, refused: {} };
  const seen = new Set([...Object.values(state.settlements).map((s) => s.witnessKey), ...Object.keys(state.refused).filter((k) => !state.refused[k].retry)]);
  const fresh = [];
  let cursor;
  do {
    const page = await env.MARKET_SETTLEMENTS.list({ prefix: PREFIX, cursor });
    for (const object of page.objects) if (!seen.has(object.key)) fresh.push(object.key);
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor && fresh.length < limit);
  const received = [];
  for (const witnessKey of fresh.slice(0, limit)) {
    const witness = await (await env.MARKET_SETTLEMENTS.get(witnessKey))?.json();
    const checked = witness ? corroborate(witness, await receiptsFor(witness.transaction, fetchImpl)) : { ok: false, reason: "witness-disappeared" };
    if (!checked.ok) { state.refused[witnessKey] = { reason: checked.reason, retry: !!checked.retry, at: now.toISOString() }; continue; }
    delete state.refused[witnessKey];
    const payer = witness.payer.toLowerCase();
    const sourceId = `evm:eip155:8453:${BASE_USDC}:${witness.payTo.toLowerCase()}:${witness.transaction.toLowerCase()}:${BigInt(checked.transfer.logIndex)}`;
    const settlement = {
      sourceId, witnessKey, transactionHash: witness.transaction.toLowerCase(), payer, receiver: witness.payTo.toLowerCase(),
      amount: witness.amount, usd: usdc(witness.amount), payerClass: groupPayers.has(payer) ? "group" : "outside",
      route: witness.route ?? null, method: witness.method ?? null, gateway: witness.gateway ?? null, sku: witness.sku ?? null,
      ledgerAccount: witness.ledgerAccount ?? null, blockNumber: Number(BigInt(checked.receipt.blockNumber)),
      recordedAt: witness.recordedAt ?? null, corroboratedAt: now.toISOString(),
    };
    state.settlements[sourceId] = settlement;
    received.push(settlement);
  }
  state.at = now.toISOString();
  await put(env.STATE, key, state);
  return { received, refused: Object.keys(state.refused).length, total: Object.keys(state.settlements).length };
}
