import { createOpenTaskClient } from "./opentask-client.mjs";
import { commercialOffers, commercialStateKey, acquirePreparedBid } from "./opentask-bid-acquisition.mjs";
import { BASE_USDC } from './settlements.mjs';
import { runBidObservationPass } from "./existing-commercial-bid-observation.mjs";

const STATE = "opentask/commercial";
const stable = (value) => value && typeof value === "object" ? Array.isArray(value) ? value.map(stable)
  : Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])])) : value;
export async function fingerprint(value) {
  const bytes = new TextEncoder().encode(JSON.stringify(stable(value)));
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), (n) => n.toString(16).padStart(2, "0")).join("");
}
const publicResult = (stage, calls = 0) => ({ stage, requests: calls, newCashExpenseUsd: 0 });
const address = (v) => typeof v === "string" && /^0x[0-9a-f]{40}$/i.test(v);
const https = (v) => { try { const u = new URL(v); return u.protocol === "https:" && !u.username && !u.password && !u.search && !u.hash; } catch { return false; } };
const same = (a, b) => JSON.stringify(stable(a)) === JSON.stringify(stable(b));

export function qualifiedInstance(instance, product, merchant) {
  if (!instance?.enabled) return "disabled";
  if (['productId','profileId','taskId','bidId','buyerId'].some(key => !/^[A-Za-z0-9_-]{1,200}$/.test(instance[key] ?? '')) ||
      !/^[1-9][0-9]{0,17}$/.test(instance.priceAmountAtomic ?? '') || typeof instance.priceText !== 'string' || !instance.priceText || instance.priceText.length > 100 || instance.priceCurrency !== "USDC" ||
      instance.network !== "BASE" || instance.maximumNewCashExpenseUsd !== 0 || !address(merchant)) return "instance-refused";
  const amount = /^(\d+)(?:\.(\d{1,6}))? USDC$/.exec(instance.priceText);
  if (!amount || BigInt(amount[1]) * 1000000n + BigInt((amount[2] ?? '').padEnd(6, '0')) !== BigInt(instance.priceAmountAtomic)) return 'price-refused';
  if (!product || !https(product.artifactUrl) || !https(product.sourceUrl) || !/^[a-f0-9]{64}$/.test(product.artifactSha256 ?? "") ||
      !/^[a-f0-9]{40}$/.test(product.sourceCommit ?? "") || typeof product.verificationInstructions !== "string" ||
      !product.criteriaEvidence || typeof product.criteriaEvidence !== "object" ||
      !Number.isSafeInteger(product.maximumInputBytes) || product.maximumInputBytes <= 0 ||
      !Number.isSafeInteger(instance.maximumInputBytes) || instance.maximumInputBytes <= 0 || instance.maximumInputBytes > product.maximumInputBytes) return "product-refused";
  return null;
}

export function contractMatches(contract, instance) {
  return contract?.source === "bid" && contract.task?.id === instance.taskId && contract.bid?.id === instance.bidId &&
    contract.seller?.id === instance.profileId && contract.buyer?.id === instance.buyerId &&
    contract.bid?.priceText === instance.priceText && ["in_progress", "submitted", "accepted", "rejected"].includes(contract.status);
}

function deliveryAllowed(context, instance) {
  const c = context.contract;
  // REST profile eligibility and fresh actor-specific actions govern REST.
  // /docs/hosted-mcp's operational.writeToolsAvailable governs that distinct
  // transport; autonomous DPoP credentials do not authenticate hosted MCP.
  const feature = c.nativeDeliveryAvailability;
  return feature?.globallyEnabled === true && feature.eligible === true && feature.enabled === true &&
    (context.availableActions ?? c.availableActions ?? []).some((action) =>
      action.schemaVersion === "opentask-available-actions-v1" && ["prepare_delivery", "revise_delivery"].includes(action.action) &&
      action.entity?.type === "contract" && action.entity.id === c.id && action.state === "available" &&
      action.actor?.eligibleProfileId === instance.profileId && action.actor.role === "worker" &&
      action.actor.requiredScopeMode === 'all' && Array.isArray(action.actor.requiredScopes) && action.actor.requiredScopes.length > 0 &&
      action.actor.requiredScopes.every(scope => ['deliveries:read', 'deliveries:write'].includes(scope)) &&
      (action.payment === null || (action.payment?.required === false && [null, '0'].includes(action.payment.amountAtomic))) && ["GET", "POST"].includes(action.invocation?.method) &&
      action.invocation?.endpoint === `/api/agent/contracts/${c.id}/deliveries` &&
      (!action.availableAfter || Date.parse(action.availableAfter) <= Date.now()) &&
      (!action.availableUntil || Date.parse(action.availableUntil) > Date.now()));
}

export function criterionClaims(pkg, product, artifactId) {
  if (!Array.isArray(pkg.criteria)) return null;
  const claims = [];
  for (const criterion of pkg.criteria) {
    const note = Object.hasOwn(product.criteriaEvidence, criterion.text) ? product.criteriaEvidence[criterion.text] : null;
    if (typeof criterion.id !== "string" || typeof note !== "string" || !note) return null;
    claims.push({ criterionId: criterion.id, claim: "satisfied", note, artifactIds: [artifactId] });
  }
  return claims;
}

function receivedPackage(pkg, contractId, product) {
  const artifact = pkg.artifacts?.find(a => a.externalUrl === product.artifactUrl &&
    a.description === `SHA-256 ${product.artifactSha256}; source ${product.sourceCommit}`);
  if (pkg.contractId !== contractId || pkg.milestoneId || !artifact || !Number.isSafeInteger(pkg.revision) || pkg.revision < 1 ||
      !/^(?:sha256:)?[a-f0-9]{64}$/i.test(pkg.manifestDigest ?? '')) return false;
  const expected = criterionClaims(pkg, product, artifact.id);
  return expected && same(expected, pkg.criteria.map(c => ({ criterionId: c.id, claim: c.sellerClaim, note: c.sellerNote, artifactIds: c.artifactIds })));
}

export function buyerConfirmation(message, expected, buyerId) {
  if (message?.author?.id !== buyerId || message.author.kind !== "agent" || typeof message.body !== "string" || message.body.length > 8000) return null;
  let value;
  try { value = JSON.parse(message.body); } catch { return null; }
  if (!value || !same(Object.keys(value).sort(), Object.keys(expected).sort())) return null;
  if (!Number.isSafeInteger(value.maximumInputBytes) || value.maximumInputBytes <= 0 || value.maximumInputBytes > expected.maximumInputBytes) return null;
  return same({ ...value, maximumInputBytes: expected.maximumInputBytes }, expected) ? value : null;
}

/** One durable stage per pulse; only the selected prepared CSV offer can write.
 * storage is PRIVATE Durable Object storage, never the public R2 registers.
 */
export async function runCommercialPass(options = {}) {
  const observation = options.observation ?? options.instance?.bidObservation;
  if (!options.instance?.enabled && observation?.enabled === true) {
    const client = (options.clientFactory ?? createOpenTaskClient)({
      storage: options.storage,
      initialCredential: options.initialCredential,
      fetchImpl: options.fetchImpl,
      budget: 12,
      now: options.clock ?? (() => Date.now())
    });
    let observationSummary = null;
    try {
      observationSummary = await runBidObservationPass({
        storage: options.storage,
        client,
        configuration: observation,
        now: options.now ?? new Date(),
        releaseId: options.releaseId
      });
    } catch {}
    return {
      stage: 'disabled',
      requests: client.calls,
      newCashExpenseUsd: 0,
      ...(observationSummary ? { observation: observationSummary } : {})
    };
  }
  const offers = commercialOffers(options.instance);
  if (offers.length === 1) return runPreparedCommercialPass(options);
  const slotKey = 'opentask/commercial-selector';
  const ordinal = await options.storage.get(slotKey) ?? 0;
  const selected = offers[ordinal % offers.length];
  await options.storage.put(slotKey, (ordinal + 1) % offers.length);
  const stateKey = commercialStateKey(options.instance, selected);
  const result = await runPreparedCommercialPass({ ...options, instance: selected, stateKey });
  return { ...result, taskId: selected.taskId, productId: selected.productId };
}

async function runPreparedCommercialPass({ storage, initialCredential, instance, products, merchant, stateKey = STATE,
  now = new Date(), clientFactory = createOpenTaskClient, fetchImpl = fetch, clock = () => Date.now(),
  observation, releaseId } = {}) {
  const STATE = stateKey;
  const product = products?.[instance?.productId];
  const refusal = qualifiedInstance({ ...instance, bidId: instance?.bidId ?? '_pending' }, product, merchant);
  if (refusal) return publicResult(refusal);
  const client = clientFactory({ storage, initialCredential, fetchImpl, budget: 12, now: clock });
  let state = await storage.get(STATE) ?? { stage: "discover", revisions: 0, observations: {} };
  const finish = async (stage) => {
    state.stage = stage;
    state.observedAt = now.toISOString();
    await storage.put(STATE, state);
    let observationSummary = null;
    const observationConfig = observation ?? instance?.bidObservation;
    if (observationConfig?.enabled === true) {
      try {
        observationSummary = await runBidObservationPass({
          storage,
          client,
          configuration: observationConfig,
          now,
          releaseId
        });
      } catch (err) {}
    }
    return {
      ...publicResult(stage, client.calls),
      ...(observationSummary ? { observation: observationSummary } : {})
    };
  };
  if (state.retryBlocked || Date.parse(state.nextAttemptAt) > now.getTime()) {
    let observationSummary = null;
    const observationConfig = observation ?? instance?.bidObservation;
    if (observationConfig?.enabled === true) {
      try {
        observationSummary = await runBidObservationPass({
          storage,
          client,
          configuration: observationConfig,
          now,
          releaseId
        });
      } catch (err) {}
    }
    return {
      ...publicResult('provider-retry-deferred', client.calls),
      ...(observationSummary ? { observation: observationSummary } : {})
    };
  }
  try {
    if (!instance.bidId && !state.bidId) {
      const stage = await acquirePreparedBid({ client, instance, state, now, save: () => storage.put(STATE, state) });
      return finish(stage);
    }
    instance = { ...instance, bidId: instance.bidId ?? state.bidId };
    if (!state.contractId) {
      const page = await client.request(`/api/agent/contracts?role=seller&limit=20${state.cursor ? `&cursor=${encodeURIComponent(state.cursor)}` : ""}`);
      const found = page.contracts?.filter((c) => contractMatches(c, instance)) ?? [];
      if (found.length > 1) return finish("multiple-contracts-held");
      if (!found.length) { state.cursor = page.nextCursor ?? null; return finish("awaiting-hire"); }
      state.contractId = found[0].id;
      state.cursor = null;
      return finish("hire-discovered");
    }
    if (!/^[A-Za-z0-9_-]{1,200}$/.test(state.contractId)) return finish("contract-id-held");
    const base = `/api/agent/contracts/${state.contractId}`;
    const context = await client.request(base), contract = context.contract;
    if (!contractMatches(contract, instance)) return finish("contract-mismatch");
    if (!contract.termsSnapshot || typeof contract.termsSnapshot !== 'object' || Array.isArray(contract.termsSnapshot)) return finish('terms-shape-held');
    const termsDigest = await fingerprint(contract.termsSnapshot);
    state.observations.hire = { contractId: contract.id, termsSnapshotSha256: termsDigest, source: "bid", status: contract.status };
    const productDigest = await fingerprint(product);
    if (state.productDigest && state.productDigest !== productDigest) return finish("product-drift-held");
    if (state.termsDigest && state.termsDigest !== termsDigest) return finish("terms-drift-held");
    state.productDigest = productDigest; state.termsDigest = termsDigest;
    const payout = await client.request(base + "/payout-destination");
    // Exact response field selected from the provider's typed destination model.
    const destination = payout.currentDestination;
    const payee = destination?.address;
    if (payout.contractId !== contract.id || payout.role !== "seller" || payout.currentDestinationActive !== true || payout.blockedReason ||
        !address(payee) || payee.toLowerCase() !== merchant.toLowerCase() || destination.token !== "USDC" || !["BASE", "EVM"].includes(destination.network)) return finish("payee-held");
    state.observations.payee = { address: merchant.toLowerCase(), at: now.toISOString() };

    const expected = { ...(product.agreement ?? { schema: "opentask-csv-agreement-v1", nullEncoding: "empty-string", missingEncoding: "empty-string", booleanEncoding: "lowercase", columns: "first-seen-union", acceptanceCommand: "python3 -m pytest -q test/test_json_to_csv.py" }), contractId: contract.id, productId: instance.productId,
      sourceCommit: product.sourceCommit, artifactSha256: product.artifactSha256, termsSnapshotSha256: termsDigest,
      maximumInputBytes: instance.maximumInputBytes,
      machineAcceptance: true, buyerFundsSettlement: true, maximumSellerCashExpenseUsd: 0 };
    const permissionBasis = { availability: contract.nativeDeliveryAvailability, actions: context.availableActions ?? contract.availableActions };
    if (!state.agreement || state.agreement.termsSnapshotSha256 !== termsDigest) {
      const page = await client.request(`${base}/messages?limit=20${state.messageCursor ? `&cursor=${encodeURIComponent(state.messageCursor)}` : ""}`);
      const agreed = (page.messages ?? []).map((message) => ({ message, confirmation: buyerConfirmation(message, expected, instance.buyerId) })).find((v) => v.confirmation);
      if (agreed) { state.agreement = agreed.confirmation; state.agreementMessageId = agreed.message.id; state.messageCursor = null; if (state.pending?.kind === 'agreement') state.pending = null; return finish("buyer-agreement-received"); }
      state.messageCursor = page.nextCursor ?? null;
      if (state.messageCursor) return finish("agreement-history-pending");
      const body = { body: `Please confirm the conditional CSV offer by replying with this exact JSON object (maximumInputBytes may be reduced). Your agent must execute the acceptance command, review the delivery criteria and fund Base USDC settlement; seller spends zero. This confirmation permits only the prepared source/artifact below; no arbitrary commands or new work are accepted.\n${JSON.stringify(expected)}` };
      const key = `csv-agreement:${await fingerprint(expected)}`;
      if (state.agreementRequest?.key === key && state.agreementRequest.received) return finish("agreement-pending");
      if (state.pending && state.pending.kind !== "agreement") return finish("uncertain-effect-held");
      state.pending = { kind: "agreement", path: `${base}/messages`, method: "POST", body, key };
      const basis = await fingerprint(permissionBasis);
      if (state.deniedEffect?.key === key && state.deniedEffect.basis === basis) return finish('provider-write-refused');
      state.effectBasis = basis;
      await storage.put(STATE, state);
      const sent = await client.request(`${base}/messages`, { method: "POST", body, key });
      if (sent.ok !== true || typeof sent.id !== "string") return finish("agreement-send-readback-pending");
      state.agreementRequest = { key, received: true, messageId: sent.id };
      state.pending = null;
      return finish("agreement-requested");
    }

    // Settlement and buyer acceptance are observed separately, never invoked.
    state.observations.acceptance = { contractStatus: contract.status };
    if (contract.hasRouterPaymentProofIssue) return finish("payment-proof-held");
    if (contract.hasRouterVerifiedPayment && contract.verifiedCryptoPaymentRequest?.id) {
      const id = contract.verifiedCryptoPaymentRequest.id;
      const value = await client.request(`${base}/crypto-payment-requests/${id}`);
      const payment = value.paymentRequest ?? value.request ?? value;
      if (payment.id !== id || payment.contractId !== contract.id || payment.status !== "verified" || payment.sellerAddress?.toLowerCase() !== merchant.toLowerCase() ||
          payment.chainId !== 8453 || payment.tokenSymbol !== "USDC" || payment.tokenDecimals !== 6 ||
          payment.tokenAddress?.toLowerCase() !== BASE_USDC ||
          payment.sellerAmountAtomic !== instance.priceAmountAtomic || !/^0x[0-9a-f]{64}$/i.test(payment.paidTxHash ?? "") ||
          !/^\d+$/.test(payment.paidBlockNumber ?? "") || !Number.isSafeInteger(payment.paidLogIndex) || payment.paidLogIndex < 0 || !payment.verifiedAt) return finish("payment-proof-held");
      state.observations.settlement = { authority: "opentask-router", requestId: id, transactionHash: payment.paidTxHash,
        blockNumber: payment.paidBlockNumber, logIndex: payment.paidLogIndex, amountAtomic: payment.sellerAmountAtomic, receiver: merchant.toLowerCase(), verifiedAt: payment.verifiedAt };
      if (!state.observations.delivery?.manifestDigest) return finish('settlement-reported-delivery-unreceived');
      return finish(contract.status === "accepted" ? "accepted-and-settlement-reported" : "settlement-reported-awaiting-acceptance");
    }
    if (contract.status === "accepted") return finish("acceptance-observed-awaiting-proof");

    const title = `Prepared CSV ${product.sourceCommit.slice(0, 12)}`;
    const listed = await client.request(base + "/deliveries");
    const packages = listed.deliveries ?? listed.packages;
    if (!Array.isArray(packages)) return finish("delivery-shape-held");
    if (listed.nextCursor) return finish("delivery-history-held"); // never infer absence from a truncated page
    const drafts = packages.filter((p) => p.status === "draft");
    const own = drafts.filter((p) => p.title === title);
    if (drafts.length > 1 || (drafts.length && own.length !== 1)) return finish("existing-draft-held");
    let pkg = own[0];
    if (pkg && state.pending?.kind === "create") state.pending = null;
    const immutable = packages.filter((p) => p.title === title && p.status !== "draft").sort((a, b) => (b.revision ?? 0) - (a.revision ?? 0))[0];
    if (!pkg && immutable && immutable.status !== "changes_requested") {
      if (!receivedPackage(immutable, contract.id, product)) return finish('immutable-evidence-held');
      state.observations.delivery = { packageId: immutable.id, revision: immutable.revision, manifestDigest: immutable.manifestDigest, status: immutable.status };
      state.pending = null;
      return finish("submitted-awaiting-buyer");
    }
    if (!deliveryAllowed(context, instance)) return finish("delivery-action-held");

    if (!pkg) {
      if (immutable?.status === "changes_requested") {
        const reviewed = (await client.request(`${base}/deliveries/${immutable.id}`)).delivery ?? immutable;
        const changes = reviewed.criteria?.filter((c) => c.buyerDecision === "changes_requested") ?? [];
        if (state.revisions >= 1 || !changes.length || changes.some((c) => !Object.hasOwn(product.criteriaEvidence, c.text) ||
            (c.buyerComment && !Object.hasOwn(product.criteriaEvidence, c.buyerComment)))) return finish("requested-change-held");
      }
      const body = { title, summary: `${product.name}. Source ${product.sourceCommit}; archive SHA-256 ${product.artifactSha256}.`,
        verificationInstructions: product.verificationInstructions, ...(immutable ? { basedOnDeliveryPackageId: immutable.id } : {}) };
      return await effect("create", base + "/deliveries", "POST", body);
    }
    const detail = await client.request(`${base}/deliveries/${pkg.id}`);
    pkg = detail.delivery ?? detail.package ?? detail;
    if (pkg.status !== "draft" || pkg.availableActions?.edit !== true) return finish("draft-edit-held");
    if (pkg.title !== title || pkg.contractId !== contract.id || pkg.milestoneId) return finish("draft-scope-held");
    const artifact = pkg.artifacts?.find((a) => a.externalUrl === product.artifactUrl && a.description === `SHA-256 ${product.artifactSha256}; source ${product.sourceCommit}`);
    if (artifact && state.pending?.kind === "attach") state.pending = null;
    if (!artifact) return await effect("attach", `${base}/deliveries/${pkg.id}/external-artifacts`, "POST", {
      expectedVersion: pkg.version, kind: "archive", label: product.name, url: product.artifactUrl,
      description: `SHA-256 ${product.artifactSha256}; source ${product.sourceCommit}`,
    });
    const claims = criterionClaims(pkg, product, artifact.id);
    if (!claims) return finish("criterion-evidence-held");
    const currentClaims = pkg.criteria.map((c) => ({ criterionId: c.id, claim: c.sellerClaim, note: c.sellerNote, artifactIds: c.artifactIds }));
    if (same(claims, currentClaims) && state.pending?.kind === "claim") state.pending = null;
    if (!same(claims, currentClaims)) return await effect("claim", `${base}/deliveries/${pkg.id}`, "PATCH", {
      expectedVersion: pkg.version, criteria: claims,
      ...(immutable ? { changeSummary: "Clarified evidence for the unchanged frozen prepared product against the requested criteria." } : {}),
    });
    if (pkg.availableActions?.submit !== true) return finish("draft-submit-held");
    return await effect("submit", `${base}/deliveries/${pkg.id}/submit`, "POST", { expectedVersion: pkg.version, confirmed: true });

    async function effect(kind, path, method, body) {
      const pending = { kind, path, method, body, key: `csv:${await fingerprint({ contractId: contract.id, kind, path, body })}` };
      const basis = await fingerprint({ ...permissionBasis, packageId: pkg?.id ?? null, packageVersion: pkg?.version ?? null });
      if (state.deniedEffect?.key === pending.key && state.deniedEffect.basis === basis) return finish('provider-write-refused');
      if (state.deniedEffect && state.deniedEffect.key === state.pending?.key && state.deniedEffect.basis !== basis) { state.pending = null; state.deniedEffect = null; }
      if (state.pending && !same(state.pending, pending)) return finish("uncertain-effect-held");
      state.pending = pending;
      state.effectBasis = basis;
      await storage.put(STATE, state); // retain exact intent before HTTP
      const result = await client.request(path, { method, body, key: pending.key });
      if (kind === "submit") {
        const delivered = result.delivery ?? result.package ?? result;
        if (!delivered.manifestDigest || !Number.isSafeInteger(delivered.revision)) return finish("submission-readback-pending");
        state.observations.delivery = { packageId: delivered.id, revision: delivered.revision, manifestDigest: delivered.manifestDigest, status: delivered.status };
        if (immutable) state.revisions++;
      }
      state.pending = null;
      return finish(kind + "-received");
    }
  } catch (error) {
    // The private state retains exact intent; the public register receives a code only.
    state.lastFailure = /^[a-z0-9_-]{1,100}$/.test(error.code ?? "") ? error.code : "commercial-failure";
    if (error.retryBlocked) state.retryBlocked = true;
    else if (Number.isFinite(error.retryAt)) state.nextAttemptAt = new Date(error.retryAt).toISOString();
    if (error.retryAfter) state.retryAfter = error.retryAfter;
    if (state.pending && (error.status === 403 || error.status === 503 || /^native_delivery_/.test(error.code ?? '')))
      state.deniedEffect = { key: state.pending.key, code: state.lastFailure, status: error.status, basis: state.effectBasis };
    return finish(state.pending ? "effect-readback-pending" : state.lastFailure);
  }
}
