// Derived from the work order's admitted examples, before the operation's source was derived.
import assert from "node:assert/strict";
import test from "node:test";
import { issuerSettlementCustodyPlan } from "../src/issuer-settlement-custody.mjs";

test("issuer-settlement-custody-plan: admitted", async () => {
  assert.deepStrictEqual(await issuerSettlementCustodyPlan({"enabled":true,"resourceAdmission":{"status":"received"},"network":"eip155:8453","asset":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913","payTo":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","operation":"issuer-revenue-comparison","method":"POST","route":"/v1/issuer-revenue-comparison","sku":"fixture-issuer-sku","gateway":"fixture-issuer-gateway","ledgerAccount":"Income:Sales:X402:IssuerResearch","amount":"50000"}), {"prefix":"issuer-settlements/","metadataKey":"issuer-settlements/capacity","witnessPrefix":"issuer-settlements/witness/","pendingPrefix":"issuer-settlements/pending/","receiptPrefix":"issuer-settlements/receipt/","objectName":"earning-loops","path":"/issuer-settlement-witness","maximumRecords":50000,"maximumCustodyBytes":268435456,"maximumRawWitnessBytes":32768,"maximumTransactionBytes":1900000,"maximumWitnessesPerPulse":4,"maximumProviderAttemptsPerWitness":4,"maximumRpcBytes":262144,"network":"eip155:8453","asset":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913","payTo":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","operation":"issuer-revenue-comparison","method":"POST","route":"/v1/issuer-revenue-comparison","sku":"fixture-issuer-sku","gateway":"fixture-issuer-gateway","ledgerAccount":"Income:Sales:X402:IssuerResearch","amount":"50000","maximumWorkerCallsPerPulse":50});
});
test("issuer-settlement-custody-plan: disabled", async () => {
  assert.deepStrictEqual(await issuerSettlementCustodyPlan({"enabled":false,"resourceAdmission":{"status":"received"},"network":"eip155:8453","asset":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913","payTo":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","operation":"issuer-revenue-comparison","method":"POST","route":"/v1/issuer-revenue-comparison","sku":"fixture-issuer-sku","gateway":"fixture-issuer-gateway","ledgerAccount":"Income:Sales:X402:IssuerResearch","amount":"50000"}), null);
});
test("issuer-settlement-custody-plan: clause assay normalized-addresses-fixed-coordinates-and-ceilings-only", async () => {
  assert.deepStrictEqual(await issuerSettlementCustodyPlan({"enabled":true,"resourceAdmission":{"status":"received"},"network":"eip155:8453","asset":"0x833589FCD6EDB6E08F4C7C32D4F71B54BDA02913","payTo":"0xABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD","operation":"issuer-revenue-comparison","method":"POST","route":"/v1/issuer-revenue-comparison","sku":"issuer-annual","gateway":"issuer-gateway","ledgerAccount":"Income:Issuer","amount":"50000","prefix":"arbitrary/","objectName":"other-object","path":"/public","maximumWorkerCallsPerPulse":999,"maximumRecords":999999}), {"prefix":"issuer-settlements/","metadataKey":"issuer-settlements/capacity","witnessPrefix":"issuer-settlements/witness/","pendingPrefix":"issuer-settlements/pending/","receiptPrefix":"issuer-settlements/receipt/","objectName":"earning-loops","path":"/issuer-settlement-witness","maximumRecords":50000,"maximumCustodyBytes":268435456,"maximumRawWitnessBytes":32768,"maximumTransactionBytes":1900000,"maximumWitnessesPerPulse":4,"maximumProviderAttemptsPerWitness":4,"maximumRpcBytes":262144,"network":"eip155:8453","asset":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913","payTo":"0xabcdefabcdefabcdefabcdefabcdefabcdefabcd","operation":"issuer-revenue-comparison","method":"POST","route":"/v1/issuer-revenue-comparison","sku":"issuer-annual","gateway":"issuer-gateway","ledgerAccount":"Income:Issuer","amount":"50000","maximumWorkerCallsPerPulse":50});
});
test("issuer-settlement-custody-plan: clause assay absent-configuration", async () => {
  assert.deepStrictEqual(await issuerSettlementCustodyPlan(null), null);
});
test("issuer-settlement-custody-plan: clause assay truthy-enabled-is-not-exact-true", async () => {
  assert.deepStrictEqual(await issuerSettlementCustodyPlan({"enabled":"true","resourceAdmission":{"status":"received"}}), null);
});
test("issuer-settlement-custody-plan: clause assay admitted-missing-identity-throws", async () => {
  await assert.rejects(async () => await issuerSettlementCustodyPlan({"enabled":true,"resourceAdmission":{"status":"received"}}), { name: "TypeError" });
});
test("issuer-settlement-custody-plan: clause assay leading-zero-amount-rejected", async () => {
  await assert.rejects(async () => await issuerSettlementCustodyPlan({"enabled":true,"resourceAdmission":{"status":"received"},"network":"eip155:8453","asset":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913","payTo":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","operation":"issuer-revenue-comparison","method":"POST","route":"/v1/issuer-revenue-comparison","sku":"issuer","gateway":"gateway","ledgerAccount":"Income:Issuer","amount":"050000"}), { name: "TypeError" });
});
test("issuer-settlement-custody-plan: clause assay wrong-asset-rejected", async () => {
  await assert.rejects(async () => await issuerSettlementCustodyPlan({"enabled":true,"resourceAdmission":{"status":"received"},"network":"eip155:8453","asset":"0x1111111111111111111111111111111111111111","payTo":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","operation":"issuer-revenue-comparison","method":"POST","route":"/v1/issuer-revenue-comparison","sku":"issuer","gateway":"gateway","ledgerAccount":"Income:Issuer","amount":"50000"}), { name: "TypeError" });
});
test("issuer-settlement-custody-plan: clause assay other-operation-rejected", async () => {
  await assert.rejects(async () => await issuerSettlementCustodyPlan({"enabled":true,"resourceAdmission":{"status":"received"},"network":"eip155:8453","asset":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913","payTo":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","operation":"other-offer","method":"POST","route":"/v1/issuer-revenue-comparison","sku":"issuer","gateway":"gateway","ledgerAccount":"Income:Issuer","amount":"50000"}), { name: "TypeError" });
});
test("issuer-settlement-custody-plan: clause assay trailing-slash-route-rejected", async () => {
  await assert.rejects(async () => await issuerSettlementCustodyPlan({"enabled":true,"resourceAdmission":{"status":"received"},"network":"eip155:8453","asset":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913","payTo":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","operation":"issuer-revenue-comparison","method":"POST","route":"/v1/issuer-revenue-comparison/","sku":"issuer","gateway":"gateway","ledgerAccount":"Income:Issuer","amount":"50000"}), { name: "TypeError" });
});
test("issuer-settlement-custody-plan: clause assay gateway-carriage-return-rejected", async () => {
  await assert.rejects(async () => await issuerSettlementCustodyPlan({"enabled":true,"resourceAdmission":{"status":"received"},"network":"eip155:8453","asset":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913","payTo":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","operation":"issuer-revenue-comparison","method":"POST","route":"/v1/issuer-revenue-comparison","sku":"issuer","gateway":"gate\rway","ledgerAccount":"Income:Issuer","amount":"50000"}), { name: "TypeError" });
});
