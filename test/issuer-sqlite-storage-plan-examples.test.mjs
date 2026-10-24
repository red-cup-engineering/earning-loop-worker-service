// Derived from the work order's admitted examples, before the operation's source was derived.
import assert from "node:assert/strict";
import test from "node:test";
import { issuerSqliteStoragePlan } from "../src/issuer-sqlite-cache.mjs";

test("issuer-sqlite-storage-plan: admitted", async () => {
  assert.deepStrictEqual(await issuerSqliteStoragePlan({"enabled":true,"resourceAdmission":{"status":"received"},"cacheKey":"issuer-research/current.json","maximumCohortBytes":524288}), {"cohortKey":"issuer-evidence/cohort","statusKey":"issuer-evidence/status","logicalStatusKey":"registers/earning-loops/issuer-research.json","cacheKey":"issuer-research/current.json","maximumCohortBytes":524288,"maximumStatusBytes":524288,"maximumTransactionBytes":1900000});
});
test("issuer-sqlite-storage-plan: disabled", async () => {
  assert.deepStrictEqual(await issuerSqliteStoragePlan({"enabled":false,"resourceAdmission":{"status":"received"},"cacheKey":"issuer-research/current.json","maximumCohortBytes":524288}), null);
});
test("issuer-sqlite-storage-plan: clause assay admitted-fixed-coordinates", async () => {
  assert.deepStrictEqual(await issuerSqliteStoragePlan({"enabled":true,"resourceAdmission":{"status":"received"},"cacheKey":"issuer-research/current.json","maximumCohortBytes":524288}), {"cohortKey":"issuer-evidence/cohort","statusKey":"issuer-evidence/status","logicalStatusKey":"registers/earning-loops/issuer-research.json","cacheKey":"issuer-research/current.json","maximumCohortBytes":524288,"maximumStatusBytes":524288,"maximumTransactionBytes":1900000});
});
test("issuer-sqlite-storage-plan: clause assay absent-configuration", async () => {
  assert.deepStrictEqual(await issuerSqliteStoragePlan(null), null);
});
test("issuer-sqlite-storage-plan: clause assay disabled-precedes-invalid-fields", async () => {
  assert.deepStrictEqual(await issuerSqliteStoragePlan({"enabled":false,"resourceAdmission":{"status":"received"},"cacheKey":"","maximumCohortBytes":0}), null);
});
test("issuer-sqlite-storage-plan: clause assay empty-cache-key", async () => {
  await assert.rejects(async () => await issuerSqliteStoragePlan({"enabled":true,"resourceAdmission":{"status":"received"},"cacheKey":"","maximumCohortBytes":1}), { name: "TypeError" });
});
test("issuer-sqlite-storage-plan: clause assay reserved-logical-status-key", async () => {
  await assert.rejects(async () => await issuerSqliteStoragePlan({"enabled":true,"resourceAdmission":{"status":"received"},"cacheKey":"registers/earning-loops/issuer-research.json","maximumCohortBytes":1}), { name: "TypeError" });
});
test("issuer-sqlite-storage-plan: clause assay zero-cohort-limit", async () => {
  await assert.rejects(async () => await issuerSqliteStoragePlan({"enabled":true,"resourceAdmission":{"status":"received"},"cacheKey":"cache","maximumCohortBytes":0}), { name: "TypeError" });
});
test("issuer-sqlite-storage-plan: clause assay cohort-limit-over-maximum", async () => {
  await assert.rejects(async () => await issuerSqliteStoragePlan({"enabled":true,"resourceAdmission":{"status":"received"},"cacheKey":"cache","maximumCohortBytes":524289}), { name: "TypeError" });
});
test("issuer-sqlite-storage-plan: clause assay trusted-coordinate-overrides-ignored", async () => {
  assert.deepStrictEqual(await issuerSqliteStoragePlan({"enabled":true,"resourceAdmission":{"status":"received"},"cacheKey":"cache","maximumCohortBytes":1,"cohortKey":"other","statusKey":"other-status","logicalStatusKey":"other-logical","maximumTransactionBytes":9999999}), {"cohortKey":"issuer-evidence/cohort","statusKey":"issuer-evidence/status","logicalStatusKey":"registers/earning-loops/issuer-research.json","cacheKey":"cache","maximumCohortBytes":1,"maximumStatusBytes":524288,"maximumTransactionBytes":1900000});
});
