// test/workerd-issuer-driver.mjs
import assert from "node:assert/strict";
var testPrivateSqliteCache = {
  async test(controller, env) {
    const object = env.CLOCK.get(env.CLOCK.idFromName("earning-loops"));
    assert.equal((await env.MARKET.fetch("https://market.invalid/read")).status, 404);
    const seeded = await (await object.fetch("https://private.invalid/fixture/seed")).json();
    const first = await env.MARKET.fetch("https://market.invalid/read");
    assert.equal(first.status, 200);
    assert.deepEqual(await first.json(), { complete: true, marker: "\xE9\u{1F642}" });
    await object.fetch("https://private.invalid/fixture/failure");
    const second = await env.MARKET.fetch("https://market.invalid/read");
    assert.deepEqual(await second.json(), { complete: true, marker: "\xE9\u{1F642}" });
    const wrong = await object.fetch("https://private.invalid/issuer-evidence?key=opentask%2Fauth");
    assert.equal(wrong.status, 404);
    const inspected = await (await object.fetch("https://private.invalid/fixture/inspect")).json();
    assert.deepEqual(inspected.auth, { marker: "PRIVATE-TEST-CUSTODY" });
    assert.equal(inspected.alarm, seeded.alarm);
    assert.deepEqual(inspected.keys, ["issuer-evidence/cohort", "issuer-evidence/status", "opentask/auth"]);
  }
};
export {
  testPrivateSqliteCache
};
