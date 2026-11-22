import assert from "node:assert/strict";
import { createUniverse, issueCapability, verifyPackage } from "../src/bpp.mjs";
import { lowerAny } from "../src/lower.mjs";

export async function runLoweringTest() {
  const rootKey = "adapter-root";
  const cap = issueCapability(rootKey, {
    subject: "creator",
    namespace: "bridge",
    ops: ["anchor_external", "route_step", "write_cell"],
  });
  const u = createUniverse({ name: "bridge", rootKey });

  const cases = [
    ["packet", lowerAny("packet", { version: 4, kind: "tensor", body_hash: "b".repeat(64), input_hash: "c".repeat(64), output_hash: "d".repeat(64) }), "L1"],
    ["certificate", lowerAny("certificate", { certificate_hash: "e".repeat(64), schedule_hash: "f".repeat(64), chain_root: "1".repeat(64), steps: 8 }), "L3"],
    ["q", lowerAny("q", { source: "@receipt L3 flow x() -> i64[1] { emit dot(x,1); }", plan_hash: "2".repeat(64) }), "L3"],
    ["model", lowerAny("model", { modelRoot: "3".repeat(64), policyHash: "4".repeat(64) }), "L1"],
    ["route", lowerAny("route", { planned: ["a", "b"], travelled: ["a", "b"], durationsMs: [1, 2], arrivalAt: "2026-11-22T00:00:00Z" }), "L2"],
    ["atom", lowerAny("atom", { kind: "word", key: "alpha", surfaces: [{ text: "alpha", count: 1 }] }), "L0"],
  ];

  const receipts = [];
  for (const [name, low, demand] of cases) {
    const spec = u.interaction({
      actor: "creator",
      capability: cap,
      namespace: "bridge",
      op: low.op,
      params: low.params,
      demand,
      external: low.external,
    });
    const result = u.apply(spec);
    assert.equal(result.ok, true, `${name} admit failed: ${result.denial}`);
    const verified = verifyPackage(u.package(result.receipt.seq), rootKey);
    assert.equal(verified.ok, true, `${name} verify failed: ${verified.code} ${verified.message}`);
    receipts.push({ name, receipt: result.receipt.receiptHash, verified: verified.ok });
  }

  const chain = u.verifyChain();
  assert.equal(chain.ok, true);
  return { ok: true, cases: receipts, chain, digest: u.digest() };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const result = await runLoweringTest();
  console.log(JSON.stringify(result, null, 2));
  if (!result.ok) process.exit(1);
}
