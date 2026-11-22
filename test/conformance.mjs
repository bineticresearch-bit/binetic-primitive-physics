import assert from "node:assert/strict";
import {
  BPP_VERSION,
  ZERO_HASH,
  hashObject,
  issueCapability,
  verifyCapability,
  createUniverse,
  verifyPackage,
  defaultOperations,
} from "../src/bpp.mjs";

const ROOT_KEY = "test-root-key";
const actor = "creator";

function cap(namespace = "ns:test", ops = ["*"]) {
  return issueCapability(ROOT_KEY, {
    subject: actor,
    namespace,
    ops,
    expiresTick: 1000,
    label: "conformance",
  });
}

function interaction(u, opts = {}) {
  return u.interaction({
    actor: opts.actor || actor,
    capability: opts.capability || cap(opts.namespace || "ns:test", opts.ops || ["*"]),
    namespace: opts.namespace || "ns:test",
    op: opts.op,
    params: opts.params || {},
    inputs: opts.inputs || [],
    demand: opts.demand || "L0",
    external: opts.external || false,
  });
}

export async function runConformance() {
  const results = [];
  const check = (name, fn) => {
    fn();
    results.push(name);
  };

  assert.equal(BPP_VERSION, 0);
  assert.equal(ZERO_HASH.length, 64);
  assert.equal(verifyCapability(issueCapability(ROOT_KEY, { subject: actor }), ROOT_KEY), true);
  assert.equal(verifyCapability(issueCapability("wrong", { subject: actor }), ROOT_KEY), false);

  const u = createUniverse({ name: "conformance", rootKey: ROOT_KEY });

  const obs = u.apply(interaction(u, {
    op: "observe_any",
    params: { data: "hello primitive physics", kind: "text" },
    demand: "L0",
  }));
  assert.equal(obs.ok, true);
  assert.equal(obs.receipt.verdict, "admit");
  results.push("observe_any admit");

  const obsRef = obs.outputs[0];
  assert.equal(obsRef.type, "text");
  const pkg1 = u.package(1);
  const verified1 = verifyPackage(pkg1, ROOT_KEY);
  assert.equal(verified1.ok, true);
  results.push("replay verify observe_any");

  const tampered = JSON.parse(JSON.stringify(pkg1));
  tampered.receipt.afterRoot = ZERO_HASH;
  assert.equal(verifyPackage(tampered, ROOT_KEY).code, "E_RECEIPT_HASH");
  const tamperedOp = JSON.parse(JSON.stringify(pkg1));
  tamperedOp.operation.params.data = "tampered";
  assert.equal(verifyPackage(tamperedOp, ROOT_KEY).code, "E_OP_REF");
  results.push("tamper rejection");

  const seedWrite = u.apply(interaction(u, {
    op: "write_cell",
    params: { type: "baseline", id: "baseline-1", value: { x: 1 } },
    demand: "L0",
  }));
  assert.equal(seedWrite.ok, true);

  const sealed = u.apply(interaction(u, {
    op: "seal_hash",
    inputs: [{ ns: obsRef.ns, type: obsRef.type, id: obsRef.id, hash: obsRef.hash }],
    params: { type: "sealed", id: "seal-1", salt: "abc" },
    demand: "L1",
  }));
  assert.equal(sealed.ok, true);
  assert.equal(sealed.receipt.demand, "L1");
  results.push("seal_hash with input ref");

  const stale = u.apply(interaction(u, {
    op: "seal_hash",
    inputs: [{ ns: obsRef.ns, type: obsRef.type, id: obsRef.id, hash: ZERO_HASH }],
    params: { type: "sealed", id: "seal-stale" },
    demand: "L1",
  }));
  assert.equal(stale.ok, false);
  assert.equal(stale.denial, "E_STALE_CELL");
  results.push("stale ref denial");

  const tooLow = u.apply(interaction(u, {
    op: "seal_hash",
    inputs: [{ ns: obsRef.ns, type: obsRef.type, id: obsRef.id, hash: obsRef.hash }],
    params: { type: "sealed", id: "seal-low" },
    demand: "L0",
  }));
  assert.equal(tooLow.ok, false);
  assert.equal(tooLow.denial, "E_DEMAND_TOO_LOW");
  results.push("receipt demand gate");

  const baselinePkg = u.package(seedWrite.receipt.seq);
  const tamperedBefore = JSON.parse(JSON.stringify(baselinePkg));
  tamperedBefore.beforeCells = { [`ns:test::baseline::baseline-1`]: {
    ns: "ns:test", type: "baseline", id: "baseline-1", hash: ZERO_HASH,
    data: { x: 999 }, owner: actor, version: 1, updatedSeq: seedWrite.receipt.seq,
  } };
  assert.equal(verifyPackage(tamperedBefore, ROOT_KEY).code, "E_BEFORE_ROOT");
  results.push("before-state tamper rejection");

  const crossed = u.apply(interaction(u, {
    namespace: "ns:other",
    op: "observe_any",
    params: { data: "cross" },
    capability: cap("ns:test"),
  }));
  assert.equal(crossed.ok, false);
  assert.equal(crossed.denial, "E_NAMESPACE_SCOPE");
  results.push("namespace scope gate");

  const badActor = u.apply(interaction(u, {
    actor: "mallory",
    op: "noop",
    capability: cap("ns:test"),
  }));
  assert.equal(badActor.ok, false);
  assert.equal(badActor.denial, "E_ACTOR_MISMATCH");
  results.push("actor gate");

  const seqRefs = [];
  for (let i = 0; i < 3; i++) {
    const r = u.apply(interaction(u, {
      op: "write_cell",
      params: { type: "atom", id: `atom-${i}`, value: { text: ["alpha", "beta", "gamma"][i] } },
      demand: "L0",
    }));
    assert.equal(r.ok, true);
    seqRefs.push({ ns: r.outputs[0].ns, type: r.outputs[0].type, id: r.outputs[0].id, hash: r.outputs[0].hash });
  }
  const composed = u.apply(interaction(u, {
    op: "compose_sequence",
    inputs: seqRefs,
    params: { type: "sequence", id: "seq-abc" },
    demand: "L1",
  }));
  assert.equal(composed.ok, true);
  const composedVerify = verifyPackage(u.package(composed.receipt.seq), ROOT_KEY);
  assert.equal(composedVerify.ok, true);
  results.push("compose_sequence + replay");

  const routed = u.apply(interaction(u, {
    op: "route_step",
    params: {
      planned: ["v4:10.0.0.1#bit0", "v4:10.0.0.1#bit1"],
      travelled: ["v4:10.0.0.1#bit0", "v4:10.0.0.1#bit1"],
      durationsMs: [3, 5],
      arrival: "2026-11-22T00:00:00.000Z",
      type: "route",
      id: "route-1",
    },
    demand: "L2",
  }));
  assert.equal(routed.ok, true);
  assert.equal(routed.evidence.totalMs, 8);
  assert.equal(verifyPackage(u.package(routed.receipt.seq), ROOT_KEY).ok, true);
  results.push("route_step replay");

  const anchored = u.apply(interaction(u, {
    op: "anchor_external",
    params: { artifactKind: "qnp_certificate", artifactHash: "a".repeat(64), claimedLevel: "L3" },
    demand: "L1",
    external: true,
  }));
  assert.equal(anchored.ok, true);
  assert.equal(anchored.evidence.external, true);
  assert.equal(anchored.evidence.claimedLevel, "L3");
  const anchoredVer = u.ops.get("anchor_external").descriptor.deterministic;
  assert.equal(anchoredVer, false);
  results.push("external anchor explicit");

  const routeCell = routed.outputs[0];
  const decoded = u.apply(interaction(u, {
    op: "decode_phase",
    inputs: [{ ns: routeCell.ns, type: routeCell.type, id: routeCell.id, hash: routeCell.hash }],
    params: { plane: "char", passHash: hashObject("decoder-pass"), type: "symbol", id: "symbols-1" },
    demand: "L1",
  }));
  assert.equal(decoded.ok, true);
  assert.equal(decoded.outputs[0].data.symbols.length, 8);
  assert.equal(verifyPackage(u.package(decoded.receipt.seq), ROOT_KEY).ok, true);
  results.push("phase decode replay");

  const evolved = u.apply(interaction(u, {
    op: "evolve_candidate",
    params: {
      score: 99.1,
      minScore: 98.0,
      proofLevel: "L2",
      minProof: "L2",
      baselineHash: hashObject("baseline"),
      candidateHash: hashObject("candidate"),
    },
    demand: "L2",
  }));
  assert.equal(evolved.ok, true);
  assert.equal(verifyPackage(u.package(evolved.receipt.seq), ROOT_KEY).ok, true);
  results.push("evolution gate");

  const evolveReject = u.apply(interaction(u, {
    op: "evolve_candidate",
    params: { score: 50, minScore: 98, proofLevel: "L0", minProof: "L2" },
    demand: "L2",
  }));
  assert.equal(evolveReject.ok, false);
  assert.ok(["E_EVOLUTION_REJECTED", "E_PROOF_REJECTED"].includes(evolveReject.denial));
  results.push("evolution rejection");

  const allPackages = [];
  for (const receipt of u.ledger.filter((r) => r.verdict === "admit")) {
    const pkg = u.package(receipt.seq);
    const verification = verifyPackage(pkg, ROOT_KEY);
    assert.equal(verification.ok, true, `${verification.code || ""} ${verification.message || ""}`);
    allPackages.push(verification.receiptHash);
  }
  assert.equal(allPackages.length, u.ledger.filter((r) => r.verdict === "admit").length);
  results.push("full ledger replay");

  const chain = u.verifyChain();
  assert.equal(chain.ok, true);
  assert.equal(chain.records, u.ledger.length);

  const digest = u.digest();
  assert.equal(digest.chain.ok, true);
  assert.ok(digest.cells >= 10);

  const ops = defaultOperations().map((d) => d.descriptor.name);
  assert.ok(ops.includes("observe_any"));
  assert.ok(ops.includes("anchor_external"));
  assert.ok(ops.includes("evolve_candidate"));

  return {
    ok: true,
    spec: "BPP-0",
    bpp: BPP_VERSION,
    results,
    count: results.length,
    chain,
    digest: {
      head: digest.head,
      stateRoot: digest.stateRoot,
      cells: digest.cells,
      ledger: digest.ledger,
    },
    receipts: {
      observe: obs.receipt.receiptHash,
      seal: sealed.receipt.receiptHash,
      sequence: composed.receipt.receiptHash,
      route: routed.receipt.receiptHash,
      anchor: anchored.receipt.receiptHash,
      decode: decoded.receipt.receiptHash,
      evolve: evolved.receipt.receiptHash,
    },
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const result = await runConformance();
  console.log(JSON.stringify(result, null, 2));
  if (!result.ok) process.exit(1);
}
