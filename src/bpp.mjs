import crypto from "node:crypto";

export const BPP_VERSION = 0;
export const ZERO_HASH = "0".repeat(64);

export function b64u(bufferOrString) {
  const buf = Buffer.isBuffer(bufferOrString)
    ? bufferOrString
    : Buffer.from(String(bufferOrString), "utf8");
  return buf.toString("base64url");
}

export function fromB64u(text) {
  return Buffer.from(String(text), "base64url");
}

export function stable(value) {
  if (value === undefined) return "null";
  if (value === null) return "null";
  if (typeof value === "bigint") return `"bigint:${value.toString()}"`;
  if (typeof value !== "object") return JSON.stringify(value);
  if (Buffer.isBuffer(value)) return `{"__bpp_bytes":"${b64u(value)}"}`;
  if (ArrayBuffer.isView(value)) {
    const buf = Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    return `{"__bpp_bytes":"${b64u(buf)}"}`;
  }
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stable(value[k])}`).join(",")}}`;
}

export function hash(value) {
  let buf;
  if (Buffer.isBuffer(value)) buf = value;
  else if (ArrayBuffer.isView(value)) buf = Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  else if (typeof value === "string") buf = Buffer.from(value, "utf8");
  else buf = Buffer.from(stable(value), "utf8");
  return crypto.createHash("sha256").update(buf).digest("hex");
}

export function hashObject(value) {
  return hash(stable(value));
}

export function byteSize(value) {
  if (Buffer.isBuffer(value)) return value.length;
  if (ArrayBuffer.isView(value)) return value.byteLength;
  if (typeof value === "string") return Buffer.byteLength(value, "utf8");
  return Buffer.byteLength(stable(value), "utf8");
}

export function cellKey(namespace, type, id) {
  return `${namespace}::${type}::${id}`;
}

export function refFromCell(cell) {
  return {
    ns: cell.ns,
    type: cell.type,
    id: cell.id,
    hash: cell.hash,
    version: cell.version,
  };
}

export function stateRoot(cells) {
  const rows = [...cells.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, cell]) => ({
      key,
      type: cell.type,
      hash: cell.hash,
      version: cell.version,
      owner: cell.owner || null,
      updatedSeq: cell.updatedSeq || 0,
    }));
  return hashObject({ bpp: BPP_VERSION, rows });
}

function hmac(rootKey, text) {
  return crypto.createHmac("sha256", rootKey).update(text).digest();
}

export function issueCapability(rootKey, body = {}) {
  const unsigned = {
    schema: "bpp.capability.v1",
    bpp: BPP_VERSION,
    capId: body.capId || null,
    issuer: body.issuer || "bpp-root",
    subject: body.subject || "anonymous",
    namespace: body.namespace || "*",
    ops: body.ops || ["*"],
    scopes: body.scopes || ["*"],
    expiresTick: body.expiresTick ?? null,
    label: body.label || null,
  };
  unsigned.capId = hashObject({ ...unsigned, capId: null });
  return { ...unsigned, signature: b64u(hmac(rootKey, unsigned.capId)) };
}

export function verifyCapability(capability, rootKey, tick = 0) {
  if (!capability || capability.schema !== "bpp.capability.v1") return false;
  const sig = capability.signature;
  const body = { ...capability };
  delete body.signature;
  if (body.capId !== hashObject({ ...body, capId: null })) return false;
  const expected = b64u(hmac(rootKey, body.capId));
  if (sig !== expected) return false;
  if (body.bpp !== BPP_VERSION) return false;
  if (body.expiresTick !== null && Number(body.expiresTick) < Number(tick)) return false;
  return true;
}

function nsAllows(scopeNamespace, requested) {
  return scopeNamespace === "*" || scopeNamespace === requested;
}

function opAllows(scopeOps, op) {
  return Array.isArray(scopeOps) && (scopeOps.includes("*") || scopeOps.includes(op));
}

function levelValue(level) {
  const map = { L0: 0, L1: 1, L2: 2, L3: 3 };
  const v = map[String(level || "L0")];
  if (v === undefined) throw Object.assign(new Error(`invalid receipt level: ${level}`), { code: "E_INVALID_LEVEL" });
  return v;
}

function ensure(condition, code, message) {
  if (!condition) throw Object.assign(new Error(message || code), { code });
}

function resolveRef(cells, ref, namespace) {
  ensure(ref && ref.ns && ref.type && ref.id, "E_BAD_REF", "input ref requires ns/type/id");
  ensure(ref.ns === namespace, "E_CROSS_NAMESPACE", "cross-namespace input requires explicit bridge op");
  const key = cellKey(ref.ns, ref.type, ref.id);
  const cell = cells.get(key);
  ensure(cell, "E_MISSING_CELL", `missing cell ${key}`);
  if (ref.hash && ref.hash !== cell.hash) {
    throw Object.assign(new Error(`stale cell ${key}`), { code: "E_STALE_CELL" });
  }
  return cell;
}

function normalizeOutputs(outputs, namespace, actor, seq) {
  ensure(Array.isArray(outputs), "E_BAD_OUTPUTS", "operation must return outputs array");
  return outputs.map((out) => {
    ensure(out && out.type && out.id, "E_BAD_OUTPUT", "output requires type/id");
    const dataHash = out.dataHash || hash(out.data ?? null);
    return {
      ns: namespace,
      type: String(out.type),
      id: String(out.id),
      hash: dataHash,
      data: out.data,
      meta: out.meta || {},
      owner: out.owner || actor || "anonymous",
      version: 1,
      updatedSeq: seq,
    };
  });
}

function applyOutputsToCells(cells, outputs) {
  const next = new Map([...cells.entries()].map(([k, v]) => [k, { ...v }]));
  for (const out of outputs) {
    const key = cellKey(out.ns, out.type, out.id);
    const prev = next.get(key);
    next.set(key, {
      ...out,
      version: (prev?.version || 0) + 1,
    });
  }
  return next;
}

export function receiptBodyFrom(receipt) {
  return {
    schema: receipt.schema,
    bpp: receipt.bpp,
    universe: receipt.universe,
    seq: receipt.seq,
    prev: receipt.prev,
    hlc: receipt.hlc,
    actor: receipt.actor,
    namespace: receipt.namespace,
    op: receipt.op,
    verdict: receipt.verdict,
    reason: receipt.reason ?? null,
    demand: receipt.demand,
    beforeRoot: receipt.beforeRoot,
    afterRoot: receipt.afterRoot,
    opRef: receipt.opRef,
    capHash: receipt.capHash,
    inputRefs: receipt.inputRefs || [],
    outputRefs: receipt.outputRefs || [],
    evidenceHash: receipt.evidenceHash,
    costHash: receipt.costHash,
  };
}

export function outputRefs(outputs) {
  return outputs.map((out) => ({
    ns: out.ns,
    type: out.type,
    id: out.id,
    hash: out.hash,
    version: out.version,
  }));
}

const descriptor = (name, version, minReceipt, deterministic = true) => ({
  name,
  version,
  minReceipt,
  deterministic,
});

export function defaultOperations() {
  return [
    {
      descriptor: descriptor("noop", 1, "L0"),
      execute: () => ({ outputs: [], evidence: { note: "no state change" }, cost: { bytes: 0, units: 1 } }),
    },
    {
      descriptor: descriptor("observe_any", 1, "L0"),
      execute: (_ctx, params = {}) => {
        ensure(params.data !== undefined, "E_NO_DATA", "observe_any requires data");
        const dataHash = hash(params.data);
        const id = String(params.id || dataHash.slice(0, 32));
        return {
          outputs: [{ type: params.type || params.kind || "observation", id, data: params.data, meta: { kind: params.kind || "any" } }],
          evidence: { dataHash, size: byteSize(params.data), kind: params.kind || "any" },
          cost: { bytes: byteSize(params.data), units: 2 },
        };
      },
    },
    {
      descriptor: descriptor("write_cell", 1, "L0"),
      execute: (_ctx, params = {}) => {
        ensure(params.type && params.id && params.value !== undefined, "E_BAD_WRITE", "write_cell requires type/id/value");
        return {
          outputs: [{ type: params.type, id: params.id, data: params.value }],
          evidence: { valueHash: hash(params.value) },
          cost: { bytes: byteSize(params.value), units: 2 },
        };
      },
    },
    {
      descriptor: descriptor("seal_hash", 1, "L1"),
      execute: (ctx, params = {}) => {
        const refs = ctx.inputRefs.map(refFromCell);
        const root = hashObject({ inputs: refs, salt: params.salt ?? null });
        return {
          outputs: [{ type: params.type || "hash", id: params.id || root.slice(0, 32), data: { root, inputs: refs } }],
          evidence: { root, inputCount: refs.length },
          cost: { bytes: 64 + refs.length * 96, units: 3 },
        };
      },
    },
    {
      descriptor: descriptor("transfer_cell", 1, "L1"),
      execute: (ctx, params = {}) => {
        ensure(ctx.inputs.length === 1, "E_BAD_TRANSFER", "transfer_cell requires exactly one input");
        const src = ctx.inputs[0];
        return {
          outputs: [{ type: params.type || src.type, id: params.id || src.id, data: src.data, dataHash: src.hash, meta: { source: refFromCell(src) } }],
          evidence: { sourceHash: src.hash },
          cost: { bytes: 96, units: 2 },
        };
      },
    },
    {
      descriptor: descriptor("compose_sequence", 1, "L1"),
      execute: (ctx, params = {}) => {
        const refs = ctx.inputRefs.map(refFromCell);
        const seqHash = hashObject({ refs, separator: params.separator ?? "|" });
        return {
          outputs: [{ type: params.type || "sequence", id: params.id || seqHash.slice(0, 32), data: { refs, hash: seqHash } }],
          evidence: { sequenceHash: seqHash, itemCount: refs.length },
          cost: { bytes: 64 + refs.length * 96, units: 2 + refs.length },
        };
      },
    },
    {
      descriptor: descriptor("route_step", 1, "L2"),
      execute: (_ctx, params = {}) => {
        const planned = Array.isArray(params.planned) ? params.planned : [];
        const travelled = Array.isArray(params.travelled) ? params.travelled : planned;
        const durationsMs = Array.isArray(params.durationsMs) ? params.durationsMs.map(Number) : [];
        const totalMs = durationsMs.reduce((a, b) => a + b, 0);
        const routeHash = hashObject({
          planned,
          travelled,
          durationsMs,
          totalMs,
          arrival: params.arrival ?? null,
        });
        return {
          outputs: [{ type: params.type || "route", id: params.id || routeHash.slice(0, 32), data: { planned, travelled, durationsMs, totalMs, arrival: params.arrival ?? null, routeHash } }],
          evidence: { routeHash, plannedHops: planned.length, travelledHops: travelled.length, totalMs },
          cost: { bytes: byteSize({ planned, travelled, durationsMs }), units: 4 },
        };
      },
    },
    {
      descriptor: descriptor("anchor_external", 1, "L1", false),
      execute: (_ctx, params = {}) => {
        ensure(params.artifactHash && /^[0-9a-f]{64}$/.test(params.artifactHash), "E_BAD_ARTIFACT", "anchor_external requires 64-hex artifactHash");
        const data = {
          artifactKind: params.artifactKind || "external",
          artifactHash: params.artifactHash,
          claimedLevel: params.claimedLevel || "external",
          verifierRef: params.verifierRef || null,
          external: true,
        };
        return {
          outputs: [{ type: params.type || "external_artifact", id: params.id || params.artifactHash.slice(0, 32), data, meta: { external: true } }],
          evidence: { artifactHash: params.artifactHash, external: true, claimedLevel: params.claimedLevel || "external" },
          cost: { bytes: 128, units: 2 },
        };
      },
    },
    {
      descriptor: descriptor("decode_phase", 1, "L1"),
      execute: (ctx, params = {}) => {
        ensure(ctx.inputs.length >= 1, "E_BAD_DECODE", "decode_phase requires an input cell");
        const source = ctx.inputs[0];
        const table = Array.isArray(params.table) && params.table.length ? params.table : ["B", "I", "N", "E", "T", "C", "O", "X"];
        const bytes = Buffer.from(source.hash, "hex");
        const values = [];
        const symbols = [];
        for (let i = 0; i < 8; i++) {
          const v = bytes[i] % table.length;
          values.push(v);
          symbols.push(table[v]);
        }
        const decoded = hashObject({ plane: params.plane || "char", passHash: params.passHash || null, values });
        return {
          outputs: [{ type: params.type || "symbol", id: params.id || decoded.slice(0, 32), data: { plane: params.plane || "char", passHash: params.passHash || null, values, symbols } }],
          evidence: { decoded, plane: params.plane || "char", symbolCount: symbols.length },
          cost: { bytes: byteSize(symbols), units: 3 },
        };
      },
    },
    {
      descriptor: descriptor("evolve_candidate", 1, "L2"),
      execute: (_ctx, params = {}) => {
        const score = Number(params.score);
        const minScore = Number(params.minScore ?? 0);
        const requested = levelValue(params.proofLevel || "L0");
        const required = levelValue(params.minProof || "L2");
        ensure(Number.isFinite(score), "E_BAD_SCORE", "evolve_candidate requires finite score");
        ensure(score >= minScore, "E_EVOLUTION_REJECTED", `score ${score} < ${minScore}`);
        ensure(requested >= required, "E_PROOF_REJECTED", "evolution proof level too low");
        const championHash = hashObject({
          baselineHash: params.baselineHash || ZERO_HASH,
          candidateHash: params.candidateHash || ZERO_HASH,
          score,
          proofLevel: params.proofLevel || "L0",
        });
        return {
          outputs: [{ type: params.type || "champion", id: params.id || championHash.slice(0, 32), data: { baselineHash: params.baselineHash || ZERO_HASH, candidateHash: params.candidateHash || ZERO_HASH, score, proofLevel: params.proofLevel || "L0" } }],
          evidence: { championHash, score, minScore, proofLevel: params.proofLevel || "L0" },
          cost: { bytes: 192, units: 5 },
        };
      },
    },
  ];
}

export class PrimitivePhysicsError extends Error {
  constructor(code, message) {
    super(message || code);
    this.code = code;
  }
}

export class PrimitiveUniverse {
  constructor(options = {}) {
    this.name = options.name || "bpp-local";
    this.rootKey = options.rootKey || "bpp-development-root-key";
    this.cells = options.cells instanceof Map ? new Map([...options.cells.entries()].map(([k, v]) => [k, { ...v }])) : new Map();
    this.ops = new Map();
    for (const def of options.operations || defaultOperations()) this.registerOp(def);
    this.head = options.head || ZERO_HASH;
    this.tick = options.tick || 0;
    this.ledger = [];
    this.operationsByReceipt = new Map();
    this.beforeByReceipt = new Map();
    this.capByReceipt = new Map();
    this.specByReceipt = new Map();
  }

  registerOp(def) {
    ensure(def && def.descriptor && typeof def.execute === "function", "E_BAD_OP_DEF", "operation requires descriptor/execute");
    this.ops.set(def.descriptor.name, def);
    return this;
  }

  operationDigest(defOrName) {
    const def = typeof defOrName === "string" ? this.ops.get(defOrName) : defOrName;
    ensure(def && def.descriptor, "E_UNKNOWN_OP", "unknown operation");
    return hashObject({ descriptor: def.descriptor, bpp: BPP_VERSION });
  }

  read(namespace, type, id) {
    return this.cells.get(cellKey(namespace, type, id)) || null;
  }

  root() {
    return stateRoot(this.cells);
  }

  apply(spec = {}) {
    const seq = this.tick + 1;
    const beforeRoot = this.root();
    const beforeCells = new Map([...this.cells.entries()].map(([k, v]) => [k, { ...v }]));
    const prev = this.head;
    const hlc = `${seq.toString(16).padStart(12, "0")}:${prev.slice(0, 8)}:${this.name}`;
    const namespace = spec.namespace || "bpp:null";
    const opName = String(spec.op || "invalid");
    const actor = String(spec.actor || "anonymous");
    const demand = String(spec.demand || "L0");
    const inputRefs = Array.isArray(spec.inputs) ? spec.inputs : [];
    let verdict = "admit";
    let reason = null;
    let outputs = [];
    let evidence = {};
    let cost = { bytes: 0, units: 0 };
    let operation = null;

    try {
      ensure(spec && spec.schema === "bpp.interaction.v1", "E_BAD_ENVELOPE", "interaction schema required");
      ensure(spec.capability, "E_NO_CAPABILITY", "capability required");
      ensure(verifyCapability(spec.capability, this.rootKey, seq), "E_BAD_CAPABILITY", "capability invalid");
      ensure(spec.capability.subject === actor, "E_ACTOR_MISMATCH", "capability subject does not match actor");
      ensure(nsAllows(spec.capability.namespace, namespace), "E_NAMESPACE_SCOPE", "capability does not permit namespace");
      ensure(opAllows(spec.capability.ops, opName), "E_OP_SCOPE", "capability does not permit op");
      const def = this.ops.get(opName);
      ensure(def, "E_UNKNOWN_OP", `unknown op ${opName}`);
      ensure(levelValue(def.descriptor.minReceipt) <= levelValue(demand), "E_DEMAND_TOO_LOW", "demand below operation minimum");
      ensure(levelValue(demand) <= 3, "E_INVALID_LEVEL", "invalid demand");
      const inputCells = inputRefs.map((ref) => resolveRef(beforeCells, ref, namespace));
      operation = {
        schema: "bpp.operation.v1",
        bpp: BPP_VERSION,
        actor,
        namespace,
        op: opName,
        opDescriptorHash: this.operationDigest(def),
        params: spec.params ?? {},
        inputs: inputRefs,
        demand,
        external: Boolean(spec.external),
      };
      const ctx = { actor, namespace, seq, inputRefs, inputs: inputCells };
      const result = def.execute(ctx, operation.params) || {};
      outputs = normalizeOutputs(result.outputs || [], namespace, actor, seq);
      evidence = result.evidence || {};
      cost = result.cost || { bytes: 0, units: 0 };
      if (!def.descriptor.deterministic) evidence.external = true;
    } catch (err) {
      verdict = "deny";
      reason = err && err.code ? err.code : String(err && err.message ? err.message : err);
      outputs = [];
      evidence = { denial: reason };
      cost = { bytes: byteSize(spec), units: 1 };
      operation = operation || {
        schema: "bpp.operation.v1",
        bpp: BPP_VERSION,
        actor,
        namespace,
        op: opName,
        opDescriptorHash: ZERO_HASH,
        params: spec.params ?? null,
        inputs: inputRefs,
        demand,
        external: Boolean(spec.external),
        denial: reason,
      };
    }

    const afterCells = verdict === "admit" ? applyOutputsToCells(beforeCells, outputs) : beforeCells;
    const afterRoot = stateRoot(afterCells);
    const opRef = hashObject(operation);
    const capHash = spec.capability ? hashObject(spec.capability) : ZERO_HASH;
    const evidenceHash = hashObject(evidence);
    const costHash = hashObject(cost);
    const receiptBody = {
      schema: "bpp.receipt.v1",
      bpp: BPP_VERSION,
      universe: this.name,
      seq,
      prev,
      hlc,
      actor,
      namespace,
      op: opName,
      verdict,
      reason: verdict === "deny" ? reason : null,
      demand,
      beforeRoot,
      afterRoot,
      opRef,
      capHash,
      inputRefs,
      outputRefs: outputRefs(outputs),
      evidenceHash,
      costHash,
      receiptHash: null,
    };
    receiptBody.receiptHash = hashObject(receiptBodyFrom(receiptBody));

    if (verdict === "admit") this.cells = afterCells;
    this.head = receiptBody.receiptHash;
    this.tick = seq;
    this.ledger.push(receiptBody);
    this.operationsByReceipt.set(this.head, operation);
    this.beforeByReceipt.set(this.head, beforeCells);
    this.capByReceipt.set(this.head, spec.capability);
    this.specByReceipt.set(this.head, spec);

    return {
      ok: verdict === "admit",
      receipt: receiptBody,
      outputs: verdict === "admit" ? outputs : [],
      evidence: verdict === "admit" ? evidence : {},
      denial: verdict === "deny" ? reason : null,
    };
  }

  interaction({ actor, capability, namespace, op, params, inputs, demand, external }) {
    return {
      schema: "bpp.interaction.v1",
      bpp: BPP_VERSION,
      actor,
      capability,
      namespace,
      op,
      params: params || {},
      inputs: inputs || [],
      demand: demand || "L0",
      external: Boolean(external),
    };
  }

  package(seq) {
    const receipt = this.ledger.find((r) => r.seq === seq);
    if (!receipt) return null;
    const h = receipt.receiptHash;
    return {
      schema: "bpp.verification-package.v1",
      receipt,
      operation: this.operationsByReceipt.get(h),
      capability: this.capByReceipt.get(h),
      beforeCells: Object.fromEntries(this.beforeByReceipt.get(h) || new Map()),
      interaction: this.specByReceipt.get(h),
    };
  }

  verifyChain() {
    let prev = ZERO_HASH;
    for (let i = 0; i < this.ledger.length; i++) {
      const receipt = this.ledger[i];
      const body = receiptBodyFrom(receipt);
      if (receipt.seq !== i + 1) return { ok: false, at: i, reason: "seq" };
      if (receipt.prev !== prev) return { ok: false, at: i, reason: "prev" };
      if (hashObject(body) !== receipt.receiptHash) return { ok: false, at: i, reason: "hash" };
      prev = receipt.receiptHash;
    }
    return { ok: true, records: this.ledger.length, head: prev };
  }

  digest() {
    return {
      bpp: BPP_VERSION,
      head: this.head,
      stateRoot: this.root(),
      cells: this.cells.size,
      ledger: this.ledger.length,
      chain: this.verifyChain(),
    };
  }
}

export function verifyPackage(pkg, rootKey, opRegistry = null) {
  try {
    ensure(pkg && pkg.schema === "bpp.verification-package.v1", "E_BAD_PACKAGE", "bad package");
    const { receipt, operation, capability } = pkg;
    const body = { ...receipt };
    const canonicalBody = receiptBodyFrom(receipt);
    ensure(hashObject(canonicalBody) === receipt.receiptHash, "E_RECEIPT_HASH", "receipt hash mismatch");
    ensure(verifyCapability(capability, rootKey, receipt.seq), "E_CAPABILITY", "capability invalid");
    ensure(hashObject(capability) === receipt.capHash, "E_CAP_HASH", "capability hash mismatch");
    ensure(operation && operation.schema === "bpp.operation.v1", "E_OP_SPEC", "operation spec missing");
    ensure(hashObject(operation) === receipt.opRef, "E_OP_REF", "operation ref mismatch");
    ensure(operation.op === receipt.op, "E_OP_NAME", "operation name mismatch");

    const beforeCells = new Map(Object.entries(pkg.beforeCells || {}).map(([k, v]) => [k, v]));
    ensure(stateRoot(beforeCells) === receipt.beforeRoot, "E_BEFORE_ROOT", "before root mismatch");

    const registry = opRegistry || new Map(defaultOperations().map((d) => [d.descriptor.name, d]));
    const def = registry.get(operation.op);
    ensure(def, "E_UNKNOWN_OP", "unknown operation");

    const inputCells = operation.inputs.map((ref) => resolveRef(beforeCells, ref, operation.namespace));
    const result = def.execute({ actor: operation.actor, namespace: operation.namespace, seq: receipt.seq, inputRefs: operation.inputs, inputs: inputCells }, operation.params) || {};
    const outputs = normalizeOutputs(result.outputs || [], operation.namespace, operation.actor, receipt.seq);
    const afterCells = applyOutputsToCells(beforeCells, outputs);
    const evidence = result.evidence || {};
    const cost = result.cost || { bytes: 0, units: 0 };

    ensure(stateRoot(afterCells) === receipt.afterRoot, "E_AFTER_ROOT", "after root mismatch");
    ensure(hashObject(outputRefs(outputs)) === hashObject(receipt.outputRefs), "E_OUTPUTS", "outputs mismatch");
    ensure(hashObject(evidence) === receipt.evidenceHash, "E_EVIDENCE", "evidence mismatch");
    ensure(hashObject(cost) === receipt.costHash, "E_COST", "cost mismatch");
    return { ok: true, seq: receipt.seq, receiptHash: receipt.receiptHash };
  } catch (err) {
    return { ok: false, code: err.code || "E_VERIFY", message: err.message || String(err) };
  }
}

export function createUniverse(options) {
  return new PrimitiveUniverse(options);
}
