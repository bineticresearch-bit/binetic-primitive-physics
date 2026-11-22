# BPP-0 — Binetic Primitive Physics

Status: formal v0 reference specification.

## 0. Purpose

BPP is the primitive layer below BNC-1. It does not replace binetic-core, binetic-q, BMF, FabricPacket, QNP, or Weave. It gives them a common law: every interaction is a verified state transition in a namespace.

The reference implementation is `src/bpp.mjs`.

## 1. Universal cell

The universe is a set of cells:

```text
cell := namespace :: type :: id -> { data, hash, owner, version, updatedSeq }
```

A cell is addressed by:

```text
key = namespace + "::" + type + "::" + id
```

A reference is:

```text
ref := { ns, type, id, hash?, version? }
```

The state root is a deterministic SHA-256 commitment over all cells.

## 2. Interaction

An interaction is:

```text
I := {
  schema: "bpp.interaction.v1",
  actor,
  capability,
  namespace,
  op,
  params,
  inputs: ref[],
  demand: L0|L1|L2|L3,
  external: bool
}
```

An interaction is valid iff all accept conditions hold:

1. schema is `bpp.interaction.v1`.
2. capability is authentic under the universe root key.
3. capability subject equals actor.
4. capabilitynamespace allows target namespace.
5. capability ops allow requested op.
6. op exists.
7. operation minimum receipt level <= interaction demand.
8. all input refs resolve in the same namespace.
9. if a ref includes a hash, it matches the current cell hash.
10. op execution succeeds.

If any fail, the universe emits a `deny` receipt with a machine-readable reason and no state mutation.

Deny is not a crash. Deny is sampled evolution pressure.

## 3. Operation

An operation is:

```text
O := {
  descriptor: { name, version, minReceipt, deterministic },
  execute(ctx, params) -> { outputs, evidence, cost }
}
```

Operation identity is:

```text
opDescriptorHash = SHA256(canonical(descriptor))
```

Deterministic ops are replayable from `(beforeCells, operation)`. Non-deterministic ops must declare `deterministic=false` and are represented only through `anchor_external`.

## 4. Receipt

A receipt commits:

```text
seq
prev
hlc
actor
namespace
op
verdict
reason
demand
beforeRoot
afterRoot
opRef
capHash
inputRefs
outputRefs
evidenceHash
costHash
receiptHash
```

The receipt chain is hash-linked from genesis.

## 5. Verification package

A package contains:

```text
receipt
operation
capability
beforeCells
interaction
```

`verifyPackage` succeeds if:

1. receipt hash matches.
2. capability verifies and matches capHash.
3. operation hash matches opRef.
4. before state root matches receipt.
5. operation descriptor hash matches registry.
6. replaying operation from beforeCells produces the same afterRoot, outputs, evidence, and cost.

This is the replay law.

## 6. Composition law

If:

```text
A: S0 -> S1
B: S1 -> S2
```

and each interaction verifies, then `A |> B` verifies as a sequence of receipts with linked heads.

The outputRefs of A can be used as inputRefs of B. Cross-namespace input is denied unless explicitly bridged by a namespace-bridge op.

## 7. Invariants

### 7.1 Nothing mutates without authority

No receipt with `verdict=admit` exists without a valid capability.

### 7.2 Nothing verifies without replay

No admission package verifies if replay disagrees.

### 7.3 External truth is explicit

Unknown systems can enter only as an external artifact hash via `anchor_external`, never as hidden state.

### 7.4 Deny is deterministic

Invalid interactions produce stable denial codes.

### 7.5 Time is logical

The canonical hash uses `seq` and `prev`, not wall-clock. HLC is metadata.

### 7.6 Meaning is typed

Every output has `ns/type/id/hash`. Every input is a typed ref.

## 8. Coverage of existing Binetic artifacts

BPP lowers existing artifacts by projection:

| Existing artifact | BPP projection |
|---|---|
| FabricPacket v3/v4 | receipt + inputRefs/outputRefs |
| ReceiptIndex view | cell type index |
| plan_hash | op descriptor or param hash |
| chain_root | receipt head |
| BMF-R model root | external artifact anchor or cell data |
| namespace model entry | namespace cell |
| capability/API key | BPP capability |
| stream certificate | verification package family |
| stream schedule | deterministic op params |
| Q graph | composed interactions |
| route genome | route_step params |
| travel receipt | admitted route_step receipt |
| atom word/op | cell type `word`/`op` |
| temporal signature | receipt seq/hlc |
| FluidSpace register | namespace cell |
| Binetic Key | capability or capability wrapper |

## 9. Default primitive operations

```text
noop
observe_any
write_cell
seal_hash
transfer_cell
compose_sequence
route_step
anchor_external
decode_phase
evolve_candidate
```

These are intentionally few. They are enough to express data, models, memory, route, decode, and evolution interactions.

## 10. Universality claim

BPP is universal in the narrow sense:

Any domain whose state can be encoded as cells and whose transformations can be made replay-verifiable can be represented as BPP interactions.

It is not universal in the sense of infinite power, persuasion, law, consensus, or physical proof.

## 11. Condition for a Binetic domain

A domain D is a Binetic domain iff:

```text
1. states encode as cells
2. transforms encode as operations
3. execution emits receipts
4. receipts replay-verify
5. authority is a capability
6. namespace is explicit
7. time is logical
```

If conditions fail, D needs an adapter or external anchor.

## 12. Next gates

- BPP-1: public-key capabilities and signatures.
- BPP-2: persistent cell store snapshots.
- BPP-3: HTTP/QNP/Tailscale transport bindings.
- BPP-4: Weave/Q lowering compiler into interaction sequences.
- BPP-5: typed block library as BPP operations.
- BPP-6: route/topology and concord transitions as first-class ops.
- BPP-7: adversarial replay/conformance suite.

## Final sentence

BPP turns Binetic from a family of systems into one primitive machine:

```text
authorized state_before -> verified transform -> state_after + receipt
```
