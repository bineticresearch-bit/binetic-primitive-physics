# Binetic Primitive Physics (BPP-0)

BPP-0 is the formal primitive layer under BNC-1.

It defines one universal object:

```text
authorized state_before -> verified transform -> state_after + receipt
```

This repository contains:

```text
spec/BPP-0.md        formal specification
src/bpp.mjs          executable reference universe
src/lower.mjs        adapters lowering existing Binetic artifacts into BPP
test/conformance.mjs conformance suite
```

## Install/run

```bash
npm test
npm run check
```

## Core properties

- capability-gated interactions
- typed namespace cells
- typed input/output references
- deterministic replay verification
- hash-chained receipts
- explicit external anchoring
- denial codes as evolution pressure
- primitive operations for data, memory, routing, decoding, and evolution

## Universality

BPP is universal in the narrow systems sense:

```text
any domain whose state can be encoded as cells and whose transforms can be replay-verified
```

It is not a claim of AGI, infinite storage, legal authority, consensus, or physical proof.

## Existing artifact lowering

`src/lower.mjs` can lower:

```text
FabricPacket
Q stream certificate
Q program
BMF/BMF-R model artifact
FluidSpace register
route record
atom/word/op
capability/API key
```

into BPP interactions, usually as explicit external anchors.
