import { hashObject, hash } from "./bpp.mjs";

export function lowerFabricPacket(packet = {}) {
  const preimage = {
    schema: "bpp.external.fabric-packet.v1",
    version: packet.version ?? null,
    kind: packet.kind ?? packet.kind_code ?? null,
    seq: packet.seq ?? null,
    modelId: packet.model_id ?? packet.modelId ?? null,
    layerId: packet.layer_id ?? packet.layerId ?? null,
    opCode: packet.op_code ?? packet.opCode ?? null,
    blockId: packet.block_id ?? packet.blockId ?? null,
    vportId: packet.vport_id ?? packet.vportId ?? null,
    routeId: packet.route_id ?? packet.routeId ?? null,
    hopIndex: packet.hop_index ?? packet.hopIndex ?? null,
    hopCount: packet.hop_count ?? packet.hopCount ?? null,
    prevHash: packet.prev_hash ?? packet.prevHash ?? null,
    bodyHash: packet.body_hash ?? packet.bodyHash ?? null,
    inputHash: packet.input_hash ?? packet.inputHash ?? null,
    outputHash: packet.output_hash ?? packet.outputHash ?? null,
    stateBefore: packet.state_before ?? packet.stateBefore ?? null,
    stateAfter: packet.state_after ?? packet.stateAfter ?? null,
    payloadLength: packet.payload_length ?? packet.payloadLength ?? null,
  };
  const artifactHash = hashObject(preimage);
  return {
    op: "anchor_external",
    params: {
      artifactKind: "binetic.fabric.packet",
      artifactHash,
      claimedLevel: packet.verificationLevel || "L1",
      verifierRef: packet.body_hash || packet.bodyHash || null,
    },
    external: true,
    preimage,
  };
}

export function lowerStreamCertificate(certificate = {}, options = {}) {
  const artifactHash = options.artifactHash || hashObject({
    schema: "bpp.external.stream-certificate.v1",
    certificateHash: certificate.certificate_hash ?? certificate.certificateHash ?? null,
    scheduleHash: certificate.schedule_hash ?? certificate.scheduleHash ?? null,
    planHash: certificate.plan_hash ?? certificate.planHash ?? null,
    chainRoot: certificate.chain_root ?? certificate.chainRoot ?? null,
    steps: certificate.steps ?? null,
    feedback: certificate.feedback ?? null,
    effect: certificate.effect ?? certificate.demand ?? null,
    finalOutput: certificate.final_output ?? certificate.finalOutput ?? null,
  });
  return {
    op: "anchor_external",
    params: {
      artifactKind: "binetic.q.stream_certificate",
      artifactHash,
      claimedLevel: certificate.claimedLevel || "L3",
      verifierRef: options.verifierRef || null,
    },
    external: true,
  };
}

export function lowerQProgram(program = {}) {
  const source = program.source ?? program.program ?? null;
  const planHash = program.planHash ?? program.plan_hash ?? null;
  const artifactHash = hashObject({
    schema: "bpp.external.q-program.v1",
    source,
    planHash,
    scheduleHash: program.scheduleHash ?? program.schedule_hash ?? null,
    demand: program.demand ?? null,
  });
  return {
    op: "anchor_external",
    params: {
      artifactKind: "binetic.q.program",
      artifactHash,
      claimedLevel: program.receiptLevel || "L3",
      verifierRef: planHash,
    },
    external: true,
  };
}

export function lowerModelArtifact(artifact = {}) {
  const artifactHash = artifact.modelRoot ?? artifact.model_root ?? artifact.capsuleRoot ?? artifact.capsule_root ?? artifact.bmfRoot ?? null;
  if (!artifactHash || !/^[0-9a-f]{64}$/.test(String(artifactHash))) {
    throw new Error("model lowering requires a 64-hex modelRoot/capsuleRoot");
  }
  return {
    op: "anchor_external",
    params: {
      artifactKind: artifact.kind || "binetic.bmf-r",
      artifactHash: String(artifactHash),
      claimedLevel: artifact.claimedLevel || "external",
      verifierRef: artifact.policyHash ?? artifact.policy_hash ?? null,
    },
    external: true,
  };
}

export function lowerFluidRegister(register = {}) {
  return {
    op: "write_cell",
    params: {
      type: "fluid.register",
      id: register.id || register.address || hashObject(register).slice(0, 32),
      value: {
        ipv4: register.ipv4 ?? null,
        ipv6: register.ipv6 ?? null,
        slot: register.slot ?? null,
        lanes: register.lanes ?? null,
        meta: register.meta ?? null,
      },
    },
    demand: "L0",
    external: false,
  };
}

export function lowerRouteRecord(record = {}) {
  return {
    op: "route_step",
    params: {
      planned: record.planned ?? record.plannedRoute ?? record.plan?.hops ?? [],
      travelled: record.travelled ?? record.travelledRoute ?? record.travel ?? [],
      durationsMs: record.durationsMs ?? record.durations_ms ?? record.timing?.durationsMs ?? [],
      arrival: record.arrival ?? record.arrivalAt ?? record.arrival_at ?? null,
      type: "route",
      id: record.id || hashObject(record).slice(0, 32),
    },
    demand: "L2",
    external: false,
  };
}

export function lowerAtom(atom = {}) {
  return {
    op: "write_cell",
    params: {
      type: atom.kind || "atom",
      id: atom.id || atom.key || hashObject(atom).slice(0, 32),
      value: {
        key: atom.key ?? null,
        surfaces: atom.surfaces ?? atom.surface ?? null,
        body: atom.body ?? null,
      },
    },
    demand: "L0",
    external: false,
  };
}

export function lowerCapability(capability = {}) {
  const artifactHash = hashObject({
    schema: "bpp.external.capability.v1",
    keyId: capability.keyId ?? capability.key_id ?? null,
    tenant: capability.tenantId ?? capability.tenant_id ?? null,
    namespace: capability.namespace ?? null,
    scopes: capability.scopes ?? null,
    modelRoot: capability.modelRoot ?? capability.model_root ?? null,
  });
  return {
    op: "anchor_external",
    params: {
      artifactKind: "binetic.capability",
      artifactHash,
      claimedLevel: capability.claimedLevel || "L1",
      verifierRef: capability.signature ?? null,
    },
    external: true,
  };
}

export function lowerAny(kind, artifact, options = {}) {
  switch (String(kind).toLowerCase()) {
    case "fabricpacket":
    case "packet":
      return lowerFabricPacket(artifact);
    case "streamcertificate":
    case "certificate":
      return lowerStreamCertificate(artifact, options);
    case "qprogram":
    case "q":
      return lowerQProgram(artifact);
    case "model":
    case "bmfr":
    case "capsule":
      return lowerModelArtifact(artifact);
    case "fluid":
    case "register":
      return lowerFluidRegister(artifact);
    case "route":
      return lowerRouteRecord(artifact);
    case "atom":
    case "word":
    case "op":
      return lowerAtom(artifact);
    case "capability":
    case "apikey":
      return lowerCapability(artifact);
    default:
      return {
        op: "anchor_external",
        params: {
          artifactKind: String(kind || "unknown"),
          artifactHash: options.artifactHash || hash(artifact),
          claimedLevel: options.claimedLevel || "external",
          verifierRef: options.verifierRef || null,
        },
        external: true,
      };
  }
}
