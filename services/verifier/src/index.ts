import { createServer } from "node:http";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as signSignature,
  verify as verifySignature,
} from "node:crypto";
import { URL } from "node:url";
import { DEMO_PRINCIPALS, type BaseEventEnvelope } from "@safr-x-atp-demo/protocol";
import {
  PolicyRepository,
  PrincipalKeyRepository,
  createSharedDatabase,
  type PrincipalSigningKey,
} from "@safr-x-atp-demo/storage";

const port = Number(process.env.PORT ?? 4103);
const eventServiceBaseUrl = process.env.EVENT_SERVICE_URL ?? "http://localhost:4101";
const archiveServiceBaseUrl = process.env.ARCHIVE_SERVICE_URL ?? "http://localhost:4102";
const identityServiceBaseUrl = process.env.IDENTITY_SERVICE_URL ?? "http://localhost:4105";
const agentPublicKeyPath =
  process.env.AGENT_PUBLIC_KEY_PATH ??
  "/Users/xyz/Documents/github/safr_x_atp_demo/services/agent-service/keys/agent_ed25519_public.pem";
const verifierPrivateKeyPath =
  process.env.VERIFIER_PRIVATE_KEY_PATH ??
  "/Users/xyz/Documents/github/safr_x_atp_demo/services/verifier/keys/verifier_ed25519_private.pem";
const verifierPublicKeyPath =
  process.env.VERIFIER_PUBLIC_KEY_PATH ??
  "/Users/xyz/Documents/github/safr_x_atp_demo/services/verifier/keys/verifier_ed25519_public.pem";
const verifierKeyId = process.env.VERIFIER_KEY_ID ?? "verifier_demo_01#ed25519#v1";
const registeredAgentKeyIds = new Set(
  (process.env.REGISTERED_AGENT_KEY_IDS ?? "ag_transfer_01#ed25519#v1")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean),
);
const sharedDb = createSharedDatabase();
const policyRepository = new PolicyRepository(sharedDb);
const principalKeyRepository = new PrincipalKeyRepository(sharedDb);
ensureVerifierKeys();
syncSigningRegistry();

type UnknownContent = Record<string, unknown>;

interface EventServiceRecord {
  eventId: string;
  flowId: string;
  kind: number;
  aiId: string;
  createdAt: number;
  payload: BaseEventEnvelope<UnknownContent>;
}

interface CurrentPolicyResponse {
  bundle: ReturnType<PolicyRepository["getActiveBundle"]>;
  policy: ReturnType<PolicyRepository["getPolicyForCurrency"]>;
}

interface EvaluationInput {
  flowId: string;
  envelopeEventId: string;
}

interface ReverifyInput {
  flowId: string;
  adminReviewEventId: string;
  firstVerifierEventId: string;
  envelopeEventId: string;
  instructionEventId: string;
}

interface AdminReviewContent {
  verifier_record_ref?: string;
  admin_id?: string;
  decision?: string;
  comment?: string;
  signature_proof?: {
    passkey_verified?: boolean;
    proof_ref?: string;
  };
}

interface SignatureProofContent {
  passkey_verified?: boolean;
  proof_ref?: string;
}

interface InstructionSigningPayloadContent {
  payload_version?: string;
  payload_type?: string;
  canonicalization?: string;
  signed_fields?: string[];
  payload_hash?: string;
}

interface InstructionContent {
  instruction_id?: string;
  principal_id?: string;
  agent_id?: string;
  action_type?: string;
  amount?: string;
  currency?: string;
  recipient_id?: string;
  recipient_account_ref?: string;
  memo?: string;
  submitted_at?: string;
  expiry_at?: string;
  instruction_nonce?: string;
  signing_payload?: InstructionSigningPayloadContent;
  signature_proof?: SignatureProofContent;
}

interface AgentSignatureContent {
  agent_principal?: string;
  agent_key_id?: string;
  agent_sig_alg?: string;
  signed_payload_c14n?: string;
  signed_payload?: string;
  agent_sig?: string;
}

interface VerifierSignatureContent {
  verifier_principal?: string;
  verifier_sig?: string;
  verifier_sig_alg?: string;
  verifier_key_id?: string;
  verifier_signed_payload?: string;
}

interface ToolTraceContent {
  tool_name?: string;
  input_ref?: string;
  output_ref?: string;
  args?: Record<string, unknown>;
  trace_id?: string;
  trace_hash?: string;
  trace_sig?: string;
  trace_sig_alg?: string;
  trace_signer?: string;
  trace_key_id?: string;
}

function sendJson(response: import("node:http").ServerResponse, status: number, body: unknown) {
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Access-Control-Allow-Origin", "*");
  response.setHeader("Access-Control-Allow-Headers", "Content-Type");
  response.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  response.end(JSON.stringify(body, null, 2));
}

async function readJson(request: import("node:http").IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  if (chunks.length === 0) {
    return {};
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf-8")) as Record<string, unknown>;
}

async function fetchEvent(eventId: string): Promise<EventServiceRecord> {
  const response = await fetch(`${eventServiceBaseUrl}/events/${eventId}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch event ${eventId}: ${response.status}`);
  }
  const body = (await response.json()) as { event: EventServiceRecord };
  return body.event;
}

async function fetchAllEvents(): Promise<EventServiceRecord[]> {
  const response = await fetch(`${eventServiceBaseUrl}/events`);
  if (!response.ok) {
    throw new Error(`Failed to fetch events: ${response.status}`);
  }
  const body = (await response.json()) as { events: EventServiceRecord[] };
  return body.events;
}

function getCurrentPolicy(currency = "USD"): CurrentPolicyResponse {
  return {
    bundle: policyRepository.getActiveBundle(),
    policy: policyRepository.getPolicyForCurrency(currency),
  };
}

function getOptionalPolicyContext(currency: string) {
  try {
    return getCurrentPolicy(currency);
  } catch {
    return {
      bundle: policyRepository.getActiveBundle(),
      policy: null,
    };
  }
}

async function writeEvent(flowId: string, payload: BaseEventEnvelope<UnknownContent>) {
  const response = await fetch(`${eventServiceBaseUrl}/events`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ flowId, payload }),
  });
  if (!response.ok) {
    throw new Error(`Failed to persist verifier event: ${response.status}`);
  }
  return (await response.json()) as { event: EventServiceRecord };
}

async function triggerArchive(flowId: string) {
  await fetch(`${archiveServiceBaseUrl}/archive`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ flowId }),
  });
}

async function validateProof(input: {
  proofId: string;
  principalId: string;
  role: string;
  proofType: "authentication";
}) {
  const response = await fetch(`${identityServiceBaseUrl}/proofs/validate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });

  if (!response.ok) {
    const body = (await response.json()) as { error?: string };
    throw new Error(body.error ?? "Identity proof validation failed");
  }

  return (await response.json()) as {
    valid: boolean;
    proof: {
      proofId: string;
      principalId: string;
      role: string;
      credentialId: string;
      proofType: string;
      createdAt: string;
      signCount: number;
    };
  };
}

function extractAmount(envelope: BaseEventEnvelope<UnknownContent>): string {
  const action = envelope.content.action as Record<string, unknown> | undefined;
  const params = action?.params as Record<string, unknown> | undefined;
  const amount = params?.amount;
  if (typeof amount !== "string") {
    throw new Error("Envelope amount is missing");
  }
  return amount;
}

function extractCurrency(envelope: BaseEventEnvelope<UnknownContent>): string {
  const action = envelope.content.action as Record<string, unknown> | undefined;
  const params = action?.params as Record<string, unknown> | undefined;
  const currency = params?.currency;
  if (typeof currency !== "string") {
    throw new Error("Envelope currency is missing");
  }
  return currency;
}

function amountToNumber(amount: string): number {
  return Number(amount);
}

function extractInstructionRef(envelope: BaseEventEnvelope<UnknownContent>): string {
  const instructionRef = envelope.content.instruction_ref;
  if (typeof instructionRef !== "string" || instructionRef.length === 0) {
    throw new Error("Envelope instruction_ref is missing");
  }
  return instructionRef;
}

function extractRecipientAccountRef(envelope: BaseEventEnvelope<UnknownContent>): string {
  const action = envelope.content.action as Record<string, unknown> | undefined;
  const params = action?.params as Record<string, unknown> | undefined;
  const recipientAccountRef = params?.recipient_account_ref;
  if (typeof recipientAccountRef !== "string" || recipientAccountRef.length === 0) {
    throw new Error("Envelope recipient account is missing");
  }
  return recipientAccountRef;
}

function canonicalStringify(value: unknown): string {
  if (typeof value === "string") {
    return asciiJsonStringify(value);
  }

  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalStringify(item)).join(",")}]`;
  }

  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
    a < b ? -1 : a > b ? 1 : 0,
  );
  return `{${entries
    .map(([key, item]) => `${asciiJsonStringify(key)}:${canonicalStringify(item)}`)
    .join(",")}}`;
}

function asciiJsonStringify(value: string): string {
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g, (char) =>
    `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

function buildEnvelopeSigningPayload(envelope: BaseEventEnvelope<UnknownContent>) {
  const content = envelope.content as Record<string, unknown>;
  return {
    instruction_ref: content.instruction_ref,
    agent_principal: content.agent_principal,
    action: content.action,
    tool_calls: content.tool_calls,
    context_metadata: content.context_metadata,
    control_bundle_v: content.control_bundle_v,
    origin_sig: content.origin_sig,
  };
}

function buildVerifierSigningPayload(content: UnknownContent) {
  const {
    verifier_sig,
    verifier_sig_alg,
    verifier_key_id,
    verifier_principal,
    verifier_signed_payload,
    ...rest
  } = content as UnknownContent & VerifierSignatureContent;
  return rest;
}

function getSignerKeyOrThrow(principalId: string, expectedRole: "agent" | "verifier") {
  const signer = principalKeyRepository.getSignerKeyByPrincipal(principalId);
  if (!signer) {
    throw new Error(`No registered signing key found for principal ${principalId}`);
  }
  if (signer.role !== expectedRole) {
    throw new Error(
      `Principal ${principalId} is registered as ${signer.role}, expected ${expectedRole}`,
    );
  }
  return signer;
}

function readPublicKeyFromRegistry(signer: PrincipalSigningKey) {
  if (signer.publicKeyPem) {
    return createPublicKey(signer.publicKeyPem);
  }
  if (signer.publicKeyPath) {
    return createPublicKey(readFileSync(signer.publicKeyPath, "utf-8"));
  }
  throw new Error(`No public key material is registered for principal ${signer.principalId}`);
}

function readPrivateKeyFromRegistry(signer: PrincipalSigningKey) {
  if (!signer.privateKeyPath) {
    throw new Error(`No private key path is registered for principal ${signer.principalId}`);
  }
  return createPrivateKey(readFileSync(signer.privateKeyPath, "utf-8"));
}

function readTextFileIfExists(path: string) {
  try {
    return readFileSync(path, "utf-8");
  } catch {
    return null;
  }
}

function syncSigningRegistry() {
  const verifierPublicKeyPem = readTextFileIfExists(verifierPublicKeyPath);
  if (!verifierPublicKeyPem) {
    throw new Error("Verifier public key could not be loaded for signer registry sync");
  }

  principalKeyRepository.upsertSignerKey({
    principalId: DEMO_PRINCIPALS.verifier,
    keyId: verifierKeyId,
    role: "verifier",
    publicKeyPem: verifierPublicKeyPem,
    publicKeyPath: verifierPublicKeyPath,
    privateKeyPath: verifierPrivateKeyPath,
  });

  const agentPublicKeyPem = readTextFileIfExists(agentPublicKeyPath);
  if (agentPublicKeyPem) {
    principalKeyRepository.upsertSignerKey({
      principalId: DEMO_PRINCIPALS.agent,
      keyId: Array.from(registeredAgentKeyIds)[0] ?? "ag_transfer_01#ed25519#v1",
      role: "agent",
      publicKeyPem: agentPublicKeyPem,
      publicKeyPath: agentPublicKeyPath,
    });
  }
}

function verifyAgentEnvelopeSignature(envelope: BaseEventEnvelope<UnknownContent>) {
  const signature = envelope.content.agent_signature as AgentSignatureContent | undefined;
  if (
    !signature?.agent_sig ||
    !signature.signed_payload ||
    !signature.agent_key_id ||
    !signature.agent_principal
  ) {
    throw new Error("Envelope agent signature is missing");
  }
  if (signature.agent_sig_alg !== "ed25519") {
    throw new Error(`Unsupported agent signature algorithm: ${signature.agent_sig_alg ?? "unknown"}`);
  }

  const expectedPayload = canonicalStringify(buildEnvelopeSigningPayload(envelope));
  if (signature.signed_payload !== expectedPayload) {
    throw new Error("Envelope signed payload does not match canonical envelope content");
  }

  const signer = getSignerKeyOrThrow(signature.agent_principal, "agent");
  if (signer.keyId !== signature.agent_key_id) {
    throw new Error(
      `Envelope agent key id ${signature.agent_key_id} does not match registered key ${signer.keyId}`,
    );
  }

  const valid = verifySignature(
    null,
    Buffer.from(signature.signed_payload, "utf-8"),
    readPublicKeyFromRegistry(signer),
    Buffer.from(signature.agent_sig, "hex"),
  );

  if (!valid) {
    throw new Error("Envelope agent signature verification failed");
  }

  return {
    valid: true as const,
    agentPrincipal: signature.agent_principal,
    agentKeyId: signature.agent_key_id,
  };
}

function assertAgentRegistered(agentPrincipal: string, agentKeyId: string) {
  if (!registeredAgentKeyIds.has(agentKeyId)) {
    throw new Error(`Agent key ${agentKeyId} is not registered`);
  }
  const signer = getSignerKeyOrThrow(agentPrincipal, "agent");
  if (signer.keyId !== agentKeyId) {
    throw new Error(
      `Agent principal ${agentPrincipal} is not registered with key ${agentKeyId}`,
    );
  }
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf-8").digest("hex");
}

function sha256Prefixed(value: string): string {
  return `sha256:${sha256Hex(value)}`;
}

function buildTraceSigningPayload(toolTrace: ToolTraceContent) {
  return {
    trace_id: toolTrace.trace_id,
    tool_name: toolTrace.tool_name,
    input_ref: toolTrace.input_ref,
    output_ref: toolTrace.output_ref,
    args: toolTrace.args ?? {},
  };
}

function verifyOrchestratorTraceSignatures(envelope: BaseEventEnvelope<UnknownContent>) {
  const content = envelope.content as Record<string, unknown>;
  const toolCalls = content.tool_calls;
  if (!Array.isArray(toolCalls) || toolCalls.length === 0) {
    throw new Error("Envelope tool_calls are missing");
  }

  const verifiedTraces = toolCalls.map((rawToolCall, index) => {
    const toolTrace = rawToolCall as ToolTraceContent;
    if (
      !toolTrace.trace_id ||
      !toolTrace.trace_hash ||
      !toolTrace.trace_sig ||
      !toolTrace.trace_sig_alg ||
      !toolTrace.trace_signer
    ) {
      throw new Error(`Tool trace evidence is incomplete at index ${index}`);
    }

    if (toolTrace.trace_sig_alg !== "ed25519") {
      throw new Error(`Unsupported trace signature algorithm at index ${index}`);
    }

    const traceSigner = getSignerKeyOrThrow(toolTrace.trace_signer, "agent");
    if (toolTrace.trace_key_id && toolTrace.trace_key_id !== traceSigner.keyId) {
      throw new Error(`Tool trace key id mismatch at index ${index}`);
    }

    const expectedHash = `sha256:${sha256Hex(canonicalStringify(buildTraceSigningPayload(toolTrace)))}`;
    if (toolTrace.trace_hash !== expectedHash) {
      throw new Error(`Tool trace hash mismatch at index ${index}`);
    }

    const valid = verifySignature(
      null,
      Buffer.from(toolTrace.trace_hash, "utf-8"),
      readPublicKeyFromRegistry(traceSigner),
      Buffer.from(toolTrace.trace_sig, "hex"),
    );

    if (!valid) {
      throw new Error(`Tool trace signature verification failed at index ${index}`);
    }

    return {
      traceId: toolTrace.trace_id,
      traceHash: toolTrace.trace_hash,
      traceSigner: toolTrace.trace_signer,
      toolName: toolTrace.tool_name ?? `tool_${index}`,
    };
  });

  return {
    valid: true as const,
    count: verifiedTraces.length,
    traces: verifiedTraces,
  };
}

function computeInstructionPayloadHash(instructionRecord: EventServiceRecord) {
  const content = instructionRecord.payload.content as InstructionContent;
  const signingPayload = content.signing_payload;
  if (!signingPayload?.signed_fields || !Array.isArray(signingPayload.signed_fields)) {
    throw new Error("Instruction signing_payload.signed_fields is missing");
  }
  const signedValues = Object.fromEntries(
    signingPayload.signed_fields.map((field) => [field, (content as Record<string, unknown>)[field]]),
  );
  return sha256Prefixed(canonicalStringify(signedValues));
}

function assertInstructionNotExpired(instructionRecord: EventServiceRecord) {
  const content = instructionRecord.payload.content as InstructionContent;
  if (!content.expiry_at) {
    throw new Error("Instruction expiry_at is missing");
  }
  const expiryAt = new Date(content.expiry_at);
  if (Number.isNaN(expiryAt.getTime())) {
    throw new Error("Instruction expiry_at is invalid");
  }
  if (expiryAt.getTime() <= Date.now()) {
    throw new Error("Instruction has expired");
  }
}

async function assertInstructionNonceUnused(instructionRecord: EventServiceRecord) {
  const content = instructionRecord.payload.content as InstructionContent;
  if (!content.instruction_nonce) {
    throw new Error("Instruction nonce is missing");
  }
  const events = await fetchAllEvents();
  const duplicateInstructions = events.filter((event) => {
    if (event.kind !== 101) {
      return false;
    }
    const otherContent = event.payload.content as InstructionContent;
    return (
      otherContent.instruction_nonce === content.instruction_nonce &&
      event.eventId !== instructionRecord.eventId
    );
  });
  if (duplicateInstructions.length > 0) {
    throw new Error(`Instruction nonce ${content.instruction_nonce} has already been used`);
  }
}

function assertControlBundleMatchesEnvelope(
  envelopeRecord: EventServiceRecord,
  activeBundle: CurrentPolicyResponse["bundle"],
) {
  const envelopeContent = envelopeRecord.payload.content as Record<string, unknown>;
  const controlBundleV = envelopeContent.control_bundle_v;
  const expectedBundleRef = `${activeBundle.bundleId}@${activeBundle.bundleVersion}`;
  if (controlBundleV !== expectedBundleRef) {
    throw new Error(
      `Envelope control bundle ${String(controlBundleV)} does not match active bundle ${expectedBundleRef}`,
    );
  }
}

function signVerifierContent(content: UnknownContent) {
  const verifierSigner = getSignerKeyOrThrow(DEMO_PRINCIPALS.verifier, "verifier");
  const canonicalPayload = canonicalStringify(buildVerifierSigningPayload(content));
  const signature = signSignature(
    null,
    Buffer.from(canonicalPayload, "utf-8"),
    readPrivateKeyFromRegistry(verifierSigner),
  );
  return {
    verifier_principal: verifierSigner.principalId,
    verifier_sig: signature.toString("hex"),
    verifier_sig_alg: "ed25519",
    verifier_key_id: verifierSigner.keyId,
    verifier_signed_payload: canonicalPayload,
  };
}

function buildEnvelopeHash(envelope: BaseEventEnvelope<UnknownContent>) {
  return sha256Prefixed(canonicalStringify(envelope));
}

function buildInstructionPayloadHashOrThrow(instructionRecord: EventServiceRecord) {
  const content = instructionRecord.payload.content as InstructionContent;
  const declaredHash = content.signing_payload?.payload_hash;
  if (!declaredHash) {
    throw new Error("Instruction signing payload hash is missing");
  }
  const computedHash = computeInstructionPayloadHash(instructionRecord);
  if (declaredHash !== computedHash) {
    throw new Error("Instruction signing payload hash does not match canonical instruction content");
  }
  return computedHash;
}

function createVerifierEnvelope(
  kind: 103 | 104 | 107 | 108,
  aiId: string,
  flowId: string,
  content: UnknownContent,
): BaseEventEnvelope<UnknownContent> {
  const idSuffix =
    kind === 103 ? "approved" : kind === 104 ? "escalate" : kind === 107 ? "reverify" : "reject";
  const signedContent = { ...content };
  Object.assign(signedContent, signVerifierContent(signedContent));
  return {
    id: `evt_verifier_${idSuffix}_${Date.now()}_hash`,
    kind,
    ai_id: aiId,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ["flow_id", flowId],
      ["source", "verifier"],
    ],
    content: signedContent,
  };
}

function ensureVerifierKeys() {
  mkdirSync(dirname(verifierPrivateKeyPath), { recursive: true });
  mkdirSync(dirname(verifierPublicKeyPath), { recursive: true });
  try {
    readFileSync(verifierPrivateKeyPath, "utf-8");
    readFileSync(verifierPublicKeyPath, "utf-8");
    return;
  } catch {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    writeFileSync(
      verifierPrivateKeyPath,
      privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    );
    writeFileSync(
      verifierPublicKeyPath,
      publicKey.export({ type: "spki", format: "pem" }).toString(),
    );
  }
}

function buildRejectDecision(input: {
  flowId: string;
  envelopeRecord: EventServiceRecord;
  instructionRecord?: EventServiceRecord;
  reasonCode: string;
  reasonMessage: string;
  currency?: string;
}): BaseEventEnvelope<UnknownContent> {
  return createVerifierEnvelope(108, DEMO_PRINCIPALS.verifier, input.flowId, {
    verifier_record_id: `vrf_reject_${Date.now()}`,
    envelope_ref: input.envelopeRecord.eventId,
    instruction_ref:
      input.instructionRecord?.eventId ??
      String((input.envelopeRecord.payload.content.instruction_ref as string | undefined) ?? ""),
    decision: "rejected",
    safr_disposition_equivalent: "reject",
    rejection_reason: {
      code: input.reasonCode,
      message: input.reasonMessage,
    },
    verification_result: {
      principal_signature_valid: input.reasonCode !== "passkey_verification_failed",
      currency_policy_valid: input.reasonCode !== "currency_not_allowed",
      recipient_account_allowed: input.reasonCode !== "recipient_not_allowlisted",
      envelope_schema_valid: true,
    },
    policy_context: input.currency ? getOptionalPolicyContext(input.currency) : undefined,
    next_step: "halt_until_new_instruction_or_policy_change",
  });
}

async function buildFirstDecision(
  flowId: string,
  envelopeRecord: EventServiceRecord,
  instructionRecord: EventServiceRecord,
): Promise<BaseEventEnvelope<UnknownContent>> {
  const amount = extractAmount(envelopeRecord.payload);
  const currency = extractCurrency(envelopeRecord.payload);
  const recipientAccountRef = extractRecipientAccountRef(envelopeRecord.payload);
  const numericAmount = amountToNumber(amount);
  const activeBundle = policyRepository.getActiveBundle();
  const signatureProof = instructionRecord.payload.content.signature_proof as SignatureProofContent | undefined;
  const proofRef = signatureProof?.proof_ref;
  let policy:
    | ReturnType<PolicyRepository["getPolicyForCurrency"]>
    | undefined;

  try {
    policy = policyRepository.getPolicyForCurrency(currency);
  } catch {
    return buildRejectDecision({
      flowId,
      envelopeRecord,
      instructionRecord,
      reasonCode: "currency_policy_missing",
      reasonMessage: `No verifier policy is configured for currency ${currency}`,
      currency,
    });
  }

  if (Number.isNaN(numericAmount) || numericAmount <= 0) {
    return buildRejectDecision({
      flowId,
      envelopeRecord,
      instructionRecord,
      reasonCode: "invalid_amount",
      reasonMessage: `Transfer amount ${amount} is invalid`,
      currency,
    });
  }

  if (!policy.allowedCurrencies.includes(currency)) {
    return buildRejectDecision({
      flowId,
      envelopeRecord,
      instructionRecord,
      reasonCode: "currency_not_allowed",
      reasonMessage: `Currency ${currency} is not allowed by active policy bundle`,
      currency,
    });
  }

  if (!proofRef) {
    return buildRejectDecision({
      flowId,
      envelopeRecord,
      instructionRecord,
      reasonCode: "passkey_verification_failed",
      reasonMessage: "Transferor passkey proof is missing",
      currency,
    });
  }

  let agentSignatureVerification:
    | {
        valid: true;
        agentPrincipal: string;
        agentKeyId: string;
      }
    | undefined;
  try {
    agentSignatureVerification = verifyAgentEnvelopeSignature(envelopeRecord.payload);
    assertAgentRegistered(
      agentSignatureVerification.agentPrincipal,
      agentSignatureVerification.agentKeyId,
    );
  } catch (error) {
    return buildRejectDecision({
      flowId,
      envelopeRecord,
      instructionRecord,
      reasonCode: "agent_signature_invalid",
      reasonMessage:
        error instanceof Error ? error.message : "Envelope agent signature verification failed",
      currency,
    });
  }
  if (!agentSignatureVerification) {
    return buildRejectDecision({
      flowId,
      envelopeRecord,
      instructionRecord,
      reasonCode: "agent_signature_invalid",
      reasonMessage: "Envelope agent signature verification did not produce a registered agent key",
      currency,
    });
  }

  let instructionPayloadHash: string;
  try {
    instructionPayloadHash = buildInstructionPayloadHashOrThrow(instructionRecord);
  } catch (error) {
    return buildRejectDecision({
      flowId,
      envelopeRecord,
      instructionRecord,
      reasonCode: "instruction_payload_hash_invalid",
      reasonMessage:
        error instanceof Error ? error.message : "Instruction payload hash verification failed",
      currency,
    });
  }

  try {
    assertInstructionNotExpired(instructionRecord);
  } catch (error) {
    return buildRejectDecision({
      flowId,
      envelopeRecord,
      instructionRecord,
      reasonCode: "instruction_expired",
      reasonMessage: error instanceof Error ? error.message : "Instruction expiry verification failed",
      currency,
    });
  }

  try {
    assertControlBundleMatchesEnvelope(envelopeRecord, activeBundle);
  } catch (error) {
    return buildRejectDecision({
      flowId,
      envelopeRecord,
      instructionRecord,
      reasonCode: "control_bundle_mismatch",
      reasonMessage:
        error instanceof Error ? error.message : "Envelope control bundle verification failed",
      currency,
    });
  }

  let traceVerification:
    | {
        valid: true;
        count: number;
        traces: Array<{
          traceId: string;
          traceHash: string;
          traceSigner: string;
          toolName: string;
        }>;
      }
    | undefined;

  try {
    traceVerification = verifyOrchestratorTraceSignatures(envelopeRecord.payload);
  } catch (error) {
    return buildRejectDecision({
      flowId,
      envelopeRecord,
      instructionRecord,
      reasonCode: "orchestrator_trace_invalid",
      reasonMessage:
        error instanceof Error ? error.message : "Orchestrator trace signature verification failed",
      currency,
    });
  }

  try {
    await assertInstructionNonceUnused(instructionRecord);
  } catch (error) {
    return buildRejectDecision({
      flowId,
      envelopeRecord,
      instructionRecord,
      reasonCode: "instruction_nonce_reused",
      reasonMessage: error instanceof Error ? error.message : "Instruction nonce reuse detected",
      currency,
    });
  }

  if (policy.recipientAllowlistRequired && recipientAccountRef !== "acct_recipient_bob_001") {
    return buildRejectDecision({
      flowId,
      envelopeRecord,
      instructionRecord,
      reasonCode: "recipient_not_allowlisted",
      reasonMessage: `Recipient account ${recipientAccountRef} is not in the allowlist`,
      currency,
    });
  }

  const common = {
    envelope_ref: envelopeRecord.eventId,
    instruction_ref: instructionRecord.eventId,
    verification_result: {
      principal_signature_valid: true,
      instruction_payload_hash_valid: true,
      instruction_not_expired: true,
      instruction_nonce_unused: true,
      agent_registered: Boolean(agentSignatureVerification?.agentPrincipal),
      agent_signature_valid: true,
      recipient_account_resolved: recipientAccountRef === "acct_recipient_bob_001",
      mandate_valid: true,
      envelope_schema_valid: true,
      control_bundle_resolved: true,
      control_bundle_hash_valid: true,
      orchestrator_trace_signature_valid: Boolean(traceVerification?.valid),
      envelope_hash_valid: true,
    },
    risk_summary: {
      amount,
      currency,
      threshold: policy.adminReviewAtOrAbove.toFixed(2),
      risk_tier: numericAmount < policy.autoExecuteBelow ? "low" : "medium",
      reason:
        numericAmount < policy.autoExecuteBelow
          ? "amount_below_auto_execute_threshold"
          : "amount_at_or_above_admin_review_threshold",
    },
    control_bundle: {
      bundle_id: activeBundle.bundleId,
      bundle_version: activeBundle.bundleVersion,
      bundle_hash: activeBundle.bundleHash,
      policy_id: policy.policyId,
      policy_name: policy.policyName,
    },
    policy_constraints: {
      auto_execute_below: policy.autoExecuteBelow.toFixed(2),
      admin_review_at_or_above: policy.adminReviewAtOrAbove.toFixed(2),
      recipient_allowlist_required: policy.recipientAllowlistRequired,
      allowed_currencies: policy.allowedCurrencies,
    },
    verified_artifacts: {
      instruction_payload_hash: instructionPayloadHash,
      envelope_hash: buildEnvelopeHash(envelopeRecord.payload),
      control_bundle_hash: activeBundle.bundleHash,
      trace_hashes: traceVerification?.traces.map((trace) => trace.traceHash) ?? [],
    },
    trace_evidence: {
      verified_trace_count: traceVerification?.count ?? 0,
      verified_traces:
        traceVerification?.traces.map((trace) => ({
          trace_id: trace.traceId,
          trace_hash: trace.traceHash,
          trace_signer: trace.traceSigner,
          tool_name: trace.toolName,
        })) ?? [],
    },
    decision_payload: {
      payload_version: "1.0",
      canonicalization: "jcs-rfc8785",
      decision_hash: `sha256:decision_${Date.now()}`,
    },
  };

  if (numericAmount < policy.autoExecuteBelow) {
    return createVerifierEnvelope(103, DEMO_PRINCIPALS.verifier, flowId, {
      verifier_record_id: `vrf_approved_${Date.now()}`,
      ...common,
      decision: "approved_auto_execute",
      safr_disposition_equivalent: "auto_execute",
      next_step: "mcp_transfer_api_may_execute",
    });
  }

  return createVerifierEnvelope(104, DEMO_PRINCIPALS.verifier, flowId, {
    verifier_record_id: `vrf_escalate_${Date.now()}`,
    ...common,
    decision: "approved_pending_admin_signature",
    safr_disposition_equivalent: "escalate",
    required_admin_action: {
      status: "pending",
      admin_role: "administrator",
      passkey_confirmation_required: true,
      required_output: "signed_admin_approval_event",
    },
    next_step: "wait_for_admin_signature_then_reverify_before_mcp_execution",
  });
}

function buildReverificationDecision(input: ReverifyInput, hashes: {
  instructionPayloadHash: string;
  envelopeHash: string;
  firstVerifierDecisionHash: string;
  adminPayloadHash: string;
}): BaseEventEnvelope<UnknownContent> {
  return createVerifierEnvelope(107, DEMO_PRINCIPALS.verifier, input.flowId, {
    reverify_id: `vrf_reverify_${Date.now()}`,
    instruction_ref: input.instructionEventId,
    envelope_ref: input.envelopeEventId,
    first_verifier_ref: input.firstVerifierEventId,
    admin_review_ref: input.adminReviewEventId,
    decision: "approved_after_admin_signature",
    safr_disposition_equivalent: "escalate_resolved_execute",
    verification_result: {
      admin_signature_valid: true,
      admin_passkey_verified: true,
      admin_role_authorized: true,
      chain_integrity_valid: true,
      first_verifier_record_valid: true,
      admin_payload_hash_valid: true,
      admin_review_bound_to_same_instruction: true,
    },
    verified_artifacts: {
      instruction_payload_hash: hashes.instructionPayloadHash,
      envelope_hash: hashes.envelopeHash,
      first_verifier_decision_hash: hashes.firstVerifierDecisionHash,
      admin_payload_hash: hashes.adminPayloadHash,
    },
    decision_payload: {
      payload_version: "1.0",
      canonicalization: "jcs-rfc8785",
      decision_hash: `sha256:reverify_${Date.now()}`,
    },
    next_step: "mcp_transfer_api_may_execute",
  });
}

function buildAdminRejectDecision(input: ReverifyInput, reasonCode: string, reasonMessage: string) {
  return createVerifierEnvelope(108, DEMO_PRINCIPALS.verifier, input.flowId, {
    verifier_record_id: `vrf_reject_admin_${Date.now()}`,
    instruction_ref: input.instructionEventId,
    envelope_ref: input.envelopeEventId,
    first_verifier_ref: input.firstVerifierEventId,
    admin_review_ref: input.adminReviewEventId,
    decision: "rejected",
    safr_disposition_equivalent: "reject_after_escalation",
    rejection_reason: {
      code: reasonCode,
      message: reasonMessage,
    },
    verification_result: {
      admin_signature_valid: reasonCode !== "admin_passkey_verification_failed",
      admin_role_authorized: reasonCode !== "admin_role_not_authorized",
      first_verifier_record_valid: reasonCode !== "first_verifier_not_escalated",
      admin_review_bound_to_same_instruction: reasonCode !== "admin_ref_mismatch",
    },
    next_step: "halt_until_valid_admin_signature_or_new_instruction",
  });
}

const server = createServer(async (request, response) => {
  if (!request.url || !request.method) {
    sendJson(response, 400, { error: "Invalid request" });
    return;
  }

  const url = new URL(request.url, `http://${request.headers.host ?? "localhost"}`);

  if (request.method === "OPTIONS") {
    response.statusCode = 204;
    response.setHeader("Access-Control-Allow-Origin", "*");
    response.setHeader("Access-Control-Allow-Headers", "Content-Type");
    response.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    response.end();
    return;
  }

  if (request.method === "GET" && url.pathname === "/health") {
    sendJson(response, 200, {
      ok: true,
      service: "verifier",
      eventServiceBaseUrl,
      archiveServiceBaseUrl,
    });
    return;
  }

  if (request.method === "GET" && url.pathname === "/verifier/policy/current") {
    try {
      const currency = url.searchParams.get("currency") ?? "USD";
      sendJson(response, 200, getCurrentPolicy(currency));
    } catch (error) {
      sendJson(response, 400, {
        error: error instanceof Error ? error.message : "Failed to load current policy",
      });
    }
    return;
  }

  if (request.method === "POST" && url.pathname === "/verifier/evaluate-envelope") {
    try {
      const body = (await readJson(request)) as unknown as EvaluationInput;
      const envelopeRecord = await fetchEvent(body.envelopeEventId);
      const instructionRecord = await fetchEvent(extractInstructionRef(envelopeRecord.payload));
      const proofRef =
        (instructionRecord.payload.content.signature_proof as SignatureProofContent | undefined)
          ?.proof_ref;
      const instructionContent = instructionRecord.payload.content as InstructionContent;
      if (!proofRef) {
        throw new Error("Instruction is missing identity proof reference");
      }
      if (!instructionContent.principal_id) {
        throw new Error("Instruction principal is missing");
      }
      await validateProof({
        proofId: proofRef,
        principalId: instructionContent.principal_id,
        role: "transferor",
        proofType: "authentication",
      });
      const decisionPayload = await buildFirstDecision(body.flowId, envelopeRecord, instructionRecord);
      const persisted = await writeEvent(body.flowId, decisionPayload);
      await triggerArchive(body.flowId);
      sendJson(response, 201, { event: persisted.event });
    } catch (error) {
      sendJson(response, 400, {
        error: error instanceof Error ? error.message : "Failed to evaluate envelope",
      });
    }
    return;
  }

  if (request.method === "POST" && url.pathname === "/verifier/reverify-admin-signature") {
    try {
      const body = (await readJson(request)) as unknown as ReverifyInput;
      const [adminReviewRecord, firstVerifierRecord] = await Promise.all([
        fetchEvent(body.adminReviewEventId),
        fetchEvent(body.firstVerifierEventId),
      ]);
      const adminContent = adminReviewRecord.payload.content as AdminReviewContent;
      let decisionPayload: BaseEventEnvelope<UnknownContent>;

      if (firstVerifierRecord.kind !== 104) {
        decisionPayload = buildAdminRejectDecision(
          body,
          "first_verifier_not_escalated",
          "Admin re-verification is only valid after an escalation decision",
        );
      } else if (adminContent.verifier_record_ref !== body.firstVerifierEventId) {
        decisionPayload = buildAdminRejectDecision(
          body,
          "admin_ref_mismatch",
          "Admin approval is not bound to the same verifier escalation record",
        );
      } else if (adminContent.decision !== "admin_signed_approval") {
        decisionPayload = buildAdminRejectDecision(
          body,
          "admin_decision_not_approved",
          "Administrator did not sign an approval decision",
        );
      } else if (!adminContent.signature_proof?.proof_ref) {
        decisionPayload = buildAdminRejectDecision(
          body,
          "admin_passkey_verification_failed",
          "Administrator identity proof is missing",
        );
      } else if (adminContent.signature_proof?.passkey_verified === false) {
        decisionPayload = buildAdminRejectDecision(
          body,
          "admin_passkey_verification_failed",
          "Administrator passkey verification failed",
        );
      } else {
        if (!adminContent.admin_id) {
          throw new Error("Administrator principal is missing");
        }
        await validateProof({
          proofId: adminContent.signature_proof.proof_ref,
          principalId: adminContent.admin_id,
          role: "administrator",
          proofType: "authentication",
        });
        const instructionRecord = await fetchEvent(body.instructionEventId);
        const envelopeRecord = await fetchEvent(body.envelopeEventId);
        const instructionPayloadHash = buildInstructionPayloadHashOrThrow(instructionRecord);
        decisionPayload = buildReverificationDecision(body, {
          instructionPayloadHash,
          envelopeHash: buildEnvelopeHash(envelopeRecord.payload),
          firstVerifierDecisionHash: buildEnvelopeHash(firstVerifierRecord.payload),
          adminPayloadHash: buildEnvelopeHash(adminReviewRecord.payload),
        });
      }

      const persisted = await writeEvent(body.flowId, decisionPayload);
      await triggerArchive(body.flowId);
      sendJson(response, 201, { event: persisted.event });
    } catch (error) {
      sendJson(response, 400, {
        error: error instanceof Error ? error.message : "Failed to reverify admin signature",
      });
    }
    return;
  }

  sendJson(response, 404, { error: "Not found" });
});

server.listen(port, () => {
  console.log(`verifier listening on http://localhost:${port}`);
});
