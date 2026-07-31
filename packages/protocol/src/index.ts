import { Principal } from "@dfinity/principal";

export const protocolVersion = "0.1.0";

export const supportedEventKinds = [101, 102, 103, 104, 105, 106, 107, 108, 109] as const;

export function normalizePrincipalText(value: string): string {
  return Principal.fromText(value).toText();
}

export function isValidPrincipal(value: string): boolean {
  try {
    normalizePrincipalText(value);
    return true;
  } catch {
    return false;
  }
}

export function assertValidPrincipal(value: string, label = "principal"): string {
  try {
    return normalizePrincipalText(value);
  } catch (error) {
    throw new Error(
      `${label} is not a valid principal: ${value}${error instanceof Error ? ` (${error.message})` : ""}`,
    );
  }
}

const DEMO_PRINCIPAL_VALUES = {
  transferor: "r2uh3-gxxja-v2mzj-y4b2j-fqxyb-mptjn-yrpfw-7jsuc-auwdf-cprav-7ae",
  recipient: "3hkzv-ss3vr-apcsm-pufqw-bbus6-a4q4t-55qde-v6emc-ma3vr-asjys-wae",
  admin: "bz3in-uqkio-u3q3m-ys7p3-7w6qt-kpvtg-kshot-aw7tn-3awlg-zcfyf-aqe",
  agent: "lrgbc-o4cs5-g5p6a-sqzpk-7birn-7wwhl-7fwsg-ijijp-sc35d-lllit-uae",
  verifier: "t2gvn-rfriz-mcm3w-wtids-uf3xv-kd52n-ce7fc-qn2rk-rxeo6-3232k-5qe",
} as const;

export function createDeterministicPrincipal(seed: string): string {
  const normalizedSeed = seed.toLowerCase();
  const directMatch = Object.entries(DEMO_PRINCIPAL_VALUES).find(([label]) =>
    normalizedSeed.includes(label),
  )?.[1];

  if (directMatch) {
    return directMatch;
  }

  const bytes = new Uint8Array(29);
  for (let index = 0; index < seed.length; index += 1) {
    bytes[index % bytes.length] = (bytes[index % bytes.length] + seed.charCodeAt(index) + index) % 256;
  }
  return Principal.selfAuthenticating(bytes).toText();
}

export function createDemoPrincipal(label: keyof typeof DEMO_PRINCIPAL_VALUES | string): string {
  if (label in DEMO_PRINCIPAL_VALUES) {
    return DEMO_PRINCIPAL_VALUES[label as keyof typeof DEMO_PRINCIPAL_VALUES];
  }
  return createDeterministicPrincipal(`safr-x-atp-demo:${label}:principal:v1`);
}

export function normalizeAccountHandle(value: string): string {
  return value.trim().toLowerCase();
}

export function isEnglishAccountHandle(value: string): boolean {
  return /^[A-Za-z][A-Za-z0-9_-]*$/.test(value.trim());
}

export function assertEnglishAccountHandle(value: string, label = "username"): string {
  const normalized = value.trim();
  if (!isEnglishAccountHandle(normalized)) {
    throw new Error(`${label} must use English letters, numbers, underscores, or hyphens, and start with a letter`);
  }
  return normalized.toLowerCase();
}

export function createAccountScopedPrincipal(handle: string, role: "transferor" | "admin" | "recipient"): string {
  const normalizedHandle = normalizeAccountHandle(handle);
  const seed = `safr-x-atp-demo:account:${normalizedHandle}:${role}:principal:v1`;
  const bytes = new Uint8Array(29);
  for (let index = 0; index < seed.length; index += 1) {
    const charCode = seed.charCodeAt(index);
    bytes[index % bytes.length] = (bytes[index % bytes.length] * 31 + charCode + index) % 256;
  }
  return Principal.selfAuthenticating(bytes).toText();
}

export function createDemoPrincipals() {
  return {
    ...DEMO_PRINCIPAL_VALUES,
  } as const;
}

export const normalizeIcpPrincipalText = normalizePrincipalText;
export const isValidIcpPrincipal = isValidPrincipal;
export const assertValidIcpPrincipal = assertValidPrincipal;

export const DEMO_PRINCIPALS = createDemoPrincipals();

export const DEMO_AGENT_IDS = {
  transfer: "ag_transfer_01",
} as const;

export type SupportedEventKind = (typeof supportedEventKinds)[number];

export type EventTag = [string, string, ...string[]];

export interface BaseEventEnvelope<TContent = Record<string, unknown>> {
  id: string;
  kind: SupportedEventKind;
  ai_id: string;
  created_at: number;
  tags: EventTag[];
  content: TContent;
}

export interface EventRecord<TContent = Record<string, unknown>> {
  eventId: string;
  flowId: string;
  kind: SupportedEventKind;
  aiId: string;
  createdAt: number;
  payload: BaseEventEnvelope<TContent>;
  instructionRef?: string;
  envelopeRef?: string;
}

export interface CreateEventInput<TContent = Record<string, unknown>> {
  flowId: string;
  payload: BaseEventEnvelope<TContent>;
  instructionRef?: string;
  envelopeRef?: string;
}

export function isSupportedEventKind(value: number): value is SupportedEventKind {
  return supportedEventKinds.includes(value as SupportedEventKind);
}

export function getTagValue(tags: EventTag[], key: string): string | undefined {
  return tags.find((tag) => tag[0] === key)?.[1];
}

export function inferFlowId<TContent>(payload: BaseEventEnvelope<TContent>): string | undefined {
  return getTagValue(payload.tags, "flow_id") ?? getTagValue(payload.tags, "flow");
}

export function createEventRecord<TContent>(
  input: CreateEventInput<TContent>,
): EventRecord<TContent> {
  return {
    eventId: input.payload.id,
    flowId: input.flowId,
    kind: input.payload.kind,
    aiId: input.payload.ai_id,
    createdAt: input.payload.created_at,
    payload: input.payload,
    instructionRef: input.instructionRef,
    envelopeRef: input.envelopeRef,
  };
}
