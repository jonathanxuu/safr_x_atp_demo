import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { useEffect, useRef, useState } from "react";
import type { RefObject } from "react";
import { DEMO_AGENT_IDS, DEMO_PRINCIPALS, assertEnglishAccountHandle } from "@safr-x-atp-demo/protocol";

declare const __GOOGLE_ADK_MODEL__: string;

type Account = {
  accountId: string;
  ownerId: string;
  ownerRole: "transferor" | "recipient";
  currency: string;
  availableBalance: number;
};

type Transaction = {
  transactionId: string;
  flowId: string;
  verifierEventId: string;
  status: "executed";
  fromAccountId: string;
  toAccountId: string;
  amount: number;
  currency: string;
  createdAt: string;
};

type EventRecord = {
  eventId: string;
  flowId: string;
  kind: number;
  aiId: string;
  createdAt: number;
  payload: {
    id: string;
    kind: number;
    ai_id: string;
    created_at: number;
    tags: string[][];
    content: Record<string, unknown>;
  };
};

type ArchiveRecord = {
  id: string;
  kind: number;
  ai_id: string;
  created_at: number;
  tags: string[][];
  content: {
    archive_record_id: string;
    flow_id: string;
    archived_entities: Array<{
      event_ref: string;
      event_kind: number;
      event_role: string;
    }>;
    append_only_index: number;
    hash_chain_prev: string;
    hash_chain_curr: string;
    written_by: string;
    write_mode: string;
  };
};

type VerifierPolicyView = {
  bundle: {
    bundleId: string;
    bundleVersion: string;
    bundleHash: string;
    status: "active" | "inactive";
    createdAt: string;
  };
  policy: {
    policyId: string;
    bundleId: string;
    policyName: string;
    currency: string;
    autoExecuteBelow: number;
    adminReviewAtOrAbove: number;
    recipientAllowlistRequired: boolean;
    allowedCurrencies: string[];
    createdAt: string;
    updatedAt: string;
  };
};

type PasskeyState = {
  registered: boolean;
  verified: boolean;
  credentialId: string;
  publicKeyRef: string;
  registeredAt: string;
  proofRef: string;
  lastVerifiedAt: string;
  proofType: string;
  deviceType: string;
  backedUp: boolean | null;
  rpId: string;
  lastUsedAt: string;
  counter: number | null;
  transports: string[];
};

type AgentTrace = {
  mode: string;
  reasoningSummary: string;
  startedAt?: string;
  completedAt?: string;
  durationMs?: number;
  promptText?: string;
  promptPreview?: string;
  skillName?: string;
  mandatoryTools?: string[];
  fallbackReason?: string | null;
  toolCalls: Array<{
    tool_name: string;
    input_ref?: string;
    output_ref?: string;
    trace_sig?: string;
    trace_id?: string;
    trace_hash?: string;
    trace_sig_alg?: string;
    trace_signer?: string;
    args?: Record<string, string>;
  }>;
};

type ExecutionBalanceSnapshot = {
  flowId: string;
  currency: string;
  amount: number;
  fromAccountId: string;
  toAccountId: string;
  fromBefore: number;
  fromAfter: number;
  toBefore: number;
  toAfter: number;
  alreadyExecuted: boolean;
};

type FlowStageId =
  | "instruction"
  | "agent_envelope"
  | "verifier"
  | "admin"
  | "agent_forward"
  | "execution"
  | "archive";

type FlowStageStatus = "done" | "current" | "pending" | "blocked" | "skipped";

type FlowStage = {
  id: FlowStageId;
  title: string;
  module: string;
  actor: string;
  artifact: string;
  kindLabel: string;
  summary: string;
  status: FlowStageStatus;
  statusLabel: string;
  checks: string[];
  path: "primary" | "conditional" | "support" | "terminal";
  signatureSummary: string[];
};

type AppTabId = "overview" | "transfer" | "agent" | "verifier" | "policy" | "trace" | "archive";

const EVENT_SERVICE_URL = "/api/event";
const VERIFIER_SERVICE_URL = "/api/verifier";
const MCP_BANK_URL = "/api/bank";
const ARCHIVE_SERVICE_URL = "/api/archive";
const IDENTITY_SERVICE_URL = "/api/identity";
const AGENT_SERVICE_URL = "/api/agent";
const FLOW_SNAPSHOT_STORAGE_KEY = "safr_x_atp_demo:last_flow_snapshot";

type ActiveAccount = {
  username: string;
  transferorPrincipalId: string;
  adminPrincipalId: string;
  recipientPrincipalId: string;
};

type AuthenticatePasskeyResult = {
  proofId: string;
  credentialId: string;
};

type PasswordStrength = {
  score: number;
  label: "Too weak" | "Almost there" | "Meets requirements";
  description: string;
  checks: string[];
};

async function fetchIdentity(path: string, init: RequestInit = {}) {
  return fetch(`${IDENTITY_SERVICE_URL}${path}`, {
    ...init,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(init.headers ?? {}),
    },
  });
}

type PersistedFlowSnapshot = {
  flowId: string;
  activeTab: AppTabId;
  amount: string;
  currency: string;
  memo: string;
  recipientAccountRef: string;
  amountError: string;
  status: string;
  lastVerifierEventId: string;
  agentTrace: AgentTrace | null;
  executionBalanceSnapshot: ExecutionBalanceSnapshot | null;
  events: EventRecord[];
  archiveRecords: ArchiveRecord[];
  selectedStageId: FlowStageId | null;
  overviewPreviewStageId: FlowStageId | null;
  spotlightStageId: FlowStageId;
};

function readPersistedFlowSnapshot(): PersistedFlowSnapshot | null {
  if (typeof window === "undefined") {
    return null;
  }

  try {
    const raw = window.localStorage.getItem(FLOW_SNAPSHOT_STORAGE_KEY);
    if (!raw) {
      return null;
    }

    const parsed = JSON.parse(raw) as Partial<PersistedFlowSnapshot>;
    if (!parsed.flowId) {
      return null;
    }

    return {
      flowId: parsed.flowId,
      activeTab: parsed.activeTab ?? "overview",
      amount: parsed.amount ?? "",
      currency: parsed.currency ?? "USD",
      memo: parsed.memo ?? "",
      recipientAccountRef: parsed.recipientAccountRef ?? "",
      amountError: parsed.amountError ?? "",
      status: parsed.status ?? "Ready",
      lastVerifierEventId: parsed.lastVerifierEventId ?? "",
      agentTrace: parsed.agentTrace ?? null,
      executionBalanceSnapshot: parsed.executionBalanceSnapshot ?? null,
      events: Array.isArray(parsed.events) ? (parsed.events as EventRecord[]) : [],
      archiveRecords: Array.isArray(parsed.archiveRecords) ? (parsed.archiveRecords as ArchiveRecord[]) : [],
      selectedStageId: parsed.selectedStageId ?? null,
      overviewPreviewStageId: parsed.overviewPreviewStageId ?? null,
      spotlightStageId: parsed.spotlightStageId ?? "instruction",
    };
  } catch {
    return null;
  }
}

function writePersistedFlowSnapshot(snapshot: PersistedFlowSnapshot | null) {
  if (typeof window === "undefined") {
    return;
  }

  try {
    if (!snapshot) {
      window.localStorage.removeItem(FLOW_SNAPSHOT_STORAGE_KEY);
      return;
    }

    window.localStorage.setItem(FLOW_SNAPSHOT_STORAGE_KEY, JSON.stringify(snapshot));
  } catch {
    // Ignore storage failures in the demo UI.
  }
}

function evaluatePasswordStrength(password: string): PasswordStrength {
  const trimmedPassword = password.trim();

  const checks = [
    {
      passed: trimmedPassword.length >= 8,
      label: "At least 8 characters",
    },
    {
      passed: /\d/.test(trimmedPassword),
      label: "Includes a number",
    },
  ];

  const score = checks.filter((check) => check.passed).length;
  const label: PasswordStrength["label"] =
    score < 2 ? (score === 0 ? "Too weak" : "Almost there") : "Meets requirements";
  const description =
    score >= 2 ? "This password meets the sign-up rule." : "Use 8+ characters and add at least one number.";

  return {
    score,
    label,
    description,
    checks: checks.map((check) => `${check.passed ? "✓" : "·"} ${check.label}`),
  };
}

function getAppStatusTone(status: string, busy = false) {
  if (busy) {
    return "processing";
  }

  const normalized = status.trim().toLowerCase();
  if (
    normalized.includes("failed") ||
    normalized.includes("error") ||
    normalized.includes("unauthorized") ||
    normalized.includes("missing") ||
    normalized.includes("invalid") ||
    normalized.includes("not found") ||
    normalized.includes("blocked")
  ) {
    return "error";
  }

  if (
    normalized.includes("registered") ||
    normalized.includes("logged in") ||
    normalized.includes("executed") ||
    normalized.includes("reset") ||
    normalized.includes("ready") ||
    normalized.includes("approved") ||
    normalized.includes("signed")
  ) {
    return "success";
  }

  return "info";
}

function sanitizeAmountInput(value: string) {
  const stripped = value.replace(/[^\d.]/g, "");
  const firstDotIndex = stripped.indexOf(".");
  if (firstDotIndex === -1) {
    return stripped;
  }

  const wholePart = stripped.slice(0, firstDotIndex) || "0";
  const fractionPart = stripped
    .slice(firstDotIndex + 1)
    .replace(/\./g, "")
    .slice(0, 2);

  return `${wholePart}.${fractionPart}`;
}

function normalizeAmountInput(value: string) {
  const sanitized = sanitizeAmountInput(value);
  if (!sanitized) {
    return "";
  }

  const parsed = Number(sanitized);
  if (!Number.isFinite(parsed)) {
    return "";
  }

  return parsed.toFixed(2);
}

function getAmountValidationMessage(value: string, availableBalance: number | null) {
  const trimmed = value.trim();
  if (!trimmed) {
    return "Enter an amount";
  }

  const sanitized = sanitizeAmountInput(trimmed);
  if (!sanitized) {
    return "Amount must be a valid number";
  }

  if (!/^\d+(\.\d{0,2})?$/.test(sanitized)) {
    return "Amount can only contain digits and up to two decimal places";
  }

  const parsed = Number(sanitized);
  if (!Number.isFinite(parsed)) {
    return "Amount must be a valid number";
  }
  if (parsed < 0) {
    return "Amount cannot be negative";
  }
  if (availableBalance !== null && parsed > availableBalance) {
    return `Amount cannot exceed your available balance of USD ${availableBalance.toFixed(2)}`;
  }

  return "";
}

export function App() {
  const persistedFlowSnapshot = readPersistedFlowSnapshot();
  const [authReady, setAuthReady] = useState(false);
  const [activeAccount, setActiveAccount] = useState<ActiveAccount | null>(null);
  const [passkeyStatusReady, setPasskeyStatusReady] = useState(false);
  const [accountUsernameInput, setAccountUsernameInput] = useState("");
  const [accountPasswordInput, setAccountPasswordInput] = useState("");
  const [authError, setAuthError] = useState("");
  const [flowId, setFlowId] = useState(() => persistedFlowSnapshot?.flowId ?? `flow_demo_${Date.now()}`);
  const [amount, setAmount] = useState(() => persistedFlowSnapshot?.amount ?? "");
  const [currency, setCurrency] = useState(() => persistedFlowSnapshot?.currency ?? "USD");
  const [memo, setMemo] = useState(() => persistedFlowSnapshot?.memo ?? "");
  const [recipientAccountRef, setRecipientAccountRef] = useState(
    () => persistedFlowSnapshot?.recipientAccountRef ?? "",
  );
  const [amountError, setAmountError] = useState(() => persistedFlowSnapshot?.amountError ?? "");
  const [passkeyTransferor, setPasskeyTransferor] = useState<PasskeyState>(createEmptyPasskeyState);
  const [passkeyAdmin, setPasskeyAdmin] = useState<PasskeyState>(createEmptyPasskeyState);
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [events, setEvents] = useState<EventRecord[]>(() => persistedFlowSnapshot?.events ?? []);
  const [archiveRecords, setArchiveRecords] = useState<ArchiveRecord[]>(
    () => persistedFlowSnapshot?.archiveRecords ?? [],
  );
  const [policyView, setPolicyView] = useState<VerifierPolicyView | null>(null);
  const [policyNotice, setPolicyNotice] = useState("");
  const [lastVerifierEventId, setLastVerifierEventId] = useState(
    () => persistedFlowSnapshot?.lastVerifierEventId ?? "",
  );
  const [agentTrace, setAgentTrace] = useState<AgentTrace | null>(() => persistedFlowSnapshot?.agentTrace ?? null);
  const [executionBalanceSnapshot, setExecutionBalanceSnapshot] = useState<ExecutionBalanceSnapshot | null>(
    () => persistedFlowSnapshot?.executionBalanceSnapshot ?? null,
  );
  const [executionSuccessModalOpen, setExecutionSuccessModalOpen] = useState(false);
  const [status, setStatus] = useState(() => persistedFlowSnapshot?.status ?? "Ready");
  const [restoreConfirmArmed, setRestoreConfirmArmed] = useState(false);
  const [restoreNotice, setRestoreNotice] = useState("");
  const [switchConfirmArmed, setSwitchConfirmArmed] = useState(false);
  const [instructionSubmitBusy, setInstructionSubmitBusy] = useState(false);
  const [selectedStageId, setSelectedStageId] = useState<FlowStageId | null>(
    () => persistedFlowSnapshot?.selectedStageId ?? null,
  );
  const [overviewPreviewStageId, setOverviewPreviewStageId] = useState<FlowStageId | null>(
    () => persistedFlowSnapshot?.overviewPreviewStageId ?? null,
  );
  const [spotlightStageId, setSpotlightStageId] = useState<FlowStageId>(
    () => persistedFlowSnapshot?.spotlightStageId ?? "instruction",
  );
  const [actionPulseStageId, setActionPulseStageId] = useState<FlowStageId | null>(null);
  const [instructionComposerOpen, setInstructionComposerOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<AppTabId>(() => persistedFlowSnapshot?.activeTab ?? "overview");
  const [workflowScrollPending, setWorkflowScrollPending] = useState(false);
  const [accountPanelOpen, setAccountPanelOpen] = useState(false);
  const [showPasskeySuccessToast, setShowPasskeySuccessToast] = useState(false);
  const [transferFailureModalOpen, setTransferFailureModalOpen] = useState(false);
  const [transferFailureVerifierEvent, setTransferFailureVerifierEvent] = useState<EventRecord | null>(null);
  const [archiveDetailOpen, setArchiveDetailOpen] = useState(false);
  const [archiveDetailLoading, setArchiveDetailLoading] = useState(false);
  const [archiveDetailError, setArchiveDetailError] = useState("");
  const [archiveDetailTransaction, setArchiveDetailTransaction] = useState<Transaction | null>(null);
  const [archiveDetailRecords, setArchiveDetailRecords] = useState<ArchiveRecord[]>([]);
  const [adminReviewPromptOpen, setAdminReviewPromptOpen] = useState(false);
  const accountPanelRef = useRef<HTMLDivElement | null>(null);
  const workflowPanelRef = useRef<HTMLElement | null>(null);
  const workflowAdminCueRef = useRef<HTMLDivElement | null>(null);
  const workflowBottomRef = useRef<HTMLDivElement | null>(null);
  const transferorRegisterButtonRef = useRef<HTMLButtonElement | null>(null);
  const adminRegisterButtonRef = useRef<HTMLButtonElement | null>(null);
  const archiveDetailRequestRef = useRef(0);
  const previousMissingPasskeyCountRef = useRef(0);
  const autoExecutionAttemptRef = useRef<string | null>(null);
  const passwordStrength = evaluatePasswordStrength(accountPasswordInput);

  function createFlowId() {
    return `flow_demo_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  }

  const transferorPrincipalId = activeAccount?.transferorPrincipalId ?? DEMO_PRINCIPALS.transferor;
  const adminPrincipalId = activeAccount?.adminPrincipalId ?? DEMO_PRINCIPALS.admin;
  const recipientPrincipalId = activeAccount?.recipientPrincipalId ?? DEMO_PRINCIPALS.recipient;
  const activeUsername = activeAccount?.username ?? "";
  const activeAccountLabel = activeUsername || "demo";
  const passkeyStatusLoading = Boolean(activeAccount) && !passkeyStatusReady;
  const passkeySetupIncomplete =
    passkeyStatusReady && (!passkeyTransferor.registered || !passkeyAdmin.registered);
  const showPasskeyOnboarding = passkeyStatusReady && passkeySetupIncomplete;
  const missingPasskeyRoles = [
    !passkeyTransferor.registered ? "Transferor passkey" : null,
    !passkeyAdmin.registered ? "Administrator passkey" : null,
  ].filter(Boolean) as string[];

  const transferorAccount = accounts.find(
    (account) => account.ownerId === transferorPrincipalId && account.ownerRole === "transferor",
  );
  const allowlistedRecipientAccount = accounts.find(
    (account) => account.ownerId === recipientPrincipalId && account.ownerRole === "recipient",
  );
  const selectedRecipientAccount = accounts.find((account) => account.accountId === recipientAccountRef) ?? null;
  const currentAccountIds = Array.from(
    new Set(
      [transferorAccount?.accountId, allowlistedRecipientAccount?.accountId].filter(
        (accountId): accountId is string => Boolean(accountId),
      ),
    ),
  );
  const archiveTransactions = transactions
    .filter(
      (transaction) =>
        transaction.status === "executed" &&
        (currentAccountIds.includes(transaction.fromAccountId) ||
          currentAccountIds.includes(transaction.toAccountId)),
    )
    .slice()
    .sort(
      (left, right) =>
        new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime() ||
        right.transactionId.localeCompare(left.transactionId),
    );
  const archiveGroupedTransactions = archiveTransactions.reduce<
    Array<{ monthKey: string; monthLabel: string; items: Transaction[] }>
  >((groups, transaction) => {
    const monthKey = transaction.createdAt.slice(0, 7);
    const currentGroup = groups.at(-1);

    if (!currentGroup || currentGroup.monthKey !== monthKey) {
      groups.push({
        monthKey,
        monthLabel: formatArchiveMonthLabel(monthKey),
        items: [],
      });
    }

    groups.at(-1)?.items.push(transaction);
    return groups;
  }, []);
  const threshold = policyView?.policy.adminReviewAtOrAbove ?? 1000;
  const transferorAvailableBalance = transferorAccount?.availableBalance ?? null;
  const normalizedAmount = normalizeAmountInput(amount);
  const amountValidationMessage = getAmountValidationMessage(amount, transferorAvailableBalance);
  const parsedAmount = normalizedAmount ? Number(normalizedAmount) : Number.NaN;
  const requiresAdmin = Number.isFinite(parsedAmount) && parsedAmount >= threshold;
  const instructionEvent = events.find((event) => event.kind === 101);
  const envelopeEvent = events.find((event) => event.kind === 102);
  const firstVerifierEvent = events.find(
    (event) => event.kind === 103 || event.kind === 104 || event.kind === 108,
  );
  const adminApprovalEvent = events.find((event) => event.kind === 105);
  const reverifyEvent = events.find((event) => event.kind === 107);
  const rejectEvent = events.find((event) => event.kind === 108);
  const executionEvent = events.find((event) => event.kind === 109);
  const latestArchiveRecord = archiveRecords.at(-1);
  const policySummary = policyView
    ? `Bundle ${policyView.bundle.bundleId} · ${policyView.policy.policyName} · Auto below ${policyView.policy.currency} ${policyView.policy.autoExecuteBelow.toFixed(2)} · Admin at ${policyView.policy.adminReviewAtOrAbove.toFixed(2)}`
    : policyNotice || "USD policy is loading.";
  const canExecute = Boolean(
    lastVerifierEventId && (!requiresAdmin ? firstVerifierEvent?.kind === 103 : reverifyEvent),
  );
  const isFlowEmpty =
    !instructionEvent && !envelopeEvent && !firstVerifierEvent && !reverifyEvent && !executionEvent;
  const isWaitingForFirstVerifier = Boolean(envelopeEvent && !firstVerifierEvent && !rejectEvent);
  const isWaitingForAdmin = requiresAdmin && firstVerifierEvent?.kind === 104 && !reverifyEvent;
  const canAdminApprove = Boolean(passkeyAdmin.registered && isWaitingForAdmin && !executionEvent);
  const isReadyForExecution = canExecute && !executionEvent;
  const activeVerifierEvent =
    reverifyEvent ??
    firstVerifierEvent ??
    rejectEvent;
  const flowStages = buildFlowStages({
    requiresAdmin,
    instructionEvent,
    envelopeEvent,
    firstVerifierEvent,
    adminApprovalEvent,
    reverifyEvent,
    rejectEvent,
    executionEvent,
    archiveRecord: latestArchiveRecord,
    agentTrace,
  });
  const currentActionLabel = executionEvent
    ? "Flow completed"
    : rejectEvent
      ? "Review rejection details"
      : isWaitingForAdmin
        ? "Administrator passkey signature required"
        : isReadyForExecution
          ? "Automatic MCP execution in progress"
          : isWaitingForFirstVerifier
            ? "Verifier is evaluating the agent envelope"
            : isFlowEmpty
              ? "Capture and sign a new human instruction"
              : "Transferor should submit this instruction to verifier";
  const currentActionHint = executionEvent
    ? "This flow has already reached MCP execution."
    : rejectEvent
      ? "The verifier halted this flow. Open the rejected step for full validation details."
      : isWaitingForAdmin
        ? "This amount crossed the policy threshold, so admin passkey approval is the next mandatory step."
        : isReadyForExecution
          ? "Verifier approval is complete. After the check passes, the agent automatically relays the package for MCP execution."
          : isWaitingForFirstVerifier
            ? "The signed instruction and agent envelope were already submitted. Wait for the verifier decision."
            : "You can operate directly from this strip without scrolling away from the live governance diagram.";
  const selectedStage = selectedStageId
    ? flowStages.find((stage) => stage.id === selectedStageId) ?? null
    : null;
  const overviewPreviewStage = overviewPreviewStageId
    ? flowStages.find((stage) => stage.id === overviewPreviewStageId) ?? null
    : null;
  const flowStatusLabel = executionEvent
    ? "Executed"
    : rejectEvent
      ? "Rejected"
      : reverifyEvent
        ? "Re-verified"
        : firstVerifierEvent?.kind === 104
          ? "Admin Review"
          : firstVerifierEvent?.kind === 103
            ? "Verifier Approved"
            : envelopeEvent
              ? "In Verification"
              : instructionEvent
                ? "At Agent"
                : "Not started";
  const currentStateSummary = passkeySetupIncomplete
    ? "Passkey setup needed"
    : passkeyStatusLoading
      ? "Checking signer passkeys"
    : executionEvent
      ? "Flow executed"
      : canExecute
        ? "Auto execution ready"
        : "Ready to transfer";
  const verifierTabDecisionLabel = !instructionEvent
    ? "No transfer yet"
    : rejectEvent
      ? "Rejected"
      : isWaitingForAdmin
        ? "Admin review required"
        : isReadyForExecution
          ? "Approved"
          : firstVerifierEvent?.kind === 103
            ? "Approved"
            : firstVerifierEvent?.kind === 104
              ? "Escalated"
              : firstVerifierEvent?.kind === 108
                ? "Rejected"
                : "Under review";
  const verifierTabNextStep = !instructionEvent
    ? "Start a transfer first. The verifier only appears once a signed instruction has been submitted."
    : rejectEvent
      ? "Review the rejected step in Trace to see the reason and evidence."
      : isWaitingForAdmin
        ? "The verifier has escalated this flow. The next step is an administrator passkey signature."
        : isReadyForExecution
          ? "The verifier approved the flow. The agent now forwards it to MCP automatically."
          : firstVerifierEvent?.kind === 103
            ? "The verifier approved the instruction and the flow can move forward."
            : "The verifier is checking the signed instruction, recipient, and policy lane.";
  const sidebarTabs: Array<{
    id: AppTabId;
    label: string;
    hint: string;
    attention?: boolean;
  }> = [
    {
      id: "overview",
      label: "Overview",
      hint: "See the full governed transfer path",
    },
    {
      id: "transfer",
      label: "Transfer",
      hint: "Start and submit a human transfer instruction",
    },
    {
      id: "agent",
      label: "Agent",
      hint: "Review Gemini Enterprise Agent Platform context",
    },
    {
      id: "verifier",
      label: "Verifier",
      hint: "See the decision layer and approval logic",
    },
    {
      id: "policy",
      label: "Policy",
      hint: "Review threshold and allowlist behavior",
    },
    {
      id: "trace",
      label: "Trace",
      hint: "Inspect stages, events, and archive checkpoints",
    },
    {
      id: "archive",
      label: "Archive",
      hint: "Review successful transfers and archive event details",
    },
  ];
  const currentTabLabel = sidebarTabs.find((tab) => tab.id === activeTab)?.label ?? "Overview";
  const currentTabDescription = (() => {
    switch (activeTab) {
      case "overview":
        return "Start here for a quick product summary, then jump into transfer, policy, or trace when needed.";
      case "transfer":
        return "Start a transfer instruction, sign it, and hand it to the agent.";
      case "agent":
        return agentTrace
          ? "Review the Gemini Enterprise Agent Platform prompt, checks, tools, and run details for this transfer."
          : "No transfer instruction has been submitted yet, so the agent has not started.";
      case "verifier":
        return activeVerifierEvent
          ? "See how the verifier reviewed the signed instruction, applied policy, and decided what happens next."
          : "No transfer instruction has been submitted yet, so the verifier has not started.";
      case "policy":
        return "Review the active governance bundle, threshold, and allowlist behavior.";
      case "trace":
        return "See how a transfer moves from signature to execution, with evidence available when you need it.";
      case "archive":
        return "Review completed transfer history for the current account and open each archive event for a quick overview.";
      default:
        return "See how a transfer moves from signature to execution, with evidence available when you need it.";
    }
  })();
  const agentModelName = __GOOGLE_ADK_MODEL__ || "gemini-3.5-flash-lite";
  const hasAgentRun = Boolean(agentTrace && instructionEvent);
  const signedEnvelopeView = getSignedEnvelopeView(envelopeEvent);
  const recipientAllowlisted = Boolean(
    selectedRecipientAccount &&
      selectedRecipientAccount.ownerId === recipientPrincipalId &&
      selectedRecipientAccount.ownerRole === "recipient",
  );
  const recipientHint = !recipientAccountRef
    ? "Choose a recipient"
    : !recipientAllowlisted
      ? "This transfer will be rejected at verifier validation."
      : `Selected: ${recipientAccountRef}`;
  const amountBelowThreshold = Number.isFinite(parsedAmount) && parsedAmount < threshold;
  const verifierCheckViews: Array<{
    label: string;
    detail: string;
    tone: "pass" | "warn" | "fail";
  }> = [
    {
      label: "Recipient is allowlisted",
      detail: recipientAllowlisted
        ? `Resolved to ${selectedRecipientAccount?.accountId || recipientAccountRef} and passed the allowlist check.`
        : "The selected recipient does not match the allowlisted recipient account.",
      tone: recipientAllowlisted ? "pass" : "fail",
    },
    {
      label: "Amount stays below the policy threshold",
      detail: Number.isFinite(parsedAmount)
        ? amountBelowThreshold
          ? `${currency} ${parsedAmount.toFixed(2)} stays below ${currency} ${threshold.toFixed(2)}.`
          : `${currency} ${parsedAmount.toFixed(2)} reaches or exceeds the policy threshold.`
        : "Set an amount to evaluate the policy lane.",
      tone: Number.isFinite(parsedAmount) ? (amountBelowThreshold ? "pass" : "warn") : "warn",
    },
  ];
  const traceDigestCards = [
    {
      eyebrow: "Model",
      title: agentModelName,
      summary: hasAgentRun
        ? "Gemini Enterprise Agent Platform already handled this transfer."
        : "No transfer instruction exists yet, so the agent stays idle.",
      meta: hasAgentRun
        ? `${agentTrace?.mandatoryTools?.length ?? 0} checks · ${agentTrace?.toolCalls.length ?? 0} tools`
        : "No transfer submitted yet",
      status: hasAgentRun ? "done" : "pending",
    },
    {
      eyebrow: "History",
      title: executionBalanceSnapshot ? "Balances updated" : "Archive ready",
      summary: executionBalanceSnapshot
        ? "The sender and recipient balances were updated, and the result was archived."
        : "Every completed flow is kept in the archive for later review.",
      meta: executionBalanceSnapshot
        ? `${executionBalanceSnapshot.currency} ${executionBalanceSnapshot.amount.toFixed(2)} transferred`
        : `${archiveRecords.length} archived checkpoints`,
      status: executionBalanceSnapshot ? "done" : archiveRecords.length > 0 ? "current" : "pending",
    },
  ] as const;
  const traceJourneyCards = [
    {
      step: "1",
      tone: "transferor" as const,
      title: "Instruction signed",
      summary: instructionEvent
        ? "The transferor used a passkey to confirm the payment instruction."
        : "No transfer has been started yet.",
      meta: instructionEvent ? "Signed instruction" : "Ready for signature",
      status: instructionEvent ? "done" : "current",
      statusLabel: instructionEvent ? "Done" : "Active",
      stageId: "instruction" as FlowStageId,
    },
    {
      step: "2",
      tone: "agent" as const,
      title: "Agent prepares transfer",
      summary: envelopeEvent
        ? "The agent wrapped the instruction and passed it to the verifier."
        : "The agent starts after a signed instruction is submitted.",
      meta: envelopeEvent ? "Prepared package" : "Not started yet",
      status: envelopeEvent ? "done" : instructionEvent ? "current" : "pending",
      statusLabel: envelopeEvent ? "Done" : instructionEvent ? "Active" : "Up next",
      stageId: "agent_envelope" as FlowStageId,
    },
    {
      step: "3",
      tone: requiresAdmin ? ("admin" as const) : ("verifier" as const),
      title: requiresAdmin ? "Admin confirmation branch" : "Verifier decision",
      summary: requiresAdmin
        ? adminApprovalEvent || reverifyEvent
          ? "This higher-value transfer has entered the admin branch and is ready for re-check."
          : "This transfer is above the threshold, so it branches to a second admin confirmation before execution."
        : "The verifier approved the transfer without an extra admin step.",
      meta: requiresAdmin ? "Conditional branch" : "Auto lane",
      status: requiresAdmin
        ? adminApprovalEvent || reverifyEvent
          ? "done"
          : "current"
        : firstVerifierEvent
          ? "done"
          : envelopeEvent
            ? "current"
            : "pending",
      statusLabel: requiresAdmin
        ? adminApprovalEvent || reverifyEvent
          ? "Done"
          : "Active"
        : firstVerifierEvent
          ? "Done"
          : envelopeEvent
            ? "Active"
            : "Up next",
      stageId: (requiresAdmin ? "admin" : "verifier") as FlowStageId,
    },
    {
      step: "4",
      tone: "mcp" as const,
      title: requiresAdmin ? "Re-check then settle" : "Payment completes",
      summary: executionEvent
        ? "The bank completed the transfer and the archive saved the final checkpoint."
        : requiresAdmin
          ? "After admin confirmation, the verifier re-checks the packet and the bank settles automatically."
          : "The flow finishes here automatically once approval clears.",
      meta: executionEvent ? "Settled" : requiresAdmin ? "After re-check" : "Auto after check",
      status: executionEvent ? "done" : reverifyEvent || firstVerifierEvent?.kind === 103 ? "current" : "pending",
      statusLabel: executionEvent
        ? "Done"
        : requiresAdmin
          ? reverifyEvent
            ? "In progress"
            : adminApprovalEvent
              ? "Re-check pending"
              : "Awaiting admin"
          : reverifyEvent || firstVerifierEvent?.kind === 103
            ? "In progress"
            : "Up next",
      stageId: executionEvent ? "execution" : "archive",
    },
  ] as const;

  useEffect(() => {
    let cancelled = false;

    async function loadSessionAccount() {
      try {
        const response = await fetchIdentity("/auth/me", { method: "GET" });
        if (!response.ok) {
          if (!cancelled) {
            setActiveAccount(null);
          }
          return;
        }

        const body = (await response.json()) as {
          authenticated: boolean;
          account: ActiveAccount | null;
        };
        if (!cancelled) {
          setActiveAccount(body.authenticated ? body.account : null);
          setAccountUsernameInput(body.account?.username ?? "");
        }
      } catch {
        if (!cancelled) {
          setActiveAccount(null);
        }
      } finally {
        if (!cancelled) {
          setAuthReady(true);
        }
      }
    }

    void loadSessionAccount();

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const currentStage =
      flowStages.find((stage) => stage.status === "current") ??
      [...flowStages].reverse().find((stage) => stage.status === "done") ??
      flowStages[0];
    if (currentStage && currentStage.id !== spotlightStageId) {
      setSpotlightStageId(currentStage.id);
    }
  }, [flowStages, spotlightStageId]);

  useEffect(() => {
    if (!actionPulseStageId) {
      return;
    }

    const timer = window.setTimeout(() => {
      setActionPulseStageId(null);
    }, 1600);

    return () => window.clearTimeout(timer);
  }, [actionPulseStageId]);

  async function fetchPasskeyStatus(
    principalId: string,
    target: "transferor" | "admin",
  ) {
    const response = await fetchIdentity(`/principals/${principalId}/passkey-status`, {
      method: "GET",
    });
    if (response.status === 401) {
      setActiveAccount(null);
      setAuthError("Session expired. Please log in again.");
      const emptyState = createEmptyPasskeyState();
      if (target === "transferor") {
        setPasskeyTransferor(emptyState);
      } else {
        setPasskeyAdmin(emptyState);
      }
      return emptyState;
    }
    const body = (await response.json()) as {
      registered: boolean;
      credentials: Array<{
        credentialId: string;
        counter: number;
        transports: string[];
        deviceType: string;
        backedUp: boolean;
        rpId: string;
        createdAt: string;
        lastUsedAt: string;
      }>;
      latestAuthenticationProof: null | {
        proofId: string;
        createdAt: string;
        credentialId: string;
        proofType: string;
      };
      latestVerifiedProof: null | {
        proofId: string;
        createdAt: string;
        credentialId: string;
        proofType: string;
      };
    };

    const firstCredential = body.credentials[0];
    const latestProof = body.latestVerifiedProof ?? body.latestAuthenticationProof;
    const nextState: PasskeyState = {
      registered: body.registered,
      verified: body.registered && Boolean(latestProof),
      credentialId: firstCredential?.credentialId ?? "",
      publicKeyRef: firstCredential?.credentialId ?? "",
      registeredAt: firstCredential?.createdAt ?? "",
      proofRef: latestProof?.proofId ?? "",
      lastVerifiedAt: latestProof?.createdAt ?? firstCredential?.createdAt ?? "",
      proofType: latestProof?.proofType ?? "",
      deviceType: firstCredential?.deviceType ?? "",
      backedUp: firstCredential?.backedUp ?? null,
      rpId: firstCredential?.rpId ?? "",
      lastUsedAt: firstCredential?.lastUsedAt ?? "",
      counter: firstCredential?.counter ?? null,
      transports: firstCredential?.transports ?? [],
    };

    if (target === "transferor") {
      setPasskeyTransferor(nextState);
      return nextState;
    }

    setPasskeyAdmin(nextState);
    return nextState;
  }

  async function refreshPasskeys() {
    if (!activeAccount) {
      setPasskeyStatusReady(false);
      return;
    }

    setPasskeyStatusReady(false);
    try {
      await Promise.all([
        fetchPasskeyStatus(transferorPrincipalId, "transferor"),
        fetchPasskeyStatus(adminPrincipalId, "admin"),
      ]);
      setPasskeyStatusReady(true);
    } catch (error) {
      setPasskeyStatusReady(true);
      throw error;
    }
  }

  async function fetchAccounts() {
    const response = await fetch(`${MCP_BANK_URL}/accounts`);
    const body = (await response.json()) as { accounts: Account[] };
    setAccounts(body.accounts);
  }

  async function fetchTransactions() {
    const response = await fetch(`${MCP_BANK_URL}/transactions`);
    const body = (await response.json()) as { transactions: Transaction[] };
    setTransactions(body.transactions);
  }

  async function fetchEvents(targetFlowId = flowId) {
    const response = await fetch(`${EVENT_SERVICE_URL}/events?flowId=${targetFlowId}`);
    const body = (await response.json()) as { events: EventRecord[] };
    setEvents(body.events);
  }

  async function fetchArchiveRecordsForFlow(targetFlowId: string) {
    const response = await fetch(`${ARCHIVE_SERVICE_URL}/archive/flows/${targetFlowId}`);
    const body = (await response.json()) as { records: ArchiveRecord[]; error?: string; detail?: string };

    if (!response.ok) {
      throw new Error(body.error ?? body.detail ?? "Failed to load archive records");
    }

    return body.records ?? [];
  }

  async function fetchArchive(targetFlowId = flowId) {
    const records = await fetchArchiveRecordsForFlow(targetFlowId);
    setArchiveRecords(records);
  }

  async function fetchPolicy() {
    const response = await fetch(`${VERIFIER_SERVICE_URL}/verifier/policy/current?currency=USD`);
    const body = (await response.json()) as unknown;
    const errorMessage =
      body && typeof body === "object" && !Array.isArray(body)
        ? ((body as { error?: string; detail?: string }).error ??
            (body as { error?: string; detail?: string }).detail ??
            "")
        : "";

    if (!response.ok || errorMessage) {
      setPolicyView(null);
      setPolicyNotice(
        errorMessage ||
          "USD is not supported by the active policy bundle",
      );
      return;
    }
    setPolicyView(body as VerifierPolicyView);
    setPolicyNotice("");
  }

  async function refreshAll(targetFlowId = flowId) {
    await Promise.all([
      fetchAccounts(),
      fetchTransactions(),
      fetchEvents(targetFlowId),
      fetchArchive(targetFlowId),
      fetchPolicy(),
      refreshPasskeys(),
    ]);
  }

  useEffect(() => {
    void refreshAll();
  }, [activeAccount?.username]);

  useEffect(() => {
    void Promise.all([fetchEvents(), fetchArchive()]);
  }, [flowId]);

  useEffect(() => {
    void fetchPolicy();
  }, []);

  useEffect(() => {
    if (!activeAccount) {
      return;
    }

    void refreshPasskeys();
  }, [activeAccount?.username, transferorPrincipalId, adminPrincipalId]);

  useEffect(() => {
    writePersistedFlowSnapshot({
      flowId,
      activeTab,
      amount,
      currency,
      memo,
      recipientAccountRef,
      amountError,
      status,
      lastVerifierEventId,
      agentTrace,
      executionBalanceSnapshot,
      events,
      archiveRecords,
      selectedStageId,
      overviewPreviewStageId,
      spotlightStageId,
    });
  }, [
    flowId,
    activeTab,
    amount,
    currency,
    memo,
    recipientAccountRef,
    amountError,
    status,
    lastVerifierEventId,
    agentTrace,
    executionBalanceSnapshot,
    events,
    archiveRecords,
    selectedStageId,
    overviewPreviewStageId,
    spotlightStageId,
  ]);

  useEffect(() => {
    const currentMissingCount = missingPasskeyRoles.length;
    const previousMissingCount = previousMissingPasskeyCountRef.current;

    if (
      accountPanelOpen &&
      currentMissingCount > 0 &&
      previousMissingCount > currentMissingCount
    ) {
      const nextMissingButton =
        !passkeyTransferor.registered ? transferorRegisterButtonRef.current : adminRegisterButtonRef.current;
      nextMissingButton?.focus();
      nextMissingButton?.scrollIntoView({ block: "nearest", inline: "nearest", behavior: "smooth" });
    }

    if (activeAccount && previousMissingCount > 0 && currentMissingCount === 0) {
      setShowPasskeySuccessToast(true);
    }

    previousMissingPasskeyCountRef.current = currentMissingCount;
  }, [
    accountPanelOpen,
    activeAccount,
    missingPasskeyRoles.length,
    passkeyTransferor.registered,
    passkeyAdmin.registered,
  ]);

  useEffect(() => {
    if (!showPasskeySuccessToast) {
      return;
    }

    const timer = window.setTimeout(() => {
      setShowPasskeySuccessToast(false);
    }, 2600);

    return () => window.clearTimeout(timer);
  }, [showPasskeySuccessToast]);

  useEffect(() => {
    if (!isReadyForExecution || executionEvent || !lastVerifierEventId) {
      return;
    }

    if (autoExecutionAttemptRef.current === lastVerifierEventId) {
      return;
    }

    autoExecutionAttemptRef.current = lastVerifierEventId;
    pulseAndRun("execution", () => void handleExecuteTransfer());
  }, [executionEvent, isReadyForExecution, lastVerifierEventId]);

  useEffect(() => {
    if (!workflowScrollPending || activeTab !== "transfer") {
      return;
    }

    const timer = window.setTimeout(() => {
      if (isWaitingForAdmin) {
        workflowAdminCueRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
      } else {
        workflowBottomRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
      }
      setWorkflowScrollPending(false);
    }, 0);

    return () => window.clearTimeout(timer);
  }, [activeTab, isWaitingForAdmin, workflowScrollPending]);

  useEffect(() => {
    if (!authReady || !activeAccount || passkeySetupIncomplete) {
      return;
    }

    setStatus((current) =>
      current === "Account registered" || current === "Logged in"
        ? "Passkey setup complete. You can now continue with the transfer flow."
        : current,
    );
  }, [authReady, activeAccount, passkeySetupIncomplete]);

  useEffect(() => {
    if (!accountPanelOpen) {
      setRestoreConfirmArmed(false);
      setRestoreNotice("");
      setSwitchConfirmArmed(false);
      return;
    }

    function handlePointerDown(event: MouseEvent) {
      if (!accountPanelRef.current?.contains(event.target as Node)) {
        setAccountPanelOpen(false);
      }
    }

    document.addEventListener("mousedown", handlePointerDown);
    return () => document.removeEventListener("mousedown", handlePointerDown);
  }, [accountPanelOpen]);

  useEffect(() => {
    if (!restoreConfirmArmed) {
      return;
    }

    const timeoutId = window.setTimeout(() => {
      setRestoreConfirmArmed(false);
      setRestoreNotice("");
    }, 4000);

    return () => window.clearTimeout(timeoutId);
  }, [restoreConfirmArmed]);

  function resetTransferForm(nextFlowId = createFlowId()) {
    setFlowId(nextFlowId);
    setAmount("");
    setAmountError("");
    setCurrency("USD");
    setMemo("");
    setRecipientAccountRef("");
    setPolicyView(null);
    setPolicyNotice("");
    setLastVerifierEventId("");
    setAgentTrace(null);
    setExecutionBalanceSnapshot(null);
    setExecutionSuccessModalOpen(false);
    setTransferFailureModalOpen(false);
    setTransferFailureVerifierEvent(null);
    setEvents([]);
    setArchiveRecords([]);
    setSelectedStageId(null);
    setInstructionComposerOpen(false);
    setStatus("Ready");
    setActionPulseStageId(null);
    setInstructionSubmitBusy(false);
    setWorkflowScrollPending(false);
    setAdminReviewPromptOpen(false);
    autoExecutionAttemptRef.current = null;
  }

  function startNewFlow() {
    resetTransferForm();
    void fetchPolicy();
    setActiveTab("transfer");
    setInstructionComposerOpen(true);
  }

  function handleTransferPrimaryAction() {
    if (isFlowEmpty) {
      setInstructionComposerOpen(true);
      return;
    }

    startNewFlow();
  }

  async function handleEnterAccount(action: "register" | "login") {
    const username = accountUsernameInput.trim();
    const password = accountPasswordInput;
    if (!username || !password) {
      setAuthError("Please enter both username and password");
      return;
    }
    try {
      assertEnglishAccountHandle(username);
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "Username must be English");
      return;
    }
    if (action === "register" && passwordStrength.score < 2) {
      setAuthError("Password must be at least 8 characters and include a number.");
      return;
    }

    try {
      setAuthError("");
      const response = await fetchIdentity(`/auth/${action}`, {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      const body = (await response.json()) as {
        ok?: boolean;
        account?: ActiveAccount;
        error?: string;
      };
      if (!response.ok || !body.account) {
        throw new Error(body.error ?? "Authentication failed");
      }

      setActiveAccount(body.account);
      setPasskeyStatusReady(false);
      setPasskeyTransferor(createEmptyPasskeyState());
      setPasskeyAdmin(createEmptyPasskeyState());
      setAccountPasswordInput("");
      resetTransferForm();
      setActiveTab("overview");
      setAccountPanelOpen(false);
      setAccountUsernameInput(body.account.username);
      setStatus(action === "register" ? "Account registered" : "Logged in");
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "Authentication failed");
    }
  }

  async function handleLogout() {
    await fetchIdentity("/auth/logout", { method: "POST" });
    setActiveAccount(null);
    setPasskeyStatusReady(false);
    setAccountUsernameInput("");
    setAccountPasswordInput("");
    setPasskeyTransferor(createEmptyPasskeyState());
    setPasskeyAdmin(createEmptyPasskeyState());
    resetTransferForm();
    setActiveTab("overview");
    setAccountPanelOpen(false);
    setAuthError("");
    setStatus("Logged out");
  }

  function handleSwitchAccountClick() {
    if (!switchConfirmArmed) {
      setSwitchConfirmArmed(true);
      return;
    }

    void handleLogout();
  }

  async function restoreOriginalBalances() {
    try {
      const response = await fetch(`${MCP_BANK_URL}/admin/reset-balances`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          transferorOwnerId: transferorPrincipalId,
          recipientOwnerId: recipientPrincipalId,
        }),
      });
      if (!response.ok) {
        const body = (await response.json()) as { error?: string };
        throw new Error(body.error ?? "Failed to restore original balances");
      }

      await refreshAll();
      setRestoreConfirmArmed(false);
      setRestoreNotice("Balances restored to original values");
    } catch (error) {
      setRestoreNotice(error instanceof Error ? error.message : "Failed to restore balances");
    }
  }

  function handleRestoreBalancesClick() {
    if (!restoreConfirmArmed) {
      setRestoreConfirmArmed(true);
      setRestoreNotice("Click ✓ to confirm resetting current account balances");
      return;
    }

    void restoreOriginalBalances();
  }

  function getMissingPasskeyMessage() {
    if (!passkeyStatusReady) {
      return "Checking passkey status. Please wait a moment and try again.";
    }

    const missing: string[] = [];

    if (!passkeyTransferor.registered) {
      missing.push("Transferor passkey");
    }
    if (!passkeyAdmin.registered) {
      missing.push("Administrator passkey");
    }

    if (missing.length === 0) {
      return "";
    }

    if (missing.length === 2) {
      return "Transferor and administrator passkeys must be registered before editing a human instruction";
    }

    return `${missing[0]} must be registered before editing a human instruction`;
  }

  function openInstructionComposerGuarded() {
    const missingPasskeyMessage = getMissingPasskeyMessage();
    if (missingPasskeyMessage) {
      setStatus(missingPasskeyMessage);
      setAccountPanelOpen(true);
      return false;
    }

    setInstructionComposerOpen(true);
    return true;
  }

  function pulseAndRun(stageId: FlowStageId, action: () => void) {
    setActionPulseStageId(stageId);
    action();
  }

  async function authenticatePasskey(
    principalId: string,
    role: "transferor" | "administrator",
  ): Promise<AuthenticatePasskeyResult> {
    const optionsResponse = await fetchIdentity("/webauthn/authenticate/options", {
      method: "POST",
      body: JSON.stringify({ principalId, role }),
    });
    const optionsBody = (await optionsResponse.json()) as { options?: unknown; error?: string };
    if (!optionsResponse.ok || !optionsBody.options) {
      throw new Error(optionsBody.error ?? "Failed to load authentication options");
    }

    const authResp = await startAuthentication({ optionsJSON: optionsBody.options as never });
    const verifyResponse = await fetchIdentity("/webauthn/authenticate/verify", {
      method: "POST",
      body: JSON.stringify({ principalId, role, response: authResp }),
    });
    const verifyBody = (await verifyResponse.json()) as {
      verified?: boolean;
      proofId?: string;
      credentialId?: string;
      error?: string;
    };
    if (!verifyResponse.ok || !verifyBody.verified || !verifyBody.proofId) {
      throw new Error(verifyBody.error ?? "Failed to verify authentication response");
    }

    void refreshPasskeys();
    return {
      proofId: verifyBody.proofId,
      credentialId: verifyBody.credentialId ?? "",
    };
  }

  async function registerPasskey(
    principalId: string,
    role: "transferor" | "administrator",
  ) {
    try {
      const optionsResponse = await fetchIdentity("/webauthn/register/options", {
        method: "POST",
        body: JSON.stringify({ principalId, role }),
      });
      const optionsBody = (await optionsResponse.json()) as { options?: unknown; error?: string };
      if (!optionsResponse.ok || !optionsBody.options) {
        throw new Error(optionsBody.error ?? "Failed to load registration options");
      }

      const attResp = await startRegistration({ optionsJSON: optionsBody.options as never });
      const verifyResponse = await fetchIdentity("/webauthn/register/verify", {
        method: "POST",
        body: JSON.stringify({ principalId, role, response: attResp }),
      });
      const verifyBody = (await verifyResponse.json()) as { error?: string };
      if (!verifyResponse.ok) {
        throw new Error(verifyBody.error ?? "Failed to verify registration");
      }

      await refreshPasskeys();
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Failed to register passkey");
    }
  }

  async function createInstructionEvent() {
    if (!passkeyTransferor.registered || !passkeyTransferor.proofRef) {
      throw new Error("Transferor must register a passkey first");
    }
    const instructionAmount = normalizeAmountInput(amount) || amount;

    const eventPayload = {
      id: `evt_instr_${flowId}_hash`,
      kind: 101,
      ai_id: transferorPrincipalId,
      created_at: Date.now(),
      tags: [
        ["flow_id", flowId],
        ["role", "transferor"],
        ["action", "transfer"],
      ],
      content: {
          instruction_id: `instr_${flowId}`,
          principal_id: transferorPrincipalId,
          agent_id: DEMO_AGENT_IDS.transfer,
          action_type: "payment.transfer",
          amount: instructionAmount,
          currency,
        recipient_id: recipientPrincipalId,
        recipient_account_ref: recipientAccountRef,
        memo,
        submitted_at: new Date().toISOString(),
        expiry_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
        instruction_nonce: `nonce_${Date.now()}`,
        signing_payload: {
          payload_version: "1.0",
          payload_type: "transfer_instruction",
          canonicalization: "jcs-rfc8785",
          signed_fields: [
            "instruction_id",
            "principal_id",
            "agent_id",
            "action_type",
            "amount",
            "currency",
            "recipient_id",
            "recipient_account_ref",
            "memo",
            "submitted_at",
            "expiry_at",
            "instruction_nonce",
          ],
          payload_hash: `sha256:instruction_${Date.now()}`,
        },
        signature_proof: {
          passkey_verified: passkeyTransferor.registered && passkeyTransferor.verified,
          signature:
            passkeyTransferor.registered && passkeyTransferor.verified
              ? "passkey_sig_demo_transferor"
              : "",
          proof_ref: passkeyTransferor.proofRef,
          signature_alg: "webauthn-passkey-es256",
          credential_id: passkeyTransferor.credentialId,
          public_key_ref: passkeyTransferor.publicKeyRef,
          challenge: `registration_ready_${flowId}`,
          signed_at: passkeyTransferor.lastVerifiedAt || passkeyTransferor.registeredAt || new Date().toISOString(),
          verifier_material_ref: "webauthn_assertion_bundle_001",
        },
      },
    };

    const response = await fetch(`${EVENT_SERVICE_URL}/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ flowId, payload: eventPayload }),
    });

    if (!response.ok) {
      throw new Error("Failed to create instruction event");
    }

    const body = (await response.json()) as { event: EventRecord };
    return body.event;
  }

  async function createEnvelopeEvent(instructionEventId: string) {
    const envelopeAmount = normalizeAmountInput(amount) || amount;
    const eventPayload = {
      id: `evt_env_${Date.now()}_hash`,
      kind: 102,
      ai_id: DEMO_AGENT_IDS.transfer,
      created_at: Date.now(),
      tags: [
        ["flow_id", flowId],
        ["action", "payment.transfer"],
      ],
      content: {
        instruction_ref: instructionEventId,
            action: {
              params: {
                amount: envelopeAmount,
                currency,
            recipient_account_ref: recipientAccountRef,
            memo,
          },
        },
      },
    };

    const response = await fetch(`${EVENT_SERVICE_URL}/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ flowId, payload: eventPayload }),
    });

    if (!response.ok) {
      throw new Error("Failed to create envelope event");
    }

    const body = (await response.json()) as { event: EventRecord };
    return body.event;
  }

  async function handleEvaluate() {
    try {
      const nextFlowId = createFlowId();
      setFlowId(nextFlowId);

      if (!passkeyTransferor.registered) {
        throw new Error("Transferor must register a passkey first");
      }
      if (!amount || !currency || !recipientAccountRef) {
        throw new Error("Please complete amount, currency, and recipient before submitting");
      }
      if (amountValidationMessage) {
        throw new Error(amountValidationMessage);
      }

      const submissionAmount = normalizedAmount;
      if (!submissionAmount) {
        throw new Error("Amount must be a valid number");
      }
      setStatus("Signing the transferor passkey challenge...");
      const transferorAuth = await authenticatePasskey(transferorPrincipalId, "transferor");
      setStatus("Using registered transferor passkey proof and sending human instruction to agent...");
      const response = await fetch(`${AGENT_SERVICE_URL}/transfers/evaluate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          flowId: nextFlowId,
          amount: submissionAmount,
          currency,
          memo,
          recipientAccountRef,
          recipientId: recipientPrincipalId,
          transferorPasskey: {
            ...passkeyTransferor,
            verified: true,
            proofRef: transferorAuth.proofId,
          },
          principalId: transferorPrincipalId,
        }),
      });

      if (!response.ok) {
        const body = (await response.json()) as { detail?: string };
        throw new Error(body.detail ?? "Agent evaluation failed");
      }

      const body = (await response.json()) as {
        agent: {
          mode: string;
          reasoning_summary: string;
          started_at?: string;
          completed_at?: string;
          duration_ms?: number;
          prompt_text?: string;
          prompt_preview?: string;
          skill_name?: string;
          mandatory_tools?: string[];
          fallback_reason?: string | null;
          tool_calls: Array<{
            tool_name: string;
            input_ref?: string;
            output_ref?: string;
            trace_sig?: string;
            trace_id?: string;
            trace_hash?: string;
            trace_sig_alg?: string;
            trace_signer?: string;
            args?: Record<string, string>;
          }>;
        };
        verifierEvent: EventRecord;
      };
      const selectedRecipientAllowlisted = Boolean(recipientAllowlisted);
      const submittedAmount = Number(submissionAmount);
      const selectedPolicyDecision = selectedRecipientAllowlisted
        ? Number.isFinite(submittedAmount) && submittedAmount >= threshold
          ? "admin_approval_required"
          : "auto_execute_allowed"
        : "policy_reject_recipient_not_allowlisted";
      const normalizedToolCalls = body.agent.tool_calls.map((toolCall) => {
        const args = toolCall.args ?? {};

        if (toolCall.tool_name === "resolve_recipient" || toolCall.tool_name === "recipient_lookup") {
          return {
            ...toolCall,
            tool_name: "resolve_recipient",
            input_ref: toolCall.input_ref ?? args.recipient_id ?? "",
            output_ref: toolCall.output_ref ?? args.account_ref ?? "",
            args: {
              ...args,
              allowlisted: String(selectedRecipientAllowlisted),
            },
            trace_sig: toolCall.trace_sig ?? "",
            trace_id: toolCall.trace_id ?? "",
            trace_hash: toolCall.trace_hash ?? "",
            trace_sig_alg: toolCall.trace_sig_alg ?? "",
            trace_signer: toolCall.trace_signer ?? "",
          };
        }

        if (toolCall.tool_name === "policy_preview") {
          const derivedOutput =
            toolCall.output_ref ??
            (args.amount ? `amount=${args.amount}` : "policy preview prepared");
          return {
            ...toolCall,
            tool_name: "validate_transfer_policy",
            input_ref: toolCall.input_ref ?? args.currency ?? currency,
            output_ref: derivedOutput,
            trace_sig: toolCall.trace_sig ?? "",
            trace_id: toolCall.trace_id ?? "",
            trace_hash: toolCall.trace_hash ?? "",
            trace_sig_alg: toolCall.trace_sig_alg ?? "",
            trace_signer: toolCall.trace_signer ?? "",
          };
        }

        if (
          toolCall.tool_name === "policy_check_preview" ||
          toolCall.tool_name === "transfer_policy_check" ||
          toolCall.tool_name === "validate_transfer_policy"
        ) {
          return {
            ...toolCall,
            tool_name: "validate_transfer_policy",
            input_ref: toolCall.input_ref ?? `${amount}|${currency}`,
            output_ref: toolCall.output_ref ?? selectedPolicyDecision,
            args: {
              ...args,
              recipient_allowlisted: String(selectedRecipientAllowlisted),
              policy_decision: selectedPolicyDecision,
            },
            trace_sig: toolCall.trace_sig ?? "",
            trace_id: toolCall.trace_id ?? "",
            trace_hash: toolCall.trace_hash ?? "",
            trace_sig_alg: toolCall.trace_sig_alg ?? "",
            trace_signer: toolCall.trace_signer ?? "",
          };
        }

        return {
          ...toolCall,
          input_ref: toolCall.input_ref ?? Object.values(args)[0] ?? "",
          output_ref: toolCall.output_ref ?? Object.values(args).slice(1).join(" | ") ?? "",
          trace_sig: toolCall.trace_sig ?? "",
          trace_id: toolCall.trace_id ?? "",
          trace_hash: toolCall.trace_hash ?? "",
          trace_sig_alg: toolCall.trace_sig_alg ?? "",
          trace_signer: toolCall.trace_signer ?? "",
        };
      });
      setAgentTrace({
        mode: body.agent.mode,
        reasoningSummary: body.agent.reasoning_summary,
        startedAt: body.agent.started_at,
        completedAt: body.agent.completed_at,
        durationMs: body.agent.duration_ms,
        promptText: body.agent.prompt_text,
        promptPreview: body.agent.prompt_preview,
        skillName: body.agent.skill_name,
        mandatoryTools: body.agent.mandatory_tools ?? [],
        fallbackReason: body.agent.fallback_reason,
        toolCalls: normalizedToolCalls,
      });
      setLastVerifierEventId(body.verifierEvent.eventId);
      const verifierStatus = describeVerifierStatus(body.verifierEvent);
      setStatus(`${verifierStatus} via ${body.agent.mode} agent orchestration`);
      await refreshAll(nextFlowId);

      if (body.verifierEvent.kind === 108) {
        setTransferFailureVerifierEvent(body.verifierEvent);
        setTransferFailureModalOpen(true);
        setInstructionComposerOpen(false);
        return false;
      }

      setTransferFailureModalOpen(false);
      setTransferFailureVerifierEvent(null);
      return true;
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Evaluation failed");
      return false;
    }
  }

  async function handleAdminApprove() {
    try {
      if (!firstVerifierEvent || !envelopeEvent || !instructionEvent) {
        throw new Error("Missing envelope or first verifier result");
      }
      if (firstVerifierEvent.kind !== 104) {
        throw new Error("Admin signature is only required for escalated transfers");
      }
      if (!passkeyAdmin.registered) {
        throw new Error("Administrator must register a passkey first");
      }

      setStatus("Signing the administrator passkey challenge...");
      const adminAuth = await authenticatePasskey(adminPrincipalId, "administrator");
      setStatus("Using registered administrator passkey proof and sending approval to agent...");
      const response = await fetch(`${AGENT_SERVICE_URL}/transfers/admin-approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          flowId,
          firstVerifierEventId: firstVerifierEvent.eventId,
          envelopeEventId: envelopeEvent.eventId,
          instructionEventId: instructionEvent.eventId,
          adminProofRef: adminAuth.proofId,
          adminVerified: true,
          adminPrincipalId,
        }),
      });

      if (!response.ok) {
        const body = (await response.json()) as { detail?: string };
        throw new Error(body.detail ?? "Admin re-verification failed");
      }

      const body = (await response.json()) as { verifierEvent: EventRecord };
      setLastVerifierEventId(body.verifierEvent.eventId);
      setStatus("Admin signed through agent and verifier re-approved");
      await refreshAll();
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Admin approval failed");
    }
  }

  async function handleExecuteTransfer() {
    try {
      if (!transferorAccount || !selectedRecipientAccount || !lastVerifierEventId) {
        throw new Error("Missing execution prerequisites");
      }
      if (!canExecute) {
        throw new Error("Current flow is not executable yet");
      }

      const fromBefore = transferorAccount.availableBalance;
      const toBefore = selectedRecipientAccount.availableBalance;
      const transferAmount = Number(amount);

      setStatus("Executing transfer in MCP bank...");
      const response = await fetch(`${AGENT_SERVICE_URL}/transfers/execute`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          flowId,
          verifierEventId: lastVerifierEventId,
          fromAccountId: transferorAccount.accountId,
          toAccountId: selectedRecipientAccount.accountId,
          amount: Number(amount),
          currency,
        }),
      });

      const body = (await response.json()) as {
        alreadyExecuted?: boolean;
        error?: string;
        executionEvent?: EventRecord;
      };
      if (!response.ok) {
        throw new Error(body.error ?? "Transfer execution failed");
      }

      const resultingBalances = body.executionEvent?.payload.content.resulting_balances as
        | {
            from_account_available_balance?: string;
            to_account_available_balance?: string;
          }
        | undefined;
      const fromAfter = Number(resultingBalances?.from_account_available_balance ?? fromBefore);
      const toAfter = Number(resultingBalances?.to_account_available_balance ?? toBefore);
      setExecutionBalanceSnapshot({
        flowId,
        currency,
        amount: Number.isFinite(transferAmount) ? transferAmount : Number(amount || 0),
        fromAccountId: transferorAccount.accountId,
        toAccountId: selectedRecipientAccount.accountId,
        fromBefore,
        fromAfter: Number.isFinite(fromAfter) ? fromAfter : fromBefore,
        toBefore,
        toAfter: Number.isFinite(toAfter) ? toAfter : toBefore,
        alreadyExecuted: Boolean(body.alreadyExecuted),
      });

      setStatus(
        body.alreadyExecuted
          ? "Transfer was already executed automatically; execution evidence has been refreshed"
          : "Transfer passed verification, executed automatically in MCP bank, and was recorded as a Kind 109 execution event",
      );
      setExecutionSuccessModalOpen(true);
      await refreshAll();
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Execution failed");
    }
  }

  async function openArchiveTransaction(transaction: Transaction) {
    const requestId = ++archiveDetailRequestRef.current;
    setArchiveDetailOpen(true);
    setArchiveDetailTransaction(transaction);
    setArchiveDetailLoading(true);
    setArchiveDetailError("");
    setArchiveDetailRecords([]);

    try {
      const records =
        transaction.flowId === flowId && archiveRecords.length > 0
          ? archiveRecords
          : await fetchArchiveRecordsForFlow(transaction.flowId);

      if (archiveDetailRequestRef.current !== requestId) {
        return;
      }

      setArchiveDetailRecords(records);
    } catch (error) {
      if (archiveDetailRequestRef.current !== requestId) {
        return;
      }

      setArchiveDetailError(error instanceof Error ? error.message : "Failed to load archive details");
    } finally {
      if (archiveDetailRequestRef.current !== requestId) {
        return;
      }

      setArchiveDetailLoading(false);
    }
  }

  function closeArchiveTransaction() {
    archiveDetailRequestRef.current += 1;
    setArchiveDetailOpen(false);
    setArchiveDetailTransaction(null);
    setArchiveDetailLoading(false);
    setArchiveDetailError("");
    setArchiveDetailRecords([]);
  }

  async function createInstructionForScenario(input: {
    flowId: string;
    amountValue: string;
    currencyValue: string;
    recipientAccount: string;
    passkeyVerified: boolean;
    memoValue: string;
  }) {
    const response = await fetch(`${EVENT_SERVICE_URL}/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        flowId: input.flowId,
        payload: {
          id: `evt_instr_${input.flowId}_hash`,
          kind: 101,
          ai_id: transferorPrincipalId,
          created_at: Date.now(),
          tags: [
            ["flow_id", input.flowId],
            ["role", "transferor"],
            ["action", "transfer"],
          ],
          content: {
            instruction_id: `instr_${input.flowId}`,
            principal_id: transferorPrincipalId,
            agent_id: DEMO_AGENT_IDS.transfer,
            action_type: "payment.transfer",
            amount: input.amountValue,
            currency: input.currencyValue,
            recipient_id: recipientPrincipalId,
            recipient_account_ref: input.recipientAccount,
            memo: input.memoValue,
            submitted_at: new Date().toISOString(),
            expiry_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
            instruction_nonce: `nonce_${Date.now()}`,
            signing_payload: {
              payload_version: "1.0",
              payload_type: "transfer_instruction",
              canonicalization: "jcs-rfc8785",
              signed_fields: ["instruction_id", "amount", "currency", "recipient_account_ref"],
              payload_hash: `sha256:scenario_instruction_${Date.now()}`,
            },
            signature_proof: {
              passkey_verified: input.passkeyVerified,
              signature: input.passkeyVerified ? "scenario_sig_ok" : "scenario_sig_bad",
              signature_alg: "webauthn-passkey-es256",
            },
          },
        },
      }),
    });

    if (!response.ok) {
      throw new Error("Failed to create scenario instruction");
    }

    return (await response.json()) as { event: EventRecord };
  }

  async function createEnvelopeForScenario(input: {
    flowId: string;
    instructionEventId: string;
    amountValue: string;
    currencyValue: string;
    recipientAccount: string;
    memoValue: string;
  }) {
    const response = await fetch(`${EVENT_SERVICE_URL}/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        flowId: input.flowId,
        payload: {
          id: `evt_env_${input.flowId}_hash`,
          kind: 102,
          ai_id: DEMO_AGENT_IDS.transfer,
          created_at: Date.now(),
          tags: [
            ["flow_id", input.flowId],
            ["action", "payment.transfer"],
          ],
          content: {
            instruction_ref: input.instructionEventId,
            action: {
              params: {
                amount: input.amountValue,
                currency: input.currencyValue,
                recipient_account_ref: input.recipientAccount,
                memo: input.memoValue,
              },
            },
          },
        },
      }),
    });

    if (!response.ok) {
      throw new Error("Failed to create scenario envelope");
    }

    return (await response.json()) as { event: EventRecord };
  }

  if (!authReady) {
    return (
      <div className="authShell">
        <main className="authCard">
          <div className="authBadge">SAFR x ATP Demo</div>
          <h1>Checking sign-in state</h1>
          <p>We are confirming with the backend whether you are already signed in.</p>
        </main>
      </div>
    );
  }

  if (!activeAccount) {
    return (
      <div className="authShell">
        <div className="authBackdrop authBackdropOne" />
        <div className="authBackdrop authBackdropTwo" />
        <main className="authCard">
          <div className="authBadge">SAFR x ATP Demo</div>
          <h1>Register or sign in to continue</h1>
          <p>
            Create a stable account for each person first. After you enter, the transferor and
            admin principals in the transfer flow will stay bound to this account, and your
            passkey will remain available.
          </p>
          <label className="authField">
            <span>Username</span>
            <input
              value={accountUsernameInput}
              onChange={(event) => setAccountUsernameInput(event.target.value)}
              placeholder="English only, e.g. alice / bob / team-lead"
              autoComplete="username"
            />
          </label>
          <label className="authField">
            <span>Password</span>
            <input
              type="password"
              value={accountPasswordInput}
              onChange={(event) => setAccountPasswordInput(event.target.value)}
              placeholder="Set or enter your password"
              autoComplete="current-password"
            />
          </label>
          <div className="authStrength" aria-live="polite">
            <div className="authStrengthHeader">
              <span>Password requirements</span>
              <strong className={`authStrengthLabel strength-${passwordStrength.score === 2 ? "strong" : passwordStrength.score === 1 ? "fair" : "weak"}`}>
                {passwordStrength.label}
              </strong>
            </div>
            <div className="authStrengthBar" aria-hidden="true">
              <div className={`authStrengthFill strength-${passwordStrength.score === 2 ? "strong" : passwordStrength.score === 1 ? "fair" : "weak"}`} style={{ width: `${Math.min(100, passwordStrength.score * 50)}%` }} />
            </div>
            <p className="authStrengthCopy">{passwordStrength.description}</p>
            <ul className="authStrengthChecks">
              {passwordStrength.checks.map((check) => (
                <li key={check}>{check}</li>
              ))}
            </ul>
          </div>
          <div className="authActions">
            <button type="button" onClick={() => void handleEnterAccount("register")}>
              Register and enter
            </button>
            <button type="button" className="secondary" onClick={() => void handleEnterAccount("login")}>
              Sign in
            </button>
          </div>
          <div className="authHint">
            <span>Accounts and sessions are stored on the backend.</span>
            <span>Username must be English only, and password must be 8+ characters with a number.</span>
          </div>
          {authError ? <div className="rejectBanner"><strong>{authError}</strong></div> : null}
        </main>
      </div>
    );
  }

  return (
    <div className={`productShellPage ${showPasskeyOnboarding ? "overlayActive" : ""}`}>
      <header className="productShellTopbar">
        <div className="productShellHero">
          <div className="productShellEyebrow">SAFR x ATP Demo</div>
          <h1>{currentTabLabel}</h1>
          <p>
            {currentTabDescription}
          </p>
        </div>
        <div className="productShellActions">
          <div className={`productShellStateChip ${passkeySetupIncomplete ? "needsSetup" : "ready"}`}>
            <span>State</span>
            <strong>{currentStateSummary}</strong>
          </div>
          <div className="accountMenu" ref={accountPanelRef}>
            <button
              className={`accountMenuTrigger ${accountPanelOpen ? "open" : ""} ${showPasskeyOnboarding ? "spotlight" : ""}`}
              type="button"
              aria-haspopup="dialog"
              aria-expanded={accountPanelOpen}
              onClick={() => setAccountPanelOpen((current) => !current)}
            >
              <span className="accountMenuAvatar">{activeAccountLabel.slice(0, 1).toUpperCase()}</span>
              <span className="accountMenuTriggerCopy">
                <strong>{activeAccountLabel}</strong>
                <small>{passkeySetupIncomplete ? "Passkeys need setup" : "Balances & passkeys"}</small>
              </span>
            </button>

            {accountPanelOpen ? (
              <div className="accountMenuPanel" role="dialog" aria-label="Account panel">
                <div className="accountMenuHeader">
                  <div>
                    <span>Account</span>
                    <strong>{activeAccountLabel}</strong>
                  </div>
                  <div className={`accountMenuStatus ${passkeySetupIncomplete ? "warning" : "ready"}`}>
                    {passkeySetupIncomplete ? "Setup needed" : "Ready"}
                  </div>
                </div>

                <div className="accountMenuBalanceSection">
                  <div className="accountMenuBalanceTop">
                    <strong>Balances</strong>
                    {restoreConfirmArmed ? (
                      <div className="accountMenuRestoreConfirm">
                        <button
                          className="accountMenuMiniButton ghost"
                          type="button"
                          aria-label="Cancel restore balances"
                          title="Cancel restore"
                          onClick={() => {
                            setRestoreConfirmArmed(false);
                            setRestoreNotice("");
                          }}
                        >
                          ✕
                        </button>
                        <button
                          className="accountMenuMiniButton danger"
                          type="button"
                          aria-label="Confirm restore balances"
                          title="Confirm restore"
                          onClick={() => void restoreOriginalBalances()}
                        >
                          ✓
                        </button>
                      </div>
                    ) : (
                      <button className="accountMenuMiniButton ghost" type="button" onClick={handleRestoreBalancesClick}>
                        Restore balances
                      </button>
                    )}
                  </div>
                  <div className="accountMenuBalanceGrid">
                    <div className="accountMenuBalanceCard">
                      <span>Transferor balance</span>
                      <strong>
                        {transferorAccount
                          ? `${transferorAccount.currency} ${transferorAccount.availableBalance.toFixed(2)}`
                          : "Loading"}
                      </strong>
                    </div>
                    <div className="accountMenuBalanceCard">
                      <span>Recipient balance</span>
                      <strong>
                        {selectedRecipientAccount
                          ? `${selectedRecipientAccount.currency} ${selectedRecipientAccount.availableBalance.toFixed(2)}`
                          : "Loading"}
                      </strong>
                    </div>
                  </div>
                  {restoreNotice ? <small className="accountMenuRestoreNotice">{restoreNotice}</small> : null}
                </div>

                <div className="accountMenuSection">
                  <div className="accountMenuSectionTop">
                    <strong>Passkeys</strong>
                    <small>
                      {missingPasskeyRoles.length > 0
                        ? `Still needed: ${missingPasskeyRoles.join(" and ")}.`
                        : "All required signer passkeys are ready."}
                    </small>
                  </div>
                  <div className="accountMenuPasskeyStack">
                    <PasskeyCard
                      compact
                      title="Transferor Passkey"
                      principalId={transferorPrincipalId}
                      state={passkeyTransferor}
                      registerButtonRef={transferorRegisterButtonRef}
                      spotlight={!passkeyTransferor.registered}
                      onRegister={() => void registerPasskey(transferorPrincipalId, "transferor")}
                    />
                    <PasskeyCard
                      compact
                      title="Administrator Passkey"
                      principalId={adminPrincipalId}
                      state={passkeyAdmin}
                      registerButtonRef={adminRegisterButtonRef}
                      spotlight={!passkeyAdmin.registered}
                      onRegister={() => void registerPasskey(adminPrincipalId, "administrator")}
                    />
                  </div>
                </div>

                <div className="accountMenuFooter">
                  {switchConfirmArmed ? (
                    <div className="accountMenuRestoreConfirm">
                      <button
                        className="accountMenuMiniButton ghost"
                        type="button"
                        aria-label="Cancel switch account"
                        title="Cancel switch"
                        onClick={() => setSwitchConfirmArmed(false)}
                      >
                        ✕
                      </button>
                      <button
                        className="accountMenuMiniButton danger"
                        type="button"
                        aria-label="Confirm switch account"
                        title="Confirm switch"
                        onClick={() => void handleLogout()}
                      >
                        ✓
                      </button>
                    </div>
                  ) : (
                    <button className="secondary" type="button" onClick={handleSwitchAccountClick}>
                      Switch account
                    </button>
                  )}
                </div>
              </div>
            ) : null}
          </div>
        </div>
      </header>

      <div className="productShellLayout">
        <aside className="productSidebar">
          <div className="productSidebarSection">
            <div className="productSidebarRail" role="tablist" aria-label="Product sections">
              {sidebarTabs.map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  className={`productSidebarTab ${activeTab === tab.id ? "active" : ""} ${tab.attention ? "attention" : ""}`}
                  onClick={() => setActiveTab(tab.id)}
                  title={tab.hint}
                >
                  <strong>{tab.label}</strong>
                </button>
              ))}
            </div>
          </div>

        </aside>

        <main className="productMain">
          {activeTab === "overview" ? (
            <>
              <section className="panel overviewHeroPanel">
                <div className="overviewHeroCopy">
                  <div className="overviewHeroText">
                    <span className="flowOverviewLabel">Overview</span>
                    <h2>Move a transfer from instruction to settlement</h2>
                    <p>
                      A transfer starts as a passkey-signed instruction, gets packaged by the agent, is checked by the
                      verifier, routes through admin re-signing only when needed, and then settles in MCP.
                    </p>
                  </div>
                  <div className="overviewHeroAside" aria-label="Overview summary">
                    <div className="overviewHeroAsideCard">
                      <span>Current state</span>
                      <strong>{currentStateSummary}</strong>
                    </div>
                    <div className="overviewHeroAsideCard">
                      <span>Agent model</span>
                      <strong>{agentModelName}</strong>
                    </div>
                  </div>
                  <div className="overviewHeroFooter">
                    <p>Start a new transfer or inspect the active policy lane before you move forward.</p>
                    <div className="actions overviewHeroActions">
                      <button type="button" onClick={handleTransferPrimaryAction}>
                        Start transfer
                      </button>
                      <button type="button" className="secondary" onClick={() => setActiveTab("policy")}>
                        Review policy
                      </button>
                    </div>
                  </div>
                </div>
              </section>

            </>
          ) : null}

          {activeTab === "agent" ? (
            <section className="panel productTabStack">
              <div className="agentOverviewHero">
                <div className="agentOverviewHeroLead compact">
                  <span className="flowOverviewLabel">Gemini Enterprise Agent Platform</span>
                  <strong>{hasAgentRun ? "Agent run for this transfer" : "Agent standing by"}</strong>
                  <p>
                    {hasAgentRun
                      ? "The signed transfer instruction has already been handled. Here is the model, the prompt, and the checks that were applied."
                      : "No transfer instruction has been submitted yet, so the agent has not been triggered."}
                  </p>
                </div>
                <div className="agentOverviewStats">
                  <FlowMiniStat label="Model" value={agentModelName} />
                  <FlowMiniStat label="Mode" value={agentTrace?.mode ?? "adk"} />
                  <FlowMiniStat label="Status" value={hasAgentRun ? "Triggered" : "Idle"} />
                </div>
              </div>

              {!hasAgentRun ? (
                <div className="agentEmptyState">
                  <strong>No transfer instruction yet</strong>
                  <p>The agent stays idle until you start a transfer and submit the signed instruction.</p>
                </div>
              ) : (
                <div className="agentRunStory">
                  <div className="agentRunStoryPrimary">
                    <div className="agentRunStoryHeader">
                      <div className="agentRunStoryHeaderCopy">
                        <span className="flowOverviewLabel">Run summary</span>
                        <strong>Prompt, checks, tools, signed envelope</strong>
                      </div>
                      <div className="agentBadge">{formatDurationMs(agentTrace?.durationMs ?? 0)}</div>
                    </div>
                  </div>

                  <div className="agentRunStoryList">
                    <div className="agentRunStoryItem">
                      <span>Prompt</span>
                      <p>{getReadableAgentPrompt(agentTrace)}</p>
                    </div>
                    <div className="agentRunStoryItem">
                      <span>Checks</span>
                      <div className="agentCheckList">
                        {buildAgentCheckViews(agentTrace).map((check) => (
                          <div key={check.label} className={`agentCheckItem tone-${check.tone}`}>
                            <span className="agentCheckIcon">{check.tone === "pass" ? "✓" : check.tone === "warn" ? "!" : "×"}</span>
                            <div>
                              <strong>{check.label}</strong>
                              <p>{check.detail}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="agentRunStoryItem wide">
                      <span>Tools used</span>
                      <div className="agentToolPills">
                        {getAgentToolPills(agentTrace).map((toolName) => (
                          <span key={toolName} className="agentToolPill">
                            {toolName}
                          </span>
                        ))}
                      </div>
                    </div>
                    <div className="agentRunStoryItem wide">
                      <span>Signed envelope</span>
                      <div className={`agentEnvelopePreview tone-${signedEnvelopeView.tone}`}>
                        <div className="agentEnvelopePreviewTop">
                          <strong>{signedEnvelopeView.statusLabel}</strong>
                          <span className={`agentEnvelopeBadge tone-${signedEnvelopeView.tone}`}>
                            {signedEnvelopeView.tone === "pass"
                              ? "✓"
                              : signedEnvelopeView.tone === "warn"
                                ? "!"
                                : "×"}
                          </span>
                        </div>
                        <p>{signedEnvelopeView.summary}</p>
                        <div className="agentEnvelopeFactGrid">
                          {signedEnvelopeView.fields.map((field) => (
                            <div key={field.label} className="agentEnvelopeFact">
                              <span>{field.label}</span>
                              <strong>{field.value}</strong>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="agentRunStats">
                    <FlowMiniStat label="Started" value={agentTrace?.startedAt ? formatAgentTimestamp(agentTrace.startedAt) : "n/a"} />
                    <FlowMiniStat label="Completed" value={agentTrace?.completedAt ? formatAgentTimestamp(agentTrace.completedAt) : "n/a"} />
                    <FlowMiniStat label="Checks" value={String(agentTrace?.mandatoryTools?.length ?? 0)} />
                    <FlowMiniStat label="Tools" value={String(agentTrace?.toolCalls.length ?? 0)} />
                  </div>
                </div>
              )}
            </section>
          ) : null}

          {activeTab === "verifier" ? (
            <section className="panel productTabStack">
              <div className="verifierOverviewHero">
                <div className="verifierOverviewHeroLead">
                  <span className="flowOverviewLabel">Verifier</span>
                  <strong>Decision center for every transfer</strong>
                  <p>{verifierTabNextStep}</p>
                  <div className="verifierOverviewBadges">
                    <span>{verifierTabDecisionLabel}</span>
                    <span>{requiresAdmin ? "Admin lane on" : "Auto lane on"}</span>
                    <span>
                      {policyView
                        ? `${policyView.policy.currency} ${policyView.policy.adminReviewAtOrAbove.toFixed(2)} threshold`
                        : "Policy loading"}
                    </span>
                  </div>
                </div>
                <div className="verifierOverviewStats">
                  <FlowMiniStat label="Decision" value={verifierTabDecisionLabel} />
                  <FlowMiniStat label="Policy lane" value={requiresAdmin ? "Admin review" : "Auto lane"} />
                  <FlowMiniStat label="Checks" value={instructionEvent ? "Active" : "Not started"} />
                  <FlowMiniStat label="Agent handoff" value={hasAgentRun ? "Ready" : "Up next"} />
                </div>
              </div>

              <div className="verifierFlowSummary">
                <div className="verifierFlowSummaryCard">
                  <span>What gets checked</span>
                  <strong>Instruction, recipient, amount</strong>
                  <p>
                    The verifier checks the signed packet, verifies the recipient, and compares the amount
                    against the active policy lane.
                  </p>
                  <div className="verifierCheckList">
                    {verifierCheckViews.map((check) => (
                      <div key={check.label} className={`verifierCheckRow tone-${check.tone}`}>
                        <span className="verifierCheckIcon">{check.tone === "pass" ? "✓" : check.tone === "warn" ? "!" : "×"}</span>
                        <div>
                          <strong>{check.label}</strong>
                          <p>{check.detail}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
                <div className="verifierFlowSummaryCard">
                  <span>Lane result</span>
                  <strong>{requiresAdmin ? "Admin confirmation required" : "Auto lane continues"}</strong>
                  <p>
                    {requiresAdmin
                      ? "Transfers at or above the threshold branch into admin confirmation, then re-check and execution."
                      : "Transfers below the threshold stay on the auto lane and continue automatically."}
                  </p>
                  <div className={`verifierLaneBadge ${requiresAdmin ? "warn" : "success"}`}>
                    {requiresAdmin ? "Admin branch" : "Auto lane"}
                  </div>
                </div>
              </div>
            </section>
          ) : null}

          {activeTab === "policy" ? (
            <section className="panel productTabStack">
              <GovernancePolicyBanner
                policyView={policyView}
                policyNotice={policyNotice}
                policySummary={policySummary}
              />

              <div className="policyScenarioHeader">
                <div>
                  <span className="flowOverviewLabel">Signing rules</span>
                  <strong>How the policy changes the approval path</strong>
                </div>
              </div>

              <div className="policyScenarioGrid">
                <section className="policyScenarioCard">
                  <div className="policyScenarioTop">
                    <div>
                      <span className="flowOverviewLabel">Rule A</span>
                      <h3>
                        Below {policyView?.policy.currency ?? "USD"}{" "}
                        {policyView?.policy.adminReviewAtOrAbove.toFixed(2) ?? "1000.00"}
                      </h3>
                    </div>
                    <div className="policyScenarioBadge success">Auto-execution</div>
                  </div>
                  <p>
                    Transferor signs, agent builds, verifier approves, agent forwards, bank executes.
                  </p>
                  <div className="policyStepFlow">
                    <PolicyStep step="1" tone="transferor" title="Transferor" detail="Signs instruction" />
                    <PolicyStep step="2" tone="agent" title="Agent" detail="Builds envelope" />
                    <PolicyStep step="3" tone="verifier" title="Verifier" detail="Checks then approves" />
                    <PolicyStep step="4" tone="agent" title="Agent" detail="Forwards approved package" />
                    <PolicyStep step="5" tone="mcp" title="MCP Bank" detail="Executes transfer" terminal />
                  </div>
                  <div className="policyRuleChips">
                    <span>Signature: Transferor only</span>
                    <span>Admin: Not needed</span>
                    <span>Lane: Auto-execution</span>
                  </div>
                </section>

                <section className="policyScenarioCard warning">
                  <div className="policyScenarioTop">
                    <div>
                      <span className="flowOverviewLabel">Rule B</span>
                      <h3>
                        At or above {policyView?.policy.currency ?? "USD"}{" "}
                        {policyView?.policy.adminReviewAtOrAbove.toFixed(2) ?? "1000.00"}
                      </h3>
                    </div>
                    <div className="policyScenarioBadge warning">Dual approval</div>
                  </div>
                  <p>
                    Transferor signs, verifier escalates, admin re-signs, verifier re-checks, then bank executes.
                  </p>
                  <div className="policyStepFlow">
                    <PolicyStep step="1" tone="transferor" title="Transferor" detail="Signs instruction" />
                    <PolicyStep step="2" tone="agent" title="Agent" detail="Builds envelope" />
                    <PolicyStep step="3" tone="verifier" title="Verifier" detail="Checks and escalates" />
                    <PolicyStep step="4" tone="admin" title="Administrator" detail="Adds second signature" />
                    <PolicyStep step="5" tone="verifier" title="Verifier" detail="Re-verifies approval" />
                    <PolicyStep step="6" tone="agent" title="Agent" detail="Forwards approved package" />
                    <PolicyStep step="7" tone="mcp" title="MCP Bank" detail="Executes transfer" terminal />
                  </div>
                  <div className="policyRuleChips">
                    <span>Signatures: Transferor + Admin</span>
                    <span>Admin: Required</span>
                    <span>Lane: Dual approval</span>
                  </div>
                </section>
              </div>
            </section>
          ) : null}

          {activeTab === "trace" ? (
            <section className="panel tracePagePanel">
              <div className="traceHero">
                <div className="traceHeroCopy">
                  <span className="flowOverviewLabel">Trace</span>
                  <h2>Transfer trace</h2>
                  <p>Start with the outcome, then open a step only when you want more detail.</p>
                </div>
                <div className="traceHeroStats">
                  <FlowMiniStat label="Model" value={agentModelName} />
                  <FlowMiniStat label="History" value={String(archiveRecords.length)} />
                </div>
              </div>

              <div className="traceSummaryRail">
                {traceDigestCards.map((card) => (
                  <div key={card.eyebrow} className={`traceSummaryItem status-${card.status}`}>
                    <span>{card.eyebrow}</span>
                    <strong>{card.title}</strong>
                    <p>{card.summary}</p>
                    <small>{card.meta}</small>
                  </div>
                ))}
              </div>

              <div className="traceJourneySection">
                <div className="sectionHeader">
                  <div>
                    <h2>What happened</h2>
                    <p className="flowSubcopy">Each row is a checkpoint. Click one to open the full evidence.</p>
                  </div>
                </div>

                <div className="traceJourneyRail">
                  {traceJourneyCards.map((card) => (
                    <button
                      key={card.title}
                      type="button"
                      className={`traceJourneyRow status-${card.status} tone-${card.tone}`}
                      onClick={() => setSelectedStageId(card.stageId)}
                    >
                      <div className="traceJourneyRowMeta">
                        <span className="traceJourneyStep">Step {card.step}</span>
                        <span className={`traceJourneyPill ${card.status}`}>{card.statusLabel}</span>
                      </div>
                      <div className="traceJourneyRowBody">
                        <div className="traceJourneyActor">{card.tone.toUpperCase()}</div>
                        <div className="traceJourneyText">
                          <strong>{card.title}</strong>
                          <p>{card.summary}</p>
                        </div>
                      </div>
                      <small>{card.meta}</small>
                    </button>
                  ))}
                </div>
              </div>

            </section>
          ) : null}

          {activeTab === "archive" ? (
            <section className="panel archivePagePanel">
              <div className="archiveHero archiveHeroLedger">
                <div className="archiveHeroCopy">
                  <span className="flowOverviewLabel">Archive</span>
                  <h2>Successful transfer history</h2>
                  <p>
                    A clean history of the current account&apos;s executed transfers, sorted newest
                    first. Open any item to review the archive event it wrote.
                  </p>
                </div>
              </div>

              {archiveTransactions.length > 0 ? (
                <div className="archiveLedger">
                  {archiveGroupedTransactions.map((group) => (
                    <div key={group.monthKey} className="archiveMonthGroup">
                      <div className="archiveMonthHeader">
                        <strong>{group.monthLabel}</strong>
                        <span>{group.items.length} records</span>
                      </div>
                      <div className="archiveLedgerTableHead" aria-hidden="true">
                        <span>Date</span>
                        <span>Counterparty</span>
                        <span>Txn</span>
                        <span className="archiveLedgerAmountHeader">Amount</span>
                      </div>
                      <div className="archiveMonthList">
                        {group.items.map((transaction) => {
                          const isOutgoing = currentAccountIds.includes(transaction.fromAccountId);
                          const counterpartyAccount = isOutgoing
                            ? transaction.toAccountId
                            : transaction.fromAccountId;
                          const signedAmount = `${isOutgoing ? "-" : "+"} ${transaction.currency} ${transaction.amount.toFixed(2)}`;

                          return (
                            <button
                              key={transaction.transactionId}
                              type="button"
                              className="archiveLedgerRow"
                              onClick={() => void openArchiveTransaction(transaction)}
                            >
                              <div className="archiveLedgerCell archiveLedgerDate">
                                <span>{formatAgentTimestamp(transaction.createdAt)}</span>
                              </div>
                              <div className="archiveLedgerCell archiveLedgerCounterparty">
                                <strong>{counterpartyAccount}</strong>
                              </div>
                              <div className="archiveLedgerCell archiveLedgerTxn">
                                <strong>{transaction.transactionId}</strong>
                              </div>
                              <div className="archiveLedgerCell archiveLedgerAmount">
                                <strong className={isOutgoing ? "archiveAmount outgoing" : "archiveAmount incoming"}>
                                  {signedAmount}
                                </strong>
                              </div>
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="archiveEmptyState">
                  <strong>No matching successful transfers</strong>
                  <p>
                    Try a different filter, or wait for the next successful transfer to appear
                    here with the archive event details.
                  </p>
                </div>
              )}
            </section>
          ) : null}

          {activeTab === "overview" ? (
            <section className="panel flowTheaterPanel overviewFlowPanel">
              <div className="sectionHeader overviewFlowHeader">
                <div>
                  <h2>How the transfer moves</h2>
                  <p className="flowSubcopy">
                    The live flow view shows the signed instruction, policy lane, agent handoff, and
                    execution proof in one place.
                  </p>
                </div>
                <button type="button" className="secondary" onClick={() => setActiveTab("trace")}>
                  Open trace
                </button>
              </div>

              <GovernancePolicyBanner
                policyView={policyView}
                policyNotice={policyNotice}
                policySummary={policySummary}
                clickable
                onClick={() => setActiveTab("policy")}
              />

              <div className="flowStageLane flowStageLaneOverview">
                <FlowRelayMap
                  stages={flowStages}
                  spotlightStageId={spotlightStageId}
                  actionPulseStageId={actionPulseStageId}
                  flowId={flowId}
                  amount={amount}
                  currency={currency}
                  memo={memo}
                  recipientAccountRef={recipientAccountRef}
                  status={status}
                  policyView={policyView}
                  onOpenStage={(stageId) => {
                    setOverviewPreviewStageId(stageId);
                  }}
                  requiresAdmin={requiresAdmin}
                  showAdminAction={requiresAdmin}
                  canAdminApprove={canAdminApprove}
                  canExecute={canExecute}
                  highlightSubmit={instructionSubmitBusy || isFlowEmpty || (!firstVerifierEvent && !envelopeEvent)}
                  highlightAdmin={isWaitingForAdmin}
                  highlightExecute={isReadyForExecution}
                  showAdminCue={false}
                  onSubmitToVerifier={() => {
                    const missingPasskeyMessage = getMissingPasskeyMessage();
                    if (missingPasskeyMessage) {
                      setStatus(missingPasskeyMessage);
                      setAccountPanelOpen(true);
                      return;
                    }
                    if (!amount || !currency || !recipientAccountRef) {
                      if (openInstructionComposerGuarded()) {
                        setActiveTab("transfer");
                      } else {
                        setAccountPanelOpen(true);
                      }
                      return;
                    }
                    pulseAndRun("instruction", () => void handleEvaluate());
                  }}
                  onAdminApprove={() => {
                    setActiveTab("policy");
                    pulseAndRun("admin", () => void handleAdminApprove());
                  }}
                />
              </div>
            </section>
          ) : null}

          {activeTab === "transfer" ? (
            <>
              <section className="panel productTabStack" ref={workflowPanelRef}>
                <div className="productTransferHero">
                  <div className="productTransferHeroLead">
                    <div className="productTransferHeroLeadMain">
                      <span className="flowOverviewLabel">Transfer</span>
                      <strong>Create a transfer instruction</strong>
                      <p>
                        Create a signed transfer instruction and submit it to the agent for processing.
                        Smaller amounts stay on the auto lane, while transfers at or above the policy
                        threshold branch into admin review.
                      </p>
                      <div className="actions productTransferHeroActions">
                        <button type="button" onClick={handleTransferPrimaryAction}>
                          Start transfer
                        </button>
                        <button type="button" className="secondary" onClick={() => setActiveTab("policy")}>
                          Review policy
                        </button>
                      </div>
                    </div>

                    <div className="productTransferHeroAside" aria-label="Transfer summary">
                      <div className="productTransferHeroAsideCard">
                        <span>Current state</span>
                        <strong>{currentStateSummary}</strong>
                        <small>{instructionEvent ? "Instruction already captured" : "No instruction submitted yet"}</small>
                      </div>
                      <div className="productTransferHeroAsideCard">
                        <span>Policy lane</span>
                        <strong>{requiresAdmin ? "Admin review" : "Auto lane"}</strong>
                        <small>
                          {policyView
                            ? `${policyView.policy.currency} ${policyView.policy.adminReviewAtOrAbove.toFixed(2)} threshold`
                            : "Policy loading"}
                        </small>
                      </div>
                      <div className="productTransferHeroAsideCard wide">
                        <span>Next step</span>
                        <strong>{instructionEvent ? "Continue into the agent" : "Create the instruction first"}</strong>
                        <small>
                          {instructionEvent
                            ? "The signed instruction will move into the governed agent envelope."
                            : "Use the primary action to open the instruction composer."}
                        </small>
                      </div>
                    </div>
                  </div>
                </div>
              </section>

              <section className="panel flowTheaterPanel productWorkflowPanel">
                <div className="sectionHeader">
                  <div>
                    <h2>Live Governance Flow</h2>
                    <p className="flowSubcopy">
                      Watch the transfer move from signed human instruction to agent envelope, verifier
                      checks, agent forwarding, and MCP execution. Click any step to inspect the ATP
                      artifact, validation checks, and raw evidence.
                    </p>
                  </div>
                </div>

                <GovernancePolicyBanner
                  policyView={policyView}
                  policyNotice={policyNotice}
                  policySummary={policySummary}
                  clickable={false}
                />

                <div className="flowStageLane">
                <FlowRelayMap
                  stages={flowStages}
                  spotlightStageId={spotlightStageId}
                  actionPulseStageId={actionPulseStageId}
                    flowId={flowId}
                    amount={amount}
                    currency={currency}
                    memo={memo}
                    recipientAccountRef={recipientAccountRef}
                    status={status}
                    policyView={policyView}
                    onOpenStage={(stageId) => {
                      setSelectedStageId(stageId);
                      setActiveTab("trace");
                    }}
                    requiresAdmin={requiresAdmin}
                    showAdminAction={requiresAdmin}
                    canAdminApprove={canAdminApprove}
                  canExecute={canExecute}
                  highlightSubmit={instructionSubmitBusy || isFlowEmpty || (!firstVerifierEvent && !envelopeEvent)}
                  highlightAdmin={isWaitingForAdmin}
                  highlightExecute={isReadyForExecution}
                  showAdminCue={isWaitingForAdmin}
                  adminCueRef={workflowAdminCueRef}
                  onSubmitToVerifier={() => {
                    const missingPasskeyMessage = getMissingPasskeyMessage();
                    if (missingPasskeyMessage) {
                        setStatus(missingPasskeyMessage);
                        setAccountPanelOpen(true);
                        return;
                      }
                      if (!amount || !currency || !recipientAccountRef) {
                        if (openInstructionComposerGuarded()) {
                          setActiveTab("transfer");
                        } else {
                          setAccountPanelOpen(true);
                        }
                        return;
                      }
                      pulseAndRun("instruction", () => void handleEvaluate());
                    }}
                    onAdminApprove={() => {
                      setActiveTab("policy");
                      pulseAndRun("admin", () => void handleAdminApprove());
                    }}
                  />
                </div>
                <div ref={workflowBottomRef} aria-hidden="true" className="workflowBottomAnchor" />
              </section>
            </>
          ) : null}
        </main>
      </div>

      {showPasskeyOnboarding ? (
        <div
          className={`passkeyOnboardingOverlay ${accountPanelOpen ? "panelOpen" : ""}`}
          role="presentation"
        >
          <div className="passkeyOnboardingCard" role="dialog" aria-modal="true" aria-label="Passkey setup required">
            <span className="passkeyOnboardingEyebrow">Passkey setup required</span>
            <h2>Register your passkeys before continuing</h2>
            <p>
              To protect transfer submission and administrator approval, this account must finish
              passkey setup first. Use the account menu in the top right to register the missing
              signer passkeys.
            </p>
            <div className="passkeyOnboardingChecklist">
              {missingPasskeyRoles.map((item) => (
                <div key={item} className="passkeyOnboardingChecklistItem">
                  <span className="passkeyOnboardingChecklistDot" />
                  <strong>{item}</strong>
                </div>
              ))}
            </div>
            <div className="passkeyOnboardingActions">
              <button type="button" onClick={() => setAccountPanelOpen(true)}>
                Open passkey setup
              </button>
              <small>
                Complete both the transferor and administrator passkeys to unlock the rest of the
                product.
              </small>
            </div>
            <div className="passkeyOnboardingPointer" aria-hidden="true">
              Continue from the highlighted account menu in the top right.
            </div>
          </div>
        </div>
      ) : null}

      {showPasskeySuccessToast ? (
        <div className="passkeySuccessToast" role="status" aria-live="polite">
          Passkey setup complete. You can continue with your transfer.
        </div>
      ) : null}

      {selectedStage ? (
        <FlowStageModal
          stage={selectedStage}
          onClose={() => setSelectedStageId(null)}
          instructionEvent={instructionEvent}
          envelopeEvent={envelopeEvent}
          verifierEvent={activeVerifierEvent}
          adminApprovalEvent={adminApprovalEvent}
          executionEvent={executionEvent}
          archiveRecord={latestArchiveRecord}
          agentTrace={agentTrace}
          policyView={policyView}
          amount={amount}
          currency={currency}
          status={status}
          transferorPrincipalId={transferorPrincipalId}
          adminPrincipalId={adminPrincipalId}
          recipientPrincipalId={recipientPrincipalId}
        />
      ) : null}

      {executionSuccessModalOpen && executionBalanceSnapshot ? (
        <ExecutionSuccessModal
          snapshot={executionBalanceSnapshot}
          onClose={() => setExecutionSuccessModalOpen(false)}
          onOpenWorkflow={() => {
            setWorkflowScrollPending(true);
            setActiveTab("transfer");
          }}
          onOpenTrace={() => setActiveTab("trace")}
        />
      ) : null}

      {adminReviewPromptOpen ? (
        <AdminReviewPromptModal
          onClose={() => setAdminReviewPromptOpen(false)}
          onOpenWorkflow={() => {
            setAdminReviewPromptOpen(false);
            setWorkflowScrollPending(true);
            setActiveTab("transfer");
          }}
        />
      ) : null}

      {transferFailureModalOpen && transferFailureVerifierEvent ? (
        <TransferFailureModal
          verifierEvent={transferFailureVerifierEvent}
          recipientAccountRef={recipientAccountRef}
          onClose={() => setTransferFailureModalOpen(false)}
          onEditTransfer={() => {
            setTransferFailureModalOpen(false);
            setInstructionComposerOpen(true);
          }}
          onOpenTrace={() => {
            setTransferFailureModalOpen(false);
            setActiveTab("trace");
          }}
        />
      ) : null}

      {archiveDetailOpen && archiveDetailTransaction ? (
        <ArchiveTransactionModal
          transaction={archiveDetailTransaction}
          records={archiveDetailRecords}
          loading={archiveDetailLoading}
          error={archiveDetailError}
          currentAccountIds={currentAccountIds}
          onClose={closeArchiveTransaction}
          onOpenTrace={() => {
            const nextFlowId = archiveDetailTransaction.flowId;
            closeArchiveTransaction();
            setFlowId(nextFlowId);
            setActiveTab("trace");
          }}
        />
      ) : null}

      {overviewPreviewStage ? (
        <FlowStagePreviewModal
          stage={overviewPreviewStage}
          onClose={() => setOverviewPreviewStageId(null)}
          policyView={policyView}
          agentTrace={agentTrace}
          agentModelName={agentModelName}
          amount={amount}
          currency={currency}
          recipientAccountRef={recipientAccountRef}
          flowStatusLabel={flowStatusLabel}
          requiresAdmin={requiresAdmin}
        />
      ) : null}

      {instructionComposerOpen ? (
        <InstructionComposerModal
          flowId={flowId}
          amount={amount}
          currency={currency}
          memo={memo}
          recipientAccountRef={recipientAccountRef}
          allowlistedRecipientAccountRef={allowlistedRecipientAccount?.accountId ?? ""}
          status={status}
          amountError={amountError || amountValidationMessage}
          recipientHint={recipientHint}
          availableBalance={transferorAvailableBalance}
          policyView={policyView}
          onClose={() => {
            setInstructionComposerOpen(false);
            setAmountError("");
          }}
          onAmountChange={(value) => {
            const nextAmount = sanitizeAmountInput(value);
            setAmount(nextAmount);
            setAmountError(getAmountValidationMessage(nextAmount, transferorAvailableBalance));
          }}
          onAmountBlur={() => {
            const normalized = normalizeAmountInput(amount);
            if (normalized) {
              setAmount(normalized);
              setAmountError(getAmountValidationMessage(normalized, transferorAvailableBalance));
              return;
            }

            setAmountError(getAmountValidationMessage(amount, transferorAvailableBalance));
          }}
          onCurrencyChange={setCurrency}
          onMemoChange={setMemo}
          onRecipientChange={setRecipientAccountRef}
          submitDisabled={instructionSubmitBusy || Boolean(amountValidationMessage) || !recipientAccountRef}
          isSubmitting={instructionSubmitBusy}
          onSubmit={async () => {
            if (instructionSubmitBusy) {
              return;
            }
            if (amountValidationMessage) {
              setAmountError(amountValidationMessage);
              return;
            }
            if (!recipientAccountRef) {
              return;
            }
            if (!recipientAllowlisted) {
              setStatus("This transfer will be rejected at verifier validation.");
            }
            setInstructionSubmitBusy(true);
            setActionPulseStageId("instruction");
            try {
              const ok = await handleEvaluate();
              if (ok) {
                setInstructionComposerOpen(false);
                if (requiresAdmin && recipientAllowlisted) {
                  setAdminReviewPromptOpen(true);
                }
              }
            } finally {
              setInstructionSubmitBusy(false);
            }
          }}
        />
      ) : null}
    </div>
  );
}

function PasskeyCard(props: {
  title: string;
  principalId: string;
  state: PasskeyState;
  onRegister: () => void;
  compact?: boolean;
  spotlight?: boolean;
  registerButtonRef?: RefObject<HTMLButtonElement | null>;
}) {
  if (props.compact) {
    return (
      <div className={`passkeyCard passkeyCardCompact ${props.spotlight ? "spotlight" : ""}`}>
        <div className="passkeyCardCompactTop">
          <div>
            <strong>{props.title}</strong>
            <small className="passkeyCardCompactHint">
              {props.state.registered ? "Ready to sign protected actions" : "Registration required"}
            </small>
          </div>
          <div className={props.state.registered ? "badge badgeVerified passkeyReadyBadge" : "badge"}>
            {props.state.registered ? "Ready" : "Not Registered"}
          </div>
        </div>

        <div className="principalLine">
          <span>Principal</span>
          <code>{props.principalId}</code>
        </div>

        {props.state.registered ? (
          <div className="passkeyCardCompactMeta">
            <small>{props.state.deviceType || "Passkey device registered"}</small>
            <small>{props.state.lastUsedAt ? `Last used: ${props.state.lastUsedAt}` : "Ready immediately after registration"}</small>
          </div>
        ) : (
          <div className="actions">
            <button ref={props.registerButtonRef} onClick={props.onRegister}>
              Register Passkey
            </button>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="passkeyCard">
      <strong>{props.title}</strong>
      <div className="principalLine">
        <span>Principal</span>
        <code>{props.principalId}</code>
      </div>
      {props.state.registered ? (
        <>
          <div className="badge badgeVerified passkeyReadyBadge">Passkey Ready</div>
          <small>{props.state.credentialId}</small>
          <div className="passkeyMetaGrid">
            <PasskeyMetaItem label="RP ID" value={props.state.rpId || "unknown"} />
            <PasskeyMetaItem label="Device Type" value={props.state.deviceType || "unknown"} />
            <PasskeyMetaItem
              label="Backed Up"
              value={
                props.state.backedUp === null ? "unknown" : props.state.backedUp ? "true" : "false"
              }
            />
            <PasskeyMetaItem
              label="Transports"
              value={props.state.transports.length > 0 ? props.state.transports.join(", ") : "none"}
            />
            <PasskeyMetaItem
              label="Sign Counter"
              value={props.state.counter === null ? "unknown" : String(props.state.counter)}
            />
            <PasskeyMetaItem
              label="Last Used"
              value={props.state.lastUsedAt || "registered just now"}
            />
          </div>
          <small>
            {props.state.lastVerifiedAt
              ? `Ready since: ${props.state.lastVerifiedAt}`
              : "Ready immediately after registration"}
          </small>
        </>
      ) : (
        <>
          <small>No passkey registered yet.</small>
          <div className="actions">
            <button ref={props.registerButtonRef} onClick={props.onRegister}>Register Passkey</button>
          </div>
        </>
      )}
    </div>
  );
}

function PolicyStep(props: {
  step: string;
  tone: "transferor" | "agent" | "verifier" | "admin" | "mcp";
  title: string;
  detail: string;
  terminal?: boolean;
}) {
  return (
    <div className={`policyStepRow ${props.terminal ? "terminal" : ""}`}>
      <div className="policyStepIndex">{props.step}</div>
      <div className={`policySignerNode ${props.tone} ${props.terminal ? "terminal" : ""}`}>
        <span className="policySignerIcon">{props.tone === "transferor" ? "T" : props.tone === "agent" ? "A" : props.tone === "verifier" ? "V" : props.tone === "admin" ? "A" : "M"}</span>
        <div className="policySignerCopy">
          <strong>{props.title}</strong>
          <small>{props.detail}</small>
        </div>
      </div>
    </div>
  );
}

function PasskeyMetaItem(props: { label: string; value: string }) {
  return (
    <div className="passkeyMetaItem">
      <span>{props.label}</span>
      <code>{props.value}</code>
    </div>
  );
}

function FlowMiniStat(props: { label: string; value: string }) {
  return (
    <div className="flowMiniStat">
      <span>{props.label}</span>
      <strong>{props.value}</strong>
    </div>
  );
}

function TraceJourneyCard(props: {
  step: string;
  tone: "transferor" | "agent" | "verifier" | "admin" | "mcp";
  title: string;
  summary: string;
  meta: string;
  status: "done" | "current" | "pending" | "skipped";
  statusLabel: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      className={`traceJourneyCard status-${props.status} tone-${props.tone}`}
      onClick={props.onClick}
    >
      <div className="traceJourneyTop">
        <span className="traceJourneyStep">Step {props.step}</span>
        <span className={`traceJourneyPill ${props.status}`}>{props.statusLabel}</span>
      </div>
      <div className="traceJourneyActor">{props.tone.toUpperCase()}</div>
      <strong>{props.title}</strong>
      <p>{props.summary}</p>
      <small>{props.meta}</small>
    </button>
  );
}

function TraceDigestCard(props: {
  eyebrow: string;
  title: string;
  summary: string;
  meta: string;
  status: "done" | "current" | "pending" | "skipped" | "branch";
}) {
  return (
    <div className={`traceDigestCard status-${props.status}`}>
      <span>{props.eyebrow}</span>
      <strong>{props.title}</strong>
      <p>{props.summary}</p>
      <small>{props.meta}</small>
    </div>
  );
}

function GovernancePolicyBanner(props: {
  policyView: VerifierPolicyView | null;
  policyNotice: string;
  policySummary: string;
  clickable?: boolean;
  onClick?: () => void;
}) {
  const BannerTag = (props.onClick ? "button" : "div") as "button" | "div";

  return (
    <BannerTag
      type={props.onClick ? "button" : undefined}
      className={`flowPolicyBanner ${props.policyView ? "flowPolicyBannerReady" : "flowPolicyBannerWarn"} ${
        props.clickable ? "flowPolicyBannerClickable" : ""
      }`}
      onClick={props.onClick}
    >
      <div className="flowPolicyBannerCopy">
        <span>Active Governance Bundle</span>
        <strong>
          {props.policyView ? `${props.policyView.bundle.bundleId} · ${props.policyView.bundle.bundleVersion}` : "Policy status"}
        </strong>
        {props.policyView ? (
          <small>Policy name, threshold, and admin path are surfaced here in one place.</small>
        ) : (
          <small>{props.policySummary || (props.policyNotice ? "Loading policy details." : "Policy details will appear here.")}</small>
        )}
      </div>
      <div className="flowPolicyBannerMeta flowPolicyBannerMetaCompact">
        {props.policyView ? (
          <>
            <div className="flowPolicyBannerMetaPolicy">
              <span>Policy name</span>
              <strong>{props.policyView.policy.policyName}</strong>
            </div>
            <div>
              <span>Currency</span>
              <strong>{props.policyView.policy.currency}</strong>
            </div>
            <div>
              <span>Threshold</span>
              <strong>
                {props.policyView.policy.currency} {props.policyView.policy.adminReviewAtOrAbove.toFixed(2)}
              </strong>
            </div>
            <div>
              <span>Admin signature</span>
              <strong>Required above threshold</strong>
            </div>
          </>
        ) : (
          <>
            <div>
              <span>State</span>
              <strong>{props.policyNotice ? "Loading" : "Standby"}</strong>
            </div>
            <div>
              <span>Policy</span>
              <strong>USD only</strong>
            </div>
          </>
        )}
      </div>
    </BannerTag>
  );
}

function ExecutionBalanceBanner(props: { snapshot: ExecutionBalanceSnapshot }) {
  const { snapshot } = props;
  const fromDelta = snapshot.fromAfter - snapshot.fromBefore;
  const toDelta = snapshot.toAfter - snapshot.toBefore;

  return (
    <div className="flowExecutionBalanceBanner statusTone-success">
      <div className="flowExecutionBalanceHeader">
        <div>
          <strong>Balance update</strong>
          <span>
            {snapshot.alreadyExecuted ? "Execution evidence refreshed" : "Transfer executed"}
          </span>
        </div>
        <div className="flowExecutionBalanceSummary">
          <span>Flow {snapshot.flowId}</span>
          <strong>
            {snapshot.currency} {snapshot.amount.toFixed(2)}
          </strong>
        </div>
      </div>

      <div className="flowExecutionBalanceGrid">
        <div className="flowExecutionBalanceCard">
          <span>Transferor</span>
          <strong>{snapshot.fromAccountId}</strong>
          <small>
            Before: {snapshot.currency} {snapshot.fromBefore.toFixed(2)}
          </small>
          <small>
            After: {snapshot.currency} {snapshot.fromAfter.toFixed(2)}
          </small>
          <small className={`flowExecutionBalanceDelta ${fromDelta <= 0 ? "down" : "up"}`}>
            Change: {fromDelta > 0 ? "+" : ""}
            {snapshot.currency} {fromDelta.toFixed(2)}
          </small>
        </div>

        <div className="flowExecutionBalanceArrow">→</div>

        <div className="flowExecutionBalanceCard">
          <span>Recipient</span>
          <strong>{snapshot.toAccountId}</strong>
          <small>
            Before: {snapshot.currency} {snapshot.toBefore.toFixed(2)}
          </small>
          <small>
            After: {snapshot.currency} {snapshot.toAfter.toFixed(2)}
          </small>
          <small className={`flowExecutionBalanceDelta ${toDelta >= 0 ? "up" : "down"}`}>
            Change: {toDelta >= 0 ? "+" : ""}
            {snapshot.currency} {toDelta.toFixed(2)}
          </small>
        </div>
      </div>
    </div>
  );
}

function FlowRelayMap(props: {
  stages: FlowStage[];
  spotlightStageId: FlowStageId;
  actionPulseStageId: FlowStageId | null;
  flowId: string;
  amount: string;
  currency: string;
  memo: string;
  recipientAccountRef: string;
  status: string;
  policyView: VerifierPolicyView | null;
  onOpenStage: (stageId: FlowStageId) => void;
  requiresAdmin: boolean;
  showAdminAction: boolean;
  canAdminApprove: boolean;
  canExecute: boolean;
  highlightSubmit: boolean;
  highlightAdmin: boolean;
  highlightExecute: boolean;
  showAdminCue?: boolean;
  adminCueRef?: RefObject<HTMLDivElement | null>;
  onSubmitToVerifier: () => void;
  onAdminApprove: () => void;
}) {
  const instruction = props.stages.find((stage) => stage.id === "instruction");
  const envelope = props.stages.find((stage) => stage.id === "agent_envelope");
  const verifier = props.stages.find((stage) => stage.id === "verifier");
  const admin = props.stages.find((stage) => stage.id === "admin");
  const forward = props.stages.find((stage) => stage.id === "agent_forward");
  const execution = props.stages.find((stage) => stage.id === "execution");
  const archive = props.stages.find((stage) => stage.id === "archive");
  const pulseInstructionPath =
    props.actionPulseStageId === "instruction" ||
    props.actionPulseStageId === "agent_envelope" ||
    props.actionPulseStageId === "verifier";
  const pulseAdminPath =
    props.actionPulseStageId === "admin" || props.actionPulseStageId === "agent_forward";
  const pulseExecutionPath = props.actionPulseStageId === "execution";
  const verifierPacketLabel = verifier?.kindLabel ?? (props.requiresAdmin ? "Kind 104" : "Kind 103");

  return (
    <div className="relayMap">
      <div className="relayHeader">
        <div className="relayHeaderText">
          <span className="flowOverviewLabel">Animated flow view</span>
          <strong>Human -&gt; Agent -&gt; Verifier -&gt; Agent -&gt; MCP</strong>
        </div>
        <div className="relayLegend">
          <span className="relayLegendItem active">Active packet</span>
          <span className="relayLegendItem branch">Review branch</span>
        </div>
      </div>

      <div className="relayTrack">
        <RelayNode
          stage={instruction}
          spotlight={props.spotlightStageId === instruction?.id}
          pulsing={props.actionPulseStageId === "instruction"}
          onClick={props.onOpenStage}
        />
        <RelayLink
          status={instruction?.status ?? "pending"}
          label={instruction?.kindLabel ?? "Kind 101"}
          pulsing={pulseInstructionPath}
        />
        <RelayNode
          stage={envelope}
          spotlight={props.spotlightStageId === envelope?.id}
          pulsing={props.actionPulseStageId === "agent_envelope"}
          onClick={props.onOpenStage}
        />
        <RelayLink
          status={envelope?.status ?? "pending"}
          label={envelope?.kindLabel ?? "Kind 102"}
          pulsing={pulseInstructionPath}
        />
        <RelayNode
          stage={verifier}
          spotlight={props.spotlightStageId === verifier?.id}
          pulsing={props.actionPulseStageId === "verifier"}
          onClick={props.onOpenStage}
        />
        <RelayLink
          status={forward?.status ?? verifier?.status ?? "pending"}
          label={verifierPacketLabel}
          pulsing={pulseExecutionPath || pulseAdminPath}
        />
        <RelayNode
          stage={forward}
          spotlight={props.spotlightStageId === forward?.id}
          pulsing={props.actionPulseStageId === "agent_forward"}
          onClick={props.onOpenStage}
          compact
        />
        <RelayLink
          status={execution?.status ?? "pending"}
          label={execution?.kindLabel ?? "Kind 109"}
          pulsing={pulseExecutionPath}
        />
        <RelayNode
          stage={execution}
          spotlight={props.spotlightStageId === execution?.id}
          pulsing={props.actionPulseStageId === "execution"}
          onClick={props.onOpenStage}
        />
      </div>

      <div className="relayBranchRow">
        <div className="relayBranchSpacer" />
        <div className={`relayBranchLink ${admin?.status ?? "pending"}`} />
        <RelayNode
          stage={admin}
          spotlight={props.spotlightStageId === admin?.id}
          pulsing={props.actionPulseStageId === "admin"}
          onClick={props.onOpenStage}
          branch
          compact
          actionLabel="Admin Sign + Reverify"
          actionTone="primary"
          actionEnabled={props.canAdminApprove}
          actionHighlighted={props.highlightAdmin}
          onAction={props.onAdminApprove}
        />
        <div className={`relayBranchLink ${forward?.status ?? "pending"}`} />
        <div className="relayBranchSpacer" />
      </div>

      {props.showAdminCue ? (
        <div className="relayAdminCueRow" ref={props.adminCueRef} aria-hidden="true">
          <div className="relayBranchSpacer" />
          <div />
          <div className="relayAdminCue">
            <span className="relayAdminCueArrow">↑</span>
            <strong>Click Admin Sign + Reverify</strong>
            <small>Re-sign the high-value transfer here.</small>
          </div>
          <div />
          <div className="relayBranchSpacer" />
        </div>
      ) : null}

      <div className="relayArchiveRow">
        <span className="relayArchiveLabel">Audit evidence path</span>
        <RelayNode
          stage={archive}
          spotlight={props.spotlightStageId === archive?.id}
          onClick={props.onOpenStage}
          compact
        />
      </div>
    </div>
  );
}

function InstructionComposerModal(props: {
  flowId: string;
  amount: string;
  currency: string;
  memo: string;
  recipientAccountRef: string;
  allowlistedRecipientAccountRef: string;
  status: string;
  amountError: string;
  recipientHint: string;
  availableBalance: number | null;
  submitDisabled: boolean;
  isSubmitting: boolean;
  policyView: VerifierPolicyView | null;
  onClose: () => void;
  onAmountChange: (value: string) => void;
  onAmountBlur: () => void;
  onCurrencyChange: (value: string) => void;
  onMemoChange: (value: string) => void;
  onRecipientChange: (value: string) => void;
  onSubmit: () => Promise<void>;
}) {
  const threshold = props.policyView?.policy.adminReviewAtOrAbove ?? 1000;
  const amountValue = Number(normalizeAmountInput(props.amount) || props.amount);
  const requiresAdmin = Number.isFinite(amountValue) && amountValue >= threshold;
  const closeDisabled = props.isSubmitting;

  return (
    <div className="flowModalBackdrop" onClick={closeDisabled ? undefined : props.onClose}>
      <div className="flowModal instructionComposerModal" onClick={(event) => event.stopPropagation()}>
        <div className="flowModalHeader">
          <div>
            <span className="flowModalEyebrow">Transfer details</span>
            <h3>Create transfer instruction</h3>
            <p>Choose the amount, recipient, and memo, then sign and submit the instruction.</p>
          </div>
          <button className="flowModalClose" type="button" onClick={props.onClose} disabled={closeDisabled}>
            Close
          </button>
        </div>

        <div className="instructionComposerGrid">
          <label className="flowCommandField">
            <span>Amount</span>
            <input
              type="text"
              inputMode="decimal"
              autoComplete="off"
              placeholder="0.00"
              value={props.amount}
              onChange={(event) => props.onAmountChange(event.target.value)}
              onBlur={props.onAmountBlur}
            />
            {props.amountError ? (
              <small className="flowFieldError">{props.amountError}</small>
            ) : props.availableBalance !== null ? (
              <small className="flowFieldHint">
                Available balance: USD {props.availableBalance.toFixed(2)}
              </small>
            ) : null}
          </label>
          <div className="flowCommandField">
            <span>Currency</span>
            <div className="flowStaticValue">USD</div>
          </div>
          <label className="flowCommandField">
            <span>Recipient</span>
            <select
              value={props.recipientAccountRef}
              onChange={(event) => props.onRecipientChange(event.target.value)}
            >
              <option value="">Select recipient account</option>
              {props.allowlistedRecipientAccountRef ? (
                <option value={props.allowlistedRecipientAccountRef}>
                  {props.allowlistedRecipientAccountRef} (Allowlisted for this account)
                </option>
              ) : null}
              <option value="acct_external_vendor_009">
                acct_external_vendor_009 (Expect Reject)
              </option>
            </select>
            {props.recipientAccountRef && props.allowlistedRecipientAccountRef !== props.recipientAccountRef ? (
              <small className="flowFieldWarning">{props.recipientHint}</small>
            ) : (
              <small className="flowFieldHint">
                {props.recipientHint}
              </small>
            )}
          </label>
          <label className="flowCommandField">
            <span>Memo</span>
            <input value={props.memo} onChange={(event) => props.onMemoChange(event.target.value)} />
          </label>
        </div>

        <div className="instructionComposerFooter">
          <div className="instructionComposerMeta">
            <div className="instructionComposerSummaryGrid">
              <div className="instructionComposerSummaryCard">
                <span>Amount</span>
                <strong>
                  {props.currency} {normalizeAmountInput(props.amount) || "0.00"}
                </strong>
                {props.availableBalance !== null ? (
                  <small>
                    Balance: {props.currency} {props.availableBalance.toFixed(2)}
                  </small>
                ) : null}
              </div>
              <div className="instructionComposerSummaryCard">
                <span>Recipient</span>
                <strong className={props.recipientAccountRef && props.recipientAccountRef !== props.allowlistedRecipientAccountRef ? "warning" : ""}>
                  {props.recipientAccountRef || "Choose recipient"}
                </strong>
                <small>
                  {!props.recipientAccountRef
                    ? "Choose a recipient"
                    : props.recipientAccountRef !== props.allowlistedRecipientAccountRef
                      ? "This transfer will be rejected at verifier validation."
                      : "Allowlisted recipient selected"}
                </small>
              </div>
              <div className="instructionComposerSummaryCard">
                <span>Route</span>
                <strong>{requiresAdmin ? "Admin review" : "Auto lane"}</strong>
                <small>
                  {requiresAdmin
                    ? `Transferor signs first, then admin re-signs above ${props.policyView?.policy.currency ?? "USD"} ${threshold.toFixed(2)}`
                    : "Transferor signs, then submits to the agent"}
                </small>
              </div>
            </div>
          </div>
            <div className="instructionComposerActionColumn">
            {requiresAdmin ? (
              <div className="instructionThresholdNotice" role="status" aria-live="polite">
                <span className="instructionThresholdNoticeLabel">Admin review required</span>
                <strong>
                  This amount is at or above the auto-execution threshold. It will require admin
                  secondary confirmation before execution.
                </strong>
              </div>
            ) : null}
            <div className="actions">
              <button
                type="button"
                className={props.isSubmitting ? "is-submitting" : ""}
                disabled={props.submitDisabled}
                onClick={() => void props.onSubmit()}
              >
                {props.isSubmitting ? "Submitting..." : "Submit transfer instruction"}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function ExecutionSuccessModal(props: {
  snapshot: ExecutionBalanceSnapshot;
  onClose: () => void;
  onOpenWorkflow: () => void;
  onOpenTrace: () => void;
}) {
  const { snapshot } = props;

  return (
    <div className="flowModalBackdrop executionSuccessBackdrop" onClick={props.onClose}>
      <div className="executionSuccessModal" onClick={(event) => event.stopPropagation()}>
        <div className="flowModalHeader">
          <div>
            <span className="flowModalEyebrow">Transfer complete</span>
            <h3>Transfer executed successfully</h3>
            <p>
              The bank finished this transfer automatically and updated both balances.
            </p>
          </div>
          <button className="flowModalClose" type="button" onClick={props.onClose}>
            Close
          </button>
        </div>

        <ExecutionBalanceBanner snapshot={snapshot} />

        <div className="executionSuccessActions">
          <button
            type="button"
            onClick={() => {
              props.onClose();
              props.onOpenWorkflow();
            }}
          >
            Open workflow table
          </button>
          <button
            type="button"
            className="secondary"
            onClick={() => {
              props.onClose();
              props.onOpenTrace();
            }}
          >
            Open trace table
          </button>
        </div>
      </div>
    </div>
  );
}

function AdminReviewPromptModal(props: {
  onClose: () => void;
  onOpenWorkflow: () => void;
}) {
  return (
    <div className="flowModalBackdrop executionSuccessBackdrop" onClick={props.onClose}>
      <div className="executionSuccessModal adminReviewPromptModal" onClick={(event) => event.stopPropagation()}>
        <div className="flowModalHeader">
          <div>
            <span className="flowModalEyebrow">Admin review required</span>
            <h3>Click Admin Sign + Reverify</h3>
            <p>
              This transfer is above the policy threshold. Open the workflow and continue at the
              admin re-sign step.
            </p>
          </div>
          <button className="flowModalClose" type="button" onClick={props.onClose}>
            Close
          </button>
        </div>

        <div className="adminReviewPromptBody">
          <div className="adminReviewPromptCard">
            <span>Next action</span>
            <strong>Click Admin Sign + Reverify</strong>
            <small>The workflow will jump to the admin branch and highlight the re-sign button.</small>
          </div>
        </div>

        <div className="executionSuccessActions">
          <button
            type="button"
            onClick={() => {
              props.onClose();
              props.onOpenWorkflow();
            }}
          >
            Go to workflow
          </button>
          <button type="button" className="secondary" onClick={props.onClose}>
            Stay here
          </button>
        </div>
      </div>
    </div>
  );
}

function TransferFailureModal(props: {
  verifierEvent: EventRecord;
  recipientAccountRef: string;
  onClose: () => void;
  onEditTransfer: () => void;
  onOpenTrace: () => void;
}) {
  const rejection = props.verifierEvent.payload.content.rejection_reason as
    | { code?: string; message?: string }
    | undefined;
  const verifierCheckSections = getVerifierChecksSections(props.verifierEvent);
  const rejectRows = getRejectDetailRows(props.verifierEvent);

  return (
    <div className="flowModalBackdrop executionFailureBackdrop" onClick={props.onClose}>
      <div className="executionFailureModal" onClick={(event) => event.stopPropagation()}>
        <div className="flowModalHeader">
          <div>
            <span className="flowModalEyebrow">Transfer rejected</span>
            <h3>Transfer could not be submitted</h3>
            <p>
              {rejection?.message ?? "The verifier rejected this transfer."} Update the recipient and try again.
            </p>
          </div>
          <button className="flowModalClose" type="button" onClick={props.onClose}>
            Close
          </button>
        </div>

        <div className="executionFailureSummary">
          <div className="executionFailureSummaryCard">
            <span>Selected recipient</span>
            <strong>{props.recipientAccountRef || "Choose recipient"}</strong>
            <small>
              {rejection?.code ?? "verifier_rejection"}
            </small>
          </div>
          <div className="executionFailureSummaryCard warning">
            <span>Next step</span>
            <strong>Choose an allowlisted recipient</strong>
            <small>
              The transfer will be rejected again until the recipient matches the allowlist.
            </small>
          </div>
        </div>

        <div className="flowModalBody">
          <section className="flowModalSection">
            <h4>Verifier checks</h4>
            <div className="flowGroupGrid">
              {verifierCheckSections.map((group) => (
                <div key={`${group.title}-${props.verifierEvent.eventId}`} className="flowGroupCard">
                  <div className="flowGroupTitle">{group.title}</div>
                  <div className="flowGroupItems">
                    {group.rows.map((row) => (
                      <span key={`${group.title}-${row.label}-${row.value}`} className={getEvidenceValueClassName(row.value)}>
                        {row.label}: {row.value}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </section>

          <section className="flowModalSection">
            <h4>Rejection details</h4>
            <div className="evidenceGrid">
              {rejectRows.map((row) => (
                <div key={`${row.label}-${row.value}`} className="evidenceRow">
                  <span>{row.label}</span>
                  <strong className={getEvidenceValueClassName(row.value)}>{row.value}</strong>
                </div>
              ))}
            </div>
          </section>
        </div>

        <div className="executionFailureActions">
          <button type="button" onClick={props.onEditTransfer}>
            Edit transfer details
          </button>
          <button type="button" className="secondary" onClick={props.onOpenTrace}>
            Open trace
          </button>
        </div>
      </div>
    </div>
  );
}

function ArchiveTransactionModal(props: {
  transaction: Transaction;
  records: ArchiveRecord[];
  loading: boolean;
  error: string;
  currentAccountIds: string[];
  onClose: () => void;
  onOpenTrace: () => void;
}) {
  const isOutgoing = props.currentAccountIds.includes(props.transaction.fromAccountId);
  const directionLabel = isOutgoing ? "Outgoing" : "Incoming";
  const counterpartyAccount = isOutgoing ? props.transaction.toAccountId : props.transaction.fromAccountId;
  const archiveRecord = props.records.at(-1) ?? null;
  const archivedEntityCount = archiveRecord?.content.archived_entities.length ?? 0;

  useEffect(() => {
    function handleEscape(event: KeyboardEvent) {
      if (event.key === "Escape") {
        props.onClose();
      }
    }

    window.addEventListener("keydown", handleEscape);
    return () => window.removeEventListener("keydown", handleEscape);
  }, [props]);

  return (
    <div className="flowModalBackdrop archiveModalBackdrop" onClick={props.onClose}>
      <div className="flowModal archiveModal" onClick={(event) => event.stopPropagation()}>
        <div className="flowModalHeader">
          <div>
            <span className="flowModalEyebrow">Archive event</span>
            <h3>Archived successful transfer</h3>
            <p>
              This view shows the append-only archive record for the selected successful transfer.
              Use it as a clean overview before opening the structured evidence.
            </p>
          </div>
          <button type="button" className="flowModalClose" onClick={props.onClose}>
            Close
          </button>
        </div>

        <div className="archiveModalSummaryGrid">
          <div className="archiveModalSummaryCard">
            <span>Direction</span>
            <strong className={`archiveDirection ${isOutgoing ? "outgoing" : "incoming"}`}>{directionLabel}</strong>
            <small>
              {props.transaction.currency} {props.transaction.amount.toFixed(2)}
            </small>
          </div>
          <div className="archiveModalSummaryCard">
            <span>Flow ID</span>
            <strong>{props.transaction.flowId}</strong>
            <small>Transaction executed successfully</small>
          </div>
          <div className="archiveModalSummaryCard">
            <span>Counterparty</span>
            <strong>{counterpartyAccount}</strong>
            <small>{isOutgoing ? "Sent from the transferor side" : "Received by the recipient side"}</small>
          </div>
          <div className="archiveModalSummaryCard">
            <span>Archive records</span>
            <strong>{props.records.length}</strong>
            <small>{archivedEntityCount} archived entities in the latest record</small>
          </div>
        </div>

        {props.loading ? (
          <div className="archiveModalLoading">Loading archive event details…</div>
        ) : props.error ? (
          <div className="archiveModalError" role="alert">
            <strong>Could not load archive details</strong>
            <p>{props.error}</p>
          </div>
        ) : archiveRecord ? (
          <>
            <div className="archiveModalOverview">
              <div className="archiveModalOverviewCard">
                <span>Created</span>
                <strong>{formatAgentTimestamp(props.transaction.createdAt)}</strong>
              </div>
              <div className="archiveModalOverviewCard">
                <span>Archive record</span>
                <strong>{archiveRecord.content.archive_record_id}</strong>
              </div>
              <div className="archiveModalOverviewCard">
                <span>Append-only index</span>
                <strong>{archiveRecord.content.append_only_index}</strong>
              </div>
              <div className="archiveModalOverviewCard">
                <span>Write mode</span>
                <strong>{archiveRecord.content.write_mode}</strong>
              </div>
            </div>

            <ArchiveEvidenceCard record={archiveRecord} domId={`archive-${props.transaction.transactionId}`} />
            <div className="archiveModalActions">
              <button type="button" onClick={props.onOpenTrace}>
                View related trace
              </button>
              <button type="button" className="secondary" onClick={props.onClose}>
                Close
              </button>
            </div>
          </>
        ) : (
          <div className="archiveModalEmpty">
            <strong>No archive record was returned for this flow.</strong>
            <p>The transaction executed successfully, but the archive lookup did not return any rows.</p>
          </div>
        )}
      </div>
    </div>
  );
}

function RelayNode(props: {
  stage?: FlowStage;
  spotlight?: boolean;
  pulsing?: boolean;
  onClick: (stageId: FlowStageId) => void;
  compact?: boolean;
  branch?: boolean;
  actionLabel?: string;
  actionTone?: "primary" | "secondary";
  actionEnabled?: boolean;
  actionHighlighted?: boolean;
  onAction?: () => void;
}) {
  const stage = props.stage;

  if (!stage) {
    return null;
  }

  return (
    <div
      role="button"
      tabIndex={0}
      className={`relayNode ${stage.status} ${props.compact ? "compact" : ""} ${props.branch ? "branch" : ""} ${props.spotlight ? "spotlight" : ""} ${props.pulsing ? "pulsing" : ""}`}
      onClick={() => props.onClick(stage.id)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          props.onClick(stage.id);
        }
      }}
    >
      <span className="relayNodeModule">{stage.module}</span>
      <strong>{stage.title}</strong>
      <small>{stage.kindLabel}</small>
      {props.actionLabel ? (
        <div className="relayNodeActionWrap">
          <button
            type="button"
            className={`relayActionChip ${props.actionTone === "secondary" ? "relayActionChipSecondary" : ""} ${props.actionHighlighted ? (props.actionTone === "secondary" ? "flowActionCurrentSecondary" : "flowActionCurrent") : ""}`}
            disabled={props.actionEnabled === false}
            onClick={(event) => {
              event.stopPropagation();
              props.onAction?.();
            }}
          >
            {props.actionLabel}
          </button>
        </div>
      ) : null}
    </div>
  );
}

function RelayLink(props: { status: FlowStageStatus; label: string; pulsing?: boolean }) {
  return (
    <div className={`relayLink ${props.status} ${props.pulsing ? "pulsing" : ""}`}>
      <div className="relayLinkLine" />
      <div className={`relayPacket ${props.status}`}>{props.label}</div>
    </div>
  );
}

function FlowStageCard(props: {
  stage: FlowStage;
  index: number;
  isLast: boolean;
  spotlight: boolean;
  onClick: () => void;
}) {
  return (
    <div className={`flowStageWrap ${props.stage.path}`}>
      <button
        type="button"
        className={`flowStageCard ${props.stage.status} ${props.stage.path} ${props.spotlight ? "spotlight" : ""}`}
        onClick={props.onClick}
      >
        <div className="flowStageBeam" />
        <div className="flowStageTop">
          <span className="flowStageIndex">Step {props.index + 1}</span>
          <span className={`flowStageStatus ${props.stage.status}`}>{props.stage.statusLabel}</span>
        </div>
        <div className="flowKindPill">{props.stage.kindLabel}</div>
        <div className="flowStageMetaRow">
          <span className="flowStageModule">{props.stage.module}</span>
          <span className="flowStageActor">{props.stage.actor}</span>
        </div>
        <strong>{props.stage.title}</strong>
        <p>{props.stage.summary}</p>
        <div className="flowArtifactBadge">{props.stage.artifact}</div>
        <div className="flowSignatureStrip">
          {props.stage.signatureSummary.slice(0, 2).map((item) => (
            <span key={item}>{item}</span>
          ))}
        </div>
        <div className="flowChecksPreview">
          {props.stage.checks.slice(0, 2).map((item) => (
            <span key={item}>{item}</span>
          ))}
        </div>
      </button>
      {!props.isLast ? (
        <div className={`flowStageConnector ${props.stage.status} ${props.stage.path}`} />
      ) : null}
    </div>
  );
}

function FlowStageModal(props: {
  stage: FlowStage;
  onClose: () => void;
  instructionEvent?: EventRecord;
  envelopeEvent?: EventRecord;
  verifierEvent?: EventRecord;
  adminApprovalEvent?: EventRecord;
  executionEvent?: EventRecord;
  archiveRecord?: ArchiveRecord;
  agentTrace: AgentTrace | null;
  policyView: VerifierPolicyView | null;
  amount: string;
  currency: string;
  status: string;
  transferorPrincipalId: string;
  adminPrincipalId: string;
  recipientPrincipalId: string;
}) {
  const [viewMode, setViewMode] = useState<"presentation" | "technical">("presentation");

  useEffect(() => {
    function handleEscape(event: KeyboardEvent) {
      if (event.key === "Escape") {
        props.onClose();
      }
    }

    window.addEventListener("keydown", handleEscape);
    return () => window.removeEventListener("keydown", handleEscape);
  }, [props]);

  const detailSections = getFlowStageDetailSections(props.stage, {
    instructionEvent: props.instructionEvent,
    envelopeEvent: props.envelopeEvent,
    verifierEvent: props.verifierEvent,
    adminApprovalEvent: props.adminApprovalEvent,
    executionEvent: props.executionEvent,
    archiveRecord: props.archiveRecord,
    agentTrace: props.agentTrace,
    policyView: props.policyView,
    amount: props.amount,
    currency: props.currency,
    status: props.status,
    transferorPrincipalId: props.transferorPrincipalId,
    adminPrincipalId: props.adminPrincipalId,
    recipientPrincipalId: props.recipientPrincipalId,
  });

  return (
    <div className="flowModalBackdrop" onClick={props.onClose}>
      <div className="flowModal" onClick={(event) => event.stopPropagation()}>
        <div className="flowModalHeader">
          <div>
            <span className="flowModalEyebrow">
              {props.stage.module} · {props.stage.actor}
            </span>
            <h3>{props.stage.title}</h3>
            <p>{props.stage.summary}</p>
          </div>
          <button type="button" className="flowModalClose" onClick={props.onClose}>
            Close
          </button>
        </div>

        <div className="flowModalMeta">
          <div className="flowModalMetaCard">
            <span>ATP Artifact</span>
            <strong>{props.stage.artifact}</strong>
          </div>
          <div className="flowModalMetaCard">
            <span>ATP Kind</span>
            <strong>{props.stage.kindLabel}</strong>
          </div>
          <div className="flowModalMetaCard">
            <span>Stage Status</span>
            <strong>{props.stage.statusLabel}</strong>
          </div>
        </div>

        <div className="flowModalViewBar">
          <div className="flowModalViewCopy">
            <span className="flowOverviewLabel">View mode</span>
            <strong>{viewMode === "presentation" ? "Presentation View" : "Technical View"}</strong>
            <p>
              {viewMode === "presentation"
                ? "A clear, user-facing summary of the transfer step."
                : "Raw evidence, signatures, and structured fields for technical review."}
            </p>
          </div>
          <div className="flowModalViewToggle" role="tablist" aria-label="View mode switch">
            <button
              type="button"
              className={viewMode === "presentation" ? "secondary activeToggle" : "secondary"}
              onClick={() => setViewMode("presentation")}
              aria-pressed={viewMode === "presentation"}
            >
              Presentation View
            </button>
            <button
              type="button"
              className={viewMode === "technical" ? "secondary activeToggle" : "secondary"}
              onClick={() => setViewMode("technical")}
              aria-pressed={viewMode === "technical"}
            >
              Technical View
            </button>
          </div>
        </div>

        {viewMode === "presentation" ? (
          <div className="flowModalPresentationIntro">
            <div className="flowPresentationNote">
              <strong>{props.stage.summary}</strong>
              <span>
                {props.stage.module} · {props.stage.actor} · {props.stage.kindLabel}
              </span>
            </div>
            <div className="flowModalPresentationSplit">
              <div className="flowModalPresentationCard">
                <span>What is checked</span>
                <ul>
                  {props.stage.checks.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
              <div className="flowModalPresentationCard">
                <span>Evidence trail</span>
                <ul>
                  {props.stage.signatureSummary.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        ) : null}

        <div className="flowModalBody">
          {detailSections.map((section) => (
            <section key={section.title} className="flowModalSection">
              <h4>{section.title}</h4>
              {section.type === "rows" ? (
                <div className="evidenceGrid">
                  {section.rows.map((row) => (
                    <div key={`${section.title}-${row.label}`} className="evidenceRow">
                      <span>{row.label}</span>
                      <strong className={getEvidenceValueClassName(row.value)}>{row.value}</strong>
                    </div>
                  ))}
                </div>
              ) : null}
              {section.type === "groups" ? (
                <div className="flowGroupGrid">
                  {section.groups.map((group) => (
                    <div key={`${section.title}-${group.title}`} className="flowGroupCard">
                      <div className="flowGroupTitle">{group.title}</div>
                      <div className="flowGroupItems">
                        {group.items.map((item) => (
                          <span key={`${group.title}-${item}`}>{item}</span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              ) : null}
              {section.type === "event" && section.event ? (
                viewMode === "technical" ? (
                  <EventEvidenceCard event={section.event} defaultMode="structured" />
                ) : (
                  <div className="flowPresentationNote">
                    <strong>{summarizeEvent(section.event)}</strong>
                    <span>
                      This ATP artifact is available in full structured form. Switch to
                      Technical View to inspect every field and signature reference.
                    </span>
                  </div>
                )
              ) : null}
              {section.type === "archive" && section.record ? (
                viewMode === "technical" ? (
                  <ArchiveEvidenceCard record={section.record} />
                ) : (
                  <div className="flowPresentationNote">
                    <strong>Append-only archive evidence preserved</strong>
                    <span>
                      The archive service has captured this step into the independent hash-chain
                      audit path. Technical View shows the exact archive rows.
                    </span>
                  </div>
                )
              ) : null}
              {section.type === "trace" && section.trace ? (
                <div className="traceEvidenceGrid">
                  <div className="agentPromptBlock">
                    <span>Prompt</span>
                    <p>{section.trace.promptPreview ?? section.trace.reasoningSummary}</p>
                  </div>
                  <div className="agentRunGrid">
                    <div className="agentRunCard">
                      <span>Mode</span>
                      <strong>{section.trace.mode.toUpperCase()}</strong>
                    </div>
                    <div className="agentRunCard">
                      <span>Started</span>
                      <strong>{formatAgentTimestamp(section.trace.startedAt)}</strong>
                    </div>
                    <div className="agentRunCard">
                      <span>Completed</span>
                      <strong>{formatAgentTimestamp(section.trace.completedAt)}</strong>
                    </div>
                    <div className="agentRunCard">
                      <span>Duration</span>
                      <strong>{formatDurationMs(section.trace.durationMs)}</strong>
                    </div>
                  </div>
                  {viewMode === "presentation" ? (
                    <div className="flowPresentationTrace">
                      {section.trace.toolCalls.map((toolCall, index) => (
                        <div key={`${toolCall.tool_name}-presentation-${index}`} className="flowPresentationTraceCard">
                          <span>Tool {index + 1}</span>
                          <strong>{getAgentToolTitle(toolCall.tool_name)}</strong>
                          <small>
                            {toolCall.input_ref || "n/a"} -&gt; {toolCall.output_ref || "n/a"}
                          </small>
                        </div>
                      ))}
                    </div>
                  ) : (
                    section.trace.toolCalls.map((toolCall, index) => (
                      <AgentTraceEvidenceCard
                        key={`${toolCall.tool_name}-modal-${index}`}
                        toolCall={toolCall}
                        index={index}
                      />
                    ))
                  )}
                </div>
              ) : null}
            </section>
          ))}
        </div>
      </div>
    </div>
  );
}

function getFlowStagePreviewSummary(
  stage: FlowStage,
  input: {
    policyView: VerifierPolicyView | null;
    agentTrace: AgentTrace | null;
    agentModelName: string;
    amount: string;
    currency: string;
    recipientAccountRef: string;
    flowStatusLabel: string;
    requiresAdmin: boolean;
  },
) {
  const baseAmount = input.amount || "0.00";
  const baseCurrency = input.currency || "USD";
  const recipient = input.recipientAccountRef || "Select recipient";

  switch (stage.id) {
    case "instruction":
      return "This is where the transfer starts: the human instruction is signed with a passkey and handed to the agent.";
    case "agent_envelope":
      return `The Gemini Enterprise Agent Platform packages the transfer, resolves the recipient, and prepares the governed request using ${input.agentModelName}.`;
    case "verifier":
      return input.policyView
        ? `The verifier checks the signed packet against ${input.policyView.policy.policyName}, the recipient rules, and the proof before approving or escalating.`
        : "The verifier checks the signed packet, recipient rules, and proof before approving or escalating.";
    case "admin":
      return input.policyView
        ? `This higher-value path asks an administrator for a second passkey signature before the verifier can continue.`
        : "This higher-value path asks an administrator for a second passkey signature before the verifier can continue.";
    case "agent_forward":
      return "Once approved, the agent forwards the signed decision package to the bank.";
    case "execution":
      return `The bank executes the approved transfer of ${baseCurrency} ${baseAmount} to ${recipient} and writes settlement proof.`;
    case "archive":
      return "An independent archive appends the evidence so the transfer can be reviewed later.";
    default:
      return `Current flow status: ${input.flowStatusLabel}.`;
  }
}

function getFlowStagePreviewProgressCopy(
  stage: FlowStage,
  input: {
    requiresAdmin: boolean;
    flowStatusLabel: string;
  },
) {
  if (stage.status === "done") {
    return {
      eyebrow: "Already reached",
      title: "This step has already run",
      text: "The flow has passed this point, so you can review the captured proof, checks, and signature trail.",
      badge: "Already done",
      accent: "done" as const,
    };
  }

  if (stage.status === "current") {
    return {
      eyebrow: "Live step",
      title: "This step is active now",
      text: "This is the point where the flow is moving right now. The cards below show what has been captured so far and what still needs to happen.",
      badge: "Active",
      accent: "current" as const,
    };
  }

  if (stage.status === "skipped") {
    return {
      eyebrow: "Not needed",
      title: "This step does not apply to the current transfer",
      text: input.requiresAdmin
        ? "Because the amount stays on the auto lane, the administrator branch is not used for this transfer."
        : "This branch is reserved for higher-value transfers, so the current flow does not need it.",
      badge: "Not used here",
      accent: "skipped" as const,
    };
  }

  if (stage.status === "blocked") {
    return {
      eyebrow: "Unavailable",
      title: "This step depends on an earlier approval",
      text: "The flow cannot enter this step yet, so the modal shows it as a future stage instead of an active one.",
      badge: "Unavailable",
      accent: "blocked" as const,
    };
  }

  const waitingText: Record<FlowStageId, string> = {
    instruction: "This is the starting point of the flow, so it becomes active first.",
    agent_envelope: "It has not been reached yet because the signed instruction still needs to be created.",
    verifier: "It will open after the agent prepares the governed envelope.",
    admin: input.requiresAdmin
      ? "It will only appear if the verifier escalates the transfer to the higher-value lane."
      : "It will not be used for this transfer because the amount stays below the admin threshold.",
    agent_forward: "It becomes available only after the verifier signs off on the packet.",
    execution: "It appears after the approved packet is forwarded to the bank.",
    archive: "It is the final step and will show up after the transfer proof is written.",
  };

  return {
    eyebrow: "Not reached yet",
    title: "This step is still ahead in the flow",
    text: waitingText[stage.id] ?? `This step has not been reached yet. ${input.flowStatusLabel}.`,
    badge: "Not reached yet",
    accent: "pending" as const,
  };
}

function FlowStagePreviewModal(props: {
  stage: FlowStage;
  onClose: () => void;
  policyView: VerifierPolicyView | null;
  agentTrace: AgentTrace | null;
  agentModelName: string;
  amount: string;
  currency: string;
  recipientAccountRef: string;
  flowStatusLabel: string;
  requiresAdmin: boolean;
}) {
  useEffect(() => {
    function handleEscape(event: KeyboardEvent) {
      if (event.key === "Escape") {
        props.onClose();
      }
    }

    window.addEventListener("keydown", handleEscape);
    return () => window.removeEventListener("keydown", handleEscape);
  }, [props]);

  const summary = getFlowStagePreviewSummary(props.stage, {
    policyView: props.policyView,
    agentTrace: props.agentTrace,
    agentModelName: props.agentModelName,
    amount: props.amount,
    currency: props.currency,
    recipientAccountRef: props.recipientAccountRef,
    flowStatusLabel: props.flowStatusLabel,
    requiresAdmin: props.requiresAdmin,
  });

  const progressCopy = getFlowStagePreviewProgressCopy(props.stage, {
    requiresAdmin: props.requiresAdmin,
    flowStatusLabel: props.flowStatusLabel,
  });

  const quickFacts = [
    { label: "ATP type", value: props.stage.artifact },
    { label: "Kind", value: props.stage.kindLabel },
    { label: "Actor", value: props.stage.actor },
    { label: "Status", value: progressCopy.badge },
  ];

  const checksToShow = props.stage.checks.slice(0, 4);
  const signatureItems = props.stage.signatureSummary.slice(0, 3);
  const amountLabel = props.amount ? `${props.currency} ${props.amount}` : "No amount set yet";
  const hasAmount = Boolean(props.amount.trim());
  const pathLabel = !hasAmount
    ? "Amount not set"
    : props.stage.path === "conditional"
      ? "Conditional path"
      : props.stage.path === "support"
        ? "Support path"
        : props.stage.path === "terminal"
          ? "Terminal step"
          : "Primary path";
  const transferLaneLabel = !hasAmount
    ? "Not selected yet"
    : props.requiresAdmin
      ? "Admin review lane"
      : "Auto lane";
  const platformLabel =
    props.stage.module === "Agent"
      ? "Gemini Enterprise Agent Platform"
      : props.stage.module === "Verifier"
        ? "Verifier policy check"
        : props.stage.module === "Admin Branch"
          ? "Admin passkey confirmation"
          : props.stage.module;
  const agentRunLabel =
    props.stage.module === "Agent"
      ? props.agentTrace
        ? "Agent run captured"
        : "No transfer instruction yet"
      : props.agentTrace
        ? "Agent evidence available"
        : "Agent not triggered yet";
  const isFutureStep = props.stage.status === "pending" || props.stage.status === "skipped";

  return (
    <div className="flowModalBackdrop" onClick={props.onClose}>
      <div className="flowPreviewModal" onClick={(event) => event.stopPropagation()}>
        <div className="flowPreviewHeader">
          <div>
            <span className="flowPreviewEyebrow">
              {props.stage.module} · {props.stage.kindLabel}
            </span>
            <h3>{props.stage.title}</h3>
            <p>{props.stage.summary}</p>
          </div>
          <button type="button" className="flowModalClose" onClick={props.onClose}>
            Close
          </button>
        </div>

        <div className={`flowPreviewStateBanner ${progressCopy.accent}`}>
          <div>
            <span className="flowPreviewLabel">{progressCopy.eyebrow}</span>
            <strong>{progressCopy.title}</strong>
            <p>{progressCopy.text}</p>
          </div>
            <span className="flowPreviewStateBadge">{progressCopy.badge}</span>
          </div>

        <div className="flowPreviewHero">
          <div className="flowPreviewHeroMain">
            <span className="flowPreviewLabel">What this means</span>
            <p>{summary}</p>
            <div className="flowPreviewPillRow">
              <span className="flowPreviewPill tone-current">{props.flowStatusLabel}</span>
              <span className="flowPreviewPill tone-actor">{props.stage.actor}</span>
              <span className="flowPreviewPill tone-lane">{transferLaneLabel}</span>
              <span className="flowPreviewPill tone-platform">{platformLabel}</span>
              <span className="flowPreviewPill tone-trace">{agentRunLabel}</span>
            </div>
          </div>

          <div className="flowPreviewHeroAside">
            <div className="flowPreviewHeroStat">
              <span>Current transfer</span>
              <strong>{amountLabel}</strong>
              <small>
                {hasAmount
                  ? `To ${props.recipientAccountRef || "choose a recipient"}`
                  : "Choose an amount before the policy lane is decided"}
              </small>
            </div>
            <div className="flowPreviewHeroStat">
              <span>Policy lane</span>
              <strong>{transferLaneLabel}</strong>
              <small>
                {hasAmount
                  ? pathLabel
                  : "The route is not decided yet because the transfer amount is still empty"}
              </small>
            </div>
          </div>
        </div>

        <div className="flowPreviewFactGrid">
          {quickFacts.map((item) => (
            <div key={item.label} className="flowPreviewFactCard">
              <span>{item.label}</span>
              <strong>{item.value}</strong>
            </div>
          ))}
        </div>

        <div className="flowPreviewTransferCard">
          <div className="flowPreviewSectionHeader">
            <div>
              <span className="flowPreviewLabel">Current transfer</span>
              <strong>{amountLabel}</strong>
            </div>
            <span className="flowPreviewMiniBadge">{pathLabel}</span>
          </div>
          <p>
            {props.requiresAdmin
              ? "Higher-value transfer: transferor signature first, then an administrator confirmation before the verifier can continue."
              : "Auto lane: transferor signature first, then the agent and verifier handle the rest unless the amount changes later."}
          </p>
          {isFutureStep ? (
            <div className="flowPreviewFutureStep">
              <span className="flowPreviewLabel">Not reached yet</span>
              <strong>Keep going in the earlier step to unlock this stage</strong>
              <p>
                {props.stage.status === "skipped"
                  ? "This branch does not apply to the current transfer, so it will stay inactive unless the amount moves into the higher-value lane."
                  : "The flow has not advanced this far yet, so this stage is shown as a preview of what will appear next."}
              </p>
            </div>
          ) : null}
        </div>

        <div className="flowPreviewSplit">
          <div className="flowPreviewSectionBlock">
            <div className="flowPreviewSectionHeader">
              <div>
                <span className="flowPreviewLabel">What gets checked</span>
                <strong>Quick policy and proof review</strong>
              </div>
            </div>
            <div className="flowPreviewCheckList">
              {checksToShow.map((item) => (
                <div key={item} className="flowPreviewCheckItem">
                  <span className="flowPreviewCheckDot" />
                  <span>{item}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="flowPreviewSectionBlock">
            <div className="flowPreviewSectionHeader">
              <div>
                <span className="flowPreviewLabel">Signatures and proof</span>
                <strong>What is attached to the step</strong>
              </div>
            </div>
            <div className="flowPreviewSignatureSummary">
              {signatureItems.map((item) => (
                <span key={item}>{item}</span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function AgentToolCard(props: {
  toolCall: {
    tool_name: string;
    input_ref?: string;
    output_ref?: string;
    trace_sig?: string;
    trace_id?: string;
    trace_hash?: string;
    trace_sig_alg?: string;
    trace_signer?: string;
    args?: Record<string, string>;
  };
  index: number;
}) {
  const title = getAgentToolTitle(props.toolCall.tool_name);
  const description = getAgentToolDescription(props.toolCall.tool_name);

  return (
    <div className="agentToolCard">
      <div className="agentToolHeader">
        <span>Step {props.index + 1}</span>
        <strong>{title}</strong>
      </div>
      <p>{description}</p>
      <small>
        Input: {props.toolCall.input_ref ?? ""}
        {" · "}
        Output: {props.toolCall.output_ref ?? ""}
      </small>
      <small>
        Trace ID: {props.toolCall.trace_id ?? "n/a"}
        {" · "}
        Signer: {props.toolCall.trace_signer ?? "n/a"}
      </small>
    </div>
  );
}

function AgentTraceEvidenceCard(props: {
  toolCall: {
    tool_name: string;
    input_ref?: string;
    output_ref?: string;
    trace_sig?: string;
    trace_id?: string;
    trace_hash?: string;
    trace_sig_alg?: string;
    trace_signer?: string;
    args?: Record<string, string>;
  };
  index: number;
}) {
  return (
    <div className="traceEvidenceCard">
      <div className="traceEvidenceTop">
        <div>
          <span className="traceEvidenceStep">Step {props.index + 1}</span>
          <strong>{getAgentToolTitle(props.toolCall.tool_name)}</strong>
        </div>
        <span className="traceEvidenceTag">Verified Trace</span>
      </div>
      <div className="traceEvidenceFlow">
        <span>{props.toolCall.input_ref || "n/a"}</span>
        <strong>{props.toolCall.output_ref || "n/a"}</strong>
      </div>
      <div className="traceEvidenceMeta">
        <div>
          <span>Trace ID</span>
          <code>{props.toolCall.trace_id || "n/a"}</code>
        </div>
        <div>
          <span>Signer</span>
          <code>{props.toolCall.trace_signer || "n/a"}</code>
        </div>
        <div>
          <span>Algorithm</span>
          <code>{props.toolCall.trace_sig_alg || "n/a"}</code>
        </div>
      </div>
      <details className="tracePayloadBlock">
        <summary>Show hash, signature, and raw args</summary>
        <div className="tracePayloadGrid">
          <div>
            <span>Trace Hash</span>
            <code>{props.toolCall.trace_hash || "n/a"}</code>
          </div>
          <div>
            <span>Trace Signature</span>
            <code>{props.toolCall.trace_sig || "n/a"}</code>
          </div>
          <div>
            <span>Raw Args</span>
            <pre>{JSON.stringify(props.toolCall.args ?? {}, null, 2)}</pre>
          </div>
        </div>
      </details>
    </div>
  );
}

function getAgentToolTitle(toolName: string) {
  if (toolName === "resolve_recipient" || toolName === "recipient_lookup") {
    return "Resolve Recipient";
  }

  if (toolName === "validate_transfer_policy") {
    return "Validate Amount Against Policy";
  }

  if (toolName === "transfer_policy_check" || toolName === "policy_check_preview") {
    return "Validate Amount Against Policy";
  }

  if (toolName === "policy_preview") {
    return "Validate Amount Against Policy";
  }

  return toolName;
}

function getAgentToolDescription(toolName: string) {
  if (toolName === "resolve_recipient" || toolName === "recipient_lookup") {
    return "The agent resolved the human-selected recipient into a concrete bank account reference before execution planning.";
  }

  if (toolName === "validate_transfer_policy") {
    return "The agent validated the transfer amount and currency against the active governance policy to decide whether it can auto-execute, needs admin approval, or must be rejected.";
  }

  if (toolName === "transfer_policy_check" || toolName === "policy_check_preview") {
    return "The agent validated the transfer amount and currency against the active governance policy to decide whether it can auto-execute, needs admin approval, or must be rejected.";
  }

  if (toolName === "policy_preview") {
    return "The agent validated the transfer amount and currency against the active governance policy to decide whether it can auto-execute, needs admin approval, or must be rejected.";
  }

  return "The agent prepared this tool step as part of the governed transfer plan.";
}

function formatAgentTimestamp(value?: string) {
  if (!value) {
    return "n/a";
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  return parsed.toLocaleString();
}

function formatArchiveMonthLabel(monthKey: string) {
  const parsed = new Date(`${monthKey}-01T00:00:00`);
  if (Number.isNaN(parsed.getTime())) {
    return monthKey;
  }

  return new Intl.DateTimeFormat("en-US", {
    month: "long",
    year: "numeric",
  }).format(parsed);
}

function formatDurationMs(value?: number) {
  if (typeof value !== "number" || Number.isNaN(value)) {
    return "n/a";
  }

  if (value < 1000) {
    return `${value} ms`;
  }

  return `${(value / 1000).toFixed(2)} s`;
}

function formatPromptText(value?: string) {
  if (!value) {
    return "No prompt payload captured.";
  }

  return value;
}

type AgentCheckView = {
  label: string;
  detail: string;
  tone: "pass" | "warn" | "fail";
};

type SignedEnvelopeView = {
  summary: string;
  statusLabel: string;
  tone: "pass" | "warn" | "fail";
  fields: Array<{ label: string; value: string }>;
};

function getReadableAgentPrompt(trace?: AgentTrace | null) {
  if (!trace) {
    return "No prompt captured yet.";
  }

  if (trace.promptPreview) {
    return trace.promptPreview;
  }

  if (trace.promptText) {
    try {
      const parsed = JSON.parse(trace.promptText) as Record<string, unknown>;
      const amount = String(parsed.amount ?? "0.00");
      const currency = String(parsed.currency ?? "USD");
      const recipientAccountRef = String(parsed.recipient_account_ref ?? "the selected recipient");
      return `Resolve the selected recipient, then check whether ${amount} ${currency} to ${recipientAccountRef} can auto-execute under the active policy.`;
    } catch {
      return trace.promptText;
    }
  }

  return "No prompt captured yet.";
}

function buildAgentCheckViews(trace?: AgentTrace | null): AgentCheckView[] {
  const resolveRecipientCall = trace?.toolCalls.find((toolCall) => toolCall.tool_name === "resolve_recipient");
  const policyCall = trace?.toolCalls.find((toolCall) => toolCall.tool_name === "validate_transfer_policy");
  const recipientMatched = String(resolveRecipientCall?.args?.allowlisted ?? "").toLowerCase() === "true";
  const policyDecision = String(policyCall?.args?.policy_decision ?? policyCall?.output_ref ?? "");
  const amount = String(policyCall?.args?.amount ?? "");
  const currency = String(policyCall?.args?.currency ?? "USD");

  const policyPass = policyDecision === "auto_execute_allowed";
  const policyWarn = policyDecision === "policy_review_required" || policyDecision === "admin_approval_required";

  return [
    {
      label: "Recipient is on the allowlist",
      detail: recipientMatched
        ? `Resolved to ${resolveRecipientCall?.output_ref || "the target account"} and passed the allowlist check.`
        : "The selected recipient is not on the allowlist.",
      tone: recipientMatched ? "pass" : "fail",
    },
    {
      label: policyPass
        ? "Amount stays below policy threshold"
        : policyWarn
          ? "Amount needs review"
          : "Policy rejected the amount",
      detail: policyPass
        ? `${amount} ${currency} stays below the auto-execution threshold.`
        : policyWarn
          ? `${amount || "The amount"} ${currency} needs additional review under the active policy.`
          : policyDecision
            ? `Policy decision: ${policyDecision}.`
            : "Policy validation did not return a decision.",
      tone: policyPass ? "pass" : policyWarn ? "warn" : "fail",
    },
  ];
}

function getAgentToolPills(trace?: AgentTrace | null) {
  const toolNames = trace?.toolCalls.length ? trace.toolCalls.map((toolCall) => getAgentToolTitle(toolCall.tool_name)) : [];
  return toolNames.length ? toolNames : ["No tools captured yet"];
}

function getSignedEnvelopeView(envelopeEvent?: EventRecord | null): SignedEnvelopeView {
  if (!envelopeEvent) {
    return {
      summary: "No signed envelope captured yet.",
      statusLabel: "Not available",
      tone: "warn",
      fields: [],
    };
  }

  const content = envelopeEvent.payload.content as Record<string, unknown>;
  const action = content.action as Record<string, unknown> | undefined;
  const params = action?.params as Record<string, unknown> | undefined;
  const agentSignature = content.agent_signature as Record<string, unknown> | undefined;
  const amount = String(params?.amount ?? content.amount ?? "unknown");
  const currency = String(params?.currency ?? content.currency ?? "USD");
  const recipientAccountRef = String(params?.recipient_account_ref ?? content.recipient_account_ref ?? "unknown");
  const signed = Boolean(agentSignature?.agent_sig || agentSignature?.signed_payload);

  return {
    summary: `Kind 102 envelope signed for ${amount} ${currency} to ${recipientAccountRef}.`,
    statusLabel: signed ? "Signed envelope" : "Envelope pending signature",
    tone: signed ? "pass" : "fail",
    fields: [
      { label: "Instruction ref", value: String(content.instruction_ref ?? "unknown") },
      { label: "Recipient account", value: recipientAccountRef },
      { label: "Amount", value: `${amount} ${currency}` },
      {
        label: "Agent signature",
        value: signed ? "Attached and traceable" : "Missing",
      },
      {
        label: "Signed payload",
        value: String(agentSignature?.signed_payload ?? agentSignature?.signed_payload_c14n ?? "unknown"),
      },
    ],
  };
}

function TraceStepCard(props: {
  step: TraceStep;
  isLast: boolean;
}) {
  const clickable = Boolean(props.step.targetDomId);

  return (
    <div className="traceStepWrap">
      <div
        className={`traceStep ${props.step.status} ${clickable ? "clickableTrace" : ""}`}
        onClick={() => {
          if (props.step.targetDomId) {
            scrollToDomId(props.step.targetDomId);
          }
        }}
      >
        <div className="traceMarker" />
        <div className="traceContent">
          <div className="traceHeader">
            <strong>{props.step.label}</strong>
            <span className={`traceBadge ${props.step.status}`}>{props.step.statusLabel}</span>
          </div>
          <small>{props.step.description}</small>
          {props.step.eventId && <code>{props.step.eventId}</code>}
        </div>
      </div>
      {!props.isLast && <div className="traceConnector" />}
    </div>
  );
}

function EventEvidenceCard(props: {
  event: EventRecord;
  defaultMode?: "structured" | "raw";
  domId?: string;
}) {
  const [mode, setMode] = useState<"structured" | "raw">(props.defaultMode ?? "structured");
  const sections = getEventEvidenceSections(props.event);

  return (
    <div className="evidenceCard" id={props.domId}>
      <div className="evidenceHeader">
        <div>
          <strong className={props.event.kind === 108 ? "kindReject" : undefined}>
            Kind {props.event.kind}
          </strong>
          <small>{summarizeEvent(props.event)}</small>
        </div>
        <div className="viewToggle">
          <button
            type="button"
            className={mode === "structured" ? "secondary activeToggle" : "secondary"}
            onClick={() => setMode("structured")}
          >
            Structured
          </button>
          <button
            type="button"
            className={mode === "raw" ? "secondary activeToggle" : "secondary"}
            onClick={() => setMode("raw")}
          >
            Raw JSON
          </button>
        </div>
      </div>

      {mode === "structured" ? (
        <div className="evidenceSections">
          {sections.map((section) => (
            <div key={section.title} className="evidenceSection">
              <h3>{section.title}</h3>
              <div className="evidenceGrid">
                {section.rows.map((item) => (
                  <div key={`${section.title}-${item.label}`} className="evidenceRow">
                    <span>{item.label}</span>
                    <strong className={getEvidenceValueClassName(item.value)}>{item.value}</strong>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <pre className="rawJson">{JSON.stringify(props.event.payload, null, 2)}</pre>
      )}
    </div>
  );
}

function ArchiveEvidenceCard(props: { record: ArchiveRecord; domId?: string }) {
  const [mode, setMode] = useState<"structured" | "raw">("structured");
  const rows = getArchiveDetailRows(props.record);
  const entityRows = getArchiveEntityRows(props.record);

  return (
    <div className="evidenceCard" id={props.domId}>
      <div className="evidenceHeader">
        <div>
          <strong>Archive Record</strong>
          <small>{props.record.id}</small>
        </div>
        <div className="viewToggle">
          <button
            type="button"
            className={mode === "structured" ? "secondary activeToggle" : "secondary"}
            onClick={() => setMode("structured")}
          >
            Structured
          </button>
          <button
            type="button"
            className={mode === "raw" ? "secondary activeToggle" : "secondary"}
            onClick={() => setMode("raw")}
          >
            Raw JSON
          </button>
        </div>
      </div>

      {mode === "structured" ? (
        <div className="evidenceSections">
          <div className="evidenceSection">
            <h3>Archive Metadata</h3>
            <div className="evidenceGrid">
              {rows.map((item) => (
                <div key={item.label} className="evidenceRow">
                  <span>{item.label}</span>
                  <strong>{item.value}</strong>
                </div>
              ))}
            </div>
          </div>

          <div className="evidenceSection">
            <h3>Archived Entities</h3>
            <div className="evidenceGrid">
              {entityRows.map((item) => (
                <div key={item.label} className="evidenceRow">
                  <span>{item.label}</span>
                  <strong>{item.value}</strong>
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : (
        <pre className="rawJson">{JSON.stringify(props.record, null, 2)}</pre>
      )}
    </div>
  );
}

function summarizeEvent(event: EventRecord): string {
  switch (event.kind) {
    case 101:
      return "Transferor passkey-signed instruction";
    case 102:
      return "Agent-generated governance envelope";
    case 103:
      return "Verifier approved auto execute";
    case 104:
      return "Verifier requires admin signature";
    case 105:
      return "Administrator signed approval";
    case 107:
      return "Verifier re-approved high-value transfer";
    case 108:
      return "Verifier rejected the transfer";
    case 109:
      return "MCP bank executed transfer and wrote execution evidence";
    default:
      return "Event recorded";
  }
}

function describeVerifierStatus(event: EventRecord): string {
  if (event.kind === 103) {
    return "Verifier approved auto execute";
  }
  if (event.kind === 104) {
    return "Verifier requires admin signature";
  }
  if (event.kind === 108) {
    const rejection = event.payload.content.rejection_reason as
      | { code?: string; message?: string }
      | undefined;
    return rejection?.message ?? "Verifier rejected transfer";
  }
  if (event.kind === 107) {
    return "Verifier re-approved after administrator signature";
  }
  return "Verifier finished evaluation";
}

function createEmptyPasskeyState(): PasskeyState {
  return {
    registered: false,
    verified: false,
    credentialId: "",
    publicKeyRef: "",
    registeredAt: "",
    proofRef: "",
    lastVerifiedAt: "",
    proofType: "",
    deviceType: "",
    backedUp: null,
    rpId: "",
    lastUsedAt: "",
    counter: null,
    transports: [],
  };
}

function getRejectDetailRows(event: EventRecord) {
  const content = event.payload.content;
  const rejection = content.rejection_reason as { code?: string; message?: string } | undefined;
  const policyContext = content.policy_context as
    | {
        bundle?: { bundleId?: string; bundle_id?: string };
        policy?: { policyId?: string; policy_id?: string } | null;
      }
    | undefined;
  const nextStep = content.next_step;

  return [
    { label: "Decision", value: String(content.decision ?? "rejected") },
    { label: "Reason Code", value: rejection?.code ?? "unknown" },
    { label: "Reason", value: rejection?.message ?? "No rejection message" },
    {
      label: "Bundle",
      value:
        policyContext?.bundle?.bundleId ??
        policyContext?.bundle?.bundle_id ??
        "No bundle context",
    },
    {
      label: "Policy",
      value:
        policyContext?.policy?.policyId ??
        policyContext?.policy?.policy_id ??
        "No active policy for this currency",
    },
    {
      label: "Next Step",
      value: typeof nextStep === "string" ? nextStep : "halt_until_new_instruction_or_policy_change",
    },
  ];
}

function getEventEvidenceSections(event: EventRecord) {
  const baseSection = {
    title: "Event Metadata",
    rows: [
      { label: "Event ID", value: event.eventId },
      { label: "Flow ID", value: event.flowId },
      { label: "AI ID", value: event.aiId },
      { label: "Created At", value: formatTimestamp(event.createdAt) },
    ],
  };

  switch (event.kind) {
    case 101:
      return [baseSection, getInstructionSection(event), getInstructionSigningSection(event)];
    case 102:
      return [baseSection, getEnvelopeSection(event), getAgentSignatureSection(event)];
    case 103:
    case 104:
      return [
        baseSection,
        getVerifierDecisionSection(event),
        getVerifierControlSection(event),
        ...getVerifierChecksSections(event),
        getVerifierArtifactsSection(event),
        getVerifierSignatureSection(event),
      ];
    case 105:
      return [baseSection, getAdminApprovalSection(event)];
    case 107:
      return [
        baseSection,
        getReverifySection(event),
        ...getVerifierChecksSections(event),
        getVerifierArtifactsSection(event),
        getVerifierSignatureSection(event),
      ];
    case 108:
      return [
        baseSection,
        getVerifierDecisionSection(event),
        { title: "Rejection Detail", rows: getRejectDetailRows(event) },
        ...getVerifierChecksSections(event),
        getVerifierArtifactsSection(event),
        getVerifierSignatureSection(event),
      ];
    case 109:
      return [
        baseSection,
        { title: "Execution Detail", rows: getExecutionDetailRows(event) },
        { title: "Settlement", rows: getExecutionSettlementRows(event) },
        { title: "Resulting Balances", rows: getExecutionBalanceRows(event) },
        { title: "Execution Attestation", rows: getExecutionAttestationRows(event) },
      ];
    default:
      return [baseSection, { title: "Payload", rows: objectToRows(event.payload.content) }];
  }
}

function getInstructionSection(event: EventRecord) {
  const content = event.payload.content;
  return {
    title: "Instruction",
    rows: [
      { label: "Instruction ID", value: String(content.instruction_id ?? "unknown") },
      { label: "Transferor Principal", value: String(content.principal_id ?? "unknown") },
      { label: "Agent ID", value: String(content.agent_id ?? "unknown") },
      { label: "Action Type", value: String(content.action_type ?? "unknown") },
      { label: "Amount", value: String(content.amount ?? "unknown") },
      { label: "Currency", value: String(content.currency ?? "unknown") },
      { label: "Recipient Principal", value: String(content.recipient_id ?? "unknown") },
      { label: "Recipient Account", value: String(content.recipient_account_ref ?? "unknown") },
      { label: "Memo", value: String(content.memo ?? "unknown") },
    ],
  };
}

function getInstructionSigningSection(event: EventRecord) {
  const signing = event.payload.content.signing_payload as Record<string, unknown> | undefined;
  const proof = event.payload.content.signature_proof as Record<string, unknown> | undefined;
  return {
    title: "Signing Proof",
    rows: [
      { label: "Payload Type", value: String(signing?.payload_type ?? "unknown") },
      { label: "Payload Hash", value: String(signing?.payload_hash ?? "unknown") },
      { label: "Canonicalization", value: String(signing?.canonicalization ?? "unknown") },
      { label: "Proof Ref", value: String(proof?.proof_ref ?? "unknown") },
      { label: "Signature Alg", value: String(proof?.signature_alg ?? "unknown") },
      { label: "Credential ID", value: String(proof?.credential_id ?? "unknown") },
      { label: "Public Key Ref", value: String(proof?.public_key_ref ?? "unknown") },
    ],
  };
}

function getEnvelopeSection(event: EventRecord) {
  const content = event.payload.content;
  const action = content.action as Record<string, unknown> | undefined;
  const params = action?.params as Record<string, unknown> | undefined;
  return {
    title: "Governance Envelope",
    rows: [
      { label: "Instruction Ref", value: String(content.instruction_ref ?? "unknown") },
      { label: "Amount", value: String(params?.amount ?? "unknown") },
      { label: "Currency", value: String(params?.currency ?? "unknown") },
      { label: "Recipient Account", value: String(params?.recipient_account_ref ?? "unknown") },
      { label: "Memo", value: String(params?.memo ?? "unknown") },
    ],
  };
}

function getAgentSignatureSection(event: EventRecord) {
  const content = event.payload.content;
  const agentSignature = content.agent_signature as Record<string, unknown> | undefined;
  return {
    title: "Agent Signature",
    rows: [
      { label: "Agent Principal", value: String(agentSignature?.agent_principal ?? "unknown") },
      { label: "Agent Sig Alg", value: String(agentSignature?.agent_sig_alg ?? "unknown") },
      {
        label: "Payload Canonicalization",
        value: String(agentSignature?.signed_payload_c14n ?? "unknown"),
      },
      { label: "Signed Payload", value: String(agentSignature?.signed_payload ?? "unknown") },
      { label: "Agent Signature", value: String(agentSignature?.agent_sig ?? "unknown") },
    ],
  };
}

function getVerifierDecisionSection(event: EventRecord) {
  const content = event.payload.content;
  return {
    title: "Verifier Decision",
    rows: [
      { label: "Decision", value: String(content.decision ?? "unknown") },
      { label: "Disposition", value: String(content.safr_disposition_equivalent ?? "unknown") },
      { label: "Instruction Ref", value: String(content.instruction_ref ?? "unknown") },
      { label: "Envelope Ref", value: String(content.envelope_ref ?? "unknown") },
      { label: "Next Step", value: String(content.next_step ?? "unknown") },
    ],
  };
}

function getVerifierSignatureSection(event: EventRecord) {
  const content = event.payload.content;
  return {
    title: "Verifier Signature",
    rows: [
      { label: "Verifier Principal", value: String(content.verifier_principal ?? "unknown") },
      { label: "Verifier Sig", value: String(content.verifier_sig ?? "unknown") },
      { label: "Verifier Sig Alg", value: String(content.verifier_sig_alg ?? "unknown") },
      {
        label: "Verifier Signed Payload",
        value: String(content.verifier_signed_payload ?? "unknown"),
      },
    ],
  };
}

function getVerifierChecksSections(event: EventRecord) {
  const verification = event.payload.content.verification_result as Record<string, unknown> | undefined;
  if (!verification) {
    return [{ title: "Verification Checks", rows: [{ label: "Checks", value: "No verification result recorded" }] }];
  }

  const rows = Object.entries(verification).map(([label, value]) => ({
    label,
    value,
  }));

  const identityChecks = rows.filter((item) =>
    [
      "principal_signature_valid",
      "admin_signature_valid",
      "admin_passkey_verified",
      "admin_role_authorized",
      "agent_registered",
    ].includes(item.label),
  );

  const integrityChecks = rows.filter((item) =>
    [
      "instruction_payload_hash_valid",
      "instruction_not_expired",
      "instruction_nonce_unused",
      "envelope_schema_valid",
      "envelope_hash_valid",
      "chain_integrity_valid",
      "admin_payload_hash_valid",
      "first_verifier_record_valid",
      "admin_review_bound_to_same_instruction",
      "orchestrator_trace_signature_valid",
    ].includes(item.label),
  );

  const policyChecks = rows.filter((item) =>
    [
      "currency_policy_valid",
      "recipient_account_allowed",
      "recipient_account_resolved",
      "mandate_valid",
      "control_bundle_resolved",
      "control_bundle_hash_valid",
    ].includes(item.label),
  );

  const remainingChecks = rows.filter(
    (item) =>
      !identityChecks.includes(item) &&
      !integrityChecks.includes(item) &&
      !policyChecks.includes(item),
  );

  return [
    identityChecks.length > 0
      ? {
          title: "Identity Checks",
          rows: identityChecks.map(({ label, value }) => ({
            label: humanizeCheckLabel(label),
            value: formatVerificationValue(value),
          })),
        }
      : null,
    integrityChecks.length > 0
      ? {
          title: "Envelope Integrity Checks",
          rows: integrityChecks.map(({ label, value }) => ({
            label: humanizeCheckLabel(label),
            value: formatVerificationValue(value),
          })),
        }
      : null,
    policyChecks.length > 0
      ? {
          title: "Policy Checks",
          rows: policyChecks.map(({ label, value }) => ({
            label: humanizeCheckLabel(label),
            value: formatVerificationValue(value),
          })),
        }
      : null,
    remainingChecks.length > 0
      ? {
          title: "Additional Checks",
          rows: remainingChecks.map(({ label, value }) => ({
            label: humanizeCheckLabel(label),
            value: formatVerificationValue(value),
          })),
        }
      : null,
  ].filter(Boolean) as Array<{ title: string; rows: Array<{ label: string; value: string }> }>;
}

function getVerifierArtifactsSection(event: EventRecord) {
  const artifacts = event.payload.content.verified_artifacts as Record<string, unknown> | undefined;
  const traces = event.payload.content.trace_evidence as Record<string, unknown> | undefined;
  const traceCount = traces?.verified_trace_count;
  const traceList = traces?.verified_traces;

  const rows = [
    ...(artifacts
      ? Object.entries(artifacts).map(([label, value]) => ({
          label: humanizeCheckLabel(label),
          value: typeof value === "string" ? value : JSON.stringify(value),
        }))
      : []),
    {
      label: "Verified Trace Count",
      value:
        typeof traceCount === "number" || typeof traceCount === "string"
          ? String(traceCount)
          : "0",
    },
    {
      label: "Verified Trace IDs",
      value: Array.isArray(traceList)
        ? traceList
            .map((item) => {
              if (item && typeof item === "object" && "trace_id" in item) {
                return String((item as Record<string, unknown>).trace_id ?? "unknown");
              }
              return "unknown";
            })
            .join(", ")
        : "none",
    },
  ];

  return {
    title: "Verified Artifacts",
    rows,
  };
}

function getVerifierControlSection(event: EventRecord) {
  const content = event.payload.content;
  const risk = content.risk_summary as Record<string, unknown> | undefined;
  const bundle = content.control_bundle as Record<string, unknown> | undefined;
  return {
    title: "Risk And Control",
    rows: [
      { label: "Risk Tier", value: String(risk?.risk_tier ?? "unknown") },
      { label: "Risk Reason", value: String(risk?.reason ?? "unknown") },
      { label: "Threshold", value: String(risk?.threshold ?? "unknown") },
      { label: "Bundle ID", value: String(bundle?.bundle_id ?? "unknown") },
      { label: "Bundle Version", value: String(bundle?.bundle_version ?? "unknown") },
      { label: "Policy ID", value: String(bundle?.policy_id ?? "unknown") },
      { label: "Policy Name", value: String(bundle?.policy_name ?? "unknown") },
    ],
  };
}

function getAdminApprovalSection(event: EventRecord) {
  const content = event.payload.content;
  const proof = content.signature_proof as Record<string, unknown> | undefined;
  return {
    title: "Administrator Authorization",
    rows: [
      { label: "Verifier Record Ref", value: String(content.verifier_record_ref ?? "unknown") },
      { label: "Admin ID", value: String(content.admin_id ?? "unknown") },
      { label: "Decision", value: String(content.decision ?? "unknown") },
      { label: "Comment", value: String(content.comment ?? "unknown") },
      { label: "Proof Ref", value: String(proof?.proof_ref ?? "unknown") },
      { label: "Passkey Verified", value: String(proof?.passkey_verified ?? "unknown") },
    ],
  };
}

function getReverifySection(event: EventRecord) {
  const content = event.payload.content;
  return {
    title: "Re-Verification",
    rows: [
      { label: "Decision", value: String(content.decision ?? "unknown") },
      { label: "Instruction Ref", value: String(content.instruction_ref ?? "unknown") },
      { label: "Envelope Ref", value: String(content.envelope_ref ?? "unknown") },
      { label: "First Verifier Ref", value: String(content.first_verifier_ref ?? "unknown") },
      { label: "Admin Review Ref", value: String(content.admin_review_ref ?? "unknown") },
      { label: "Disposition", value: String(content.safr_disposition_equivalent ?? "unknown") },
      { label: "Next Step", value: String(content.next_step ?? "unknown") },
    ],
  };
}

function formatTimestamp(value: number) {
  if (!Number.isFinite(value)) {
    return "unknown";
  }
  return new Date(value < 1e12 ? value * 1000 : value).toISOString();
}

function humanizeCheckLabel(value: string) {
  return value
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatVerificationValue(value: unknown) {
  if (typeof value === "boolean") {
    return value ? "Passed" : "Failed";
  }
  if (typeof value === "string") {
    return value;
  }
  return JSON.stringify(value);
}

function getEvidenceValueClassName(value: string) {
  if (value === "Passed") {
    return "evidenceValueBadge evidenceValuePassed";
  }

  if (value === "Failed") {
    return "evidenceValueBadge evidenceValueFailed";
  }

  return "";
}

function objectToRows(value: Record<string, unknown>) {
  return Object.entries(value).map(([label, item]) => ({
    label,
    value: typeof item === "string" ? item : JSON.stringify(item),
  }));
}

function getExecutionDetailRows(event: EventRecord) {
  const content = event.payload.content;

  return [
    { label: "Execution ID", value: String(content.execution_id ?? "unknown") },
    { label: "Verifier Decision Ref", value: String(content.verifier_decision_ref ?? "unknown") },
    { label: "Instruction Ref", value: String(content.instruction_ref ?? "unknown") },
    { label: "Envelope Ref", value: String(content.envelope_ref ?? "unknown") },
    { label: "Transaction ID", value: String(content.transaction_id ?? "unknown") },
    { label: "Execution Status", value: String(content.execution_status ?? "unknown") },
    { label: "Executed At", value: String(content.executed_at ?? "unknown") },
    { label: "Next Step", value: String(content.next_step ?? "unknown") },
  ];
}

function getExecutionSettlementRows(event: EventRecord) {
  const settlement = event.payload.content.settlement as
    | {
        from_account_id?: string;
        to_account_id?: string;
        amount?: string;
        currency?: string;
      }
    | undefined;

  return [
    { label: "From Account", value: settlement?.from_account_id ?? "unknown" },
    { label: "To Account", value: settlement?.to_account_id ?? "unknown" },
    { label: "Amount", value: settlement?.amount ?? "unknown" },
    { label: "Currency", value: settlement?.currency ?? "unknown" },
  ];
}

function getExecutionBalanceRows(event: EventRecord) {
  const balances = event.payload.content.resulting_balances as
    | {
        from_account_available_balance?: string;
        to_account_available_balance?: string;
      }
    | undefined;

  return [
    {
      label: "Transferor Balance After Execution",
      value: balances?.from_account_available_balance ?? "unknown",
    },
    {
      label: "Recipient Balance After Execution",
      value: balances?.to_account_available_balance ?? "unknown",
    },
  ];
}

function getExecutionAttestationRows(event: EventRecord) {
  const attestation = event.payload.content.execution_attestation as
    | {
        execution_engine?: string;
        execution_sig?: string;
        execution_sig_alg?: string;
      }
    | undefined;

  return [
    { label: "Execution Engine", value: attestation?.execution_engine ?? "unknown" },
    { label: "Execution Signature", value: attestation?.execution_sig ?? "unknown" },
    { label: "Signature Algorithm", value: attestation?.execution_sig_alg ?? "unknown" },
  ];
}

function getArchiveDetailRows(record: ArchiveRecord) {
  return [
    { label: "Archive Record ID", value: record.content.archive_record_id },
    { label: "Flow ID", value: record.content.flow_id },
    { label: "Append Only Index", value: String(record.content.append_only_index) },
    { label: "Hash Chain Prev", value: record.content.hash_chain_prev },
    { label: "Hash Chain Curr", value: record.content.hash_chain_curr },
    { label: "Written By", value: record.content.written_by },
    { label: "Write Mode", value: record.content.write_mode },
    { label: "Created At", value: formatTimestamp(record.created_at) },
  ];
}

function getArchiveEntityRows(record: ArchiveRecord) {
  if (record.content.archived_entities.length === 0) {
    return [{ label: "Entities", value: "No archived entities" }];
  }

  return record.content.archived_entities.map((entity, index) => ({
    label: `Entity ${index + 1}`,
    value: `${entity.event_kind} · ${entity.event_role} · ${entity.event_ref}`,
  }));
}

function buildVerifierCheckGroups(event?: EventRecord) {
  const verification = event?.payload.content.verification_result as Record<string, unknown> | undefined;

  if (!verification) {
    return [
      {
        title: "Verifier Gate",
        items: [
          "Envelope and signatures have not been recorded yet",
          "No verifier check result written yet",
        ],
      },
    ];
  }

  const groups = getVerifierChecksSections(event ?? ({} as EventRecord));
  if (groups.length === 0) {
    return [
      {
        title: "Verifier Gate",
        items: ["Verifier finished but no grouped checks were recorded"],
      },
    ];
  }

  return groups.map((group) => ({
    title: group.title,
    items: group.rows.map((row) => `${row.label}: ${row.value}`),
  }));
}

function getStatusTone(verifierEvent?: EventRecord, executionEvent?: EventRecord) {
  if (executionEvent) {
    return "Success";
  }
  if (verifierEvent?.kind === 108) {
    return "Danger";
  }
  if (verifierEvent?.kind === 104) {
    return "Warn";
  }
  if (verifierEvent?.kind === 103 || verifierEvent?.kind === 107) {
    return "Info";
  }
  return "Neutral";
}

function buildFlowStages(input: {
  requiresAdmin: boolean;
  instructionEvent?: EventRecord;
  envelopeEvent?: EventRecord;
  firstVerifierEvent?: EventRecord;
  adminApprovalEvent?: EventRecord;
  reverifyEvent?: EventRecord;
  rejectEvent?: EventRecord;
  executionEvent?: EventRecord;
  archiveRecord?: ArchiveRecord;
  agentTrace: AgentTrace | null;
}): FlowStage[] {
  const verifierApproved = input.firstVerifierEvent?.kind === 103 || Boolean(input.reverifyEvent);
  const verifierEscalated = input.firstVerifierEvent?.kind === 104;
  const verifierRejected = input.firstVerifierEvent?.kind === 108 || input.rejectEvent?.kind === 108;

  return [
    {
      id: "instruction",
      title: "Transfer Instruction",
      module: "Human",
      actor: "Human -> Agent",
      artifact: "Kind 101 Transfer Instruction",
      kindLabel: "Kind 101",
      summary: "Transferor signs the original instruction with passkey-backed proof and submits it to the agent.",
      status: input.instructionEvent ? "done" : "current",
      statusLabel: input.instructionEvent ? "Captured" : "Ready for signature",
      checks: [
        "Passkey authentication completed",
        "Instruction payload hash bound",
        "Transferor proof reference attached",
      ],
      path: "primary",
      signatureSummary: [
        "WebAuthn passkey assertion captured",
        "Transferor proof ref attached to instruction",
      ],
    },
    {
      id: "agent_envelope",
      title: "Governance Envelope",
      module: "Agent",
      actor: "Agent",
      artifact: "Kind 102 Governance Envelope",
      kindLabel: "Kind 102",
      summary: "Agent resolves recipient, applies the fixed transfer skill, and signs the governed envelope.",
      status: input.envelopeEvent ? "done" : input.instructionEvent ? "current" : "pending",
      statusLabel: input.envelopeEvent ? "Envelope Signed" : input.instructionEvent ? "Agent Running" : "Up next",
      checks: [
        "Resolve recipient tool called",
        "Transfer policy tool called",
        "Agent trace signatures generated",
      ],
      path: "primary",
      signatureSummary: [
        "Agent envelope signed with registered agent key",
        "Tool trace signatures generated for replay",
      ],
    },
    {
      id: "verifier",
      title: "Verification Decision",
      module: "Verifier",
      actor: "Verifier",
      artifact:
        input.reverifyEvent?.kind === 107
          ? "Kind 107 Re-Verification Decision"
          : input.firstVerifierEvent?.kind === 104
            ? "Kind 104 Escalation Decision"
            : input.firstVerifierEvent?.kind === 108
              ? "Kind 108 Rejection Decision"
              : "Kind 103 Approval Decision",
      kindLabel:
        input.reverifyEvent?.kind === 107
          ? "Kind 107"
          : input.firstVerifierEvent?.kind === 104
            ? "Kind 104"
            : input.firstVerifierEvent?.kind === 108
              ? "Kind 108"
              : "Kind 103",
      summary: "Verifier validates instruction proof, agent signature, trace signatures, policy bundle, recipient constraints, and risk tier.",
      status:
        input.firstVerifierEvent || input.reverifyEvent
          ? "done"
          : input.envelopeEvent
            ? "current"
            : "pending",
      statusLabel:
        input.reverifyEvent
          ? "Re-Verified"
          : input.firstVerifierEvent?.kind === 103
            ? "Approved"
            : input.firstVerifierEvent?.kind === 104
              ? "Escalated"
              : input.firstVerifierEvent?.kind === 108
                ? "Rejected"
                : input.envelopeEvent
                  ? "Checking"
                  : "Up next",
      checks: [
        "Transferor proof reference validated",
        "Agent envelope signature verified",
        "Trace signatures verified",
        "Policy and bundle matched",
      ],
      path: "primary",
      signatureSummary: [
        "Verifier signs decision payload",
        "Envelope and trace signatures are re-validated",
      ],
    },
    {
      id: "admin",
      title: "Administrator Authorization",
      module: "Admin Branch",
      actor: "Administrator",
      artifact: "Kind 105 Administrator Authorization",
      kindLabel: "Kind 105",
      summary: "High-value transfers require administrator passkey signature before the verifier can re-approve them.",
      status: input.adminApprovalEvent
        ? "done"
        : verifierEscalated
          ? "current"
          : input.requiresAdmin
            ? "pending"
            : "skipped",
      statusLabel: input.adminApprovalEvent
        ? "Signed"
        : verifierEscalated
          ? "Admin Review"
          : input.requiresAdmin
            ? "Up next"
            : "Not Needed",
      checks: [
        "Admin role authorization",
        "Admin passkey signature",
        "Admin proof bound to same flow",
      ],
      path: "conditional",
      signatureSummary: [
        "Administrator signs approval with passkey",
        "Approval remains bound to the escalated flow",
      ],
    },
    {
      id: "agent_forward",
      title: "Execution Package Relay",
      module: "Agent",
      actor: "Agent -> MCP",
      artifact: "Kind 104 Execution Relay Package",
      kindLabel: "Kind 104",
      summary: "After verifier approval, the agent relays the verifier-signed decision package to the MCP bank interface for automatic execution.",
      status: input.executionEvent
        ? "done"
        : verifierRejected
          ? "blocked"
          : verifierApproved
            ? "current"
            : "pending",
      statusLabel: input.executionEvent
        ? "Forwarded"
        : verifierRejected
          ? "Unavailable"
          : verifierApproved
            ? "Relaying"
            : "Up next",
      checks: [
        "Verifier signature present",
        "Execution package references current flow",
        "Only approved verifier output can be forwarded",
      ],
      path: verifierEscalated ? "conditional" : "primary",
      signatureSummary: [
        "Verifier-signed package preserved in transit",
        "Agent forwards governed package instead of raw human input",
      ],
    },
    {
      id: "execution",
      title: "Transfer Execution",
      module: "MCP",
      actor: "MCP Bank",
      artifact: "Kind 109 Execution Event",
      kindLabel: "Kind 109",
      summary: "The bank transfer interface automatically executes the approved payment and emits settlement evidence.",
      status: input.executionEvent
        ? "done"
        : verifierRejected
          ? "blocked"
          : verifierApproved
            ? "current"
            : "pending",
      statusLabel: input.executionEvent
        ? "Executed"
        : verifierRejected
          ? "Unavailable"
          : verifierApproved
            ? "Auto Executing"
            : "Up next",
      checks: [
        "Verifier-approved package accepted",
        "Balances updated in bank ledger",
        "Execution attestation written",
      ],
      path: "terminal",
      signatureSummary: [
        "Execution attestation emitted by bank service",
        "Settlement evidence recorded for replay",
      ],
    },
    {
      id: "archive",
      title: "Archive Record",
      module: "Archive",
      actor: "Archive Service",
      artifact: "Kind 106 Archive Record",
      kindLabel: "Kind 106",
      summary: "Archive service appends the flow evidence into the append-only hash chain for audit and governance replay.",
      status: input.archiveRecord
        ? "done"
        : input.instructionEvent || input.envelopeEvent || input.firstVerifierEvent || input.executionEvent
          ? "current"
          : "pending",
      statusLabel: input.archiveRecord ? "Archived" : input.instructionEvent ? "Appending" : "Up next",
      checks: [
        "Append-only write path",
        "Hash chain continuity",
        "Archived entity references preserved",
      ],
      path: "support",
      signatureSummary: [
        "Hash-chain evidence extended",
        "Independent archive path preserves audit trail",
      ],
    },
  ];
}

function getFlowStageDetailSections(
  stage: FlowStage,
  input: {
    instructionEvent?: EventRecord;
    envelopeEvent?: EventRecord;
    verifierEvent?: EventRecord;
    adminApprovalEvent?: EventRecord;
    executionEvent?: EventRecord;
    archiveRecord?: ArchiveRecord;
    agentTrace: AgentTrace | null;
    policyView: VerifierPolicyView | null;
    amount: string;
    currency: string;
    status: string;
    transferorPrincipalId: string;
    adminPrincipalId: string;
    recipientPrincipalId: string;
  },
): Array<
  | { title: string; type: "rows"; rows: Array<{ label: string; value: string }> }
  | { title: string; type: "groups"; groups: Array<{ title: string; items: string[] }> }
  | { title: string; type: "event"; event?: EventRecord }
  | { title: string; type: "archive"; record?: ArchiveRecord }
  | { title: string; type: "trace"; trace?: AgentTrace | null }
> {
  switch (stage.id) {
    case "instruction":
      const instructionContent = input.instructionEvent?.payload.content as Record<string, unknown> | undefined;
      const instructionAmount = String(instructionContent?.amount ?? input.amount ?? "unknown");
      const instructionCurrency = String(instructionContent?.currency ?? input.currency ?? "USD");
      return [
        {
          title: "Step Summary",
          type: "rows",
          rows: [
            { label: "What happens here", value: "Human signs the transfer instruction with passkey-backed identity proof" },
            { label: "Transfer amount", value: `${instructionCurrency} ${instructionAmount}` },
            { label: "Current status", value: stage.statusLabel },
            { label: "Recipient Principal", value: input.recipientPrincipalId },
            { label: "Primary handoff", value: "Kind 101 transfer instruction -> Agent" },
          ],
        },
        {
          title: "Checks Performed",
          type: "groups",
          groups: [
            {
              title: "Identity Binding",
              items: [
                "Transferor passkey authenticated at submit time",
                "Proof reference captured from identity service",
                "Credential bound to transferor principal",
              ],
            },
            {
              title: "Instruction Integrity",
              items: [
                "Canonical payload hash attached",
                "Nonce and expiry attached to instruction",
                "Kind 101 persisted before agent handoff",
              ],
            },
          ],
        },
        { title: "Kind 101 Event", type: "event", event: input.instructionEvent },
      ];
    case "agent_envelope":
      return [
        {
          title: "Agent Execution Summary",
          type: "rows",
          rows: [
            { label: "Skill contract", value: input.agentTrace?.skillName ?? "governed_transfer_skill_v1" },
            { label: "Transferor Principal", value: input.transferorPrincipalId },
            { label: "Recipient Principal", value: input.recipientPrincipalId },
            { label: "Agent Principal", value: DEMO_PRINCIPALS.agent },
            {
              label: "Mandatory tools",
              value:
                (input.agentTrace?.mandatoryTools ?? ["resolve_recipient", "validate_transfer_policy"]).join(
                  " -> ",
                ),
            },
          ],
        },
        {
          title: "Checks Performed",
          type: "groups",
          groups: [
            {
              title: "Prompt And Skill Contract",
              items: [
                "Transfer skill invoked with fixed tool contract",
                "Agent prompt bound to current flow context",
                "Agent run timestamps captured for replay",
              ],
            },
            {
              title: "Envelope Construction",
              items: [
                "Recipient resolution result embedded",
                "Policy preview result embedded",
                "Agent signature and trace signatures attached",
              ],
            },
          ],
        },
        { title: "Agent Trace", type: "trace", trace: input.agentTrace },
        { title: "Kind 102 Event", type: "event", event: input.envelopeEvent },
      ];
    case "verifier":
      return [
        {
          title: "Verifier Checks Overview",
          type: "rows",
          rows: [
            { label: "Transferor Principal", value: input.transferorPrincipalId },
            { label: "Recipient Principal", value: input.recipientPrincipalId },
            { label: "Verifier Principal", value: DEMO_PRINCIPALS.verifier },
            { label: "Checks", value: "Instruction proof, agent signature, trace signatures, policy bundle, risk, recipient constraints" },
            { label: "Decision status", value: stage.statusLabel },
            { label: "Decision output", value: input.verifierEvent ? summarizeEvent(input.verifierEvent) : "No verifier output yet" },
          ],
        },
        {
          title: "Checks Performed",
          type: "groups",
          groups: buildVerifierCheckGroups(input.verifierEvent),
        },
        { title: "Verifier Event", type: "event", event: input.verifierEvent },
      ];
    case "admin":
      return [
        {
          title: "Admin Escalation Rules",
          type: "rows",
          rows: [
            { label: "Administrator Principal", value: input.adminPrincipalId },
            {
              label: "When required",
              value: input.policyView
                ? `Amount at or above ${input.policyView.policy.adminReviewAtOrAbove.toFixed(2)} ${input.policyView.policy.currency}`
                : "When transfer exceeds active policy threshold",
            },
            { label: "Current status", value: stage.statusLabel },
            { label: "Authorization result", value: "Administrator passkey signature is attached and returned for verifier re-check" },
          ],
        },
        {
          title: "Checks Performed",
          type: "groups",
          groups: [
            {
              title: "Escalation Policy",
              items: [
                "Transfer amount compared against active threshold",
                "High-risk branch requires admin signature",
                "Approval stays bound to the same flow and envelope",
              ],
            },
            {
              title: "Identity Review",
              items: [
                "Admin passkey authentication required",
                "Admin role authorization checked",
                "Approval evidence returned for verifier re-check",
              ],
            },
          ],
        },
        { title: "Kind 105 Event", type: "event", event: input.adminApprovalEvent },
      ];
    case "agent_forward":
      return [
        {
          title: "Execution Relay",
          type: "rows",
          rows: [
            { label: "Transferor Principal", value: input.transferorPrincipalId },
            { label: "Recipient Principal", value: input.recipientPrincipalId },
            { label: "Agent Principal", value: DEMO_PRINCIPALS.agent },
            { label: "Verifier Principal", value: DEMO_PRINCIPALS.verifier },
            { label: "Routing", value: "Agent receives the verifier-approved decision and relays the execution package to MCP" },
            { label: "Why agent forwards", value: "Keeps orchestration consistent: human -> agent -> verifier -> agent -> MCP" },
            { label: "Current engine status", value: input.status },
          ],
        },
        {
          title: "Checks Performed",
          type: "groups",
          groups: [
            {
              title: "Forwarding Gate",
              items: [
                "Only verifier-approved package may continue",
                "Verifier signature must be present before forwarding",
                "Forwarded package must reference the current flow",
              ],
            },
            {
              title: "Agent Relay Responsibility",
              items: [
                "Agent preserves verifier decision context",
                "Agent keeps orchestration trace continuous",
                "MCP receives governed execution package rather than raw instruction",
              ],
            },
          ],
        },
        { title: "Agent Trace", type: "trace", trace: input.agentTrace },
      ];
    case "execution":
      return [
        {
          title: "Automatic Execution",
          type: "rows",
          rows: [
            { label: "Transferor Principal", value: input.transferorPrincipalId },
            { label: "Recipient Principal", value: input.recipientPrincipalId },
            { label: "Agent Principal", value: DEMO_PRINCIPALS.agent },
            { label: "Verifier Principal", value: DEMO_PRINCIPALS.verifier },
            { label: "Required input", value: "Verifier-approved decision package" },
            { label: "Execution rule", value: "MCP executes automatically after verifier approval or re-verification" },
            { label: "Current status", value: stage.statusLabel },
          ],
        },
        {
          title: "Checks Performed",
          type: "groups",
          groups: [
            {
              title: "Bank Side Execution",
              items: [
                "Verifier event reference accepted by MCP",
                "Source and destination balances updated",
                "Execution evidence written as Kind 109",
              ],
            },
            {
              title: "Post-Execution Evidence",
              items: [
                "Transaction id recorded",
                "Settlement details persisted",
                "Execution attestation attached",
              ],
            },
          ],
        },
        { title: "Kind 109 Event", type: "event", event: input.executionEvent },
      ];
    case "archive":
      return [
        {
          title: "Archive Guarantees",
          type: "rows",
          rows: [
            { label: "Write mode", value: "Append-only" },
            { label: "Purpose", value: "Independent audit path and evidence retention" },
            { label: "Current status", value: stage.statusLabel },
          ],
        },
        {
          title: "Checks Performed",
          type: "groups",
          groups: [
            {
              title: "Archive Guarantees",
              items: [
                "Append-only write path used",
                "Hash chain previous and current values maintained",
                "Archived entity references preserved for replay",
              ],
            },
            {
              title: "Audit Use",
              items: [
                "Independent from business write path",
                "Supports downstream investigation",
                "Supports SAFR evidence-chain review",
              ],
            },
          ],
        },
        { title: "Kind 106 Record", type: "archive", record: input.archiveRecord },
      ];
    default:
      return [];
  }
}

type TraceStep = {
  label: string;
  description: string;
  eventId?: string;
  targetDomId?: string;
  status: "done" | "current" | "pending" | "branch";
  statusLabel: string;
};

function buildTraceSteps(input: {
  instructionEvent?: EventRecord;
  envelopeEvent?: EventRecord;
  firstVerifierEvent?: EventRecord;
  adminApprovalEvent?: EventRecord;
  reverifyEvent?: EventRecord;
  rejectEvent?: EventRecord;
  executionEvent?: EventRecord;
  archiveRecords: ArchiveRecord[];
}): TraceStep[] {
  const latestArchive = input.archiveRecords.at(-1);
  const firstDecisionIsEscalate = input.firstVerifierEvent?.kind === 104;
  const firstDecisionIsReject = input.firstVerifierEvent?.kind === 108 || input.rejectEvent?.kind === 108;
  const archiveReady = Boolean(
    input.instructionEvent ||
      input.envelopeEvent ||
      input.firstVerifierEvent ||
      input.adminApprovalEvent ||
      input.reverifyEvent ||
      input.rejectEvent ||
      input.executionEvent,
  );

  return [
    {
      label: "Kind 101 Transfer Instruction",
      description: "Transferor signs the original payment instruction with passkey-backed proof.",
      eventId: input.instructionEvent?.eventId,
      targetDomId: input.instructionEvent ? getEventCardDomId(input.instructionEvent.eventId) : undefined,
      status: input.instructionEvent ? "done" : "current",
      statusLabel: input.instructionEvent ? "Done" : "Active",
    },
    {
      label: "Kind 102 Governance Envelope",
      description: "Agent converts the human instruction into an ATP-style governed tool envelope.",
      eventId: input.envelopeEvent?.eventId,
      targetDomId: input.envelopeEvent ? getEventCardDomId(input.envelopeEvent.eventId) : undefined,
      status: input.envelopeEvent ? "done" : input.instructionEvent ? "current" : "pending",
      statusLabel: input.envelopeEvent ? "Done" : input.instructionEvent ? "Active" : "Up next",
    },
    {
      label: "Kind 103/104 Verification Decision",
      description: "Verifier evaluates policy, identity proof, recipient constraints, and risk tier.",
      eventId: input.firstVerifierEvent?.eventId,
      targetDomId: input.firstVerifierEvent
        ? getEventCardDomId(input.firstVerifierEvent.eventId)
        : undefined,
      status: input.firstVerifierEvent ? "done" : input.envelopeEvent ? "current" : "pending",
      statusLabel: input.firstVerifierEvent ? "Done" : input.envelopeEvent ? "Active" : "Up next",
    },
    {
      label: "Kind 105 Administrator Authorization",
      description: firstDecisionIsEscalate
        ? "Administrator signs the high-value transfer approval."
        : "Only required when the first verifier decision escalates.",
      eventId: input.adminApprovalEvent?.eventId,
      targetDomId: input.adminApprovalEvent
        ? getEventCardDomId(input.adminApprovalEvent.eventId)
        : undefined,
      status: input.adminApprovalEvent
        ? "done"
        : firstDecisionIsEscalate
          ? "current"
          : "branch",
      statusLabel: input.adminApprovalEvent
        ? "Done"
        : firstDecisionIsEscalate
          ? "Active"
          : "Not used",
    },
    {
      label: "Kind 107 Re-Verification",
      description: firstDecisionIsEscalate
        ? "Verifier re-checks the admin-signed approval before bank execution."
        : "Only required after an escalation branch.",
      eventId: input.reverifyEvent?.eventId,
      targetDomId: input.reverifyEvent ? getEventCardDomId(input.reverifyEvent.eventId) : undefined,
      status: input.reverifyEvent
        ? "done"
        : input.adminApprovalEvent
          ? "current"
          : firstDecisionIsEscalate
            ? "pending"
            : "branch",
      statusLabel: input.reverifyEvent
        ? "Done"
        : input.adminApprovalEvent
          ? "Active"
          : firstDecisionIsEscalate
            ? "Up next"
            : "Not used",
    },
    {
      label: "Kind 108 Rejection Decision",
      description: "If policy or proof validation fails, the flow halts with a signed rejection event.",
      eventId: input.rejectEvent?.eventId,
      targetDomId: input.rejectEvent ? getEventCardDomId(input.rejectEvent.eventId) : undefined,
      status: input.rejectEvent
        ? "done"
        : firstDecisionIsReject
          ? "current"
          : "branch",
      statusLabel: input.rejectEvent ? "Triggered" : "Not Used",
    },
    {
      label: "Kind 109 Execution Event",
      description: "MCP bank executes the approved transfer automatically and writes the execution evidence event.",
      eventId: input.executionEvent?.eventId,
      targetDomId: input.executionEvent ? getEventCardDomId(input.executionEvent.eventId) : undefined,
      status: input.executionEvent
        ? "done"
        : input.rejectEvent
          ? "branch"
          : input.reverifyEvent || input.firstVerifierEvent?.kind === 103
            ? "current"
            : "pending",
      statusLabel: input.executionEvent
        ? "Done"
        : input.rejectEvent
          ? "Unavailable"
          : input.reverifyEvent || input.firstVerifierEvent?.kind === 103
            ? "Active"
            : "Up next",
    },
    {
      label: "Kind 106 Archive Record",
      description: "Archive service appends the current flow state into the append-only evidence chain.",
      eventId: latestArchive?.id,
      targetDomId: latestArchive ? getArchiveCardDomId(latestArchive.id) : undefined,
      status: latestArchive ? "done" : archiveReady ? "current" : "pending",
      statusLabel: latestArchive ? "Done" : archiveReady ? "Active" : "Up next",
    },
  ];
}

function getEventCardDomId(eventId: string) {
  return `event-card-${eventId}`;
}

function getArchiveCardDomId(archiveId: string) {
  return `archive-card-${archiveId}`;
}

function scrollToDomId(domId: string) {
  const element = document.getElementById(domId);
  if (!element) {
    return;
  }
  element.scrollIntoView({ behavior: "smooth", block: "start" });
}
