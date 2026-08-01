import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { useEffect, useState } from "react";
import { DEMO_AGENT_IDS, DEMO_PRINCIPALS, assertEnglishAccountHandle } from "@safr-x-atp-demo/protocol";

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

const EVENT_SERVICE_URL = "/api/event";
const VERIFIER_SERVICE_URL = "/api/verifier";
const MCP_BANK_URL = "/api/bank";
const ARCHIVE_SERVICE_URL = "/api/archive";
const IDENTITY_SERVICE_URL = "/api/identity";
const AGENT_SERVICE_URL = "/api/agent";

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
  const [authReady, setAuthReady] = useState(false);
  const [activeAccount, setActiveAccount] = useState<ActiveAccount | null>(null);
  const [accountUsernameInput, setAccountUsernameInput] = useState("");
  const [accountPasswordInput, setAccountPasswordInput] = useState("");
  const [authError, setAuthError] = useState("");
  const [flowId, setFlowId] = useState(() => `flow_demo_${Date.now()}`);
  const [amount, setAmount] = useState("");
  const [currency, setCurrency] = useState("USD");
  const [memo, setMemo] = useState("");
  const [recipientAccountRef, setRecipientAccountRef] = useState("");
  const [amountError, setAmountError] = useState("");
  const [passkeyTransferor, setPasskeyTransferor] = useState<PasskeyState>(createEmptyPasskeyState);
  const [passkeyAdmin, setPasskeyAdmin] = useState<PasskeyState>(createEmptyPasskeyState);
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [archiveRecords, setArchiveRecords] = useState<ArchiveRecord[]>([]);
  const [policyView, setPolicyView] = useState<VerifierPolicyView | null>(null);
  const [policyNotice, setPolicyNotice] = useState("");
  const [lastVerifierEventId, setLastVerifierEventId] = useState("");
  const [agentTrace, setAgentTrace] = useState<AgentTrace | null>(null);
  const [executionBalanceSnapshot, setExecutionBalanceSnapshot] = useState<ExecutionBalanceSnapshot | null>(null);
  const [status, setStatus] = useState("Ready");
  const [instructionSubmitBusy, setInstructionSubmitBusy] = useState(false);
  const [selectedStageId, setSelectedStageId] = useState<FlowStageId | null>(null);
  const [spotlightStageId, setSpotlightStageId] = useState<FlowStageId>("instruction");
  const [actionPulseStageId, setActionPulseStageId] = useState<FlowStageId | null>(null);
  const [instructionComposerOpen, setInstructionComposerOpen] = useState(false);
  const passwordStrength = evaluatePasswordStrength(accountPasswordInput);

  const transferorPrincipalId = activeAccount?.transferorPrincipalId ?? DEMO_PRINCIPALS.transferor;
  const adminPrincipalId = activeAccount?.adminPrincipalId ?? DEMO_PRINCIPALS.admin;
  const recipientPrincipalId = activeAccount?.recipientPrincipalId ?? DEMO_PRINCIPALS.recipient;
  const activeUsername = activeAccount?.username ?? "";
  const activeAccountLabel = activeUsername || "demo";

  const transferorAccount = accounts.find(
    (account) => account.ownerId === transferorPrincipalId && account.ownerRole === "transferor",
  );
  const recipientAccount = accounts.find(
    (account) => account.ownerId === recipientPrincipalId && account.ownerRole === "recipient",
  );
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
  const isDraft =
    !instructionEvent && !envelopeEvent && !firstVerifierEvent && !reverifyEvent && !executionEvent;
  const isWaitingForFirstVerifier = Boolean(envelopeEvent && !firstVerifierEvent && !rejectEvent);
  const isWaitingForAdmin = requiresAdmin && firstVerifierEvent?.kind === 104 && !reverifyEvent;
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
          ? "Forward approved package to MCP bank"
          : isWaitingForFirstVerifier
            ? "Verifier is evaluating the agent envelope"
            : isDraft
              ? "Capture and sign a new human instruction"
              : "Transferor should submit this instruction to verifier";
  const currentActionHint = executionEvent
    ? "This flow has already reached MCP execution."
    : rejectEvent
      ? "The verifier halted this flow. Open the rejected step for full validation details."
      : isWaitingForAdmin
        ? "This amount crossed the policy threshold, so admin passkey approval is the next mandatory step."
        : isReadyForExecution
          ? "Verifier approval is complete. The agent can now relay the approved execution package."
          : isWaitingForFirstVerifier
            ? "The signed instruction and agent envelope were already submitted. Wait for the verifier decision."
            : "You can operate directly from this strip without scrolling away from the live governance diagram.";
  const selectedStage = selectedStageId
    ? flowStages.find((stage) => stage.id === selectedStageId) ?? null
    : null;

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
      return;
    }

    await Promise.all([
      fetchPasskeyStatus(transferorPrincipalId, "transferor"),
      fetchPasskeyStatus(adminPrincipalId, "admin"),
    ]);
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

  async function fetchEvents() {
    const response = await fetch(`${EVENT_SERVICE_URL}/events?flowId=${flowId}`);
    const body = (await response.json()) as { events: EventRecord[] };
    setEvents(body.events);
  }

  async function fetchArchive() {
    const response = await fetch(`${ARCHIVE_SERVICE_URL}/archive/flows/${flowId}`);
    const body = (await response.json()) as { records: ArchiveRecord[] };
    setArchiveRecords(body.records ?? []);
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

  async function refreshAll() {
    await Promise.all([
      fetchAccounts(),
      fetchTransactions(),
      fetchEvents(),
      fetchArchive(),
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
    // Only auto-fill the default allowlisted recipient when the form is empty.
    // Do not overwrite an explicit user choice such as the expected-reject option.
    if (!recipientAccountRef && recipientAccount) {
      setRecipientAccountRef(recipientAccount.accountId);
    }
  }, [recipientAccount?.accountId, recipientAccountRef]);

  useEffect(() => {
    void fetchPolicy();
  }, []);

  useEffect(() => {
    if (!activeAccount) {
      return;
    }

    void refreshPasskeys();
  }, [activeAccount?.username, transferorPrincipalId, adminPrincipalId]);

  function resetTransferForm(nextFlowId = `flow_demo_${Date.now()}`) {
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
    setEvents([]);
    setArchiveRecords([]);
    setSelectedStageId(null);
    setInstructionComposerOpen(false);
    setStatus("Ready");
    setActionPulseStageId(null);
    setInstructionSubmitBusy(false);
  }

  function startNewFlowDraft() {
    resetTransferForm();
    void fetchPolicy();
    setInstructionComposerOpen(true);
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
      setPasskeyTransferor(createEmptyPasskeyState());
      setPasskeyAdmin(createEmptyPasskeyState());
      setAccountPasswordInput("");
      resetTransferForm();
      setAccountUsernameInput(body.account.username);
      setStatus(action === "register" ? "Account registered" : "Logged in");
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "Authentication failed");
    }
  }

  async function handleLogout() {
    await fetchIdentity("/auth/logout", { method: "POST" });
    setActiveAccount(null);
    setAccountUsernameInput("");
    setAccountPasswordInput("");
    setPasskeyTransferor(createEmptyPasskeyState());
    setPasskeyAdmin(createEmptyPasskeyState());
    resetTransferForm();
    setAuthError("");
    setStatus("Logged out");
  }

  async function restoreOriginalBalances() {
    try {
      setStatus("Restoring original account balances...");
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
      setStatus("Account balances restored to their original values");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Failed to restore balances");
    }
  }

  function getMissingPasskeyMessage() {
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
      created_at: Math.floor(Date.now() / 1000),
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
      created_at: Math.floor(Date.now() / 1000),
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
          flowId,
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
      const normalizedToolCalls = body.agent.tool_calls.map((toolCall) => {
        const args = toolCall.args ?? {};

        if (toolCall.tool_name === "resolve_recipient" || toolCall.tool_name === "recipient_lookup") {
          return {
            ...toolCall,
            tool_name: "resolve_recipient",
            input_ref: toolCall.input_ref ?? args.recipient_id ?? "",
            output_ref: toolCall.output_ref ?? args.account_ref ?? "",
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
            output_ref: toolCall.output_ref ?? "policy preview prepared",
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
      setStatus(
        `${describeVerifierStatus(body.verifierEvent)} via ${body.agent.mode} agent orchestration`,
      );
      await refreshAll();
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
      if (!transferorAccount || !recipientAccount || !lastVerifierEventId) {
        throw new Error("Missing execution prerequisites");
      }
      if (!canExecute) {
        throw new Error("Current flow is not executable yet");
      }

      const fromBefore = transferorAccount.availableBalance;
      const toBefore = recipientAccount.availableBalance;
      const transferAmount = Number(amount);

      setStatus("Executing transfer in MCP bank...");
      const response = await fetch(`${AGENT_SERVICE_URL}/transfers/execute`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          flowId,
          verifierEventId: lastVerifierEventId,
          fromAccountId: transferorAccount.accountId,
          toAccountId: recipientAccount.accountId,
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
        toAccountId: recipientAccount.accountId,
        fromBefore,
        fromAfter: Number.isFinite(fromAfter) ? fromAfter : fromBefore,
        toBefore,
        toAfter: Number.isFinite(toAfter) ? toAfter : toBefore,
        alreadyExecuted: Boolean(body.alreadyExecuted),
      });

      setStatus(
        body.alreadyExecuted
          ? "Transfer was already executed; execution evidence has been refreshed"
          : "Transfer executed in MCP bank and recorded as a Kind 109 execution event",
      );
      await refreshAll();
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Execution failed");
    }
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
          created_at: Math.floor(Date.now() / 1000),
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
          created_at: Math.floor(Date.now() / 1000),
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
    <div className="page">
      <header className="hero">
        <div>
          <h1>SAFR x ATP Transfer Demo</h1>
          <p>
            Active account: <strong>{activeAccountLabel}</strong> · Transferor:{" "}
            <code>{transferorPrincipalId}</code> · Admin: <code>{adminPrincipalId}</code>
          </p>
        </div>
        <div className="heroActions">
          <button className="danger" onClick={() => void restoreOriginalBalances()}>
            Restore balances
          </button>
          <button className="secondary" onClick={() => void handleLogout()}>
            Switch account
          </button>
        </div>
      </header>

      <section className="panel">
        <h2>Architecture Walkthrough</h2>
        <div className="walkthroughGrid">
          <div className="walkthroughCard">
            <strong>1. Signed Human Instruction</strong>
            <small>
              Transferor signs a Kind 101 instruction with passkey-backed identity proof.
            </small>
          </div>
          <div className="walkthroughCard">
            <strong>2. Agent Envelope</strong>
            <small>
              The agent converts the instruction into a Kind 102 envelope for governed tool use.
            </small>
          </div>
          <div className="walkthroughCard">
            <strong>3. Verifier Decision</strong>
            <small>
              Verifier checks policy bundle, amount threshold, allowlist, and signature validity.
            </small>
          </div>
          <div className="walkthroughCard">
            <strong>4. Escalation Or Reject</strong>
            <small>
              High-value flows escalate to admin review; invalid flows emit Kind 108 rejection.
            </small>
          </div>
          <div className="walkthroughCard">
            <strong>5. MCP Bank Execution</strong>
            <small>
              Only executable verifier decisions can reach the bank transfer interface.
            </small>
          </div>
          <div className="walkthroughCard">
            <strong>6. Independent Archive</strong>
            <small>
              Each flow stage is copied into append-only archive records for audit evidence.
            </small>
          </div>
        </div>
      </section>

      <section className="roles">
        <RoleCard
          title="Transferor"
          subtitle="Signs original instruction"
          status={
            passkeyTransferor.registered
              ? "Passkey Ready"
              : "Passkey Not Registered"
          }
          principal={transferorPrincipalId}
          detail={transferorAccount ? `${transferorAccount.accountId} · $${transferorAccount.availableBalance}` : "Loading account"}
        />
        <RoleCard
          title="Recipient"
          subtitle="Read-only balance view"
          status="Read Only"
          principal={recipientPrincipalId}
          detail={recipientAccount ? `${recipientAccount.accountId} · $${recipientAccount.availableBalance}` : "Loading account"}
        />
        <RoleCard
          title="Administrator"
          subtitle="Signs only for high-value transfers"
          status={
            passkeyAdmin.registered
              ? "Passkey Ready"
              : "Passkey Not Registered"
          }
          principal={adminPrincipalId}
          detail={requiresAdmin ? "Needed for this transfer" : "Not needed below threshold"}
        />
      </section>

      <section className="panel">
        <h2>Passkey Setup</h2>
        <div className="passkeyGrid">
          <PasskeyCard
            title="Transferor Passkey"
            principalId={transferorPrincipalId}
            state={passkeyTransferor}
            onRegister={() => void registerPasskey(transferorPrincipalId, "transferor")}
          />
          <PasskeyCard
            title="Administrator Passkey"
            principalId={adminPrincipalId}
            state={passkeyAdmin}
            onRegister={() => void registerPasskey(adminPrincipalId, "administrator")}
          />
        </div>
        <p className="hint">
          Passkeys start empty on entry. Once registered, they move straight into a ready state and
          can be used directly for transfer submission or administrator approval.
        </p>
      </section>

      <section className="panel flowTheaterPanel">
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

        <div className={`flowPolicyBanner ${policyView ? "flowPolicyBannerReady" : "flowPolicyBannerWarn"}`}>
          <div className="flowPolicyBannerCopy">
            <span>Active Governance Bundle</span>
            <strong>
              {policyView ? `${policyView.bundle.bundleId} · ${policyView.bundle.bundleVersion}` : "Policy status"}
            </strong>
            <small>{policySummary}</small>
          </div>
          <div className="flowPolicyBannerMeta flowPolicyBannerMetaCompact">
            {policyView ? (
              <>
                <div>
                  <span>Currency</span>
                  <strong>{policyView.policy.currency}</strong>
                </div>
                <div>
                  <span>Threshold</span>
                  <strong>{policyView.policy.currency} {policyView.policy.adminReviewAtOrAbove.toFixed(2)}</strong>
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
                  <strong>{policyNotice ? "Loading" : "Waiting"}</strong>
                </div>
                <div>
                  <span>Policy</span>
                  <strong>USD only</strong>
                </div>
              </>
            )}
          </div>
        </div>

        {status !== "Ready" ? (
          <div className={`flowStatusBanner statusTone-${getAppStatusTone(status, instructionSubmitBusy)}`}>
            <strong>
              {getAppStatusTone(status, instructionSubmitBusy) === "error"
                ? "Error"
                : getAppStatusTone(status, instructionSubmitBusy) === "success"
                  ? "Success"
                  : getAppStatusTone(status, instructionSubmitBusy) === "processing"
                    ? "Processing"
                    : "Status"}
            </strong>
            <span>{status}</span>
          </div>
        ) : null}

        {executionBalanceSnapshot ? (
          <ExecutionBalanceBanner snapshot={executionBalanceSnapshot} />
        ) : null}

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
            currentActionLabel={currentActionLabel}
            currentActionHint={currentActionHint}
            status={status}
            policyView={policyView}
            onOpenStage={(stageId) => setSelectedStageId(stageId)}
            onOpenInstructionComposer={openInstructionComposerGuarded}
            onNewInstruction={startNewFlowDraft}
            requiresAdmin={requiresAdmin}
            showAdminAction={requiresAdmin}
            canAdminApprove={Boolean(passkeyAdmin.registered && firstVerifierEvent?.kind === 104)}
            canExecute={canExecute}
            highlightSubmit={instructionSubmitBusy || isDraft || (!firstVerifierEvent && !envelopeEvent)}
            highlightAdmin={isWaitingForAdmin}
            highlightExecute={isReadyForExecution}
            onSubmitToVerifier={() => {
              const missingPasskeyMessage = getMissingPasskeyMessage();
              if (missingPasskeyMessage) {
                setStatus(missingPasskeyMessage);
                return;
              }
              if (!amount || !currency || !recipientAccountRef) {
                openInstructionComposerGuarded();
                return;
              }
              pulseAndRun("instruction", () => void handleEvaluate());
            }}
            onAdminApprove={() => pulseAndRun("admin", () => void handleAdminApprove())}
            onExecuteTransfer={() => pulseAndRun("execution", () => void handleExecuteTransfer())}
          />
        </div>

        <div className="flowStageLane">
          {flowStages.map((stage, index) => (
            <FlowStageCard
              key={stage.id}
              stage={stage}
              index={index}
              isLast={index === flowStages.length - 1}
              spotlight={spotlightStageId === stage.id}
              onClick={() => setSelectedStageId(stage.id)}
            />
          ))}
        </div>

        <div className="flowControlGrid">
          <div className="flowOverviewCard">
            <div className="flowOverviewTop">
              <div>
                <span className="flowOverviewLabel">Current flow</span>
                <strong>{flowId}</strong>
              </div>
              <div className={`flowStatusPill flowStatus${getStatusTone(activeVerifierEvent, executionEvent)}`}>
                {executionEvent
                  ? "Executed"
                  : rejectEvent
                    ? "Rejected"
                    : reverifyEvent
                      ? "Re-verified"
                      : firstVerifierEvent?.kind === 104
                        ? "Awaiting Admin"
                        : firstVerifierEvent?.kind === 103
                          ? "Verifier Approved"
                          : envelopeEvent
                            ? "In Verification"
                            : instructionEvent
                              ? "At Agent"
                              : "Draft"}
              </div>
            </div>
            <div className="flowOverviewHero">
              <div className="flowOverviewHeroMetric">
                <span className="flowOverviewLabel">Stage</span>
                <strong>{currentActionLabel}</strong>
              </div>
              <div className="flowOverviewHeroMetric">
                <span className="flowOverviewLabel">Path</span>
                <strong>{requiresAdmin ? "Admin approval lane" : "Auto-execution lane"}</strong>
              </div>
            </div>
            <div className="flowMiniStats">
              <FlowMiniStat label="ATP Events" value={String(events.length)} />
              <FlowMiniStat label="Archived Checkpoints" value={String(archiveRecords.length)} />
              <FlowMiniStat
                label="Agent Duration"
                value={agentTrace ? formatDurationMs(agentTrace.durationMs) : "n/a"}
              />
              <FlowMiniStat
                label="Executed Txns"
                value={String(transactions.filter((item) => item.flowId === flowId).length)}
              />
            </div>
            {rejectEvent ? (
              <div className="rejectBanner">
                <strong>Rejected</strong>
                <span>{describeVerifierStatus(rejectEvent)}</span>
              </div>
            ) : null}
            <p className="flowOverviewHint">
              Archived checkpoints count append-only governance snapshots, not duplicate rows.
              High-value flows usually archive after first verifier review, after admin reverify,
              and after MCP execution.
            </p>
          </div>
        </div>
      </section>

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
          status={status}
          transferorPrincipalId={transferorPrincipalId}
          adminPrincipalId={adminPrincipalId}
          recipientPrincipalId={recipientPrincipalId}
        />
      ) : null}

      {instructionComposerOpen ? (
        <InstructionComposerModal
          flowId={flowId}
          amount={amount}
          currency={currency}
          memo={memo}
          recipientAccountRef={recipientAccountRef}
          allowlistedRecipientAccountRef={recipientAccount?.accountId ?? ""}
          status={status}
          amountError={amountError || amountValidationMessage}
          availableBalance={transferorAvailableBalance}
          policyView={policyView}
          onClose={() => {
            setInstructionComposerOpen(false);
            setAmountError("");
          }}
          onNewInstruction={startNewFlowDraft}
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
          submitDisabled={instructionSubmitBusy}
          onSubmit={async () => {
            if (instructionSubmitBusy) {
              return;
            }
            if (amountValidationMessage) {
              setAmountError(amountValidationMessage);
              return;
            }
            setInstructionSubmitBusy(true);
            setActionPulseStageId("instruction");
            try {
              const ok = await handleEvaluate();
              if (ok) {
                setInstructionComposerOpen(false);
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

function RoleCard(props: {
  title: string;
  subtitle: string;
  status: string;
  detail: string;
  principal?: string;
}) {
  const badgeClassName = props.status === "Passkey Ready" ? "badge badgeVerified" : "badge";

  return (
    <div className="roleCard">
      <h3>{props.title}</h3>
      <p>{props.subtitle}</p>
      <div className={badgeClassName}>{props.status}</div>
      {props.principal ? (
        <div className="principalLine">
          <span>Principal</span>
          <code>{props.principal}</code>
        </div>
      ) : null}
      <small>{props.detail}</small>
    </div>
  );
}

function PasskeyCard(props: {
  title: string;
  principalId: string;
  state: PasskeyState;
  onRegister: () => void;
}) {
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
            <button onClick={props.onRegister}>Register Passkey</button>
          </div>
        </>
      )}
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
  currentActionLabel: string;
  currentActionHint: string;
  status: string;
  policyView: VerifierPolicyView | null;
  onOpenStage: (stageId: FlowStageId) => void;
  onOpenInstructionComposer: () => void;
  onNewInstruction: () => void;
  requiresAdmin: boolean;
  showAdminAction: boolean;
  canAdminApprove: boolean;
  canExecute: boolean;
  highlightSubmit: boolean;
  highlightAdmin: boolean;
  highlightExecute: boolean;
  onSubmitToVerifier: () => void;
  onAdminApprove: () => void;
  onExecuteTransfer: () => void;
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
  const hasDraftInstruction = Boolean(
    props.amount || props.currency || props.recipientAccountRef || props.memo,
  );

  return (
    <div className="relayMap">
      <div className="relayHeader">
        <div>
          <span className="flowOverviewLabel">Animated flow view</span>
          <strong>Human -&gt; Agent -&gt; Verifier -&gt; Agent -&gt; MCP</strong>
        </div>
        <div className="relayLegend">
          <span className="relayLegendItem active">Current packet</span>
          <span className="relayLegendItem branch">Conditional branch</span>
        </div>
      </div>

      <div className="relayTrack">
        <RelayNode
          stage={instruction}
          spotlight={props.spotlightStageId === instruction?.id}
          pulsing={props.actionPulseStageId === "instruction"}
          onClick={props.onOpenStage}
          actionLabel={hasDraftInstruction ? "Edit Human Instruction" : "Create Human Instruction"}
          actionTone="primary"
          actionEnabled
          actionHighlighted={props.highlightSubmit}
          onAction={props.onOpenInstructionComposer}
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
          actionLabel="Execute Transfer"
          actionTone="secondary"
          actionEnabled={props.canExecute}
          actionHighlighted={props.highlightExecute}
          onAction={props.onExecuteTransfer}
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

      <div className="relayArchiveRow">
        <span className="relayArchiveLabel">Side evidence path</span>
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
  availableBalance: number | null;
  submitDisabled: boolean;
  policyView: VerifierPolicyView | null;
  onClose: () => void;
  onNewInstruction: () => void;
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

  return (
    <div className="flowModalBackdrop" onClick={props.onClose}>
      <div className="flowModal instructionComposerModal" onClick={(event) => event.stopPropagation()}>
        <div className="flowModalHeader">
          <div>
            <span className="flowModalEyebrow">Human instruction</span>
            <h3>Create and Sign Human Instruction</h3>
            <p>Enter the transfer details here, then confirm to submit them into the verifier flow.</p>
          </div>
          <button className="flowModalClose" type="button" onClick={props.onClose}>
            Close
          </button>
          <button
            className="flowModalSecondaryAction"
            type="button"
            onClick={props.onNewInstruction}
          >
            New Instruction
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
          </label>
          <label className="flowCommandField">
            <span>Memo</span>
            <input value={props.memo} onChange={(event) => props.onMemoChange(event.target.value)} />
          </label>
        </div>

        <div className="instructionComposerFooter">
          <div className="instructionComposerMeta">
            <div className="flowBundleMeta">
              <span>Flow</span>
              <strong>{props.flowId}</strong>
            </div>
            <div className="flowBundleMeta">
              <span>Status</span>
              <strong className={`instructionComposerStatus statusTone-${getAppStatusTone(props.status, props.submitDisabled)}`}>
                {props.status}
              </strong>
            </div>
            {props.policyView ? (
              <div className="flowBundleMeta">
                <span>Policy</span>
                <strong>
                  Auto below {props.policyView.policy.currency}{" "}
                  {props.policyView.policy.autoExecuteBelow.toFixed(2)} · Admin at{" "}
                  {props.policyView.policy.adminReviewAtOrAbove.toFixed(2)} or above
                </strong>
              </div>
            ) : null}
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
                disabled={props.submitDisabled || Boolean(props.amountError)}
                onClick={() => void props.onSubmit()}
              >
                {props.submitDisabled ? "Submitting..." : "Confirm and Submit To Verifier"}
              </button>
            </div>
          </div>
        </div>
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
          <span className="relayActionLabel">
            {stage.module === "Human" ? "Human action" : stage.module === "MCP" ? "MCP action" : "Admin action"}
          </span>
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

        <div className="flowModalViewToggle">
          <button
            type="button"
            className={viewMode === "presentation" ? "secondary activeToggle" : "secondary"}
            onClick={() => setViewMode("presentation")}
          >
            Presentation View
          </button>
          <button
            type="button"
            className={viewMode === "technical" ? "secondary activeToggle" : "secondary"}
            onClick={() => setViewMode("technical")}
          >
            Technical View
          </button>
        </div>

        <div className="flowModalSignatureSummary">
          {props.stage.signatureSummary.map((item) => (
            <span key={item}>{item}</span>
          ))}
        </div>

        <div className="flowModalChecks">
          {props.stage.checks.map((item) => (
            <span key={item}>{item}</span>
          ))}
        </div>

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
    title: "Administrator Approval",
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
  return new Date(value * 1000).toISOString();
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
          "Waiting for envelope and signatures",
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
      title: "Signed Human Instruction",
      module: "Human",
      actor: "Human -> Agent",
      artifact: "Kind 101 Signed Instruction",
      kindLabel: "Kind 101",
      summary: "Transferor signs the original instruction with passkey-backed proof and submits it to the agent.",
      status: input.instructionEvent ? "done" : "current",
      statusLabel: input.instructionEvent ? "Captured" : "Waiting For Signature",
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
      title: "Agent Builds Envelope",
      module: "Agent",
      actor: "Agent",
      artifact: "Kind 102 Governance Envelope",
      kindLabel: "Kind 102",
      summary: "Agent resolves recipient, applies the fixed transfer skill, and signs the governed envelope.",
      status: input.envelopeEvent ? "done" : input.instructionEvent ? "current" : "pending",
      statusLabel: input.envelopeEvent ? "Envelope Signed" : input.instructionEvent ? "Agent Running" : "Pending",
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
      title: "Verifier Evaluates Envelope",
      module: "Verifier",
      actor: "Verifier",
      artifact:
        input.reverifyEvent?.kind === 107
          ? "Kind 107 Re-Verification"
          : input.firstVerifierEvent?.kind === 104
            ? "Kind 104 Escalation Decision"
            : input.firstVerifierEvent?.kind === 108
              ? "Kind 108 Rejection"
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
                  : "Pending",
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
      title: "Administrator Approval",
      module: "Admin Branch",
      actor: "Administrator",
      artifact: "Kind 105 Admin Approval",
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
          ? "Awaiting Admin"
          : input.requiresAdmin
            ? "Pending"
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
      title: "Agent Forwards Approved Package",
      module: "Agent",
      actor: "Agent -> MCP",
      artifact: "Verifier-Approved Execution Package",
      kindLabel: "Agent Relay",
      summary: "After verifier approval, the agent forwards the verifier-signed decision package to the MCP bank interface.",
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
          ? "Blocked"
          : verifierApproved
            ? "Ready To Forward"
            : "Pending",
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
      title: "MCP Executes Transfer",
      module: "MCP",
      actor: "MCP Bank",
      artifact: "Kind 109 Execution Event",
      kindLabel: "Kind 109",
      summary: "The bank transfer interface executes the approved payment and emits settlement evidence.",
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
          ? "Blocked"
          : verifierApproved
            ? "Ready"
            : "Pending",
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
      title: "Independent Archive",
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
      statusLabel: input.archiveRecord ? "Archived" : input.instructionEvent ? "Appending" : "Pending",
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
      return [
        {
          title: "Step Summary",
          type: "rows",
          rows: [
            { label: "What happens here", value: "Human signs the transfer instruction with passkey-backed identity proof" },
            { label: "Current status", value: stage.statusLabel },
            { label: "Transferor Principal", value: input.transferorPrincipalId },
            { label: "Recipient Principal", value: input.recipientPrincipalId },
            { label: "Primary handoff", value: "Signed Kind 101 instruction -> Agent" },
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
            { label: "Execution started", value: formatAgentTimestamp(input.agentTrace?.startedAt) },
            { label: "Execution duration", value: formatDurationMs(input.agentTrace?.durationMs) },
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
            { label: "Admin action", value: "Administrator passkey signature is attached and sent back for verifier re-check" },
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
          title: "Forwarding Package",
          type: "rows",
          rows: [
            { label: "Transferor Principal", value: input.transferorPrincipalId },
            { label: "Recipient Principal", value: input.recipientPrincipalId },
            { label: "Agent Principal", value: DEMO_PRINCIPALS.agent },
            { label: "Verifier Principal", value: DEMO_PRINCIPALS.verifier },
            { label: "Routing", value: "Agent receives verifier-approved decision and forwards execution package to MCP" },
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
          title: "Execution Gate",
          type: "rows",
          rows: [
            { label: "Transferor Principal", value: input.transferorPrincipalId },
            { label: "Recipient Principal", value: input.recipientPrincipalId },
            { label: "Agent Principal", value: DEMO_PRINCIPALS.agent },
            { label: "Verifier Principal", value: DEMO_PRINCIPALS.verifier },
            { label: "Required input", value: "Verifier-approved decision package" },
            { label: "Execution rule", value: "MCP can execute only after verifier approval or re-verification" },
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
      label: "Kind 101 Signed Instruction",
      description: "Transferor signs the original payment instruction with passkey-backed proof.",
      eventId: input.instructionEvent?.eventId,
      targetDomId: input.instructionEvent ? getEventCardDomId(input.instructionEvent.eventId) : undefined,
      status: input.instructionEvent ? "done" : "current",
      statusLabel: input.instructionEvent ? "Done" : "Waiting",
    },
    {
      label: "Kind 102 Governance Envelope",
      description: "Agent converts the human instruction into an ATP-style governed tool envelope.",
      eventId: input.envelopeEvent?.eventId,
      targetDomId: input.envelopeEvent ? getEventCardDomId(input.envelopeEvent.eventId) : undefined,
      status: input.envelopeEvent ? "done" : input.instructionEvent ? "current" : "pending",
      statusLabel: input.envelopeEvent ? "Done" : input.instructionEvent ? "Waiting" : "Pending",
    },
    {
      label: "First Verifier Decision",
      description: "Verifier evaluates policy, identity proof, recipient constraints, and risk tier.",
      eventId: input.firstVerifierEvent?.eventId,
      targetDomId: input.firstVerifierEvent
        ? getEventCardDomId(input.firstVerifierEvent.eventId)
        : undefined,
      status: input.firstVerifierEvent ? "done" : input.envelopeEvent ? "current" : "pending",
      statusLabel: input.firstVerifierEvent ? "Done" : input.envelopeEvent ? "Waiting" : "Pending",
    },
    {
      label: "Kind 105 Admin Signature",
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
          ? "Waiting"
          : "Skipped",
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
          ? "Waiting"
          : firstDecisionIsEscalate
            ? "Pending"
            : "Skipped",
    },
    {
      label: "Kind 108 Reject Branch",
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
      label: "Kind 109 Bank Execution",
      description: "MCP bank executes the approved transfer and writes the execution evidence event.",
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
          ? "Blocked"
          : input.reverifyEvent || input.firstVerifierEvent?.kind === 103
            ? "Ready"
            : "Pending",
    },
    {
      label: "Kind 106 Archive Record",
      description: "Archive service appends the current flow state into the append-only evidence chain.",
      eventId: latestArchive?.id,
      targetDomId: latestArchive ? getArchiveCardDomId(latestArchive.id) : undefined,
      status: latestArchive ? "done" : archiveReady ? "current" : "pending",
      statusLabel: latestArchive ? "Done" : archiveReady ? "Waiting" : "Pending",
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
