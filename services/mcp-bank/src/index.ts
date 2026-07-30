import { createServer } from "node:http";
import { URL } from "node:url";
import { type BaseEventEnvelope } from "@safr-x-atp-demo/protocol";
import { createSharedDatabase } from "@safr-x-atp-demo/storage";
import { InMemoryBankStore } from "./store.js";

const port = Number(process.env.PORT ?? 4104);
const eventServiceBaseUrl = process.env.EVENT_SERVICE_URL ?? "http://localhost:4101";
const archiveServiceBaseUrl = process.env.ARCHIVE_SERVICE_URL ?? "http://localhost:4102";
const bankStore = new InMemoryBankStore(createSharedDatabase());

interface EventServiceRecord {
  eventId: string;
  flowId: string;
  kind: number;
  aiId: string;
  createdAt: number;
  payload: BaseEventEnvelope<Record<string, unknown>>;
}

interface TransferTransaction {
  transactionId: string;
  flowId: string;
  verifierEventId: string;
  status: "executed";
  fromAccountId: string;
  toAccountId: string;
  amount: number;
  currency: string;
  createdAt: string;
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

async function fetchVerifierEvent(eventId: string): Promise<EventServiceRecord> {
  const response = await fetch(`${eventServiceBaseUrl}/events/${eventId}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch verifier event: ${response.status}`);
  }
  const body = (await response.json()) as { event: EventServiceRecord };
  return body.event;
}

async function listExecutionEvents(flowId: string): Promise<EventServiceRecord[]> {
  const response = await fetch(`${eventServiceBaseUrl}/events?flowId=${flowId}&kind=109`);
  if (!response.ok) {
    throw new Error(`Failed to list execution events: ${response.status}`);
  }
  const body = (await response.json()) as { events?: EventServiceRecord[] };
  return body.events ?? [];
}

async function writeExecutionEvent(flowId: string, payload: BaseEventEnvelope<Record<string, unknown>>) {
  const response = await fetch(`${eventServiceBaseUrl}/events`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      flowId,
      payload,
      instructionRef:
        typeof payload.content.instruction_ref === "string" ? payload.content.instruction_ref : undefined,
      envelopeRef:
        typeof payload.content.envelope_ref === "string" ? payload.content.envelope_ref : undefined,
    }),
  });

  if (!response.ok) {
    const body = (await response.json()) as { error?: string };
    throw new Error(body.error ?? `Failed to persist execution event: ${response.status}`);
  }

  return (await response.json()) as { event: EventServiceRecord };
}

async function triggerArchive(flowId: string) {
  const response = await fetch(`${archiveServiceBaseUrl}/archive`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ flowId }),
  });

  if (!response.ok) {
    const body = (await response.json()) as { error?: string };
    throw new Error(body.error ?? `Failed to archive flow: ${response.status}`);
  }

  return (await response.json()) as { archive: Record<string, unknown> };
}

function isExecutableVerifierDecision(record: EventServiceRecord): boolean {
  if (record.kind !== 103 && record.kind !== 107) {
    return false;
  }
  const decision = record.payload.content.decision;
  return (
    decision === "approved_auto_execute" ||
    decision === "approved_after_admin_signature"
  );
}

function createExecutionEventPayload(input: {
  flowId: string;
  verifierRecord: EventServiceRecord;
  transaction: TransferTransaction;
  fromAvailableBalance: number;
  toAvailableBalance: number;
}): BaseEventEnvelope<Record<string, unknown>> {
  const content = input.verifierRecord.payload.content;

  return {
    id: `evt_exec_${input.transaction.transactionId}_hash`,
    kind: 109,
    ai_id: "mcp_bank_demo_01",
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ["flow_id", input.flowId],
      ["source", "mcp-bank"],
      ["status", "executed"],
    ],
    content: {
      execution_id: `exec_${input.transaction.transactionId}`,
      verifier_decision_ref: input.verifierRecord.eventId,
      instruction_ref:
        typeof content.instruction_ref === "string" ? content.instruction_ref : "",
      envelope_ref:
        typeof content.envelope_ref === "string" ? content.envelope_ref : "",
      transaction_id: input.transaction.transactionId,
      execution_status: input.transaction.status,
      executed_at: input.transaction.createdAt,
      settlement: {
        from_account_id: input.transaction.fromAccountId,
        to_account_id: input.transaction.toAccountId,
        amount: input.transaction.amount.toFixed(2),
        currency: input.transaction.currency,
      },
      resulting_balances: {
        from_account_available_balance: input.fromAvailableBalance.toFixed(2),
        to_account_available_balance: input.toAvailableBalance.toFixed(2),
      },
      execution_attestation: {
        execution_engine: "mcp-bank",
        execution_sig: `mcp_bank_sig_${input.transaction.transactionId}`,
        execution_sig_alg: "ed25519",
      },
      next_step: "archive_execution_and_expose_balance_update",
    },
  };
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
      service: "mcp-bank",
      eventServiceBaseUrl,
      archiveServiceBaseUrl,
    });
    return;
  }

  if (request.method === "GET" && url.pathname === "/accounts") {
    sendJson(response, 200, { accounts: bankStore.listAccounts() });
    return;
  }

  if (request.method === "GET" && url.pathname.startsWith("/accounts/")) {
    const accountId = url.pathname.replace("/accounts/", "");
    const account = bankStore.getAccount(accountId);
    if (!account) {
      sendJson(response, 404, { error: "Account not found" });
      return;
    }
    sendJson(response, 200, { account });
    return;
  }

  if (request.method === "GET" && url.pathname === "/transactions") {
    sendJson(response, 200, { transactions: bankStore.listTransactions() });
    return;
  }

  if (request.method === "POST" && url.pathname === "/admin/reset-demo") {
    try {
      bankStore.reset();
      sendJson(response, 200, { ok: true, service: "mcp-bank", reset: "bank_state_reset" });
    } catch (error) {
      sendJson(response, 400, {
        error: error instanceof Error ? error.message : "Failed to reset bank state",
      });
    }
    return;
  }

  if (request.method === "POST" && url.pathname === "/transfers/execute") {
    try {
      const body = await readJson(request);
      const flowId = typeof body.flowId === "string" ? body.flowId : "";
      const verifierEventId = typeof body.verifierEventId === "string" ? body.verifierEventId : "";
      const fromAccountId = typeof body.fromAccountId === "string" ? body.fromAccountId : "";
      const toAccountId = typeof body.toAccountId === "string" ? body.toAccountId : "";
      const currency = typeof body.currency === "string" ? body.currency : "";
      const amount = Number(body.amount);

      if (!flowId || !verifierEventId || !fromAccountId || !toAccountId || !currency || !amount) {
        throw new Error("Missing transfer execution fields");
      }

      const verifierRecord = await fetchVerifierEvent(verifierEventId);
      if (!isExecutableVerifierDecision(verifierRecord)) {
        throw new Error("Verifier decision is not executable");
      }

      let transaction = bankStore.getTransactionByVerifierEventId(verifierEventId);
      let alreadyExecuted = true;

      if (!transaction) {
        alreadyExecuted = false;
        transaction = bankStore.executeTransfer({
          flowId,
          verifierEventId,
          fromAccountId,
          toAccountId,
          amount,
          currency,
        });
      }

      const executionEvents = await listExecutionEvents(flowId);
      let executionEvent =
        executionEvents.find(
          (event) => event.payload.content.transaction_id === transaction.transactionId,
        ) ?? null;

      if (!executionEvent) {
        const fromAccount = bankStore.getAccount(transaction.fromAccountId);
        const toAccount = bankStore.getAccount(transaction.toAccountId);
        if (!fromAccount || !toAccount) {
          throw new Error("Failed to load post-transfer balances");
        }

        const persisted = await writeExecutionEvent(
          flowId,
          createExecutionEventPayload({
            flowId,
            verifierRecord,
            transaction,
            fromAvailableBalance: fromAccount.availableBalance,
            toAvailableBalance: toAccount.availableBalance,
          }),
        );
        executionEvent = persisted.event;
      }

      const archive = await triggerArchive(flowId);

      sendJson(response, alreadyExecuted ? 200 : 201, {
        transaction,
        executionEvent,
        archive: archive.archive,
        alreadyExecuted,
      });
    } catch (error) {
      sendJson(response, 400, {
        error: error instanceof Error ? error.message : "Failed to execute transfer",
      });
    }
    return;
  }

  sendJson(response, 404, { error: "Not found" });
});

server.listen(port, () => {
  console.log(`mcp-bank listening on http://localhost:${port}`);
});
