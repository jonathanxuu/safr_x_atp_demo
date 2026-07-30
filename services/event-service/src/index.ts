import { createServer } from "node:http";
import { URL } from "node:url";
import { type EventRecord } from "@safr-x-atp-demo/protocol";
import { createSharedDatabase } from "@safr-x-atp-demo/storage";
import { InMemoryEventStore, normalizeCreateEventPayload } from "./store.js";

const port = Number(process.env.PORT ?? 4101);
const store = new InMemoryEventStore(createSharedDatabase());

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

function serializeRecord(record: EventRecord) {
  return {
    eventId: record.eventId,
    flowId: record.flowId,
    kind: record.kind,
    aiId: record.aiId,
    createdAt: record.createdAt,
    instructionRef: record.instructionRef,
    envelopeRef: record.envelopeRef,
    payload: record.payload,
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
    sendJson(response, 200, { ok: true, service: "event-service" });
    return;
  }

  if (request.method === "POST" && url.pathname === "/events") {
    try {
      const body = await readJson(request);
      const normalized = normalizeCreateEventPayload(body);
      const record = store.create(normalized);
      sendJson(response, 201, { event: serializeRecord(record) });
    } catch (error) {
      sendJson(response, 400, {
        error: error instanceof Error ? error.message : "Failed to create event",
      });
    }
    return;
  }

  if (request.method === "POST" && url.pathname === "/admin/reset-demo") {
    try {
      store.reset();
      sendJson(response, 200, { ok: true, service: "event-service", reset: "events_cleared" });
    } catch (error) {
      sendJson(response, 400, {
        error: error instanceof Error ? error.message : "Failed to reset event data",
      });
    }
    return;
  }

  if (request.method === "GET" && url.pathname === "/events") {
    const flowId = url.searchParams.get("flowId") ?? undefined;
    const kindParam = url.searchParams.get("kind");
    const kind = kindParam ? Number(kindParam) : undefined;
    const events = store.list({ flowId, kind });
    sendJson(response, 200, { events: events.map(serializeRecord) });
    return;
  }

  if (request.method === "GET" && url.pathname.startsWith("/events/")) {
    const eventId = url.pathname.replace("/events/", "");
    const record = store.get(eventId);
    if (!record) {
      sendJson(response, 404, { error: "Event not found" });
      return;
    }
    sendJson(response, 200, { event: serializeRecord(record) });
    return;
  }

  if (request.method === "GET" && url.pathname.startsWith("/flows/") && url.pathname.endsWith("/events")) {
    const flowId = url.pathname.replace("/flows/", "").replace("/events", "");
    const events = store.list({ flowId });
    sendJson(response, 200, { flowId, events: events.map(serializeRecord) });
    return;
  }

  sendJson(response, 404, { error: "Not found" });
});

server.listen(port, () => {
  console.log(`event-service listening on http://localhost:${port}`);
});
