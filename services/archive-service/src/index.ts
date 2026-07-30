import { createServer } from "node:http";
import { URL } from "node:url";
import { createSharedDatabase } from "@safr-x-atp-demo/storage";
import { InMemoryArchiveStore, mapEventRole, type EventServiceRecord } from "./store.js";

const port = Number(process.env.PORT ?? 4102);
const eventServiceBaseUrl = process.env.EVENT_SERVICE_URL ?? "http://localhost:4101";
const store = new InMemoryArchiveStore(createSharedDatabase());

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

async function fetchFlowEvents(flowId: string): Promise<EventServiceRecord[]> {
  const response = await fetch(`${eventServiceBaseUrl}/flows/${flowId}/events`);
  if (!response.ok) {
    throw new Error(`Failed to fetch flow events: ${response.status}`);
  }
  const body = (await response.json()) as { events?: EventServiceRecord[] };
  return body.events ?? [];
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
      service: "archive-service",
      eventServiceBaseUrl,
    });
    return;
  }

  if (request.method === "POST" && url.pathname === "/archive") {
    try {
      const body = await readJson(request);
      const flowId = typeof body.flowId === "string" ? body.flowId : undefined;
      if (!flowId) {
        throw new Error("Missing flowId");
      }

      const events = await fetchFlowEvents(flowId);
      if (events.length === 0) {
        throw new Error(`No events found for flowId: ${flowId}`);
      }

      const archivedEntities = events.map((event) => ({
        event_ref: event.eventId,
        event_kind: event.kind,
        event_role: mapEventRole(event.kind),
      }));

      const record = store.append(flowId, archivedEntities);
      sendJson(response, 201, { archive: record });
    } catch (error) {
      sendJson(response, 400, {
        error: error instanceof Error ? error.message : "Failed to archive flow",
      });
    }
    return;
  }

  if (request.method === "POST" && url.pathname === "/admin/reset-demo") {
    try {
      store.reset();
      sendJson(response, 200, {
        ok: true,
        service: "archive-service",
        reset: "archive_cleared",
      });
    } catch (error) {
      sendJson(response, 400, {
        error: error instanceof Error ? error.message : "Failed to reset archive data",
      });
    }
    return;
  }

  if (request.method === "GET" && url.pathname.startsWith("/archive/flows/")) {
    const flowId = url.pathname.replace("/archive/flows/", "");
    sendJson(response, 200, { flowId, records: store.getByFlow(flowId) });
    return;
  }

  if (request.method === "GET" && url.pathname.startsWith("/archive/records/")) {
    const archiveId = url.pathname.replace("/archive/records/", "");
    const record = store.getById(archiveId);
    if (!record) {
      sendJson(response, 404, { error: "Archive record not found" });
      return;
    }
    sendJson(response, 200, { archive: record });
    return;
  }

  sendJson(response, 404, { error: "Not found" });
});

server.listen(port, () => {
  console.log(`archive-service listening on http://localhost:${port}`);
});
