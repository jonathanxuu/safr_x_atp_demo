import { createServer } from "node:http";
import { URL } from "node:url";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import {
  IdentityRepository,
  createSharedDatabase,
  type IdentityPasskeyCredential,
} from "@safr-x-atp-demo/storage";
import { assertEnglishAccountHandle, assertValidIcpPrincipal } from "@safr-x-atp-demo/protocol";

const port = Number(process.env.PORT ?? 4105);
const rpName = process.env.WEBAUTHN_RP_NAME ?? "SAFR x ATP Demo";
const rpID = process.env.WEBAUTHN_RP_ID ?? "localhost";
const expectedOrigin = process.env.WEBAUTHN_ORIGIN ?? "http://localhost:4173";
const bankServiceBaseUrl = process.env.BANK_SERVICE_URL ?? "http://localhost:4104";
const repository = new IdentityRepository(createSharedDatabase());
const sessionCookieName = "safr_demo_session";
const sessionLifetimeMs = 7 * 24 * 60 * 60 * 1000;

function setCorsHeaders(response: import("node:http").ServerResponse) {
  response.setHeader("Access-Control-Allow-Origin", expectedOrigin);
  response.setHeader("Access-Control-Allow-Credentials", "true");
  response.setHeader("Access-Control-Allow-Headers", "Content-Type");
  response.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  response.setHeader("Vary", "Origin");
}

function sendJson(
  response: import("node:http").ServerResponse,
  status: number,
  body: unknown,
  extraHeaders: Record<string, string> = {},
) {
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  setCorsHeaders(response);
  for (const [key, value] of Object.entries(extraHeaders)) {
    response.setHeader(key, value);
  }
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

function getRequiredString(body: Record<string, unknown>, key: string) {
  const value = body[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Missing ${key}`);
  }
  return value;
}

function getRequiredPrincipalId(body: Record<string, unknown>, key = "principalId") {
  return assertValidIcpPrincipal(getRequiredString(body, key), key);
}

function serializeAccount(account: {
  username: string;
  transferorPrincipalId: string;
  adminPrincipalId: string;
  recipientPrincipalId: string;
}) {
  return {
    username: account.username,
    transferorPrincipalId: account.transferorPrincipalId,
    adminPrincipalId: account.adminPrincipalId,
    recipientPrincipalId: account.recipientPrincipalId,
  };
}

function serializeStatus(principalId: string) {
  const status = repository.getPrincipalPasskeyStatus(principalId);
  return {
    principalId,
    registered: status.registered,
    credentials: status.credentials.map((credential) => ({
      credentialId: credential.credentialId,
      counter: credential.counter,
      transports: credential.transports,
      deviceType: credential.deviceType,
      backedUp: credential.backedUp,
      rpId: credential.rpId,
      createdAt: credential.createdAt,
      lastUsedAt: credential.lastUsedAt,
    })),
    latestAuthenticationProof: status.latestAuthenticationProof
      ? {
          proofId: status.latestAuthenticationProof.proofId,
          createdAt: status.latestAuthenticationProof.createdAt,
          credentialId: status.latestAuthenticationProof.credentialId,
          verified: status.latestAuthenticationProof.verified,
          proofType: status.latestAuthenticationProof.proofType,
        }
      : null,
    latestVerifiedProof: status.latestVerifiedProof
      ? {
          proofId: status.latestVerifiedProof.proofId,
          createdAt: status.latestVerifiedProof.createdAt,
          credentialId: status.latestVerifiedProof.credentialId,
          verified: status.latestVerifiedProof.verified,
          proofType: status.latestVerifiedProof.proofType,
        }
      : null,
  };
}

async function bootstrapAccountSpace(account: {
  transferorPrincipalId: string;
  recipientPrincipalId: string;
}) {
  const bootstrapRequests = [
    {
      ownerId: account.transferorPrincipalId,
      ownerRole: "transferor" as const,
      currency: "USD",
    },
    {
      ownerId: account.recipientPrincipalId,
      ownerRole: "recipient" as const,
      currency: "USD",
    },
  ];

  for (const payload of bootstrapRequests) {
    const response = await fetch(`${bankServiceBaseUrl}/accounts/bootstrap`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const body = (await response.json()) as { error?: string };
      throw new Error(body.error ?? `Failed to bootstrap bank account: ${response.status}`);
    }
  }
}

function parseCookieHeader(header: string | undefined) {
  const entries = new Map<string, string>();
  if (!header) {
    return entries;
  }

  for (const part of header.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (!name) {
      continue;
    }
    entries.set(name, rest.join("="));
  }

  return entries;
}

function getSessionId(request: import("node:http").IncomingMessage) {
  return parseCookieHeader(request.headers.cookie).get(sessionCookieName);
}

function buildSessionCookie(sessionId: string, maxAgeMs = sessionLifetimeMs) {
  const maxAgeSeconds = Math.max(0, Math.floor(maxAgeMs / 1000));
  return `${sessionCookieName}=${sessionId}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}`;
}

function clearSessionCookie() {
  return `${sessionCookieName}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
}

function getActiveAccountFromRequest(request: import("node:http").IncomingMessage) {
  const sessionId = getSessionId(request);
  if (!sessionId) {
    return undefined;
  }
  return repository.getAccountBySession(sessionId);
}

function requireActiveAccount(request: import("node:http").IncomingMessage) {
  const account = getActiveAccountFromRequest(request);
  if (!account) {
    throw new Error("Authentication required");
  }
  return account;
}

function assertPrincipalForAccount(
  account: { transferorPrincipalId: string; adminPrincipalId: string },
  principalId: string,
  role: "transferor" | "administrator",
) {
  const expectedPrincipalId = role === "transferor" ? account.transferorPrincipalId : account.adminPrincipalId;
  if (expectedPrincipalId !== principalId) {
    throw new Error("Principal does not belong to the current account");
  }
}

function credentialForVerification(credential: IdentityPasskeyCredential) {
  return {
    id: credential.credentialId,
    publicKey: Uint8Array.from(Buffer.from(credential.publicKeyB64u, "base64url")),
    counter: credential.counter,
    transports: credential.transports as never,
  };
}

function toBase64Url(value: string) {
  return value.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function normalizeCredentialId(value: unknown): string | null {
  if (typeof value !== "string" || value.length === 0) {
    return null;
  }

  return toBase64Url(value);
}

function maybeDecodeNestedBase64Url(value: string): string | null {
  try {
    const pad = "=".repeat((4 - (value.length % 4)) % 4);
    const normalized = `${value}${pad}`.replace(/-/g, "+").replace(/_/g, "/");
    const decoded = Buffer.from(normalized, "base64").toString("utf-8");
    if (/^[A-Za-z0-9_-]+$/.test(decoded)) {
      return decoded;
    }
    return null;
  } catch {
    return null;
  }
}

function encodeCredentialIdForLegacyLookup(value: string): string {
  return Buffer.from(value, "utf-8").toString("base64url");
}

function resolveCredentialFromAuthenticationResponse(
  repository: IdentityRepository,
  principalId: string,
  response: Record<string, unknown>,
) {
  const candidates = [
    normalizeCredentialId(response.id),
    normalizeCredentialId(response.rawId),
  ].filter((value): value is string => Boolean(value));

  for (const candidate of candidates) {
    const repositoryCandidates = [candidate, encodeCredentialIdForLegacyLookup(candidate)];
    const nested = maybeDecodeNestedBase64Url(candidate);
    if (nested && nested !== candidate) {
      repositoryCandidates.push(nested);
    }

    for (const repositoryCandidate of repositoryCandidates) {
      const credential = repository.getCredential(repositoryCandidate);
      if (credential) {
        return {
          credential,
          matchedCredentialId: repositoryCandidate,
          candidates,
        };
      }
    }
  }

  return {
    credential: undefined,
    matchedCredentialId: null,
    candidates,
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
    setCorsHeaders(response);
    response.end();
    return;
  }

  if (request.method === "GET" && url.pathname === "/health") {
    sendJson(response, 200, {
      ok: true,
      service: "identity-service",
      rpName,
      rpID,
      expectedOrigin,
    });
    return;
  }

  if (request.method === "POST" && url.pathname === "/auth/register") {
    try {
      const body = await readJson(request);
      const username = assertEnglishAccountHandle(getRequiredString(body, "username"));
      const password = getRequiredString(body, "password");
      const account = repository.createAuthAccount({ username, password });
      await bootstrapAccountSpace(account);
      const session = repository.createSession(account.username, sessionLifetimeMs / (60 * 1000));
      sendJson(
        response,
        200,
        {
          ok: true,
          account: serializeAccount(account),
        },
        {
          "Set-Cookie": buildSessionCookie(session.sessionId),
        },
      );
    } catch (error) {
      sendJson(response, 400, {
        error: error instanceof Error ? error.message : "Failed to register account",
      });
    }
    return;
  }

  if (request.method === "POST" && url.pathname === "/auth/login") {
    try {
      const body = await readJson(request);
      const username = assertEnglishAccountHandle(getRequiredString(body, "username"));
      const password = getRequiredString(body, "password");
      const account = repository.verifyAuthAccount(username, password);
      if (!account) {
        throw new Error("Invalid username or password");
      }
      await bootstrapAccountSpace(account);
      const session = repository.createSession(account.username, sessionLifetimeMs / (60 * 1000));
      sendJson(
        response,
        200,
        {
          ok: true,
          account: serializeAccount(account),
        },
        {
          "Set-Cookie": buildSessionCookie(session.sessionId),
        },
      );
    } catch (error) {
      sendJson(response, 400, {
        error: error instanceof Error ? error.message : "Failed to log in",
      });
    }
    return;
  }

  if (request.method === "GET" && url.pathname === "/auth/me") {
    const account = getActiveAccountFromRequest(request);
    if (!account) {
      sendJson(response, 200, { authenticated: false, account: null });
      return;
    }

    const sessionId = getSessionId(request);
    if (sessionId) {
      repository.touchSession(sessionId);
    }

    sendJson(response, 200, {
      authenticated: true,
      account: serializeAccount(account),
    });
    return;
  }

  if (request.method === "POST" && url.pathname === "/auth/logout") {
    const sessionId = getSessionId(request);
    if (sessionId) {
      repository.revokeSession(sessionId);
    }
    sendJson(
      response,
      200,
      { ok: true },
      {
        "Set-Cookie": clearSessionCookie(),
      },
    );
    return;
  }

  if (request.method === "GET" && url.pathname.startsWith("/principals/") && url.pathname.endsWith("/passkey-status")) {
    try {
      requireActiveAccount(request);
      const principalId = assertValidIcpPrincipal(
        url.pathname.replace("/principals/", "").replace("/passkey-status", ""),
        "principalId",
      );
      sendJson(response, 200, serializeStatus(principalId));
    } catch (error) {
      sendJson(response, 400, {
        error: error instanceof Error ? error.message : "Failed to load passkey status",
      });
    }
    return;
  }

  if (request.method === "POST" && url.pathname === "/webauthn/register/options") {
    try {
      const body = await readJson(request);
      const principalId = getRequiredPrincipalId(body);
      const role = getRequiredString(body, "role");
      const account = requireActiveAccount(request);
      assertPrincipalForAccount(account, principalId, role === "transferor" ? "transferor" : "administrator");
      const principal = repository.getPrincipal(principalId);
      if (!principal) {
        throw new Error("Principal not found for current account");
      }
      const existingCredentials = repository.listCredentials(principalId);

      const options = await generateRegistrationOptions({
        rpName,
        rpID,
        userName: principal.username,
        userDisplayName: principal.displayName,
        userID: Uint8Array.from(Buffer.from(principal.webauthnUserId, "utf-8")),
        attestationType: "none",
        authenticatorSelection: {
          residentKey: "required",
          userVerification: "required",
        },
        excludeCredentials: existingCredentials.map((credential) => ({
          id: credential.credentialId,
          transports: credential.transports as never,
        })),
      });

      repository.createChallenge({
        principalId,
        flowType: "registration",
        challenge: options.challenge,
        rpId: rpID,
        origin: expectedOrigin,
        expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      });

      sendJson(response, 200, { options });
    } catch (error) {
      sendJson(response, 400, {
        error: error instanceof Error ? error.message : "Failed to generate registration options",
      });
    }
    return;
  }

  if (request.method === "POST" && url.pathname === "/webauthn/register/verify") {
    try {
      const body = await readJson(request);
      const principalId = getRequiredPrincipalId(body);
      const role = getRequiredString(body, "role");
      const account = requireActiveAccount(request);
      assertPrincipalForAccount(account, principalId, role === "transferor" ? "transferor" : "administrator");
      const webauthnResponse = body.response;
      const challenge = repository.getLatestActiveChallenge(principalId, "registration");
      if (!challenge) {
        throw new Error("No active registration challenge");
      }

      const verification = await verifyRegistrationResponse({
        response: webauthnResponse as never,
        expectedChallenge: challenge.challenge,
        expectedOrigin,
        expectedRPID: rpID,
        requireUserVerification: true,
      });

      if (!verification.verified || !verification.registrationInfo) {
        throw new Error("Registration verification failed");
      }

      const rawCredentialId = verification.registrationInfo.credential.id;
      const credentialId =
        typeof rawCredentialId === "string"
          ? rawCredentialId
          : Buffer.from(rawCredentialId).toString("base64url");
      repository.saveCredential({
        credentialId,
        principalId,
        publicKeyB64u: Buffer.from(verification.registrationInfo.credential.publicKey).toString("base64url"),
        counter: verification.registrationInfo.credential.counter,
        transports: (verification.registrationInfo.credential.transports ?? []) as string[],
        deviceType: verification.registrationInfo.credentialDeviceType,
        backedUp: verification.registrationInfo.credentialBackedUp,
        rpId: rpID,
        createdAt: new Date().toISOString(),
        lastUsedAt: new Date().toISOString(),
      });

      repository.consumeChallenge(challenge.challengeId);
      const proof = repository.saveVerificationProof({
        principalId,
        role,
        credentialId,
        challengeId: challenge.challengeId,
        proofType: "registration",
        verified: true,
        origin: expectedOrigin,
        rpId: rpID,
        signCount: verification.registrationInfo.credential.counter,
        payloadJson: JSON.stringify(webauthnResponse),
      });

      sendJson(response, 200, {
        verified: true,
        proofId: proof.proofId,
        credentialId,
        status: serializeStatus(principalId),
      });
    } catch (error) {
      sendJson(response, 400, {
        error: error instanceof Error ? error.message : "Failed to verify registration response",
      });
    }
    return;
  }

  if (request.method === "POST" && url.pathname === "/webauthn/authenticate/options") {
    try {
      const body = await readJson(request);
      const principalId = getRequiredPrincipalId(body);
      const role = getRequiredString(body, "role");
      const account = requireActiveAccount(request);
      assertPrincipalForAccount(account, principalId, role === "transferor" ? "transferor" : "administrator");
      const credentials = repository.listCredentials(principalId);
      if (credentials.length === 0) {
        throw new Error("No registered passkey found for principal");
      }
      const activeCredential = credentials[credentials.length - 1];

      const options = await generateAuthenticationOptions({
        rpID,
        allowCredentials: [
          {
            id: activeCredential.credentialId,
          },
        ],
        userVerification: "required",
      });

      repository.createChallenge({
        principalId,
        flowType: "authentication",
        challenge: options.challenge,
        rpId: rpID,
        origin: expectedOrigin,
        expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      });

      sendJson(response, 200, { options });
    } catch (error) {
      sendJson(response, 400, {
        error: error instanceof Error ? error.message : "Failed to generate authentication options",
      });
    }
    return;
  }

  if (request.method === "POST" && url.pathname === "/webauthn/authenticate/verify") {
    try {
      const body = await readJson(request);
      const principalId = getRequiredPrincipalId(body);
      const role = getRequiredString(body, "role");
      const account = requireActiveAccount(request);
      assertPrincipalForAccount(account, principalId, role === "transferor" ? "transferor" : "administrator");
      const webauthnResponse = body.response as Record<string, unknown>;
      const challenge = repository.getLatestActiveChallenge(principalId, "authentication");
      if (!challenge) {
        throw new Error("No active authentication challenge");
      }

      const resolved = resolveCredentialFromAuthenticationResponse(repository, principalId, webauthnResponse);
      const credential = resolved.credential;
      if (!credential) {
        const knownCredentialIds = repository.listCredentials(principalId).map((item) => item.credentialId);
        throw new Error(
          `Credential not found. responseCandidates=${resolved.candidates.join(",") || "none"} knownCredentials=${knownCredentialIds.join(",") || "none"}`,
        );
      }
      if (credential.principalId !== principalId) {
        throw new Error("Credential does not belong to the requested principal");
      }

      const verification = await verifyAuthenticationResponse({
        response: body.response as never,
        expectedChallenge: challenge.challenge,
        expectedOrigin,
        expectedRPID: rpID,
        credential: credentialForVerification(credential),
        requireUserVerification: true,
      });

      if (!verification.verified) {
        throw new Error("Authentication verification failed");
      }

      repository.updateCredentialCounter(credential.credentialId, verification.authenticationInfo.newCounter);
      repository.consumeChallenge(challenge.challengeId);
      const proof = repository.saveVerificationProof({
        principalId,
        role,
        credentialId: credential.credentialId,
        challengeId: challenge.challengeId,
        proofType: "authentication",
        verified: true,
        origin: expectedOrigin,
        rpId: rpID,
        signCount: verification.authenticationInfo.newCounter,
        payloadJson: JSON.stringify(body.response),
      });

      sendJson(response, 200, {
        verified: true,
        proofId: proof.proofId,
        credentialId: credential.credentialId,
        status: serializeStatus(principalId),
      });
    } catch (error) {
      sendJson(response, 400, {
        error: error instanceof Error ? error.message : "Failed to verify authentication response",
      });
    }
    return;
  }

  if (request.method === "POST" && url.pathname === "/proofs/validate") {
    try {
      const body = await readJson(request);
      const proofId = getRequiredString(body, "proofId");
      const principalId = getRequiredPrincipalId(body);
      const role = getRequiredString(body, "role");
      const proofType = typeof body.proofType === "string" && body.proofType.length > 0 ? body.proofType : null;
      const proof = repository.getVerificationProof(proofId);
      if (!proof) {
        throw new Error("Proof not found");
      }
      if (!proof.verified) {
        throw new Error("Proof is not verified");
      }
      if (proof.principalId !== principalId || proof.role !== role) {
        throw new Error("Proof does not match principal or role");
      }
      if (proofType && proof.proofType !== proofType) {
        throw new Error("Proof does not match proof type");
      }

      sendJson(response, 200, {
        valid: true,
        proof: {
          proofId: proof.proofId,
          principalId: proof.principalId,
          role: proof.role,
          credentialId: proof.credentialId,
          proofType: proof.proofType,
          createdAt: proof.createdAt,
          signCount: proof.signCount,
        },
      });
    } catch (error) {
      sendJson(response, 400, {
        error: error instanceof Error ? error.message : "Failed to validate proof",
      });
    }
    return;
  }

  if (request.method === "POST" && url.pathname === "/admin/reset-demo") {
    try {
      repository.clearIdentityData();
      sendJson(response, 200, { ok: true, service: "identity-service", reset: "identity_cleared" });
    } catch (error) {
      sendJson(response, 400, {
        error: error instanceof Error ? error.message : "Failed to clear identity data",
      });
    }
    return;
  }

  sendJson(response, 404, { error: "Not found" });
});

server.listen(port, () => {
  console.log(`identity-service listening on http://localhost:${port}`);
});
