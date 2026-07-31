import { randomBytes, randomUUID, scryptSync, timingSafeEqual } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import {
  assertEnglishAccountHandle,
  createAccountScopedPrincipal,
  normalizeAccountHandle,
} from "@safr-x-atp-demo/protocol";

export interface IdentityPrincipal {
  principalId: string;
  role: string;
  username: string;
  displayName: string;
  webauthnUserId: string;
  createdAt: string;
  updatedAt: string;
}

export interface IdentityPasskeyCredential {
  credentialId: string;
  principalId: string;
  publicKeyB64u: string;
  counter: number;
  transports: string[];
  deviceType: string;
  backedUp: boolean;
  rpId: string;
  createdAt: string;
  lastUsedAt: string;
}

export interface IdentityChallenge {
  challengeId: string;
  principalId: string;
  flowType: "registration" | "authentication";
  challenge: string;
  rpId: string;
  origin: string;
  expiresAt: string;
  usedAt?: string;
  createdAt: string;
}

export interface IdentityVerificationProof {
  proofId: string;
  principalId: string;
  role: string;
  credentialId: string;
  challengeId?: string;
  proofType: "registration" | "authentication";
  verified: boolean;
  origin: string;
  rpId: string;
  signCount: number;
  createdAt: string;
  payloadJson: string;
}

export interface AuthAccount {
  username: string;
  passwordSalt: string;
  passwordHash: string;
  transferorPrincipalId: string;
  adminPrincipalId: string;
  recipientPrincipalId: string;
  createdAt: string;
  updatedAt: string;
}

export interface AuthSession {
  sessionId: string;
  username: string;
  createdAt: string;
  expiresAt: string;
  lastSeenAt: string;
  revokedAt?: string;
}

export class IdentityRepository {
  constructor(private readonly db: DatabaseSync) {}

  createAuthAccount(input: { username: string; password: string }): AuthAccount {
    const username = assertEnglishAccountHandle(input.username);
    const existing = this.getAuthAccount(username);
    if (existing) {
      throw new Error("Username already exists");
    }

    const salt = randomBytes(16).toString("base64url");
    const passwordHash = hashPassword(input.password, salt);
    const now = new Date().toISOString();
    const account: AuthAccount = {
      username,
      passwordSalt: salt,
      passwordHash,
      transferorPrincipalId: createAccountScopedPrincipal(username, "transferor"),
      adminPrincipalId: createAccountScopedPrincipal(username, "admin"),
      recipientPrincipalId: createAccountScopedPrincipal(username, "recipient"),
      createdAt: now,
      updatedAt: now,
    };

    this.db.prepare(`
      INSERT INTO auth_accounts (
        username, password_salt, password_hash,
        transferor_principal_id, admin_principal_id,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      account.username,
      account.passwordSalt,
      account.passwordHash,
      account.transferorPrincipalId,
      account.adminPrincipalId,
      account.createdAt,
      account.updatedAt,
    );

    this.ensurePrincipal({
      principalId: account.transferorPrincipalId,
      role: "transferor",
      username: `${username}.transferor`,
      displayName: `${username} Transferor`,
    });
    this.ensurePrincipal({
      principalId: account.adminPrincipalId,
      role: "administrator",
      username: `${username}.admin`,
      displayName: `${username} Administrator`,
    });
    this.ensurePrincipal({
      principalId: account.recipientPrincipalId,
      role: "recipient",
      username: `${username}.recipient`,
      displayName: `${username} Recipient`,
    });

    return account;
  }

  getAuthAccount(username: string): AuthAccount | undefined {
    const normalized = normalizeAccountHandle(username);
    const row = this.db.prepare(`
      SELECT username, password_salt, password_hash,
             transferor_principal_id, admin_principal_id,
             created_at, updated_at
      FROM auth_accounts
      WHERE username = ?
    `).get(normalized) as AuthAccountRow | undefined;

    return row ? mapAuthAccountRow(row) : undefined;
  }

  verifyAuthAccount(username: string, password: string): AuthAccount | undefined {
    const account = this.getAuthAccount(username);
    if (!account) {
      return undefined;
    }

    const candidate = hashPassword(password, account.passwordSalt);
    const current = Buffer.from(account.passwordHash, "base64url");
    const next = Buffer.from(candidate, "base64url");
    if (current.length !== next.length || !timingSafeEqual(current, next)) {
      return undefined;
    }

    return account;
  }

  createSession(username: string, ttlMinutes = 24 * 7): AuthSession {
    const now = new Date();
    const session: AuthSession = {
      sessionId: `sess_${randomUUID()}`,
      username: normalizeAccountHandle(username),
      createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + ttlMinutes * 60 * 1000).toISOString(),
      lastSeenAt: now.toISOString(),
    };

    this.db.prepare(`
      INSERT INTO auth_sessions (
        session_id, username, created_at, expires_at, last_seen_at, revoked_at
      ) VALUES (?, ?, ?, ?, ?, NULL)
    `).run(
      session.sessionId,
      session.username,
      session.createdAt,
      session.expiresAt,
      session.lastSeenAt,
    );

    return session;
  }

  getSession(sessionId: string): AuthSession | undefined {
    const row = this.db.prepare(`
      SELECT session_id, username, created_at, expires_at, last_seen_at, revoked_at
      FROM auth_sessions
      WHERE session_id = ?
    `).get(sessionId) as AuthSessionRow | undefined;

    if (!row) {
      return undefined;
    }

    return mapAuthSessionRow(row);
  }

  getActiveSession(sessionId: string): AuthSession | undefined {
    const session = this.getSession(sessionId);
    if (!session || session.revokedAt) {
      return undefined;
    }
    const expiresAt = new Date(session.expiresAt).getTime();
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
      return undefined;
    }
    return session;
  }

  revokeSession(sessionId: string) {
    this.db.prepare(`
      UPDATE auth_sessions
      SET revoked_at = ?
      WHERE session_id = ?
    `).run(new Date().toISOString(), sessionId);
  }

  touchSession(sessionId: string) {
    this.db.prepare(`
      UPDATE auth_sessions
      SET last_seen_at = ?
      WHERE session_id = ?
    `).run(new Date().toISOString(), sessionId);
  }

  getAccountBySession(sessionId: string): AuthAccount | undefined {
    const session = this.getActiveSession(sessionId);
    if (!session) {
      return undefined;
    }
    return this.getAuthAccount(session.username);
  }

  ensurePrincipal(input: {
    principalId: string;
    role: string;
    username: string;
    displayName: string;
  }): IdentityPrincipal {
    const existing = this.getPrincipal(input.principalId);
    if (existing) {
      return existing;
    }

    const now = new Date().toISOString();
    const principal: IdentityPrincipal = {
      principalId: input.principalId,
      role: input.role,
      username: input.username,
      displayName: input.displayName,
      webauthnUserId: randomUUID(),
      createdAt: now,
      updatedAt: now,
    };

    this.db.prepare(`
      INSERT INTO identity_principals (
        principal_id, role, username, display_name, webauthn_user_id, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      principal.principalId,
      principal.role,
      principal.username,
      principal.displayName,
      principal.webauthnUserId,
      principal.createdAt,
      principal.updatedAt,
    );

    return principal;
  }

  getPrincipal(principalId: string): IdentityPrincipal | undefined {
    const row = this.db.prepare(`
      SELECT principal_id, role, username, display_name, webauthn_user_id, created_at, updated_at
      FROM identity_principals
      WHERE principal_id = ?
    `).get(principalId) as PrincipalRow | undefined;

    return row ? mapPrincipalRow(row) : undefined;
  }

  listCredentials(principalId: string): IdentityPasskeyCredential[] {
    const rows = this.db.prepare(`
      SELECT credential_id, principal_id, public_key_b64u, counter, transports_json,
             device_type, backed_up, rp_id, created_at, last_used_at
      FROM identity_passkey_credentials
      WHERE principal_id = ?
      ORDER BY created_at ASC
    `).all(principalId) as CredentialRow[];

    return rows.map(mapCredentialRow);
  }

  getCredential(credentialId: string): IdentityPasskeyCredential | undefined {
    const row = this.db.prepare(`
      SELECT credential_id, principal_id, public_key_b64u, counter, transports_json,
             device_type, backed_up, rp_id, created_at, last_used_at
      FROM identity_passkey_credentials
      WHERE credential_id = ?
    `).get(credentialId) as CredentialRow | undefined;

    return row ? mapCredentialRow(row) : undefined;
  }

  saveCredential(input: IdentityPasskeyCredential) {
    this.db.prepare(`
      INSERT INTO identity_passkey_credentials (
        credential_id, principal_id, public_key_b64u, counter, transports_json,
        device_type, backed_up, rp_id, created_at, last_used_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      input.credentialId,
      input.principalId,
      input.publicKeyB64u,
      input.counter,
      JSON.stringify(input.transports),
      input.deviceType,
      input.backedUp ? 1 : 0,
      input.rpId,
      input.createdAt,
      input.lastUsedAt,
    );
  }

  updateCredentialCounter(credentialId: string, counter: number) {
    this.db.prepare(`
      UPDATE identity_passkey_credentials
      SET counter = ?, last_used_at = ?
      WHERE credential_id = ?
    `).run(counter, new Date().toISOString(), credentialId);
  }

  createChallenge(input: {
    principalId: string;
    flowType: "registration" | "authentication";
    challenge: string;
    rpId: string;
    origin: string;
    expiresAt: string;
  }): IdentityChallenge {
    const challenge: IdentityChallenge = {
      challengeId: randomUUID(),
      principalId: input.principalId,
      flowType: input.flowType,
      challenge: input.challenge,
      rpId: input.rpId,
      origin: input.origin,
      expiresAt: input.expiresAt,
      createdAt: new Date().toISOString(),
    };

    this.db.prepare(`
      INSERT INTO identity_webauthn_challenges (
        challenge_id, principal_id, flow_type, challenge, rp_id, origin, expires_at, used_at, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)
    `).run(
      challenge.challengeId,
      challenge.principalId,
      challenge.flowType,
      challenge.challenge,
      challenge.rpId,
      challenge.origin,
      challenge.expiresAt,
      challenge.createdAt,
    );

    return challenge;
  }

  getLatestActiveChallenge(principalId: string, flowType: "registration" | "authentication") {
    const row = this.db.prepare(`
      SELECT challenge_id, principal_id, flow_type, challenge, rp_id, origin, expires_at, used_at, created_at
      FROM identity_webauthn_challenges
      WHERE principal_id = ? AND flow_type = ? AND used_at IS NULL
      ORDER BY created_at DESC
      LIMIT 1
    `).get(principalId, flowType) as ChallengeRow | undefined;

    return row ? mapChallengeRow(row) : undefined;
  }

  consumeChallenge(challengeId: string) {
    this.db.prepare(`
      UPDATE identity_webauthn_challenges
      SET used_at = ?
      WHERE challenge_id = ?
    `).run(new Date().toISOString(), challengeId);
  }

  saveVerificationProof(input: Omit<IdentityVerificationProof, "proofId" | "createdAt">) {
    const proof: IdentityVerificationProof = {
      proofId: `proof_${randomUUID()}`,
      createdAt: new Date().toISOString(),
      ...input,
    };

    this.db.prepare(`
      INSERT INTO identity_verification_proofs (
        proof_id, principal_id, role, credential_id, challenge_id, proof_type, verified,
        origin, rp_id, sign_count, created_at, payload_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      proof.proofId,
      proof.principalId,
      proof.role,
      proof.credentialId,
      proof.challengeId ?? null,
      proof.proofType,
      proof.verified ? 1 : 0,
      proof.origin,
      proof.rpId,
      proof.signCount,
      proof.createdAt,
      proof.payloadJson,
    );

    return proof;
  }

  getVerificationProof(proofId: string): IdentityVerificationProof | undefined {
    const row = this.db.prepare(`
      SELECT proof_id, principal_id, role, credential_id, challenge_id, proof_type, verified,
             origin, rp_id, sign_count, created_at, payload_json
      FROM identity_verification_proofs
      WHERE proof_id = ?
    `).get(proofId) as ProofRow | undefined;

    return row ? mapProofRow(row) : undefined;
  }

  getPrincipalPasskeyStatus(principalId: string) {
    const principal = this.getPrincipal(principalId);
    const credentials = this.listCredentials(principalId);
    const latestAuthenticationProof = this.db.prepare(`
      SELECT proof_id, principal_id, role, credential_id, challenge_id, proof_type, verified,
             origin, rp_id, sign_count, created_at, payload_json
      FROM identity_verification_proofs
      WHERE principal_id = ? AND proof_type = 'authentication'
      ORDER BY created_at DESC
      LIMIT 1
    `).get(principalId) as ProofRow | undefined;
    const latestVerifiedProof = this.db.prepare(`
      SELECT proof_id, principal_id, role, credential_id, challenge_id, proof_type, verified,
             origin, rp_id, sign_count, created_at, payload_json
      FROM identity_verification_proofs
      WHERE principal_id = ? AND verified = 1
      ORDER BY created_at DESC
      LIMIT 1
    `).get(principalId) as ProofRow | undefined;

    return {
      principal,
      registered: credentials.length > 0,
      credentials,
      latestAuthenticationProof: latestAuthenticationProof ? mapProofRow(latestAuthenticationProof) : undefined,
      latestVerifiedProof: latestVerifiedProof ? mapProofRow(latestVerifiedProof) : undefined,
    };
  }

  clearIdentityData() {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("DELETE FROM identity_verification_proofs").run();
      this.db.prepare("DELETE FROM identity_webauthn_challenges").run();
      this.db.prepare("DELETE FROM identity_passkey_credentials").run();
      this.db.prepare("DELETE FROM identity_principals").run();
      this.db.prepare("DELETE FROM auth_sessions").run();
      this.db.prepare("DELETE FROM auth_accounts").run();
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }
}

interface PrincipalRow {
  principal_id: string;
  role: string;
  username: string;
  display_name: string;
  webauthn_user_id: string;
  created_at: string;
  updated_at: string;
}

interface CredentialRow {
  credential_id: string;
  principal_id: string;
  public_key_b64u: string;
  counter: number;
  transports_json: string;
  device_type: string;
  backed_up: number;
  rp_id: string;
  created_at: string;
  last_used_at: string;
}

interface ChallengeRow {
  challenge_id: string;
  principal_id: string;
  flow_type: "registration" | "authentication";
  challenge: string;
  rp_id: string;
  origin: string;
  expires_at: string;
  used_at: string | null;
  created_at: string;
}

interface ProofRow {
  proof_id: string;
  principal_id: string;
  role: string;
  credential_id: string;
  challenge_id: string | null;
  proof_type: "registration" | "authentication";
  verified: number;
  origin: string;
  rp_id: string;
  sign_count: number;
  created_at: string;
  payload_json: string;
}

interface AuthAccountRow {
  username: string;
  password_salt: string;
  password_hash: string;
  transferor_principal_id: string;
  admin_principal_id: string;
  created_at: string;
  updated_at: string;
}

interface AuthSessionRow {
  session_id: string;
  username: string;
  created_at: string;
  expires_at: string;
  last_seen_at: string;
  revoked_at: string | null;
}

function mapPrincipalRow(row: PrincipalRow): IdentityPrincipal {
  return {
    principalId: row.principal_id,
    role: row.role,
    username: row.username,
    displayName: row.display_name,
    webauthnUserId: row.webauthn_user_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapCredentialRow(row: CredentialRow): IdentityPasskeyCredential {
  return {
    credentialId: row.credential_id,
    principalId: row.principal_id,
    publicKeyB64u: row.public_key_b64u,
    counter: row.counter,
    transports: JSON.parse(row.transports_json) as string[],
    deviceType: row.device_type,
    backedUp: Boolean(row.backed_up),
    rpId: row.rp_id,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
  };
}

function mapChallengeRow(row: ChallengeRow): IdentityChallenge {
  return {
    challengeId: row.challenge_id,
    principalId: row.principal_id,
    flowType: row.flow_type,
    challenge: row.challenge,
    rpId: row.rp_id,
    origin: row.origin,
    expiresAt: row.expires_at,
    usedAt: row.used_at ?? undefined,
    createdAt: row.created_at,
  };
}

function mapProofRow(row: ProofRow): IdentityVerificationProof {
  return {
    proofId: row.proof_id,
    principalId: row.principal_id,
    role: row.role,
    credentialId: row.credential_id,
    challengeId: row.challenge_id ?? undefined,
    proofType: row.proof_type,
    verified: Boolean(row.verified),
    origin: row.origin,
    rpId: row.rp_id,
    signCount: row.sign_count,
    createdAt: row.created_at,
    payloadJson: row.payload_json,
  };
}

function mapAuthAccountRow(row: AuthAccountRow): AuthAccount {
  const recipientPrincipalId = createAccountScopedPrincipal(row.username, "recipient");
  return {
    username: row.username,
    passwordSalt: row.password_salt,
    passwordHash: row.password_hash,
    transferorPrincipalId: row.transferor_principal_id,
    adminPrincipalId: row.admin_principal_id,
    recipientPrincipalId,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapAuthSessionRow(row: AuthSessionRow): AuthSession {
  return {
    sessionId: row.session_id,
    username: row.username,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    lastSeenAt: row.last_seen_at,
    revokedAt: row.revoked_at ?? undefined,
  };
}

function hashPassword(password: string, salt: string) {
  return scryptSync(password, salt, 64).toString("base64url");
}
