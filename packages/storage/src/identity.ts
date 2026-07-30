import { randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";

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

export class IdentityRepository {
  constructor(private readonly db: DatabaseSync) {}

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
    const latestProof = this.db.prepare(`
      SELECT proof_id, principal_id, role, credential_id, challenge_id, proof_type, verified,
             origin, rp_id, sign_count, created_at, payload_json
      FROM identity_verification_proofs
      WHERE principal_id = ? AND proof_type = 'authentication'
      ORDER BY created_at DESC
      LIMIT 1
    `).get(principalId) as ProofRow | undefined;

    return {
      principal,
      registered: credentials.length > 0,
      credentials,
      latestAuthenticationProof: latestProof ? mapProofRow(latestProof) : undefined,
    };
  }

  clearIdentityData() {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("DELETE FROM identity_verification_proofs").run();
      this.db.prepare("DELETE FROM identity_webauthn_challenges").run();
      this.db.prepare("DELETE FROM identity_passkey_credentials").run();
      this.db.prepare("DELETE FROM identity_principals").run();
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
