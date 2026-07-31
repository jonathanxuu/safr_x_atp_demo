import { mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import {
  DEMO_PRINCIPALS,
  type BaseEventEnvelope,
  type CreateEventInput,
  type EventRecord,
  type SupportedEventKind,
  createEventRecord,
  inferFlowId,
  isSupportedEventKind,
} from "@safr-x-atp-demo/protocol";
export * from "./identity.js";

export interface ListEventsFilter {
  flowId?: string;
  kind?: number;
}

export interface ArchivedEntity {
  event_ref: string;
  event_kind: number;
  event_role: string;
}

export interface ArchiveRecordContent {
  archive_record_id: string;
  flow_id: string;
  archived_entities: ArchivedEntity[];
  append_only_index: number;
  hash_chain_prev: string;
  hash_chain_curr: string;
  written_by: string;
  write_mode: "append_only";
}

export type ArchiveRecordEnvelope = BaseEventEnvelope<ArchiveRecordContent>;

export interface BankAccount {
  accountId: string;
  ownerId: string;
  ownerRole: "transferor" | "recipient";
  currency: string;
  availableBalance: number;
}

export interface TransferTransaction {
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

export interface PolicyBundle {
  bundleId: string;
  bundleVersion: string;
  bundleHash: string;
  status: "active" | "inactive";
  createdAt: string;
}

export interface VerifierPolicy {
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
}

export interface PrincipalSigningKey {
  principalId: string;
  keyId: string;
  role: string;
  keyType: "ed25519";
  algorithm: "ed25519";
  publicKeyPem?: string;
  publicKeyPath?: string;
  privateKeyPath?: string;
  createdAt: string;
  updatedAt: string;
}

const defaultAgentPublicKeyPath = fileURLToPath(
  new URL("../../../services/agent-service/keys/agent_ed25519_public.pem", import.meta.url),
);
const defaultAgentPrivateKeyPath = fileURLToPath(
  new URL("../../../services/agent-service/keys/agent_ed25519_private.pem", import.meta.url),
);
const defaultVerifierPublicKeyPath = fileURLToPath(
  new URL("../../../services/verifier/keys/verifier_ed25519_public.pem", import.meta.url),
);
const defaultVerifierPrivateKeyPath = fileURLToPath(
  new URL("../../../services/verifier/keys/verifier_ed25519_private.pem", import.meta.url),
);

export function getSharedDatabasePath() {
  if (process.env.DATABASE_FILE) {
    return resolve(process.cwd(), process.env.DATABASE_FILE);
  }

  return fileURLToPath(new URL("../../../data/safr-atp-demo.sqlite", import.meta.url));
}

export function createSharedDatabase(databaseFile = getSharedDatabasePath()) {
  mkdirSync(dirname(databaseFile), { recursive: true });
  const db = new DatabaseSync(databaseFile);
  db.exec("PRAGMA busy_timeout = 5000;");
  runWithRetry(() => {
    db.exec("PRAGMA journal_mode = WAL;");
    db.exec("PRAGMA foreign_keys = ON;");
    applyMigrations(db);
  });
  return db;
}

function runWithRetry(callback: () => void, attempts = 10, waitMs = 150) {
  let lastError: unknown;

  for (let index = 0; index < attempts; index += 1) {
    try {
      callback();
      return;
    } catch (error) {
      lastError = error;
      if (!isSqliteBusyError(error) || index === attempts - 1) {
        throw error;
      }
      sleep(waitMs);
    }
  }

  throw lastError;
}

function isSqliteBusyError(error: unknown) {
  return error instanceof Error && /database is locked/i.test(error.message);
}

function sleep(waitMs: number) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, waitMs);
}

const migrations = [
  {
    version: 1,
    name: "initial_core_tables",
    sql: `
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      applied_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS event_events (
      id TEXT PRIMARY KEY,
      flow_id TEXT NOT NULL,
      kind INTEGER NOT NULL,
      ai_id TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      instruction_ref TEXT,
      envelope_ref TEXT,
      payload_json TEXT NOT NULL,
      payload_hash TEXT NOT NULL,
      signature_json TEXT,
      status TEXT NOT NULL DEFAULT 'recorded'
    );

    CREATE INDEX IF NOT EXISTS idx_event_events_flow_created
      ON event_events (flow_id, created_at, id);

    CREATE INDEX IF NOT EXISTS idx_event_events_kind
      ON event_events (kind);

    CREATE TABLE IF NOT EXISTS event_tags (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id TEXT NOT NULL,
      tag_key TEXT NOT NULL,
      tag_value TEXT NOT NULL,
      FOREIGN KEY (event_id) REFERENCES event_events(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_event_tags_event
      ON event_tags (event_id);

    CREATE INDEX IF NOT EXISTS idx_event_tags_key_value
      ON event_tags (tag_key, tag_value);

    CREATE TABLE IF NOT EXISTS archive_records (
      id TEXT PRIMARY KEY,
      archive_record_id TEXT NOT NULL UNIQUE,
      flow_id TEXT NOT NULL,
      append_only_index INTEGER NOT NULL UNIQUE,
      hash_chain_prev TEXT NOT NULL,
      hash_chain_curr TEXT NOT NULL,
      written_by TEXT NOT NULL,
      write_mode TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      record_json TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_archive_records_flow
      ON archive_records (flow_id, append_only_index);

    CREATE TABLE IF NOT EXISTS archive_entities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      archive_id TEXT NOT NULL,
      event_ref TEXT NOT NULL,
      event_kind INTEGER NOT NULL,
      event_role TEXT NOT NULL,
      FOREIGN KEY (archive_id) REFERENCES archive_records(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_archive_entities_archive
      ON archive_entities (archive_id);

    CREATE TABLE IF NOT EXISTS bank_accounts (
      account_id TEXT PRIMARY KEY,
      owner_id TEXT NOT NULL,
      owner_role TEXT NOT NULL,
      currency TEXT NOT NULL,
      available_balance REAL NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS bank_transactions (
      transaction_id TEXT PRIMARY KEY,
      flow_id TEXT NOT NULL,
      verifier_event_id TEXT NOT NULL,
      status TEXT NOT NULL,
      from_account_id TEXT NOT NULL,
      to_account_id TEXT NOT NULL,
      amount REAL NOT NULL,
      currency TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_bank_transactions_flow
      ON bank_transactions (flow_id, created_at);
    `,
  },
  {
    version: 2,
    name: "verifier_policy_tables",
    sql: `
    CREATE TABLE IF NOT EXISTS policy_bundles (
      bundle_id TEXT PRIMARY KEY,
      bundle_version TEXT NOT NULL,
      bundle_hash TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS verifier_policies (
      policy_id TEXT PRIMARY KEY,
      bundle_id TEXT NOT NULL,
      policy_name TEXT NOT NULL,
      currency TEXT NOT NULL,
      auto_execute_below REAL NOT NULL,
      admin_review_at_or_above REAL NOT NULL,
      recipient_allowlist_required INTEGER NOT NULL,
      allowed_currencies_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY (bundle_id) REFERENCES policy_bundles(bundle_id)
    );

    CREATE INDEX IF NOT EXISTS idx_verifier_policies_bundle
      ON verifier_policies (bundle_id);
    `,
  },
  {
    version: 3,
    name: "identity_webauthn_tables",
    sql: `
    CREATE TABLE IF NOT EXISTS identity_principals (
      principal_id TEXT PRIMARY KEY,
      role TEXT NOT NULL,
      username TEXT NOT NULL,
      display_name TEXT NOT NULL,
      webauthn_user_id TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS identity_passkey_credentials (
      credential_id TEXT PRIMARY KEY,
      principal_id TEXT NOT NULL,
      public_key_b64u TEXT NOT NULL,
      counter INTEGER NOT NULL,
      transports_json TEXT NOT NULL,
      device_type TEXT NOT NULL,
      backed_up INTEGER NOT NULL,
      rp_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      last_used_at TEXT NOT NULL,
      FOREIGN KEY (principal_id) REFERENCES identity_principals(principal_id)
    );

    CREATE INDEX IF NOT EXISTS idx_identity_credentials_principal
      ON identity_passkey_credentials (principal_id);

    CREATE TABLE IF NOT EXISTS identity_webauthn_challenges (
      challenge_id TEXT PRIMARY KEY,
      principal_id TEXT NOT NULL,
      flow_type TEXT NOT NULL,
      challenge TEXT NOT NULL,
      rp_id TEXT NOT NULL,
      origin TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used_at TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY (principal_id) REFERENCES identity_principals(principal_id)
    );

    CREATE INDEX IF NOT EXISTS idx_identity_challenges_principal_flow
      ON identity_webauthn_challenges (principal_id, flow_type, created_at);

    CREATE TABLE IF NOT EXISTS identity_verification_proofs (
      proof_id TEXT PRIMARY KEY,
      principal_id TEXT NOT NULL,
      role TEXT NOT NULL,
      credential_id TEXT NOT NULL,
      challenge_id TEXT,
      proof_type TEXT NOT NULL,
      verified INTEGER NOT NULL,
      origin TEXT NOT NULL,
      rp_id TEXT NOT NULL,
      sign_count INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      FOREIGN KEY (principal_id) REFERENCES identity_principals(principal_id)
    );

    CREATE INDEX IF NOT EXISTS idx_identity_proofs_principal
      ON identity_verification_proofs (principal_id, proof_type, created_at);
    `,
  },
  {
    version: 4,
    name: "migrate_demo_subject_ids_to_icp_principals",
    sql: `
    PRAGMA foreign_keys = OFF;

    UPDATE bank_accounts
    SET owner_id = '${DEMO_PRINCIPALS.transferor}'
    WHERE owner_id = 'usr_transferor_alice';

    UPDATE bank_accounts
    SET owner_id = '${DEMO_PRINCIPALS.recipient}'
    WHERE owner_id = 'usr_recipient_bob';

    UPDATE identity_principals
    SET principal_id = '${DEMO_PRINCIPALS.transferor}'
    WHERE principal_id = 'usr_transferor_alice';

    UPDATE identity_principals
    SET principal_id = '${DEMO_PRINCIPALS.admin}'
    WHERE principal_id = 'usr_admin_zoe';

    UPDATE identity_passkey_credentials
    SET principal_id = '${DEMO_PRINCIPALS.transferor}'
    WHERE principal_id = 'usr_transferor_alice';

    UPDATE identity_passkey_credentials
    SET principal_id = '${DEMO_PRINCIPALS.admin}'
    WHERE principal_id = 'usr_admin_zoe';

    UPDATE identity_webauthn_challenges
    SET principal_id = '${DEMO_PRINCIPALS.transferor}'
    WHERE principal_id = 'usr_transferor_alice';

    UPDATE identity_webauthn_challenges
    SET principal_id = '${DEMO_PRINCIPALS.admin}'
    WHERE principal_id = 'usr_admin_zoe';

    UPDATE identity_verification_proofs
    SET principal_id = '${DEMO_PRINCIPALS.transferor}'
    WHERE principal_id = 'usr_transferor_alice';

    UPDATE identity_verification_proofs
    SET principal_id = '${DEMO_PRINCIPALS.admin}'
    WHERE principal_id = 'usr_admin_zoe';

    PRAGMA foreign_keys = ON;
    `,
  },
  {
    version: 5,
    name: "principal_signing_key_registry",
    sql: `
    CREATE TABLE IF NOT EXISTS principal_signing_keys (
      principal_id TEXT PRIMARY KEY,
      key_id TEXT NOT NULL UNIQUE,
      role TEXT NOT NULL,
      key_type TEXT NOT NULL,
      algorithm TEXT NOT NULL,
      public_key_pem TEXT,
      public_key_path TEXT,
      private_key_path TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_principal_signing_keys_role
      ON principal_signing_keys (role);
    `,
  },
  {
    version: 6,
    name: "auth_accounts_and_sessions",
    sql: `
    CREATE TABLE IF NOT EXISTS auth_accounts (
      username TEXT PRIMARY KEY,
      password_salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      transferor_principal_id TEXT NOT NULL UNIQUE,
      admin_principal_id TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS auth_sessions (
      session_id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL,
      revoked_at TEXT,
      FOREIGN KEY (username) REFERENCES auth_accounts(username) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_auth_sessions_username
      ON auth_sessions (username, created_at DESC);
    `,
  },
];

function applyMigrations(db: DatabaseSync) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      applied_at TEXT NOT NULL
    );
  `);

  for (const migration of migrations) {
    const existing = db
      .prepare("SELECT version FROM schema_migrations WHERE version = ?")
      .get(migration.version) as { version?: number } | undefined;

    if (existing?.version) {
      continue;
    }

    db.exec("BEGIN IMMEDIATE");
    try {
      db.exec(migration.sql);
      db.prepare(`
        INSERT INTO schema_migrations (version, name, applied_at)
        VALUES (?, ?, ?)
      `).run(migration.version, migration.name, new Date().toISOString());
      db.exec("COMMIT");
    } catch (error) {
      db.exec("ROLLBACK");
      throw error;
    }
  }
}

function safeParseJson<T>(value: string): T {
  return JSON.parse(value) as T;
}

function extractSignatureJson(payload: BaseEventEnvelope<Record<string, unknown>>) {
  const content = payload.content;
  const signatureCandidates = [
    content.signature_proof,
    content.origin_sig,
    content.verifier_sig,
  ].filter((value) => value !== undefined);

  return signatureCandidates.length > 0 ? JSON.stringify(signatureCandidates) : null;
}

export class EventRepository {
  constructor(private readonly db: DatabaseSync) {}

  create<TContent extends Record<string, unknown>>(input: CreateEventInput<TContent>): EventRecord<TContent> {
    const { payload } = input;
    if (!isSupportedEventKind(payload.kind)) {
      throw new Error(`Unsupported event kind: ${payload.kind}`);
    }

    const existing = this.db
      .prepare("SELECT id FROM event_events WHERE id = ?")
      .get(payload.id) as { id?: string } | undefined;
    if (existing?.id) {
      throw new Error(`Event already exists: ${payload.id}`);
    }

    const record = createEventRecord(input);
    const payloadJson = JSON.stringify(record.payload);
    const payloadHash = hashJson(record.payload);
    const signatureJson = extractSignatureJson(record.payload as BaseEventEnvelope<Record<string, unknown>>);

    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db
        .prepare(`
          INSERT INTO event_events (
            id, flow_id, kind, ai_id, created_at, instruction_ref, envelope_ref,
            payload_json, payload_hash, signature_json, status
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .run(
          record.eventId,
          record.flowId,
          record.kind,
          record.aiId,
          record.createdAt,
          record.instructionRef ?? null,
          record.envelopeRef ?? null,
          payloadJson,
          payloadHash,
          signatureJson,
          "recorded",
        );

      const insertTag = this.db.prepare(`
        INSERT INTO event_tags (event_id, tag_key, tag_value)
        VALUES (?, ?, ?)
      `);

      for (const [tagKey, tagValue] of record.payload.tags) {
        insertTag.run(record.eventId, tagKey, tagValue);
      }

      this.db.exec("COMMIT");
      return record;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  get(eventId: string): EventRecord | undefined {
    const row = this.db
      .prepare(`
        SELECT id, flow_id, kind, ai_id, created_at, instruction_ref, envelope_ref, payload_json
        FROM event_events
        WHERE id = ?
      `)
      .get(eventId) as EventEventRow | undefined;

    return row ? this.mapEventRow(row) : undefined;
  }

  list(filter: ListEventsFilter = {}): EventRecord[] {
    const clauses: string[] = [];
    const args: Array<string | number> = [];

    if (filter.flowId) {
      clauses.push("flow_id = ?");
      args.push(filter.flowId);
    }
    if (typeof filter.kind === "number") {
      clauses.push("kind = ?");
      args.push(filter.kind);
    }

    const whereClause = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";
    const rows = this.db
      .prepare(`
        SELECT id, flow_id, kind, ai_id, created_at, instruction_ref, envelope_ref, payload_json
        FROM event_events
        ${whereClause}
        ORDER BY created_at ASC, id ASC
      `)
      .all(...args) as EventEventRow[];

    return rows.map((row) => this.mapEventRow(row));
  }

  reset() {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("DELETE FROM event_tags").run();
      this.db.prepare("DELETE FROM event_events").run();
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  private mapEventRow(row: EventEventRow): EventRecord {
    return {
      eventId: row.id,
      flowId: row.flow_id,
      kind: row.kind as SupportedEventKind,
      aiId: row.ai_id,
      createdAt: row.created_at,
      instructionRef: row.instruction_ref ?? undefined,
      envelopeRef: row.envelope_ref ?? undefined,
      payload: safeParseJson<BaseEventEnvelope<Record<string, unknown>>>(row.payload_json),
    };
  }
}

export class ArchiveRepository {
  constructor(private readonly db: DatabaseSync) {}

  append(flowId: string, archivedEntities: ArchivedEntity[]): ArchiveRecordEnvelope {
    const lastRecord = this.db
      .prepare(`
        SELECT append_only_index, record_json
        FROM archive_records
        ORDER BY append_only_index DESC
        LIMIT 1
      `)
      .get() as { append_only_index: number; record_json: string } | undefined;

    const appendOnlyIndex = (lastRecord?.append_only_index ?? 0) + 1;
    const previousHash = lastRecord
      ? safeParseJson<ArchiveRecordEnvelope>(lastRecord.record_json).content.hash_chain_curr
      : "genesis";

    const archiveRecordId = `arc_${String(appendOnlyIndex).padStart(4, "0")}`;
    const contentWithoutCurrentHash = {
      archive_record_id: archiveRecordId,
      flow_id: flowId,
      archived_entities: archivedEntities,
      append_only_index: appendOnlyIndex,
      hash_chain_prev: previousHash,
      written_by: "archive_service_demo_01",
      write_mode: "append_only" as const,
    };

    const currentHash = hashJson({
      ...contentWithoutCurrentHash,
      hash_chain_curr: "",
    });

    const record: ArchiveRecordEnvelope = {
      id: `evt_archive_${String(appendOnlyIndex).padStart(4, "0")}_hash`,
      kind: 106,
      ai_id: "archive_service_demo_01",
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ["flow_id", flowId],
        ["stage", "archive_written"],
      ],
      content: {
        ...contentWithoutCurrentHash,
        hash_chain_curr: currentHash,
      },
    };

    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db
        .prepare(`
          INSERT INTO archive_records (
            id, archive_record_id, flow_id, append_only_index, hash_chain_prev,
            hash_chain_curr, written_by, write_mode, created_at, record_json
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .run(
          record.id,
          record.content.archive_record_id,
          record.content.flow_id,
          record.content.append_only_index,
          record.content.hash_chain_prev,
          record.content.hash_chain_curr,
          record.content.written_by,
          record.content.write_mode,
          record.created_at,
          JSON.stringify(record),
        );

      const insertEntity = this.db.prepare(`
        INSERT INTO archive_entities (archive_id, event_ref, event_kind, event_role)
        VALUES (?, ?, ?, ?)
      `);

      for (const entity of archivedEntities) {
        insertEntity.run(record.id, entity.event_ref, entity.event_kind, entity.event_role);
      }

      this.db.exec("COMMIT");
      return record;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  getByFlow(flowId: string): ArchiveRecordEnvelope[] {
    const rows = this.db
      .prepare(`
        SELECT record_json
        FROM archive_records
        WHERE flow_id = ?
        ORDER BY append_only_index ASC
      `)
      .all(flowId) as Array<{ record_json: string }>;

    return rows.map((row) => safeParseJson<ArchiveRecordEnvelope>(row.record_json));
  }

  getById(recordId: string): ArchiveRecordEnvelope | undefined {
    const row = this.db
      .prepare("SELECT record_json FROM archive_records WHERE id = ?")
      .get(recordId) as { record_json: string } | undefined;

    return row ? safeParseJson<ArchiveRecordEnvelope>(row.record_json) : undefined;
  }

  reset() {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("DELETE FROM archive_entities").run();
      this.db.prepare("DELETE FROM archive_records").run();
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }
}

export class BankRepository {
  constructor(private readonly db: DatabaseSync) {
    this.seedDefaults();
  }

  ensureAccount(input: {
    ownerId: string;
    ownerRole: "transferor" | "recipient";
    currency: string;
    availableBalance?: number;
  }): BankAccount {
    const existing = this.getAccountByOwner(input.ownerId, input.ownerRole, input.currency);
    if (existing) {
      return existing;
    }

    const account: BankAccount = {
      accountId: createDeterministicBankAccountId(input.ownerId, input.ownerRole, input.currency),
      ownerId: input.ownerId,
      ownerRole: input.ownerRole,
      currency: input.currency,
      availableBalance: input.availableBalance ?? (input.ownerRole === "transferor" ? 25000 : 3200),
    };
    const now = new Date().toISOString();

    this.db.prepare(`
      INSERT INTO bank_accounts (
        account_id, owner_id, owner_role, currency, available_balance, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      account.accountId,
      account.ownerId,
      account.ownerRole,
      account.currency,
      account.availableBalance,
      now,
    );

    return account;
  }

  listAccounts(): BankAccount[] {
    const rows = this.db
      .prepare(`
        SELECT account_id, owner_id, owner_role, currency, available_balance
        FROM bank_accounts
        ORDER BY account_id ASC
      `)
      .all() as BankAccountRow[];

    return rows.map((row) => ({
      accountId: row.account_id,
      ownerId: row.owner_id,
      ownerRole: row.owner_role as "transferor" | "recipient",
      currency: row.currency,
      availableBalance: row.available_balance,
    }));
  }

  listAccountsByOwner(ownerId: string): BankAccount[] {
    const rows = this.db
      .prepare(`
        SELECT account_id, owner_id, owner_role, currency, available_balance
        FROM bank_accounts
        WHERE owner_id = ?
        ORDER BY owner_role ASC, currency ASC, account_id ASC
      `)
      .all(ownerId) as BankAccountRow[];

    return rows.map((row) => ({
      accountId: row.account_id,
      ownerId: row.owner_id,
      ownerRole: row.owner_role as "transferor" | "recipient",
      currency: row.currency,
      availableBalance: row.available_balance,
    }));
  }

  getAccount(accountId: string): BankAccount | undefined {
    const row = this.db
      .prepare(`
        SELECT account_id, owner_id, owner_role, currency, available_balance
        FROM bank_accounts
        WHERE account_id = ?
      `)
      .get(accountId) as BankAccountRow | undefined;

    if (!row) {
      return undefined;
    }

    return {
      accountId: row.account_id,
      ownerId: row.owner_id,
      ownerRole: row.owner_role as "transferor" | "recipient",
      currency: row.currency,
      availableBalance: row.available_balance,
    };
  }

  getAccountByOwner(ownerId: string, ownerRole: "transferor" | "recipient", currency: string) {
    const row = this.db
      .prepare(`
        SELECT account_id, owner_id, owner_role, currency, available_balance
        FROM bank_accounts
        WHERE owner_id = ? AND owner_role = ? AND currency = ?
        LIMIT 1
      `)
      .get(ownerId, ownerRole, currency) as BankAccountRow | undefined;

    if (!row) {
      return undefined;
    }

    return {
      accountId: row.account_id,
      ownerId: row.owner_id,
      ownerRole: row.owner_role as "transferor" | "recipient",
      currency: row.currency,
      availableBalance: row.available_balance,
    };
  }

  listTransactions(): TransferTransaction[] {
    const rows = this.db
      .prepare(`
        SELECT transaction_id, flow_id, verifier_event_id, status, from_account_id,
               to_account_id, amount, currency, created_at
        FROM bank_transactions
        ORDER BY created_at DESC, transaction_id DESC
      `)
      .all() as BankTransactionRow[];

    return rows.map((row) => ({
      transactionId: row.transaction_id,
      flowId: row.flow_id,
      verifierEventId: row.verifier_event_id,
      status: row.status as "executed",
      fromAccountId: row.from_account_id,
      toAccountId: row.to_account_id,
      amount: row.amount,
      currency: row.currency,
      createdAt: row.created_at,
    }));
  }

  getTransactionByVerifierEventId(verifierEventId: string): TransferTransaction | undefined {
    const row = this.db
      .prepare(`
        SELECT transaction_id, flow_id, verifier_event_id, status, from_account_id,
               to_account_id, amount, currency, created_at
        FROM bank_transactions
        WHERE verifier_event_id = ?
        LIMIT 1
      `)
      .get(verifierEventId) as BankTransactionRow | undefined;

    if (!row) {
      return undefined;
    }

    return {
      transactionId: row.transaction_id,
      flowId: row.flow_id,
      verifierEventId: row.verifier_event_id,
      status: row.status as "executed",
      fromAccountId: row.from_account_id,
      toAccountId: row.to_account_id,
      amount: row.amount,
      currency: row.currency,
      createdAt: row.created_at,
    };
  }

  executeTransfer(input: {
    flowId: string;
    verifierEventId: string;
    fromAccountId: string;
    toAccountId: string;
    amount: number;
    currency: string;
  }): TransferTransaction {
    const from = this.getAccountOrThrow(input.fromAccountId);
    const to = this.getAccountOrThrow(input.toAccountId);

    if (from.currency !== input.currency || to.currency !== input.currency) {
      throw new Error("Currency mismatch");
    }
    if (from.availableBalance < input.amount) {
      throw new Error("Insufficient balance");
    }

    const now = new Date().toISOString();
    const transaction: TransferTransaction = {
      transactionId: `txn_${Date.now()}`,
      flowId: input.flowId,
      verifierEventId: input.verifierEventId,
      status: "executed",
      fromAccountId: from.accountId,
      toAccountId: to.accountId,
      amount: input.amount,
      currency: input.currency,
      createdAt: now,
    };

    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db
        .prepare(`
          UPDATE bank_accounts
          SET available_balance = ?, updated_at = ?
          WHERE account_id = ?
        `)
        .run(from.availableBalance - input.amount, now, from.accountId);

      this.db
        .prepare(`
          UPDATE bank_accounts
          SET available_balance = ?, updated_at = ?
          WHERE account_id = ?
        `)
        .run(to.availableBalance + input.amount, now, to.accountId);

      this.db
        .prepare(`
          INSERT INTO bank_transactions (
            transaction_id, flow_id, verifier_event_id, status, from_account_id,
            to_account_id, amount, currency, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .run(
          transaction.transactionId,
          transaction.flowId,
          transaction.verifierEventId,
          transaction.status,
          transaction.fromAccountId,
          transaction.toAccountId,
          transaction.amount,
          transaction.currency,
          transaction.createdAt,
        );

      this.db.exec("COMMIT");
      return transaction;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  resetBalancesForOwners(ownerIds: string[]) {
    const uniqueOwnerIds = Array.from(new Set(ownerIds.map((ownerId) => ownerId.trim()).filter(Boolean)));
    if (uniqueOwnerIds.length === 0) {
      return;
    }

    const now = new Date().toISOString();
    this.db.exec("BEGIN IMMEDIATE");
    try {
      for (const ownerId of uniqueOwnerIds) {
        this.db
          .prepare(`
            UPDATE bank_accounts
            SET available_balance = CASE owner_role
              WHEN 'transferor' THEN 25000
              WHEN 'recipient' THEN 3200
              ELSE available_balance
            END,
            updated_at = ?
            WHERE owner_id = ?
          `)
          .run(now, ownerId);
      }
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  reset() {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("DELETE FROM bank_transactions").run();
      this.db.prepare("DELETE FROM bank_accounts").run();
      this.seedDefaults();
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  private getAccountOrThrow(accountId: string): BankAccount {
    const account = this.getAccount(accountId);
    if (!account) {
      throw new Error(`Account not found: ${accountId}`);
    }
    return account;
  }

  private seedDefaults() {
    const existing = this.db
      .prepare("SELECT COUNT(*) AS count FROM bank_accounts")
      .get() as { count: number };

    if (existing.count > 0) {
      return;
    }

    const now = new Date().toISOString();
    const insert = this.db.prepare(`
      INSERT INTO bank_accounts (
        account_id, owner_id, owner_role, currency, available_balance, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `);

    insert.run("acct_transferor_alice_001", DEMO_PRINCIPALS.transferor, "transferor", "USD", 25000, now);
    insert.run("acct_recipient_bob_001", DEMO_PRINCIPALS.recipient, "recipient", "USD", 3200, now);
  }
}

export class PrincipalKeyRepository {
  constructor(private readonly db: DatabaseSync) {
    this.seedDefaults();
  }

  getSignerKeyByPrincipal(principalId: string): PrincipalSigningKey | undefined {
    const row = this.db
      .prepare(`
        SELECT principal_id, key_id, role, key_type, algorithm, public_key_pem,
               public_key_path, private_key_path, created_at, updated_at
        FROM principal_signing_keys
        WHERE principal_id = ?
      `)
      .get(principalId) as PrincipalSigningKeyRow | undefined;

    return row ? mapPrincipalSigningKeyRow(row) : undefined;
  }

  getSignerKeyByKeyId(keyId: string): PrincipalSigningKey | undefined {
    const row = this.db
      .prepare(`
        SELECT principal_id, key_id, role, key_type, algorithm, public_key_pem,
               public_key_path, private_key_path, created_at, updated_at
        FROM principal_signing_keys
        WHERE key_id = ?
      `)
      .get(keyId) as PrincipalSigningKeyRow | undefined;

    return row ? mapPrincipalSigningKeyRow(row) : undefined;
  }

  listSignerKeys(): PrincipalSigningKey[] {
    const rows = this.db
      .prepare(`
        SELECT principal_id, key_id, role, key_type, algorithm, public_key_pem,
               public_key_path, private_key_path, created_at, updated_at
        FROM principal_signing_keys
        ORDER BY role ASC, principal_id ASC
      `)
      .all() as PrincipalSigningKeyRow[];

    return rows.map(mapPrincipalSigningKeyRow);
  }

  upsertSignerKey(input: {
    principalId: string;
    keyId: string;
    role: string;
    publicKeyPem?: string;
    publicKeyPath?: string;
    privateKeyPath?: string;
  }): PrincipalSigningKey {
    const existing = this.getSignerKeyByPrincipal(input.principalId);
    const existingByKeyId = this.getSignerKeyByKeyId(input.keyId);

    if (existingByKeyId && existingByKeyId.principalId !== input.principalId) {
      this.db.prepare("DELETE FROM principal_signing_keys WHERE key_id = ?").run(input.keyId);
    }

    const now = new Date().toISOString();
    const record: PrincipalSigningKey = {
      principalId: input.principalId,
      keyId: input.keyId,
      role: input.role,
      keyType: "ed25519",
      algorithm: "ed25519",
      publicKeyPem: input.publicKeyPem ?? existing?.publicKeyPem,
      publicKeyPath: input.publicKeyPath ?? existing?.publicKeyPath,
      privateKeyPath: input.privateKeyPath ?? existing?.privateKeyPath,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };

    this.db.prepare(`
      INSERT INTO principal_signing_keys (
        principal_id, key_id, role, key_type, algorithm, public_key_pem,
        public_key_path, private_key_path, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(principal_id) DO UPDATE SET
        key_id = excluded.key_id,
        role = excluded.role,
        key_type = excluded.key_type,
        algorithm = excluded.algorithm,
        public_key_pem = excluded.public_key_pem,
        public_key_path = excluded.public_key_path,
        private_key_path = excluded.private_key_path,
        updated_at = excluded.updated_at
    `).run(
      record.principalId,
      record.keyId,
      record.role,
      record.keyType,
      record.algorithm,
      record.publicKeyPem ?? null,
      record.publicKeyPath ?? null,
      record.privateKeyPath ?? null,
      record.createdAt,
      record.updatedAt,
    );

    return record;
  }

  reset() {
    this.db.prepare("DELETE FROM principal_signing_keys").run();
    this.seedDefaults();
  }

  private seedDefaults() {
    const existing = this.db
      .prepare("SELECT COUNT(*) AS count FROM principal_signing_keys")
      .get() as { count: number };

    if (existing.count > 0) {
      return;
    }

    const now = new Date().toISOString();
    const insert = this.db.prepare(`
      INSERT INTO principal_signing_keys (
        principal_id, key_id, role, key_type, algorithm, public_key_pem,
        public_key_path, private_key_path, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insert.run(
      DEMO_PRINCIPALS.agent,
      "ag_transfer_01#ed25519#v1",
      "agent",
      "ed25519",
      "ed25519",
      null,
      defaultAgentPublicKeyPath,
      defaultAgentPrivateKeyPath,
      now,
      now,
    );

    insert.run(
      DEMO_PRINCIPALS.verifier,
      "verifier_demo_01#ed25519#v1",
      "verifier",
      "ed25519",
      "ed25519",
      null,
      defaultVerifierPublicKeyPath,
      defaultVerifierPrivateKeyPath,
      now,
      now,
    );
  }
}

export class PolicyRepository {
  constructor(private readonly db: DatabaseSync) {
    this.seedDefaults();
  }

  getActiveBundle(): PolicyBundle {
    const row = this.db.prepare(`
      SELECT bundle_id, bundle_version, bundle_hash, status, created_at
      FROM policy_bundles
      WHERE status = 'active'
      ORDER BY created_at DESC
      LIMIT 1
    `).get() as PolicyBundleRow | undefined;

    if (!row) {
      throw new Error("No active policy bundle found");
    }

    return {
      bundleId: row.bundle_id,
      bundleVersion: row.bundle_version,
      bundleHash: row.bundle_hash,
      status: row.status as "active" | "inactive",
      createdAt: row.created_at,
    };
  }

  getPolicyForCurrency(currency: string): VerifierPolicy {
    const row = this.db.prepare(`
      SELECT policy_id, bundle_id, policy_name, currency, auto_execute_below,
             admin_review_at_or_above, recipient_allowlist_required,
             allowed_currencies_json, created_at, updated_at
      FROM verifier_policies
      WHERE currency = ?
      ORDER BY updated_at DESC
      LIMIT 1
    `).get(currency) as VerifierPolicyRow | undefined;

    if (!row) {
      throw new Error(`No verifier policy found for currency: ${currency}`);
    }

    return this.mapPolicyRow(row);
  }

  private mapPolicyRow(row: VerifierPolicyRow): VerifierPolicy {
    return {
      policyId: row.policy_id,
      bundleId: row.bundle_id,
      policyName: row.policy_name,
      currency: row.currency,
      autoExecuteBelow: row.auto_execute_below,
      adminReviewAtOrAbove: row.admin_review_at_or_above,
      recipientAllowlistRequired: Boolean(row.recipient_allowlist_required),
      allowedCurrencies: safeParseJson<string[]>(row.allowed_currencies_json),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  private seedDefaults() {
    const existing = this.db
      .prepare("SELECT COUNT(*) AS count FROM policy_bundles")
      .get() as { count: number };

    if (existing.count > 0) {
      return;
    }

    const now = new Date().toISOString();
    const bundleId = "bundle_demo_finance_001";
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare(`
        INSERT INTO policy_bundles (bundle_id, bundle_version, bundle_hash, status, created_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(bundleId, "1.0.0", "sha256:demo_policy_bundle_001", "active", now);

      this.db.prepare(`
        INSERT INTO verifier_policies (
          policy_id, bundle_id, policy_name, currency, auto_execute_below,
          admin_review_at_or_above, recipient_allowlist_required,
          allowed_currencies_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        "policy_transfer_usd_001",
        bundleId,
        "default_usd_transfer_policy",
        "USD",
        1000,
        1000,
        1,
        JSON.stringify(["USD", "SGD"]),
        now,
        now,
      );

      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }
}

export function normalizeCreateEventPayload<TContent extends Record<string, unknown>>(
  payload: Record<string, unknown>,
): CreateEventInput<TContent> {
  const envelope = payload.payload as BaseEventEnvelope<TContent> | undefined;
  const providedFlowId = typeof payload.flowId === "string" ? payload.flowId : undefined;
  const flowId = providedFlowId ?? (envelope ? inferFlowId(envelope) : undefined);

  if (!envelope) {
    throw new Error("Missing payload envelope");
  }
  if (!flowId) {
    throw new Error("Missing flowId");
  }

  return {
    flowId,
    payload: envelope,
    instructionRef: typeof payload.instructionRef === "string" ? payload.instructionRef : undefined,
    envelopeRef: typeof payload.envelopeRef === "string" ? payload.envelopeRef : undefined,
  };
}

export function hashJson(value: unknown): string {
  const digest = createHash("sha256").update(JSON.stringify(value)).digest("hex");
  return `sha256:${digest}`;
}

interface EventEventRow {
  id: string;
  flow_id: string;
  kind: number;
  ai_id: string;
  created_at: number;
  instruction_ref: string | null;
  envelope_ref: string | null;
  payload_json: string;
}

interface BankAccountRow {
  account_id: string;
  owner_id: string;
  owner_role: string;
  currency: string;
  available_balance: number;
}

interface BankTransactionRow {
  transaction_id: string;
  flow_id: string;
  verifier_event_id: string;
  status: string;
  from_account_id: string;
  to_account_id: string;
  amount: number;
  currency: string;
  created_at: string;
}

interface PolicyBundleRow {
  bundle_id: string;
  bundle_version: string;
  bundle_hash: string;
  status: string;
  created_at: string;
}

interface VerifierPolicyRow {
  policy_id: string;
  bundle_id: string;
  policy_name: string;
  currency: string;
  auto_execute_below: number;
  admin_review_at_or_above: number;
  recipient_allowlist_required: number;
  allowed_currencies_json: string;
  created_at: string;
  updated_at: string;
}

interface PrincipalSigningKeyRow {
  principal_id: string;
  key_id: string;
  role: string;
  key_type: "ed25519";
  algorithm: "ed25519";
  public_key_pem: string | null;
  public_key_path: string | null;
  private_key_path: string | null;
  created_at: string;
  updated_at: string;
}

function mapPrincipalSigningKeyRow(row: PrincipalSigningKeyRow): PrincipalSigningKey {
  return {
    principalId: row.principal_id,
    keyId: row.key_id,
    role: row.role,
    keyType: row.key_type,
    algorithm: row.algorithm,
    publicKeyPem: row.public_key_pem ?? undefined,
    publicKeyPath: row.public_key_path ?? undefined,
    privateKeyPath: row.private_key_path ?? undefined,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function createDeterministicBankAccountId(ownerId: string, ownerRole: "transferor" | "recipient", currency: string) {
  const digest = createHash("sha256")
    .update(`${ownerId}:${ownerRole}:${currency}:bank_account:v1`)
    .digest("hex")
    .slice(0, 16);
  return `acct_${ownerRole}_${currency.toLowerCase()}_${digest}`;
}
