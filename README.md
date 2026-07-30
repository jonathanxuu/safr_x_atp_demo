# SAFR x ATP Demo

Monorepo for a decoupled SAFR x ATP transfer demo built around the flow:

`Kind 101 instruction -> Kind 102 envelope -> verifier -> admin signature -> re-verifier -> MCP bank`

## Modules

- `apps/frontend`: React demo page for transferor, recipient, and administrator views
- `services/event-service`: flow event write/read service for Kind `101/102/103/104/105/107`
- `services/archive-service`: independent append-only archive service for Kind `106`
- `services/verifier`: governance decision service for first-pass and second-pass verification
- `services/mcp-bank`: bank-style transfer execution service with accounts and balances
- `packages/protocol`: shared ATP-style event envelope types and helpers

## Storage

The demo now uses one centralized database file with separated logical domains:

- shared database file: `data/safr-atp-demo.sqlite`
- `event-service` writes only `event_events` and `event_tags`
- `archive-service` writes only `archive_records` and `archive_entities`
- `mcp-bank` writes only `bank_accounts` and `bank_transactions`

This keeps services decoupled while storing event data and archive data in one managed place.

### Migrations

Initialize or upgrade the centralized database:

```bash
npm run db:migrate
```

This applies the built-in schema migrations and seeds a default verifier policy bundle.

### Verifier Policy

The verifier no longer hardcodes the `1000 USD` threshold in code. It now reads:

- `policy_bundles`: active governance bundle metadata
- `verifier_policies`: transfer policy for a currency

Default seeded policy:

- `USD`
- auto execute below `1000.00`
- admin review at or above `1000.00`
- allowed currencies `["USD", "SGD"]`
- recipient allowlist required `true`

## Run

```bash
npm install
npm run dev --workspace @safr-x-atp-demo/event-service
npm run dev --workspace @safr-x-atp-demo/archive-service
npm run dev --workspace @safr-x-atp-demo/verifier
npm run dev --workspace @safr-x-atp-demo/mcp-bank
npm run dev --workspace @safr-x-atp-demo/frontend
```

Frontend default URL:

- `http://localhost:4173`

Service ports:

- `4101` event-service
- `4102` archive-service
- `4103` verifier
- `4104` mcp-bank
