# Testing Guide

This guide covers how to verify that OpenShart works correctly — from a 30-second local check to full distributed testing across multiple machines with a shared Postgres backend.

## Quick Start (Local, ~30 seconds)

```bash
git clone https://github.com/bcharleson/openshart.git
cd openshart
npm install
npm test
```

You should see **64 tests passing** across 6 unit test suites (the 7th suite, Postgres integration, auto-skips without `OPENSHART_PG_URL`). If all pass, the core cryptographic pipeline (Shamir's Secret Sharing, AES-256-GCM, HKDF key derivation, searchable encryption) is working correctly on your machine.

## Test Suites

| Suite | File | Tests | What It Validates |
|-------|------|-------|-------------------|
| **Smoke** | `test/smoke.test.ts` | 9 | Full store → recall → search → forget lifecycle, large content, unicode |
| **Crypto** | `test/crypto.test.ts` | 17 | Shamir split/reconstruct, AES-GCM encrypt/decrypt, HKDF key derivation, fragment engine end-to-end |
| **PII** | `test/pii.test.ts` | 13 | PII detection (SSN, email, phone, IP, financial), redaction, auto-classification, fragmentation scaling |
| **Security Levels** | `test/security-levels.test.ts` | 8 | Standard/enterprise/government/classified modes, ChainLock protocol, Bell-LaPadula enforcement |
| **Audit** | `test/audit.test.ts` | 6 | Audit logging, SHA-256 hash chain integrity, tamper evidence |
| **Edge Cases** | `test/edge-cases.test.ts` | 11 | Key validation, TTL/expiry, concurrent operations, encryption key isolation, cryptographic erasure |
| **Postgres** | `test/postgres.integration.test.ts` | 6 | Full pipeline against a real Postgres database (auto-skipped without config) |

## Available Commands

```bash
npm test              # Run all unit tests — 64 tests, in-memory backend
npm run validate      # Quick 13-check end-to-end validation
npm run test:watch    # Watch mode — re-runs on file changes
npm run test:coverage # Run with coverage report
npm run test:pg       # Run Postgres integration tests (requires OPENSHART_PG_URL)
npm run test:distributed  # Run distributed multi-node test (requires Postgres + shared key)
npm run lint          # Type-check without emitting
```

---

## Level 1: Unit Tests (In-Memory)

These use the in-memory storage backend and require zero infrastructure. They validate that the entire cryptographic pipeline works: plaintext → Shamir split → AES-256-GCM encrypt → store → retrieve → decrypt → Shamir reconstruct → plaintext.

```bash
npm test
```

**What "passing" proves:**
- Shamir's Secret Sharing correctly splits and reconstructs secrets from any K-of-N combination
- AES-256-GCM encryption/decryption works with tamper detection
- HKDF derives unique, deterministic keys per fragment
- PII detection identifies sensitive data and scales fragmentation accordingly
- Searchable encryption (HMAC tokens) finds content without decrypting
- Audit hash chain maintains integrity
- Different encryption keys produce complete data isolation

---

## Level 2: Postgres Integration Tests

These test the full pipeline against a real Postgres database, proving that encrypted fragments survive serialization to/from BYTEA columns and that queries work across the schema.

### Option A: Local Postgres (Docker)

```bash
# Start a local Postgres
docker run -d --name openshart-pg \
  -e POSTGRES_USER=openshart \
  -e POSTGRES_PASSWORD=testpass \
  -e POSTGRES_DB=openshart_test \
  -p 5432:5432 \
  postgres:17

# Run the tests
OPENSHART_PG_URL=postgres://openshart:testpass@localhost:5432/openshart_test npm run test:pg

# Clean up
docker stop openshart-pg && docker rm openshart-pg
```

### Option B: DigitalOcean Managed Postgres

See [Distributed Testing](#level-3-distributed-testing-multiple-machines) below — the same Postgres instance serves both integration and distributed tests.

### Option C: Any Postgres (Supabase, Neon, RDS, etc.)

```bash
OPENSHART_PG_URL=postgres://user:password@host:port/dbname?sslmode=require npm run test:pg
```

The test creates and cleans up its own `openshart_test` schema. It does not touch other data.

**What "passing" proves:**
- Encrypted fragments correctly round-trip through Postgres BYTEA columns
- Metadata, search tokens, and audit entries persist correctly
- Connection pooling and auto-migration work
- Encryption key isolation holds at the database level

---

## Level 3: Distributed Testing (Multiple Machines)

This is the real test — proving that multiple agents on different machines can share encrypted memory through a common Postgres backend. Agent A stores a memory on Machine 1, and Agent B recalls it on Machine 2.

### Architecture

```
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│  Machine 1        │    │  Machine 2        │    │  Machine 3        │
│  (Mac Mini)       │    │  (Mac Mini)       │    │  (DO Droplet)     │
│                   │    │                   │    │                   │
│  AGENT_ID=mini-1  │    │  AGENT_ID=mini-2  │    │  AGENT_ID=drop-1  │
│  Same shared key  │    │  Same shared key  │    │  Same shared key  │
└────────┬──────────┘    └────────┬──────────┘    └────────┬──────────┘
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  │
                         ┌────────▼────────┐
                         │   Postgres DB    │
                         │   (shared)       │
                         └─────────────────┘
```

### What the distributed test validates

1. **Cross-node store/recall** — Agent A stores, Agent B recalls the same memory
2. **Cross-node search** — HMAC search tokens are deterministic across machines (same key = same token)
3. **Encryption key isolation** — A different key on the same DB cannot read anyone's data
4. **Cross-node forget** — Cryptographic erasure propagates (forgotten = gone for everyone)
5. **Audit trail** — All operations from all agents logged with hash chain

### Step 1: Provision a Shared Postgres

You need one Postgres instance accessible from all machines. Pick any option:

**DigitalOcean Managed Postgres (recommended for testing):**

```bash
# Prerequisites
brew install doctl jq   # macOS
doctl auth init          # paste your DO API token

# One-command setup — creates DB, user, outputs connection string + shared key
./scripts/setup-digitalocean.sh
```

This creates a managed Postgres cluster (~$15/month), a database, a user, and generates a shared encryption key. It saves everything to `.env.distributed`.

**Docker (if all machines are on the same network):**

```bash
docker run -d --name openshart-pg \
  -e POSTGRES_USER=openshart \
  -e POSTGRES_PASSWORD=<strong-password> \
  -e POSTGRES_DB=openshart \
  -p 5432:5432 \
  postgres:17
```

**Any cloud Postgres** (Supabase, Neon, RDS, etc.) works — you just need a connection string.

### Step 2: Generate a Shared Encryption Key

All agents must use the **exact same encryption key**. Generate one and share it securely:

```bash
# Generate a 256-bit key (64 hex characters)
openssl rand -hex 32
```

Save this key. Every machine in the test needs it.

### Step 3: Set Up Each Machine

On **every machine** (Mac Minis, DO droplets, etc.):

```bash
# Clone the repo
git clone https://github.com/bcharleson/openshart.git
cd openshart

# Install dependencies
npm install

# Verify the build
npm run lint

# Run unit tests to make sure this machine works
npm test
```

Then set the environment variables. You can export them directly or create a `.env.distributed` file:

```bash
export OPENSHART_PG_URL="postgres://openshart:password@db-host:port/openshart?sslmode=require"
export OPENSHART_SHARED_KEY="<64-hex-char-key-from-step-2>"
export AGENT_COUNT=3  # total number of machines in the test
```

### Step 4: Run the Distributed Test

Start the test on **all machines at roughly the same time** (within ~2 minutes of each other). Each agent writes its memories, then waits for all other agents before proceeding to cross-reads.

```bash
# Machine 1 (Mac Mini 1)
AGENT_ID=mac-mini-1 npm run test:distributed

# Machine 2 (Mac Mini 2)
AGENT_ID=mac-mini-2 npm run test:distributed

# Machine 3 (DO Droplet)
AGENT_ID=do-droplet-1 npm run test:distributed
```

Each machine will output a report:

```
══════════════════════════════════════════════════
  Agent: mac-mini-1
  Passed: 19
  Failed: 0
  Total:  19
  Result: ✅ ALL PASSED
══════════════════════════════════════════════════
```

### Step 5: Secure the Database (Post-Testing)

If using DigitalOcean, restrict access to only your machine IPs:

```bash
CLUSTER_ID=$(doctl databases list --format ID,Name --no-header | grep openshart-db | awk '{print $1}')
doctl databases firewalls append $CLUSTER_ID --rule ip_addr:<MACHINE_1_IP>
doctl databases firewalls append $CLUSTER_ID --rule ip_addr:<MACHINE_2_IP>
doctl databases firewalls append $CLUSTER_ID --rule ip_addr:<MACHINE_3_IP>
```

### Teardown

```bash
# DigitalOcean — delete the DB cluster
doctl databases delete <CLUSTER_ID>

# Docker — stop and remove
docker stop openshart-pg && docker rm openshart-pg
```

---

## CI / GitHub Actions

Tests run automatically on every push and pull request. The CI workflow runs unit tests on Node 20 and 22.

To add Postgres integration tests to CI, set the `OPENSHART_PG_URL` secret in your GitHub repository settings.

---

## Writing New Tests

Tests use [Vitest](https://vitest.dev/) and follow these conventions:

**File naming:** `test/<area>.test.ts` for unit tests, `test/<area>.integration.test.ts` for tests requiring infrastructure.

**Auto-skip pattern for infrastructure tests:**

```typescript
const PG_URL = process.env['OPENSHART_PG_URL'];

describe.skipIf(!PG_URL)('My Postgres Test', () => {
  // Tests here run ONLY when OPENSHART_PG_URL is set.
  // They are silently skipped otherwise.
});
```

**Boilerplate for a new OpenShart test:**

```typescript
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import { OpenShart } from '../src/core/openshart.js';
import { MemoryBackend } from '../src/storage/memory.js';

describe('My Feature', () => {
  let shart: OpenShart;

  beforeEach(async () => {
    shart = await OpenShart.init({
      storage: new MemoryBackend(),
      encryptionKey: randomBytes(32),
    });
  });

  afterEach(async () => {
    await shart.close();
  });

  it('should do the thing', async () => {
    const result = await shart.store('test content');
    const memory = await shart.recall(result.id);
    expect(memory.content).toBe('test content');
  });
});
```

**Security levels to test against:**

```typescript
// Standard — no ChainLock, no FIPS
{ securityLevel: 'standard' }

// Enterprise — key entropy validation
{ securityLevel: 'enterprise' }

// Government — ChainLock enabled, FIPS mode
{ securityLevel: 'government' }

// Classified — ChainLock + Bell-LaPadula + increased fragmentation
{ securityLevel: 'classified', clearance: { maxClassification: Classification.TOP_SECRET, compartments: [] } }
```

---

## Troubleshooting

**`npm test` fails with Shamir reconstruction errors:**
Make sure you're on the latest version. An earlier release had a bug in the GF(2^8) field arithmetic lookup tables (generator order 51 instead of 255) that caused silent data corruption during Shamir reconstruction.

**Postgres tests skip silently:**
Set the `OPENSHART_PG_URL` environment variable. Tests auto-skip when it's not present.

**Distributed test hangs at "Waiting for other agents":**
All agents must be started within the 2-minute wait window. Check that `AGENT_COUNT` matches the actual number of nodes you're running.

**`pg is required for PostgresBackend`:**
Run `npm install pg` — it's a peer dependency.

**`better-sqlite3` build fails:**
The SQLite backend requires native compilation. On macOS: `xcode-select --install`. On Linux: `apt-get install build-essential python3`.

**`encryption key has insufficient entropy`:**
The key must have at least 8 unique bytes. Use `openssl rand -hex 32` or `crypto.randomBytes(32)` to generate a proper key. Do not use test keys like `Buffer.alloc(32, 0x42)`.
