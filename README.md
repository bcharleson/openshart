# Engram

> **Enterprise-grade encrypted memory framework for AI agents.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![npm](https://img.shields.io/npm/v/engram)](https://www.npmjs.com/package/engram)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20%2B-green)](https://nodejs.org)

Fragmented, encrypted, searchable memory with **enterprise hierarchical access control**. SOC2 and HIPAA compliant by design.

---

## Why Engram?

AI agents accumulate context — conversations, user preferences, business data, PII. Today that context is stored in plaintext vector databases. That's a liability.

Engram treats agent memory the way it should be treated: **fragmented, encrypted, and reconstructable only by authorized entities**. No single storage location holds a complete memory. No database breach reveals usable data. Enterprise hierarchy controls who sees what.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     AGENT APPLICATION                        │
│  (Any framework: OpenClaw, LangChain, CrewAI, custom)        │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                       ENGRAM SDK                             │
│                                                              │
│  ┌─────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌──────────┐│
│  │  STORE  │ │ SEARCH │ │ RECALL │ │ FORGET │ │HIERARCHY ││
│  └────┬────┘ └───┬────┘ └───┬────┘ └───┬────┘ └────┬─────┘│
│       │          │          │          │           │        │
│  ┌────▼──────────▼──────────▼──────────▼───────────▼──────┐│
│  │              PII DETECTION + CLASSIFICATION             ││
│  │   emails · phones · SSNs · credit cards · PHI · names   ││
│  └──────────────────────────┬──────────────────────────────┘│
│                             │                                │
│  ┌──────────────────────────▼──────────────────────────────┐│
│  │                   FRAGMENT ENGINE                        ││
│  │   Shamir's Secret Sharing (K-of-N) → AES-256-GCM       ││
│  └──────────────────────────┬──────────────────────────────┘│
│                             │                                │
│  ┌──────────────┐  ┌───────▼──────┐  ┌───────────────────┐ │
│  │ SEARCH INDEX │  │  AUDIT LOG   │  │ ENTERPRISE ACCESS │ │
│  │ (HMAC-SHA256)│  │ (hash chain) │  │  (hierarchy keys) │ │
│  └──────┬───────┘  └──────┬───────┘  └───────┬───────────┘ │
└─────────┼─────────────────┼──────────────────┼──────────────┘
          │                 │                  │
          ▼                 ▼                  ▼
┌─────────────────────────────────────────────────────────────┐
│                    STORAGE BACKEND                           │
│  ┌──────────┐  ┌────────────┐  ┌──────────┐                │
│  │  SQLite  │  │ PostgreSQL │  │  Memory  │                │
│  │(default) │  │(production)│  │ (testing)│                │
│  └──────────┘  └────────────┘  └──────────┘                │
└─────────────────────────────────────────────────────────────┘
```

## Install

```bash
npm install engram
```

## Quickstart

```typescript
import { Engram, MemoryBackend } from 'engram';
import { randomBytes } from 'node:crypto';

// Initialize with an in-memory backend
const engram = await Engram.init({
  storage: new MemoryBackend(),
  encryptionKey: randomBytes(32),
});

// Store — auto-detects PII, fragments, and encrypts
const { id, piiLevel, detectedPII } = await engram.store(
  'Customer John (john@acme.com) approved $150k budget for Q3',
  { tags: ['customer', 'budget'] }
);
// piiLevel: 'CRITICAL', detectedPII: ['EMAIL', 'FINANCIAL']

// Search — encrypted, never decrypts content
const results = await engram.search('budget');

// Recall — reconstructs in-memory only
const memory = await engram.recall(id);
console.log(memory.content);

// Forget — cryptographic erasure (GDPR Article 17)
await engram.forget(id);

await engram.close();
```

## Enterprise Hierarchy

The key differentiator: **context flows DOWN, intelligence flows UP**.

```typescript
import { ContextFlowManager, DepartmentManager, KeyChain, Role } from 'engram';

const departments = new DepartmentManager();
departments.registerDepartment({
  id: 'engineering',
  name: 'Engineering',
  encryptionNamespace: 'eng-ns-2026',
});
departments.registerDepartment({
  id: 'sales',
  name: 'Sales',
  encryptionNamespace: 'sales-ns-2026',
});

const flow = new ContextFlowManager(departments);

// CEO shares strategy downward — PII auto-redacted for lower roles
const pushed = flow.pushDown(
  'Q3 target: $2M ARR. Contact jane@corp.com for details.',
  Role.EXECUTIVE,
  Role.CONTRIBUTOR,
);
// pushed.content: 'Q3 target: [FINANCIAL_REDACTED] ARR. Contact [EMAIL_REDACTED] for details.'

// IC intelligence bubbles up — PII stripped automatically
const bubbled = flow.bubbleUp(
  'Agent found that user john@example.com prefers dark mode',
  Role.AGENT,
  Role.DIRECTOR,
);
// bubbled.content: 'Agent found that user [EMAIL_REDACTED] prefers dark mode'

// Temporary cross-department access
flow.grantLateral('sales-agent-1', 'eng-agent-2', 'sales', 'engineering', ['api-docs'], 3600000);
```

## API Reference

### `Engram.init(options)`

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `storage` | `StorageBackend` | ✅ | Storage backend instance |
| `encryptionKey` | `Buffer` | ✅ | 32-byte master key |
| `agentId` | `string` | | Agent identifier for audit |
| `role` | `Role` | | Agent's hierarchy role |
| `department` | `string` | | Agent's department |
| `pii` | `PIIConfig` | | PII detection settings |
| `fragment` | `FragmentConfig` | | Fragment engine overrides |
| `audit` | `AuditConfig` | | Audit logging settings |

### `engram.store(content, options?)`

Stores a memory. Auto-detects PII, adjusts fragment parameters accordingly.

### `engram.search(query, options?)`

Searches using HMAC tokens. Never decrypts content. Returns metadata only.

### `engram.recall(memoryId)`

Reconstructs memory from encrypted fragments. Plaintext exists only in-memory.

### `engram.forget(memoryId)`

Cryptographic erasure. Overwrites fragments with random data, purges search tokens, logs to audit chain.

### `engram.list(filters?)`

Lists memory metadata with optional filters (tags, PII level, date range).

### `engram.export(filters?)`

Exports audit log entries for compliance reporting.

### `engram.verifyAuditChain()`

Verifies the tamper-evident hash chain integrity.

## Security Model

| Threat | Mitigation |
|--------|-----------|
| Database breach | Content fragmented via Shamir's SSS + AES-256-GCM encrypted |
| Admin reads data | Per-fragment derived keys via HKDF. Admin sees only ciphertext |
| Search interception | Queries are HMAC-SHA256 tokens. Zero plaintext exposure |
| Partial fragment leak | K-1 shares reveal zero information (information-theoretic) |
| Audit tampering | SHA-256 hash chain — any modification invalidates the chain |
| Cross-department access | Department encryption namespaces + explicit access grants |

## Compliance

- **GDPR Article 17**: `forget()` implements cryptographic erasure with audit trail
- **HIPAA**: PHI detection, minimum necessary standard enforcement
- **SOC2**: Automated compliance checks, access logging, encryption verification

## Storage Backends

| Backend | Use Case | Install |
|---------|----------|---------|
| `MemoryBackend` | Testing | Built-in |
| `SQLiteBackend` | Development, single-agent | `npm install better-sqlite3` |
| `PostgresBackend` | Production | `npm install pg` |

## Contributing

```bash
git clone https://github.com/bcharleson/engram.git
cd engram
npm install
npm test
```

- TypeScript strict mode
- ESM only
- All crypto via Node.js built-in `crypto` module
- No `any` types
- Conventional commits

## License

MIT
