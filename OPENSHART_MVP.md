# OpenShart — MVP Specification

> **The secure memory layer for AI agents.**
> Fragmented, encrypted, searchable — enterprise-grade context security for PII, business intelligence, and agent cognition.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![npm](https://img.shields.io/npm/v/openshart)](https://www.npmjs.com/package/openshart)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)](https://www.typescriptlang.org/)

---

## Table of Contents

1. [Vision](#vision)
2. [Architecture Overview](#architecture-overview)
3. [The Four Operations](#the-four-operations)
4. [Technical Stack](#technical-stack)
5. [TypeScript Interfaces](#typescript-interfaces)
6. [Core SDK API](#core-sdk-api)
7. [PII Auto-Detection](#pii-auto-detection)
8. [Fragment Engine](#fragment-engine)
9. [Searchable Encryption](#searchable-encryption)
10. [Storage Backends](#storage-backends)
11. [Audit Log](#audit-log)
12. [Integration Examples](#integration-examples)
13. [Repository Structure](#repository-structure)
14. [Quickstart](#quickstart)
15. [Security Model](#security-model)
16. [Compliance](#compliance)
17. [Roadmap](#roadmap)
18. [Contributing](#contributing)

---

## Vision

AI agents accumulate context — conversations, user preferences, business data, PII. Today that context is stored in plaintext vector databases or ephemeral chat histories. This is a liability.

**OpenShart** treats agent memory the way biological brains treat human memory: fragmented, distributed, and reconstructable only by the entity that created it. No single storage location holds a complete memory. No database breach reveals usable data. No admin can read agent context without the agent's key.

### Design Principles

1. **Fragment everything** — No complete memory exists in any single location
2. **Encrypt at rest, in transit, and in search** — Even queries don't reveal what you're looking for
3. **Agent-sovereign keys** — Only the agent (or its operator) can reconstruct memories
4. **Zero framework lock-in** — Works with any agent framework or none at all
5. **Compliance by default** — GDPR Article 17 (right to erasure) is a first-class operation, not an afterthought

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AGENT APPLICATION                            │
│  (OpenClaw, LangChain, CrewAI, custom)                              │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         OPENSHART SDK                                  │
│                                                                     │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐       │
│  │   STORE   │  │  SEARCH   │  │  RECALL   │  │  FORGET   │       │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘       │
│        │              │              │              │               │
│        ▼              ▼              ▼              ▼               │
│  ┌─────────────────────────────────────────────────────────┐       │
│  │                   PII DETECTOR                          │       │
│  │  emails · phones · SSNs · credit cards · names · addrs  │       │
│  └─────────────────────────┬───────────────────────────────┘       │
│                            │                                        │
│                            ▼                                        │
│  ┌─────────────────────────────────────────────────────────┐       │
│  │                  FRAGMENT ENGINE                         │       │
│  │         Shamir's Secret Sharing (K-of-N)                │       │
│  │     AES-256-GCM per-fragment encryption                 │       │
│  └─────────────────────────┬───────────────────────────────┘       │
│                            │                                        │
│                            ▼                                        │
│  ┌──────────────────┐  ┌──────────────────┐                        │
│  │  SEARCH INDEX    │  │   AUDIT LOG      │                        │
│  │  (HMAC tokens)   │  │  (hash chain)    │                        │
│  └────────┬─────────┘  └────────┬─────────┘                        │
│           │                     │                                   │
└───────────┼─────────────────────┼───────────────────────────────────┘
            │                     │
            ▼                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      STORAGE BACKEND                                │
│                                                                     │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────┐               │
│  │   SQLite    │  │  PostgreSQL   │  │   Memory    │               │
│  │  (default)  │  │ (production)  │  │  (testing)  │               │
│  └─────────────┘  └──────────────┘  └─────────────┘               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Data Flow: Storing a Memory

```
"User John (john@acme.com) prefers dark mode and has budget $50k"
                               │
                    ┌──────────▼──────────┐
                    │   PII Detection     │
                    │                     │
                    │  "john@acme.com" ── │── EMAIL (HIGH)
                    │  "$50k" ────────── │── FINANCIAL (CRITICAL)
                    │  "John" ─────────  │── NAME (MEDIUM)
                    │                     │
                    │  Classification:    │
                    │  CRITICAL           │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Fragment Engine     │
                    │                     │
                    │  CRITICAL → 5-of-8  │
                    │  Split into 8       │
                    │  fragments via SSS  │
                    │                     │
                    │  Each fragment:     │
                    │  • Unique AES key   │
                    │  • Unique IV        │
                    │  • Encrypted        │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
        ┌──────────┐   ┌──────────┐     ┌──────────┐
        │ Frag 1/8 │   │ Frag 2/8 │ ... │ Frag 8/8 │
        │ Slot A   │   │ Slot B   │     │ Slot H   │
        └──────────┘   └──────────┘     └──────────┘
              │                │                │
              └────────────────┼────────────────┘
                               ▼
                    ┌──────────────────────┐
                    │  Search Index        │
                    │  HMAC("dark mode")   │
                    │  HMAC("budget")      │
                    │  HMAC("preferences") │
                    │  → Fragment IDs      │
                    └──────────────────────┘
```

---

## The Four Operations

### 1. STORE

Agent writes a memory. OpenShart:
1. Scans content for PII → auto-classifies sensitivity level
2. Generates search tokens (HMAC-based) from content keywords and provided tags
3. Splits plaintext into N shares via Shamir's Secret Sharing
4. Encrypts each share with a unique AES-256-GCM derived key
5. Distributes encrypted fragments across storage slots
6. Writes search index entries (token → fragment IDs mapping)
7. Appends to audit log with cryptographic hash chain

### 2. SEARCH

Agent queries memories. OpenShart:
1. Generates HMAC search token from query
2. Looks up matching fragment IDs in the encrypted search index — **content is never decrypted during search**
3. Returns metadata (memory ID, tags, timestamp, PII level) without content
4. Agent decides which memories to RECALL

### 3. RECALL

Agent retrieves a specific memory. OpenShart:
1. Fetches K-of-N fragments from storage
2. Decrypts each fragment with derived keys
3. Reassembles original content via Shamir reconstruction
4. Returns plaintext to agent **in-memory only**
5. Plaintext is never written to disk during recall

### 4. FORGET

Agent (or compliance process) deletes a memory. OpenShart:
1. Identifies all N fragments for the memory
2. Cryptographically destroys each fragment (overwrite + delete)
3. Purges all search index entries referencing the memory
4. Records deletion in audit log (tamper-evident)
5. Returns confirmation with audit receipt

This is **GDPR Article 17 compliant** by design — deletion is cryptographic, verifiable, and auditable.

---

## Technical Stack

| Component | Technology | Rationale |
|---|---|---|
| Language | TypeScript 5.x (ESM) | Matches agent ecosystem (OpenClaw, LangChain.js) |
| Runtime | Node.js 20+ | LTS, broad compatibility |
| Fragment encryption | AES-256-GCM | Authenticated encryption, hardware-accelerated |
| Secret sharing | Shamir's Secret Sharing | Information-theoretic security, configurable threshold |
| Search encryption | HMAC-SHA256 tokens | Searchable Symmetric Encryption (SSE) |
| Key derivation | HKDF-SHA256 | Per-fragment key derivation from master key |
| Default storage | better-sqlite3 | Zero-config, embedded, fast |
| Production storage | pg (node-postgres) | Connection pooling, LISTEN/NOTIFY for events |
| Test storage | In-memory Map | Zero setup, deterministic |
| Package manager | npm | Universal distribution |

### Dependencies (minimal)

```
openshart
├── better-sqlite3     # SQLite backend (optional peer dep)
├── pg                 # Postgres backend (optional peer dep)
└── (no other runtime dependencies)
```

All cryptographic operations use Node.js built-in `crypto` module. No external crypto libraries.

---

## TypeScript Interfaces

```typescript
// ─── Core Types ───────────────────────────────────────────────

/** Sensitivity classification for stored content */
export enum PIILevel {
  /** No PII detected */
  LOW = 'LOW',
  /** Business PII: company names, job titles, business emails */
  MEDIUM = 'MEDIUM',
  /** Personal PII: personal emails, phone numbers, names, addresses */
  HIGH = 'HIGH',
  /** Financial/health PII: SSNs, credit cards, health records, financial data */
  CRITICAL = 'CRITICAL',
}

/** Unique identifier for a stored memory */
export type MemoryId = string & { readonly __brand: 'MemoryId' };

/** Unique identifier for a fragment */
export type FragmentId = string & { readonly __brand: 'FragmentId' };

/** Encrypted fragment stored in backend */
export interface EncryptedFragment {
  id: FragmentId;
  memoryId: MemoryId;
  /** Fragment index (1-based, e.g., 3 of 5) */
  index: number;
  /** Total fragments for this memory */
  total: number;
  /** AES-256-GCM encrypted Shamir share */
  ciphertext: Buffer;
  /** GCM initialization vector */
  iv: Buffer;
  /** GCM authentication tag */
  authTag: Buffer;
  /** Storage slot identifier for logical distribution */
  slot: string;
  /** ISO 8601 creation timestamp */
  createdAt: string;
}

/** Memory metadata returned by list/search (never includes content) */
export interface MemoryMeta {
  id: MemoryId;
  /** Encrypted tags (decryptable by agent) */
  tags: string[];
  piiLevel: PIILevel;
  /** Number of fragments */
  fragmentCount: number;
  /** Shamir threshold (K required to reconstruct) */
  threshold: number;
  /** ISO 8601 timestamps */
  createdAt: string;
  updatedAt: string;
  /** Expiry time (null = no expiry) */
  expiresAt: string | null;
  /** Content byte length (before encryption) */
  contentLength: number;
}

/** Reconstructed memory returned by recall */
export interface Memory {
  id: MemoryId;
  content: string;
  tags: string[];
  piiLevel: PIILevel;
  createdAt: string;
  updatedAt: string;
}

// ─── Configuration ────────────────────────────────────────────

/** Fragment engine configuration */
export interface FragmentConfig {
  /** Minimum shares needed to reconstruct (K). Default by PII level. */
  threshold?: number;
  /** Total shares generated (N). Default by PII level. */
  totalShares?: number;
  /** Number of logical storage slots. Default: totalShares */
  slots?: number;
}

/** PII detection configuration */
export interface PIIConfig {
  /** Enable/disable auto-detection. Default: true */
  enabled?: boolean;
  /** Custom PII patterns to detect */
  customPatterns?: PIIPattern[];
  /** Override default fragment config per PII level */
  fragmentOverrides?: Partial<Record<PIILevel, FragmentConfig>>;
  /** Override default TTL per PII level (ms). null = no expiry */
  ttlOverrides?: Partial<Record<PIILevel, number | null>>;
}

/** Custom PII detection pattern */
export interface PIIPattern {
  name: string;
  regex: RegExp;
  level: PIILevel;
}

/** Storage backend interface — implement this for custom backends */
export interface StorageBackend {
  /** Store an encrypted fragment */
  putFragment(fragment: EncryptedFragment): Promise<void>;
  /** Retrieve a fragment by ID */
  getFragment(id: FragmentId): Promise<EncryptedFragment | null>;
  /** Retrieve all fragments for a memory */
  getFragments(memoryId: MemoryId): Promise<EncryptedFragment[]>;
  /** Delete all fragments for a memory */
  deleteFragments(memoryId: MemoryId): Promise<number>;
  /** Store memory metadata */
  putMeta(meta: MemoryMeta): Promise<void>;
  /** Retrieve memory metadata */
  getMeta(memoryId: MemoryId): Promise<MemoryMeta | null>;
  /** Delete memory metadata */
  deleteMeta(memoryId: MemoryId): Promise<void>;
  /** List memories matching filters */
  listMeta(filters: ListFilters): Promise<MemoryMeta[]>;
  /** Store search index entry */
  putSearchToken(token: string, memoryId: MemoryId): Promise<void>;
  /** Lookup memories by search token */
  lookupSearchToken(token: string): Promise<MemoryId[]>;
  /** Delete all search tokens for a memory */
  deleteSearchTokens(memoryId: MemoryId): Promise<void>;
  /** Append audit log entry */
  appendAuditLog(entry: AuditEntry): Promise<void>;
  /** Read audit log entries */
  readAuditLog(filters: AuditFilters): Promise<AuditEntry[]>;
  /** Close connections / cleanup */
  close(): Promise<void>;
}

/** OpenShart initialization options */
export interface OpenShartOptions {
  /** Storage backend instance */
  storage: StorageBackend;
  /**
   * Master encryption key (32 bytes).
   * All fragment keys and search tokens are derived from this via HKDF.
   * NEVER log or persist this key.
   */
  encryptionKey: Buffer;
  /** Fragment engine config. Defaults are PII-level-aware. */
  fragment?: FragmentConfig;
  /** PII detection config */
  pii?: PIIConfig;
  /** Audit log config */
  audit?: AuditConfig;
}

// ─── Store Options ────────────────────────────────────────────

export interface StoreOptions {
  /** Tags for categorization and search */
  tags?: string[];
  /** Explicit PII level (overrides auto-detection) */
  piiLevel?: PIILevel;
  /** Time-to-live in milliseconds. null = no expiry. Default: PII-level-aware. */
  ttl?: number | null;
  /** Override fragment config for this memory */
  fragment?: FragmentConfig;
  /** Arbitrary metadata (stored encrypted alongside memory meta) */
  metadata?: Record<string, unknown>;
}

export interface StoreResult {
  id: MemoryId;
  piiLevel: PIILevel;
  fragmentCount: number;
  threshold: number;
  /** PII entities detected (types only, not values) */
  detectedPII: string[];
  auditId: string;
}

// ─── Search Options ───────────────────────────────────────────

export interface SearchOptions {
  /** Max results. Default: 10 */
  limit?: number;
  /** Filter by tags */
  tags?: string[];
  /** Filter by PII level (max) */
  maxPIILevel?: PIILevel;
  /** Date range filter */
  after?: Date;
  before?: Date;
}

export interface SearchResult {
  memories: MemoryMeta[];
  /** Total matching (may exceed limit) */
  total: number;
  /** Search executed without decrypting any content */
  encrypted: true;
}

// ─── List Options ─────────────────────────────────────────────

export interface ListFilters {
  tags?: string[];
  piiLevel?: PIILevel;
  after?: Date;
  before?: Date;
  limit?: number;
  offset?: number;
}

// ─── Audit Types ──────────────────────────────────────────────

export enum AuditOperation {
  STORE = 'STORE',
  SEARCH = 'SEARCH',
  RECALL = 'RECALL',
  FORGET = 'FORGET',
  EXPORT = 'EXPORT',
}

export interface AuditEntry {
  id: string;
  operation: AuditOperation;
  memoryId: MemoryId | null;
  timestamp: string;
  /** SHA-256 hash of previous entry (hash chain) */
  previousHash: string;
  /** SHA-256 hash of this entry */
  hash: string;
  /** Operation-specific details (no content, no keys) */
  details: Record<string, unknown>;
}

export interface AuditConfig {
  /** Enable audit logging. Default: true */
  enabled?: boolean;
  /** Maximum entries before rotation. Default: 100_000 */
  maxEntries?: number;
}

export interface AuditFilters {
  operation?: AuditOperation;
  memoryId?: MemoryId;
  after?: Date;
  before?: Date;
  limit?: number;
}

// ─── Forget Result ────────────────────────────────────────────

export interface ForgetResult {
  memoryId: MemoryId;
  fragmentsDestroyed: number;
  searchTokensPurged: number;
  auditId: string;
}
```

---

## Core SDK API

### Initialization

```typescript
import { OpenShart, SQLiteBackend } from 'openshart';
import { randomBytes } from 'node:crypto';

// Generate a new key (store this securely — loss = permanent data loss)
const key = randomBytes(32);

// Or load from secure storage
// const key = Buffer.from(process.env.OPENSHART_KEY!, 'hex');

const openshart = await OpenShart.init({
  storage: new SQLiteBackend({ path: './agent-memory.db' }),
  encryptionKey: key,
});
```

### openshart.store(content, options?)

Store a memory. Content is PII-scanned, fragmented, encrypted, indexed, and audited.

```typescript
const result = await openshart.store(
  'Customer John Smith (john.smith@acme.com) approved $150k budget for Q3',
  {
    tags: ['customer', 'budget', 'acme'],
    ttl: 90 * 24 * 60 * 60 * 1000, // 90 days
  }
);

console.log(result);
// {
//   id: 'mem_a1b2c3d4e5f6',
//   piiLevel: 'CRITICAL',
//   fragmentCount: 8,
//   threshold: 5,
//   detectedPII: ['EMAIL', 'PERSON_NAME', 'FINANCIAL_AMOUNT'],
//   auditId: 'aud_x1y2z3'
// }
```

### openshart.search(query, options?)

Search memories without decrypting content. Returns metadata only.

```typescript
const results = await openshart.search('budget approval', {
  tags: ['customer'],
  limit: 5,
});

console.log(results);
// {
//   memories: [
//     {
//       id: 'mem_a1b2c3d4e5f6',
//       tags: ['customer', 'budget', 'acme'],
//       piiLevel: 'CRITICAL',
//       fragmentCount: 8,
//       threshold: 5,
//       createdAt: '2026-02-17T19:00:00.000Z',
//       ...
//     }
//   ],
//   total: 1,
//   encrypted: true
// }
```

### openshart.recall(memoryId)

Retrieve and reconstruct a specific memory. Plaintext exists only in-memory.

```typescript
const memory = await openshart.recall(results.memories[0].id);

console.log(memory.content);
// 'Customer John Smith (john.smith@acme.com) approved $150k budget for Q3'

// memory.content is available in working memory only
// It is never written to disk during recall
```

### openshart.forget(memoryId)

Cryptographically destroy a memory. All fragments, search tokens, and metadata are purged.

```typescript
const forgetResult = await openshart.forget(results.memories[0].id);

console.log(forgetResult);
// {
//   memoryId: 'mem_a1b2c3d4e5f6',
//   fragmentsDestroyed: 8,
//   searchTokensPurged: 12,
//   auditId: 'aud_q9r8s7'
// }

// Attempting to recall a forgotten memory throws
await openshart.recall(forgetResult.memoryId); // throws OpenShartNotFoundError
```

### openshart.list(filters?)

List memory metadata. Never returns content.

```typescript
const metas = await openshart.list({
  tags: ['customer'],
  piiLevel: PIILevel.CRITICAL,
  after: new Date('2026-01-01'),
  limit: 20,
});
```

### openshart.export(filters?)

Export audit log for compliance reporting.

```typescript
const auditLog = await openshart.export({
  operation: AuditOperation.FORGET,
  after: new Date('2026-01-01'),
});
// Returns AuditEntry[] for compliance/legal teams
```

### openshart.close()

Gracefully close storage connections.

```typescript
await openshart.close();
```

---

## PII Auto-Detection

### Detection Pipeline

```
Input text
    │
    ▼
┌────────────────────────┐
│  Pattern Matchers      │
│                        │
│  EMAIL ────────► HIGH  │
│  PHONE ────────► HIGH  │
│  SSN ──────────► CRIT  │
│  CREDIT_CARD ──► CRIT  │
│  PERSON_NAME ──► MED   │
│  ADDRESS ──────► HIGH  │
│  DATE_OF_BIRTH ► HIGH  │
│  IP_ADDRESS ───► MED   │
│  FINANCIAL ────► CRIT  │
│  HEALTH ───────► CRIT  │
│                        │
│  Custom patterns ─► ?  │
└───────────┬────────────┘
            │
            ▼
  Highest level wins
  → determines fragment config
```

### Default Fragment Configuration by PII Level

| PII Level | Threshold (K) | Total Shares (N) | Default TTL | Use Case |
|---|---|---|---|---|
| LOW | 2 of 3 | 3 | None | General agent context, preferences |
| MEDIUM | 3 of 5 | 5 | 1 year | Business contacts, company info |
| HIGH | 4 of 7 | 7 | 180 days | Personal emails, phone numbers |
| CRITICAL | 5 of 8 | 8 | 90 days | SSNs, credit cards, health data |

### Built-in PII Patterns

```typescript
const BUILTIN_PATTERNS: PIIPattern[] = [
  // Email addresses
  { name: 'EMAIL', regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, level: PIILevel.HIGH },

  // US phone numbers
  { name: 'PHONE_US', regex: /(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g, level: PIILevel.HIGH },

  // US Social Security Numbers
  { name: 'SSN', regex: /\b\d{3}-\d{2}-\d{4}\b/g, level: PIILevel.CRITICAL },

  // Credit card numbers (Luhn-validated at runtime)
  { name: 'CREDIT_CARD', regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g, level: PIILevel.CRITICAL },

  // Financial amounts
  { name: 'FINANCIAL', regex: /\$\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?(?:\s?[kKmMbB])?/g, level: PIILevel.CRITICAL },

  // IP addresses
  { name: 'IP_ADDRESS', regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, level: PIILevel.MEDIUM },

  // Dates of birth (common formats)
  { name: 'DOB', regex: /\b(?:0[1-9]|1[0-2])[\/\-](?:0[1-9]|[12]\d|3[01])[\/\-](?:19|20)\d{2}\b/g, level: PIILevel.HIGH },

  // US addresses (simplified)
  { name: 'ADDRESS', regex: /\b\d{1,5}\s+[\w\s]+(?:St|Ave|Blvd|Dr|Rd|Ln|Way|Ct|Pl)\.?\b/gi, level: PIILevel.HIGH },
];
```

### Custom PII Patterns

```typescript
const openshart = await OpenShart.init({
  storage: new SQLiteBackend(),
  encryptionKey: key,
  pii: {
    customPatterns: [
      {
        name: 'EMPLOYEE_ID',
        regex: /EMP-\d{6}/g,
        level: PIILevel.MEDIUM,
      },
      {
        name: 'MEDICAL_RECORD',
        regex: /MRN-\d{8}/g,
        level: PIILevel.CRITICAL,
      },
    ],
  },
});
```

---

## Fragment Engine

### Shamir's Secret Sharing

OpenShart uses Shamir's Secret Sharing (SSS) over GF(2^8) to split memory content into N shares where any K shares can reconstruct the original.

```
Original: "Hello World"  (K=3, N=5)
                │
    ┌───────────┼───────────┐
    │     Shamir Split      │
    │   polynomial degree   │
    │       K-1 = 2         │
    └───────────┬───────────┘
                │
    ┌───┬───┬───┬───┬───┐
    │ S1│ S2│ S3│ S4│ S5│   ← 5 shares
    └─┬─┘ └─┬─┘ └─┬─┘ └─┘
      │     │     │
      │     │     │         ← Any 3 reconstruct
      ▼     ▼     ▼
    ┌───────────────────┐
    │  Lagrange interp  │
    │  → "Hello World"  │
    └───────────────────┘
```

### Per-Fragment Encryption

Each Shamir share is independently encrypted before storage:

```typescript
// Pseudocode for fragment encryption
function encryptFragment(share: Buffer, masterKey: Buffer, memoryId: string, index: number): EncryptedFragment {
  // Derive unique key for this fragment via HKDF
  const fragmentKey = hkdf(masterKey, {
    salt: memoryId,
    info: `openshart-fragment-${index}`,
    length: 32,
  });

  // Encrypt with AES-256-GCM
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', fragmentKey, iv);
  const ciphertext = Buffer.concat([cipher.update(share), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return { ciphertext, iv, authTag, /* ... */ };
}
```

### Logical Slot Distribution

Even with a single storage backend, fragments are distributed across logical slots. This means:
- Fragments have different derived keys
- Fragments are stored in separate logical partitions (tables/rows/prefixes)
- Compromising one slot reveals nothing about the memory

```
Memory mem_abc123 (CRITICAL → 5-of-8)
    │
    ├── Slot A: Fragment 1 (key derived from masterKey + "mem_abc123" + "1")
    ├── Slot B: Fragment 2 (key derived from masterKey + "mem_abc123" + "2")
    ├── Slot C: Fragment 3 (...)
    ├── Slot D: Fragment 4
    ├── Slot E: Fragment 5
    ├── Slot F: Fragment 6
    ├── Slot G: Fragment 7
    └── Slot H: Fragment 8
```

---

## Searchable Encryption

### HMAC-Based Search Tokens

OpenShart implements a simplified Searchable Symmetric Encryption (SSE) scheme using HMAC-SHA256 tokens.

```
Search query: "budget approval"
                │
                ▼
┌──────────────────────────────┐
│  Tokenization                │
│  → ["budget", "approval"]    │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│  HMAC Token Generation       │
│                              │
│  searchKey = HKDF(master,    │
│    info="openshart-search")     │
│                              │
│  token("budget") =           │
│    HMAC-SHA256(searchKey,    │
│    "budget")                 │
│    → "a3f8c2..."            │
│                              │
│  token("approval") =         │
│    HMAC-SHA256(searchKey,    │
│    "approval")               │
│    → "7b1d9e..."            │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│  Index Lookup                │
│                              │
│  "a3f8c2..." → [mem_abc123]  │
│  "7b1d9e..." → [mem_abc123]  │
│                              │
│  Intersection:               │
│  → [mem_abc123]              │
└──────────────────────────────┘
```

### Token Generation at Store Time

When a memory is stored, OpenShart:
1. Tokenizes the content (word-level + n-grams)
2. Generates HMAC tokens for each search term
3. Generates HMAC tokens for each tag
4. Stores `token → memoryId` mappings in the search index

### Search Security Properties

- **Tokens are deterministic** — same word always produces the same token (enables exact match)
- **Tokens are one-way** — knowing a token reveals nothing about the original word
- **No content decryption during search** — only HMAC comparisons on tokens
- **Query pattern leakage** — repeated searches for the same term are linkable (acceptable for MVP; addressed in v0.3 with oblivious search)

### Tag Encryption

Tags are encrypted for storage but searchable via HMAC tokens:

```typescript
// Store time
const encryptedTag = encrypt(tag, tagKey);     // stored in meta
const tagToken = hmac(searchKey, `tag:${tag}`); // stored in index

// Search time
const queryToken = hmac(searchKey, `tag:${queriedTag}`);
// Lookup queryToken in index → matching memory IDs
```

---

## Storage Backends

### StorageBackend Interface

Any storage backend implements the `StorageBackend` interface (defined above in [TypeScript Interfaces](#typescript-interfaces)). This enables:

- Swapping backends without changing application code
- Custom backends for specialized infrastructure
- Testing with in-memory backend

### SQLiteBackend (Default)

Zero-config local storage. Perfect for development, single-agent deployments, and CLI tools.

```typescript
import { SQLiteBackend } from 'openshart';

const storage = new SQLiteBackend({
  /** Database file path. Default: './openshart.db' */
  path: './agent-memory.db',
  /** Enable WAL mode for better concurrency. Default: true */
  wal: true,
  /** Run PRAGMA optimize on close. Default: true */
  optimize: true,
});
```

**Schema:**

```sql
CREATE TABLE fragments (
  id TEXT PRIMARY KEY,
  memory_id TEXT NOT NULL,
  idx INTEGER NOT NULL,
  total INTEGER NOT NULL,
  ciphertext BLOB NOT NULL,
  iv BLOB NOT NULL,
  auth_tag BLOB NOT NULL,
  slot TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE memory_meta (
  id TEXT PRIMARY KEY,
  tags_encrypted BLOB,
  pii_level TEXT NOT NULL,
  fragment_count INTEGER NOT NULL,
  threshold INTEGER NOT NULL,
  content_length INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  expires_at TEXT
);

CREATE TABLE search_index (
  token TEXT NOT NULL,
  memory_id TEXT NOT NULL,
  PRIMARY KEY (token, memory_id)
);

CREATE TABLE audit_log (
  id TEXT PRIMARY KEY,
  operation TEXT NOT NULL,
  memory_id TEXT,
  timestamp TEXT NOT NULL,
  previous_hash TEXT NOT NULL,
  hash TEXT NOT NULL,
  details TEXT NOT NULL
);

CREATE INDEX idx_fragments_memory ON fragments(memory_id);
CREATE INDEX idx_meta_pii ON memory_meta(pii_level);
CREATE INDEX idx_meta_expires ON memory_meta(expires_at);
CREATE INDEX idx_search_token ON search_index(token);
CREATE INDEX idx_audit_ts ON audit_log(timestamp);
```

### PostgresBackend

Production backend with connection pooling.

```typescript
import { PostgresBackend } from 'openshart/backends/postgres';

const storage = new PostgresBackend({
  connectionString: process.env.DATABASE_URL!,
  /** Connection pool size. Default: 10 */
  poolSize: 10,
  /** Schema name. Default: 'openshart' */
  schema: 'openshart',
  /** Run migrations on init. Default: true */
  autoMigrate: true,
});
```

### MemoryBackend

In-memory only — perfect for unit tests.

```typescript
import { MemoryBackend } from 'openshart';

const storage = new MemoryBackend();
// All data lost when process exits
```

---

## Audit Log

### Hash Chain

Every audit entry includes a SHA-256 hash of the previous entry, forming a tamper-evident chain:

```
Entry 1                    Entry 2                    Entry 3
┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│ id: aud_001      │      │ id: aud_002      │      │ id: aud_003      │
│ op: STORE        │      │ op: SEARCH       │      │ op: FORGET       │
│ prevHash: "0000" │─────►│ prevHash: hash(1)│─────►│ prevHash: hash(2)│
│ hash: SHA256(    │      │ hash: SHA256(    │      │ hash: SHA256(    │
│   this entry)    │      │   this entry)    │      │   this entry)    │
└──────────────────┘      └──────────────────┘      └──────────────────┘
```

If any entry is modified after the fact, all subsequent hashes become invalid.

### Audit Entry Contents

Audit entries **never** contain:
- Memory content (plaintext or ciphertext)
- Encryption keys or key material
- Search queries in plaintext

Audit entries **do** contain:
- Operation type (STORE, SEARCH, RECALL, FORGET)
- Memory ID (for STORE, RECALL, FORGET)
- Timestamp
- Fragment count (for STORE)
- PII level detected (for STORE)
- Number of search results (for SEARCH)
- Fragments destroyed count (for FORGET)

### Compliance Export

```typescript
// Export all FORGET operations for GDPR compliance reporting
const deletions = await openshart.export({
  operation: AuditOperation.FORGET,
  after: new Date('2026-01-01'),
  before: new Date('2026-03-01'),
});

// Verify chain integrity
const isValid = await openshart.verifyAuditChain();
// true if no entries have been tampered with
```

---

## Integration Examples

### OpenClaw Memory Provider

```typescript
// openclaw-openshart-provider.ts
import { OpenShart, SQLiteBackend } from 'openshart';
import type { MemoryProvider } from 'openclaw/plugin-sdk';

export class OpenShartMemoryProvider implements MemoryProvider {
  private openshart: OpenShart;

  async init(config: Record<string, unknown>) {
    this.openshart = await OpenShart.init({
      storage: new SQLiteBackend({ path: config.dbPath as string }),
      encryptionKey: Buffer.from(config.encryptionKey as string, 'hex'),
    });
  }

  async store(content: string, metadata?: Record<string, unknown>) {
    const result = await this.openshart.store(content, {
      tags: metadata?.tags as string[],
    });
    return result.id;
  }

  async search(query: string, limit = 10) {
    const results = await this.openshart.search(query, { limit });
    // Recall content for top results
    return Promise.all(
      results.memories.map(async (meta) => {
        const memory = await this.openshart.recall(meta.id);
        return { id: meta.id, content: memory.content, score: 1.0 };
      })
    );
  }

  async forget(id: string) {
    await this.openshart.forget(id as any);
  }

  async close() {
    await this.openshart.close();
  }
}
```

### LangChain.js Memory Class

```typescript
// langchain-openshart.ts
import { OpenShart, SQLiteBackend } from 'openshart';
import { BaseMemory, InputValues, OutputValues } from '@langchain/core/memory';

export class OpenShartMemory extends BaseMemory {
  private openshart: OpenShart;
  memoryKey = 'history';

  constructor(openshart: OpenShart) {
    super();
    this.openshart = openshart;
  }

  get memoryKeys(): string[] {
    return [this.memoryKey];
  }

  async loadMemoryVariables(values: InputValues): Promise<Record<string, string>> {
    const query = values.input || values.question || '';
    const results = await this.openshart.search(String(query), { limit: 5 });

    const memories = await Promise.all(
      results.memories.map((m) => this.openshart.recall(m.id))
    );

    return {
      [this.memoryKey]: memories.map((m) => m.content).join('\n'),
    };
  }

  async saveContext(input: InputValues, output: OutputValues): Promise<void> {
    const text = `Human: ${input.input}\nAI: ${output.output}`;
    await this.openshart.store(text, { tags: ['conversation'] });
  }

  async clear(): Promise<void> {
    const all = await this.openshart.list({ tags: ['conversation'] });
    await Promise.all(all.map((m) => this.openshart.forget(m.id)));
  }
}

// Usage
import { ChatOpenAI } from '@langchain/openai';
import { ConversationChain } from 'langchain/chains';

const openshart = await OpenShart.init({
  storage: new SQLiteBackend(),
  encryptionKey: Buffer.from(process.env.OPENSHART_KEY!, 'hex'),
});

const chain = new ConversationChain({
  llm: new ChatOpenAI(),
  memory: new OpenShartMemory(openshart),
});
```

### Standalone Usage

```typescript
import { OpenShart, SQLiteBackend } from 'openshart';
import { randomBytes } from 'node:crypto';

const openshart = await OpenShart.init({
  storage: new SQLiteBackend({ path: './my-agent.db' }),
  encryptionKey: randomBytes(32),
});

// Store user context securely
await openshart.store('User prefers dark mode and metric units', {
  tags: ['preferences', 'ui'],
});

await openshart.store('Meeting with Jane (jane@partner.com) on March 5th about API integration', {
  tags: ['meeting', 'partner'],
});

// Search without decrypting
const results = await openshart.search('API integration');

// Recall when needed
if (results.memories.length > 0) {
  const memory = await openshart.recall(results.memories[0].id);
  console.log(memory.content);
}

// Clean up
await openshart.close();
```

### Express Middleware for Agent APIs

```typescript
import express from 'express';
import { OpenShart, SQLiteBackend } from 'openshart';

const app = express();
app.use(express.json());

let openshart: OpenShart;

app.use(async (req, res, next) => {
  if (!openshart) {
    openshart = await OpenShart.init({
      storage: new SQLiteBackend({ path: './api-memory.db' }),
      encryptionKey: Buffer.from(process.env.OPENSHART_KEY!, 'hex'),
    });
  }
  req.openshart = openshart;
  next();
});

app.post('/memory', async (req, res) => {
  const { content, tags } = req.body;
  const result = await req.openshart.store(content, { tags });
  res.json(result);
});

app.get('/memory/search', async (req, res) => {
  const { q, limit } = req.query;
  const results = await req.openshart.search(String(q), { limit: Number(limit) || 10 });
  res.json(results);
});

app.get('/memory/:id', async (req, res) => {
  const memory = await req.openshart.recall(req.params.id as any);
  res.json(memory);
});

app.delete('/memory/:id', async (req, res) => {
  const result = await req.openshart.forget(req.params.id as any);
  res.json(result);
});

app.listen(3000);
```

---

## Repository Structure

```
openshart/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                  # Lint, test, build on PR
│   │   ├── release.yml             # npm publish on tag
│   │   └── security-audit.yml      # Weekly dependency audit
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   └── pull_request_template.md
├── src/
│   ├── index.ts                    # Public API exports
│   ├── openshart.ts                   # Core OpenShart class
│   ├── types.ts                    # All TypeScript interfaces/enums
│   ├── crypto/
│   │   ├── aes.ts                  # AES-256-GCM encrypt/decrypt
│   │   ├── hkdf.ts                 # HKDF key derivation
│   │   ├── hmac.ts                 # HMAC token generation
│   │   └── shamir.ts               # Shamir's Secret Sharing (GF(2^8))
│   ├── pii/
│   │   ├── detector.ts             # PII detection engine
│   │   ├── patterns.ts             # Built-in PII patterns
│   │   └── classifier.ts           # PII level classification
│   ├── fragment/
│   │   ├── engine.ts               # Fragment engine (split/reconstruct)
│   │   └── config.ts               # Default fragment configs by PII level
│   ├── search/
│   │   ├── indexer.ts              # Token generation + index writes
│   │   └── query.ts               # Search query execution
│   ├── audit/
│   │   ├── logger.ts              # Audit log writer
│   │   ├── chain.ts               # Hash chain verification
│   │   └── export.ts              # Compliance export
│   ├── backends/
│   │   ├── interface.ts           # StorageBackend interface
│   │   ├── sqlite.ts             # SQLite backend
│   │   ├── postgres.ts           # Postgres backend
│   │   └── memory.ts             # In-memory backend
│   └── errors.ts                  # Custom error classes
├── test/
│   ├── openshart.test.ts             # Core API tests
│   ├── crypto/
│   │   ├── aes.test.ts
│   │   ├── shamir.test.ts
│   │   └── hmac.test.ts
│   ├── pii/
│   │   └── detector.test.ts
│   ├── fragment/
│   │   └── engine.test.ts
│   ├── search/
│   │   └── query.test.ts
│   ├── audit/
│   │   └── chain.test.ts
│   ├── backends/
│   │   ├── sqlite.test.ts
│   │   └── memory.test.ts
│   └── integration/
│       ├── store-recall.test.ts
│       ├── search.test.ts
│       ├── forget.test.ts
│       └── pii-levels.test.ts
├── benchmarks/
│   ├── store.bench.ts
│   ├── search.bench.ts
│   └── fragment.bench.ts
├── examples/
│   ├── basic.ts                   # Minimal usage
│   ├── langchain.ts               # LangChain integration
│   ├── openclaw.ts                # OpenClaw memory provider
│   └── express-api.ts             # REST API wrapper
├── package.json
├── tsconfig.json
├── vitest.config.ts
├── LICENSE                        # MIT
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md                    # Security policy + responsible disclosure
└── OPENSHART_MVP.md                  # This document
```

---

## Quickstart

### Install

```bash
npm install openshart
```

### Generate an Encryption Key

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# Store this key securely. Loss = permanent data loss.
```

### Basic Usage

```typescript
import { OpenShart, SQLiteBackend } from 'openshart';

const openshart = await OpenShart.init({
  storage: new SQLiteBackend(),
  encryptionKey: Buffer.from(process.env.OPENSHART_KEY!, 'hex'),
});

// Store
const { id } = await openshart.store('Remember: user likes dark mode');

// Search
const results = await openshart.search('dark mode');

// Recall
const memory = await openshart.recall(id);
console.log(memory.content); // "Remember: user likes dark mode"

// Forget
await openshart.forget(id);

await openshart.close();
```

---

## Security Model

### Threat Model

| Threat | Mitigation |
|---|---|
| Database breach | All content is fragmented + encrypted. No single fragment reveals content. |
| Storage admin reads data | Fragments are AES-256-GCM encrypted with agent-held keys. Admin sees ciphertext. |
| Search query interception | Queries are HMAC tokens. Attacker learns nothing about the search term. |
| Memory reconstruction from partial fragments | Shamir's SSS requires K-of-N shares. K-1 shares reveal zero information. |
| Audit log tampering | SHA-256 hash chain. Modifying any entry invalidates all subsequent hashes. |
| Key compromise | Per-fragment derived keys via HKDF. Key rotation supported (re-encrypt all). |
| Memory not actually deleted | FORGET overwrites fragment data before deletion + purges search index. |

### What OpenShart Does NOT Protect Against (MVP)

- **Key exfiltration from the agent process** — if the agent's memory space is compromised, the master key is exposed. (Addressed in v0.3 with TPM/Secure Enclave binding.)
- **Access pattern analysis** — an observer can see *when* and *how often* memories are accessed. (Addressed in v0.3 with ORAM.)
- **Side-channel attacks** — timing attacks on HMAC comparison. (Mitigated with constant-time comparison in Node.js `crypto.timingSafeEqual`.)

### Key Management

```typescript
// RECOMMENDED: Environment variable
const key = Buffer.from(process.env.OPENSHART_KEY!, 'hex');

// RECOMMENDED: Hardware security module (future)
// const key = await hsm.getKey('openshart-master');

// ACCEPTABLE: File-based (restricted permissions)
// const key = readFileSync('/etc/openshart/master.key');
// chmod 600 /etc/openshart/master.key

// NEVER: Hardcoded in source
// const key = Buffer.from('abc123...'); // DO NOT DO THIS
```

---

## Compliance

### GDPR Article 17 — Right to Erasure

`openshart.forget()` provides cryptographic erasure:

1. All N fragments overwritten with random data, then deleted
2. All search index entries referencing the memory are purged
3. Memory metadata is deleted
4. Audit log records the deletion with timestamp and fragment count
5. Audit chain remains intact (deletion entry cannot be removed)

### Audit Trail for Regulators

```typescript
// Generate compliance report
const report = await openshart.export({
  after: new Date('2026-01-01'),
  before: new Date('2026-04-01'),
});

// Verify no tampering
const chainValid = await openshart.verifyAuditChain();

// Report includes:
// - Every STORE (what PII level, when, fragment count — never content)
// - Every SEARCH (when, result count — never query text)
// - Every RECALL (when, which memory — never content)
// - Every FORGET (when, what was deleted, fragment destruction count)
```

### Data Residency

Storage backends determine data residency. With SQLiteBackend, data stays on the local filesystem. With PostgresBackend, data residency follows the database location. This is the operator's responsibility to configure.

---

## Roadmap

### MVP (v0.1) — 2 weeks
- [x] Core SDK: store, search, recall, forget, list
- [x] SQLite backend
- [x] In-memory backend (testing)
- [x] PII auto-detection (built-in patterns)
- [x] Fragment engine (Shamir's Secret Sharing)
- [x] AES-256-GCM per-fragment encryption
- [x] HMAC-based searchable encryption
- [x] Audit log with hash chain
- [x] TypeScript, ESM, zero external crypto deps
- [x] Vitest test suite
- [x] npm package published

### v0.2 — +2 weeks
- [ ] PostgreSQL backend with connection pooling
- [ ] Audit dashboard (web UI for compliance teams)
- [ ] Memory TTL enforcement (background expiry)
- [ ] Bulk operations (store/forget many)
- [ ] CLI tool (`npx openshart store "..."`, `npx openshart search "..."`)

### v0.3 — +4 weeks
- [ ] Hardware key binding (TPM 2.0 / macOS Secure Enclave / Android Keystore)
- [ ] Oblivious RAM (ORAM) for access pattern hiding
- [ ] Key rotation without re-encryption (envelope encryption)
- [ ] S3 backend for distributed fragment storage
- [ ] Semantic search (encrypted embeddings via FAISS + encryption layer)

### v0.4 — +4 weeks
- [ ] Multi-agent memory isolation (agent A cannot read agent B's memories)
- [ ] Role-Based Access Control (RBAC) for memory operations
- [ ] Memory sharing between agents (selective, encrypted handoff)
- [ ] Webhook notifications (memory stored, PII detected, TTL expiring)
- [ ] OpenTelemetry integration for observability

### v1.0 — Enterprise
- [ ] SSO integration (SAML, OIDC) for key management
- [ ] Compliance dashboards (GDPR, HIPAA, SOC 2)
- [ ] Managed cloud offering (OpenShart Cloud)
- [ ] SDK for Python, Go, Rust
- [ ] Formal security audit by third party
- [ ] SOC 2 Type II certification

---

## Contributing

### Development Setup

```bash
git clone https://github.com/anthropic/openshart.git
cd openshart
npm install
npm test
```

### Running Tests

```bash
# Unit tests
npm test

# With coverage
npm run test:coverage

# Integration tests (requires SQLite)
npm run test:integration

# Benchmarks
npm run bench
```

### Code Style

- TypeScript strict mode
- ESM only (no CommonJS)
- All crypto operations use Node.js built-in `crypto`
- No `any` types
- 100% test coverage on crypto and fragment modules
- Conventional commits

### Security Issues

**Do not open a public issue for security vulnerabilities.** Email security@openshart.dev with details. See [SECURITY.md](SECURITY.md).

---

## License

MIT — see [LICENSE](LICENSE).

---

*OpenShart: because agent memory should be as secure as human memory is private.*
