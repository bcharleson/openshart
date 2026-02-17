# Engram

> **Enterprise-grade encrypted memory framework for AI agents.**
> **Now with ChainLock temporal sequence locks, government classification, and FIPS compliance.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![npm](https://img.shields.io/npm/v/engram)](https://www.npmjs.com/package/engram)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20%2B-green)](https://nodejs.org)
[![FIPS Ready](https://img.shields.io/badge/FIPS_140--2-Ready-green)](https://csrc.nist.gov/publications/detail/fips/140/2/final)
[![SOC2](https://img.shields.io/badge/SOC2-Compliant-blue)](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2)
[![HIPAA](https://img.shields.io/badge/HIPAA-Compliant-blue)](https://www.hhs.gov/hipaa)
[![FedRAMP Ready](https://img.shields.io/badge/FedRAMP-Ready-green)](https://www.fedramp.gov/)

Fragmented, encrypted, searchable memory with **enterprise hierarchical access control**, **government classification levels**, and **ChainLock temporal sequence locks**. SOC2, HIPAA, and FedRAMP compliant by design.

---

## Why Engram?

AI agents accumulate context — conversations, user preferences, business data, PII. Today that context is stored in plaintext vector databases. That's a liability.

Engram treats agent memory the way it should be treated: **fragmented, encrypted, and reconstructable only by authorized entities**. No single storage location holds a complete memory. No database breach reveals usable data. Enterprise hierarchy controls who sees what.

## 🔐 ChainLock — Temporal Sequence Lock

**ChainLock** is a novel security primitive unique to Engram. Fragments must be decrypted in a specific, cryptographically random sequence, within strict time windows, with chain tokens linking each step.

```
Recall Request
     │
     ▼
┌──────────────────────────────┐
│  1. Generate session nonce    │
│  2. Decrypt sequence order    │
│  3. Start temporal clock      │
└──────────────┬───────────────┘
               │
     ┌─────────▼─────────┐
     │  Step 1 (≤2000ms)  │ decrypt fragment[seq[0]] → chain_token_1
     └─────────┬─────────┘
               │ chain_token_1
     ┌─────────▼─────────┐
     │  Step 2 (≤2000ms)  │ decrypt fragment[seq[1]] + chain_token_1 → chain_token_2
     └─────────┬─────────┘
               │ chain_token_2
     ┌─────────▼─────────┐
     │  Step N (≤2000ms)  │ decrypt fragment[seq[N]] + chain_token_N-1 → chain_token_N
     └─────────┬─────────┘
               │
     ┌─────────▼─────────┐
     │  Reconstruct       │ all fragments + valid chain → plaintext
     │  Rotate sequence   │ new random order for next recall
     │  Wipe ephemeral    │ zero all tokens from memory
     └───────────────────┘
```

**Why it matters:**
- **Stolen fragments are useless** without the sequence, timing, and chain tokens
- **Automated attacks detected** via timing analysis (uniform step durations = bot)
- **Replay attacks prevented** — sequence rotates after every successful recall
- **Breach lockdown** — configurable failure threshold triggers lockdown requiring admin unlock

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     AGENT APPLICATION                        │
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
│  │  ACCESS CONTROL · BELL-LAPADULA · CLASSIFICATION       ││
│  │  FIPS Crypto · Key Rotation · Need-to-Know             ││
│  └──────────────────────────┬──────────────────────────────┘│
│                             │                                │
│  ┌──────────────────────────▼──────────────────────────────┐│
│  │           PII DETECTION + CLASSIFICATION                 ││
│  └──────────────────────────┬──────────────────────────────┘│
│                             │                                │
│  ┌──────────────────────────▼──────────────────────────────┐│
│  │              FRAGMENT ENGINE + CHAINLOCK                  ││
│  │  Shamir's SSS (K-of-N) → AES-256-GCM → Temporal Lock   ││
│  └──────────────────────────┬──────────────────────────────┘│
│                             │                                │
│  ┌──────────────┐  ┌───────▼──────┐  ┌───────────────────┐ │
│  │ SEARCH INDEX │  │  AUDIT LOG   │  │  KEY MANAGEMENT   │ │
│  │ (HMAC-SHA256)│  │ (hash chain) │  │ (HSM · rotation)  │ │
│  └──────┬───────┘  └──────┬───────┘  └───────┬───────────┘ │
└─────────┼─────────────────┼──────────────────┼──────────────┘
          ▼                 ▼                  ▼
┌─────────────────────────────────────────────────────────────┐
│                    STORAGE BACKEND                           │
│  ┌──────────┐  ┌────────────┐  ┌──────────┐                │
│  │  SQLite  │  │ PostgreSQL │  │  Memory  │                │
│  └──────────┘  └────────────┘  └──────────┘                │
└─────────────────────────────────────────────────────────────┘
```

## Install

```bash
npm install engram
```

## Security Presets

Engram ships with four security presets that progressively enable security features:

| Preset | Features |
|--------|----------|
| **`standard`** | AES-256-GCM, basic fragmentation (3-of-5), PII detection, audit log |
| **`enterprise`** | + RBAC, department isolation, key rotation, SOC2 controls |
| **`government`** | + ChainLock, FIPS mode, classification levels, Bell-LaPadula, compartments, HSM-ready |
| **`classified`** | + TS/SCI compartments, two-person integrity, air-gap mode, canary tokens |

## Quickstart

```typescript
import { Engram, MemoryBackend, Classification } from 'engram';
import { randomBytes } from 'node:crypto';

// Simple usage — all security is automatic
const engram = await Engram.init({
  storage: new MemoryBackend(),
  encryptionKey: randomBytes(32),
  // Security preset: 'standard' | 'enterprise' | 'government' | 'classified'
  securityLevel: 'government',
  // ChainLock automatically enabled at 'government' and above
});

// Store — PII detection, fragmentation, ChainLock all automatic
const { id } = await engram.store(
  "Patient John Doe, SSN 123-45-6789, diagnosed with...",
  {
    classification: Classification.SECRET,
    compartments: ['MEDICAL'],
    tags: ['patient', 'diagnosis'],
  }
);

// Recall — ChainLock sequence + timing enforced transparently
const memory = await engram.recall(id);
console.log(memory.content);

// Forget — DoD 5220.22-M 3-pass overwrite + cryptographic erasure
await engram.forget(id);

await engram.close();
```

## Government Classification

Engram supports the full US government classification hierarchy:

```typescript
import { Classification, checkClassifiedAccess } from 'engram';

// Classification levels (hierarchical):
// UNCLASSIFIED → CUI → CONFIDENTIAL → SECRET → TOP_SECRET → TS_SCI

// SCI Compartments: GAMMA, HCS, SI, TK, ORCON, NOFORN

// Bell-LaPadula enforced:
// - No Read Up: agents cannot read above their clearance
// - No Write Down: agents cannot write below their clearance (prevents leaks)

// Need-to-Know: even with clearance, must have explicit grant
```

## Key Management

```typescript
import { KeyRotationManager, createEscrow, recoverFromEscrow, SecureBuffer } from 'engram';

// Secure key wrapper — auto-zeros on destroy
const key = new SecureBuffer(masterKeyBuffer);

// Key rotation — re-encrypts all fragments
const rotator = new KeyRotationManager(storage);
await rotator.rotateAll(oldKey, newKey);

// Key escrow — Shamir split of master key for M-of-N recovery
const shares = createEscrow(masterKey, custodianKeys, { threshold: 3, totalShares: 5 });
const recovered = recoverFromEscrow(shares.slice(0, 3), custodianKeys);
```

## FIPS Compliance

```typescript
import { enableFIPS, isFIPSEnabled } from 'engram';

// FIPS mode auto-enabled at 'government' security level
// When enabled:
// - Only FIPS 140-2 approved algorithms (AES-256-GCM, HMAC-SHA256, HKDF-SHA256)
// - Key entropy validation
// - Self-tests (KAT) on initialization
// - Proper HKDF salts (non-empty, per NIST SP 800-56C)
```

## Enterprise Hierarchy

```typescript
import { ContextFlowManager, DepartmentManager, Role } from 'engram';

const departments = new DepartmentManager();
departments.registerDepartment({
  id: 'engineering',
  name: 'Engineering',
  encryptionNamespace: 'eng-ns-2026',
});

const flow = new ContextFlowManager(departments);

// Context flows DOWN with PII auto-redaction
const pushed = flow.pushDown(
  'Q3 target: $2M ARR. Contact jane@corp.com for details.',
  Role.EXECUTIVE,
  Role.CONTRIBUTOR,
);
// pushed.content: 'Q3 target: [FINANCIAL_REDACTED] ARR. Contact [EMAIL_REDACTED] for details.'
```

## API Reference

### `Engram.init(options)`

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `storage` | `StorageBackend` | ✅ | Storage backend instance |
| `encryptionKey` | `Buffer` | ✅ | 32-byte master key |
| `securityLevel` | `SecurityLevel` | | `'standard'` \| `'enterprise'` \| `'government'` \| `'classified'` |
| `agentId` | `string` | | Agent identifier for audit |
| `role` | `Role` | | Agent's hierarchy role |
| `department` | `string` | | Agent's department |
| `clearance` | `ClearanceProfile` | | Government clearance profile |
| `chainLock` | `ChainLockConfig` | | ChainLock overrides |

### `engram.store(content, options?)`

Stores a memory with optional classification. Auto-detects PII, fragments, encrypts, and indexes.

### `engram.recall(memoryId)`

Reconstructs memory. Uses ChainLock at government+ levels. Enforces access control.

### `engram.search(query, options?)`

Searches using HMAC tokens. Never decrypts content. Filters by access control.

### `engram.forget(memoryId)`

DoD 5220.22-M 3-pass overwrite + cryptographic erasure. GDPR Article 17 compliant.

## Security Model

| Threat | Mitigation |
|--------|-----------|
| Database breach | Shamir's SSS + AES-256-GCM + ChainLock temporal lock |
| Automated extraction | ChainLock timing analysis detects uniform step durations |
| Replay attack | Sequence rotated after every successful recall |
| Brute force | Exponential backoff + lockdown after N failures |
| Insider threat | Bell-LaPadula MAC + compartmentalization + need-to-know |
| Key compromise | Key rotation + HSM-ready + Shamir escrow |
| Quantum (future) | Architecture ready for post-quantum hybrid encryption |

## Compliance

| Framework | Status |
|-----------|--------|
| **SOC2 Type II** | ✅ Compliant — automated checks, hash chain audit |
| **HIPAA** | ✅ Compliant — PHI detection, minimum necessary, cryptographic erasure |
| **GDPR** | ✅ Compliant — Article 17 right-to-erasure with verification |
| **FIPS 140-2** | 🟡 Ready — approved algorithms, self-tests, awaiting validated module |
| **FedRAMP** | 🟡 Ready — NIST 800-53 controls, classification, audit trail |
| **NIST 800-53** | 🟡 Partial — AC, AU, SC, SI families implemented |

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

## License

MIT
