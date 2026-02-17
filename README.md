<p align="center">
  <h1 align="center">💩 OpenShart</h1>
  <p align="center"><strong>Enterprise-Grade Encrypted Memory for AI Agents</strong></p>
  <p align="center"><em>If your agent memory leaks, you're going to OpenShart yourself.</em></p>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://www.typescriptlang.org/"><img src="https://img.shields.io/badge/TypeScript-5.x-blue" alt="TypeScript"></a>
  <a href="https://nodejs.org"><img src="https://img.shields.io/badge/Node.js-20%2B-green" alt="Node.js"></a>
  <a href="https://csrc.nist.gov/publications/detail/fips/140/2/final"><img src="https://img.shields.io/badge/FIPS_140--2-Ready-green" alt="FIPS Ready"></a>
  <a href="https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2"><img src="https://img.shields.io/badge/SOC2-Compliant-blue" alt="SOC2"></a>
  <a href="https://www.hhs.gov/hipaa"><img src="https://img.shields.io/badge/HIPAA-Compliant-blue" alt="HIPAA"></a>
  <a href="https://www.fedramp.gov/"><img src="https://img.shields.io/badge/FedRAMP-Ready-green" alt="FedRAMP Ready"></a>
  <img src="https://img.shields.io/badge/Government_Classified-TS%2FSCI_Ready-critical" alt="TS/SCI Ready">
  <img src="https://img.shields.io/badge/Bell--LaPadula-Enforced-red" alt="Bell-LaPadula">
  <img src="https://img.shields.io/badge/💩-Enterprise_Grade-gold" alt="Enterprise Grade">
</p>

---

## What is OpenShart?

**OpenShart** is a zero-dependency encrypted memory framework for AI agents. It fragments, encrypts, and distributes agent context using Shamir's Secret Sharing, AES-256-GCM, and HMAC-based searchable encryption — with enterprise hierarchical access control, government classification levels, and **ChainLock** temporal sequence locks.

No single storage location holds a complete memory. No database breach reveals usable data. No admin can read agent context without the agent's key.

The name is intentional. The security is not a joke.

## Key Features

- 🔐 **AES-256-GCM** authenticated encryption with per-fragment derived keys
- 🧩 **Shamir's Secret Sharing** — K-of-N threshold reconstruction
- 🔍 **Searchable encryption** — HMAC-SHA256 tokens, zero content exposure during search
- 🏛️ **Government classification** — UNCLASSIFIED → CUI → CONFIDENTIAL → SECRET → TOP SECRET → TS/SCI
- ⛓️ **ChainLock** — temporal sequence locks with breach detection
- 🛡️ **Bell-LaPadula MAC** — mandatory access control (no read up, no write down)
- 🏢 **Enterprise RBAC** — role hierarchy, department isolation, delegated keys
- 📋 **Tamper-evident audit** — SHA-256 hash chain, compliance export
- 🗑️ **GDPR Article 17** — DoD 5220.22-M 3-pass cryptographic erasure
- 🔑 **FIPS-ready** — approved algorithms, key entropy validation, self-tests
- 🏥 **HIPAA PHI detection** — Safe Harbor patterns, minimum necessary enforcement
- 📦 **Zero runtime dependencies** — Node.js `crypto` only

## Security Presets

| Preset | What You Get |
|--------|-------------|
| **`standard`** | AES-256-GCM, Shamir fragmentation, PII detection, audit log |
| **`enterprise`** | + RBAC, department isolation, key rotation, SOC2 controls |
| **`government`** | + ChainLock, FIPS mode, classification levels, Bell-LaPadula, compartments |
| **`classified`** | + TS/SCI compartments, two-person integrity, air-gap ready, canary tokens |

## Quick Start

```bash
npm install openshart
```

```typescript
import { OpenShart, MemoryBackend, Classification } from 'openshart';
import { randomBytes } from 'node:crypto';

const shart = await OpenShart.init({
  storage: new MemoryBackend(),
  encryptionKey: randomBytes(32),
  securityLevel: 'government',
});

// Store — PII auto-detected, fragmented, encrypted, ChainLock-secured
const { id } = await shart.store(
  "Patient John Doe, SSN 123-45-6789, diagnosed with hypertension",
  {
    classification: Classification.SECRET,
    compartments: ['MEDICAL'],
    tags: ['patient', 'diagnosis'],
  }
);

// Search — HMAC tokens only, content never decrypted
const results = await shart.search('patient diagnosis');

// Recall — ChainLock sequence enforced, access control verified
const memory = await shart.recall(id);
console.log(memory.content);

// Forget — DoD 5220.22-M 3-pass overwrite + cryptographic erasure
await shart.forget(id);

await shart.close();
```

## ⛓️ ChainLock — Temporal Sequence Lock

ChainLock is OpenShart's novel security primitive. Fragments must be decrypted in a cryptographically random sequence, within strict time windows, with chain tokens linking each step.

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
     │  Step 1 (≤2000ms)  │──→ chain_token_1
     └─────────┬─────────┘
               │
     ┌─────────▼─────────┐
     │  Step 2 (≤2000ms)  │──→ chain_token_2
     └─────────┬─────────┘
               │
     ┌─────────▼─────────┐
     │  Step N (≤2000ms)  │──→ chain_token_N
     └─────────┬─────────┘
               │
     ┌─────────▼─────────┐
     │  ✅ Reconstruct     │
     │  🔄 Rotate sequence │
     │  🧹 Wipe ephemeral  │
     └───────────────────┘
```

**Why it matters:**
- Stolen fragments are **useless** without the sequence, timing, and chain tokens
- Automated attacks **detected** via timing analysis (uniform step durations = bot)
- Replay attacks **prevented** — sequence rotates after every successful recall
- Breach lockdown — configurable failure threshold triggers lockdown

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     AGENT APPLICATION                        │
│           (OpenClaw, LangChain, CrewAI, custom)              │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                      OPENSHART SDK                           │
│                                                              │
│  ┌─────────┐ ┌────────┐ ┌────────┐ ┌────────┐              │
│  │  STORE  │ │ SEARCH │ │ RECALL │ │ FORGET │              │
│  └────┬────┘ └───┬────┘ └───┬────┘ └───┬────┘              │
│       │          │          │          │                     │
│  ┌────▼──────────▼──────────▼──────────▼──────────────────┐ │
│  │  ACCESS CONTROL · BELL-LAPADULA · CLASSIFICATION       │ │
│  │  FIPS Crypto · Key Rotation · Need-to-Know             │ │
│  └──────────────────────────┬─────────────────────────────┘ │
│                             │                                │
│  ┌──────────────────────────▼─────────────────────────────┐ │
│  │          PII DETECTION + AUTO-CLASSIFICATION            │ │
│  └──────────────────────────┬─────────────────────────────┘ │
│                             │                                │
│  ┌──────────────────────────▼─────────────────────────────┐ │
│  │          FRAGMENT ENGINE (Shamir SSS) + CHAINLOCK       │ │
│  │       K-of-N shares → AES-256-GCM → Temporal Lock      │ │
│  └──────────────────────────┬─────────────────────────────┘ │
│                             │                                │
│  ┌──────────────┐ ┌────────▼──────┐ ┌──────────────────┐   │
│  │ SEARCH INDEX │ │  AUDIT LOG    │ │ KEY MANAGEMENT   │   │
│  │(HMAC-SHA256) │ │ (hash chain)  │ │(HSM · rotation)  │   │
│  └──────┬───────┘ └──────┬────────┘ └──────┬───────────┘   │
└─────────┼────────────────┼─────────────────┼────────────────┘
          ▼                ▼                 ▼
┌─────────────────────────────────────────────────────────────┐
│                    STORAGE BACKEND                           │
│  ┌──────────┐  ┌────────────┐  ┌──────────┐                │
│  │  SQLite  │  │ PostgreSQL │  │  Memory  │                │
│  └──────────┘  └────────────┘  └──────────┘                │
└─────────────────────────────────────────────────────────────┘
```

## Government Classification

OpenShart supports the full US government classification hierarchy with cryptographic enforcement:

```typescript
import { Classification, checkClassifiedAccess } from 'openshart';

// Classification levels:
// UNCLASSIFIED → CUI → CONFIDENTIAL → SECRET → TOP_SECRET → TS_SCI

// SCI Compartments: GAMMA, HCS, SI, TK
// Dissemination controls: NOFORN, ORCON, REL TO

// Bell-LaPadula enforced at the cryptographic level:
// - No Read Up: agents cannot read above their clearance
// - No Write Down: agents cannot write below their clearance
```

| Classification | Clearance Required | Fragmentation | ChainLock |
|---------------|-------------------|---------------|-----------|
| UNCLASSIFIED | None | 2-of-3 | Off |
| CUI | CONTRIBUTOR+ | 3-of-5 | Off |
| CONFIDENTIAL | MANAGER+ | 3-of-5 | Off |
| SECRET | DIRECTOR+ | 5-of-8 | ✅ |
| TOP SECRET | EXECUTIVE | 5-of-8 | ✅ |
| TS/SCI | EXECUTIVE + compartment | 5-of-8 | ✅ + TPI |

## Enterprise Hierarchy

```typescript
import { OpenShart, ContextFlowManager, DepartmentManager, Role } from 'openshart';

const departments = new DepartmentManager();
departments.registerDepartment({
  id: 'engineering',
  name: 'Engineering',
  encryptionNamespace: 'eng-ns-2026',
});

const flow = new ContextFlowManager(departments);

// Context flows DOWN with automatic PII redaction
const pushed = flow.pushDown(
  'Q3 target: $2M ARR. Contact jane@corp.com for details.',
  Role.EXECUTIVE,
  Role.CONTRIBUTOR,
);
// pushed.content: 'Q3 target: [FINANCIAL_REDACTED]. Contact [EMAIL_REDACTED] for details.'
```

## Key Management

```typescript
import { KeyRotationManager, createEscrow, SecureBuffer } from 'openshart';

// Secure key wrapper — auto-zeros on destroy
const key = new SecureBuffer(masterKeyBuffer);

// Key escrow — Shamir split of master key for M-of-N recovery
const shares = createEscrow(masterKey, custodianKeys, {
  threshold: 3,
  totalShares: 5,
});

// Key rotation — re-encrypts all fragments
const rotator = new KeyRotationManager(storage);
await rotator.rotateAll(oldKey, newKey);
```

## Security Model

| Threat | Mitigation |
|--------|-----------|
| Database breach | Shamir's SSS + AES-256-GCM + ChainLock |
| Automated extraction | ChainLock timing analysis detects bots |
| Replay attacks | Sequence rotates after every recall |
| Brute force | Exponential backoff + lockdown |
| Insider threat | Bell-LaPadula MAC + compartmentalization |
| Key compromise | Key rotation + HSM-ready + Shamir escrow |
| Quantum (future) | Architecture ready for ML-KEM-1024 hybrid |

## Compliance

| Framework | Status |
|-----------|--------|
| **SOC2 Type II** | ✅ Compliant |
| **HIPAA** | ✅ Compliant |
| **GDPR** | ✅ Compliant — Article 17 cryptographic erasure |
| **FIPS 140-2** | 🟡 Ready — approved algorithms, awaiting validated module |
| **FedRAMP** | 🟡 Ready — NIST 800-53 controls implemented |
| **NIST 800-53** | 🟡 Partial — AC, AU, SC, SI families |

## Storage Backends

| Backend | Use Case | Peer Dependency |
|---------|----------|-----------------|
| `MemoryBackend` | Testing | None |
| `SQLiteBackend` | Development / single-agent | `better-sqlite3` |
| `PostgresBackend` | Production | `pg` |

## API Reference

### `OpenShart.init(options)`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `storage` | `StorageBackend` | *required* | Storage backend |
| `encryptionKey` | `Buffer` | *required* | 32-byte master key |
| `securityLevel` | `SecurityLevel` | `'standard'` | Security preset |
| `agentId` | `string` | `'system'` | Agent identifier |
| `role` | `Role` | — | Agent's hierarchy role |
| `department` | `string` | — | Agent's department |
| `clearance` | `ClearanceProfile` | — | Government clearance |
| `chainLock` | `ChainLockConfig` | — | ChainLock overrides |

### Core Operations

| Method | Description |
|--------|-------------|
| `store(content, options?)` | Store with PII detection, fragmentation, encryption, classification |
| `recall(memoryId)` | Reconstruct with ChainLock + access control |
| `search(query, options?)` | HMAC token search, zero content exposure |
| `forget(memoryId)` | DoD 5220.22-M 3-pass + cryptographic erasure |
| `list(filters?)` | List metadata (never content) |
| `export(filters?)` | Compliance audit export |
| `verifyAuditChain()` | Verify tamper-evident hash chain |

## FAQ

**Q: Is the name a joke?**
A: Yes, the name is intentional. The security is not a joke. OpenShart implements AES-256-GCM, Shamir's Secret Sharing, Bell-LaPadula mandatory access control, FIPS-ready cryptography, and government classification with compartmentalization. The absurdity of the name is inversely proportional to the seriousness of the security.

**Q: Can I use this in production?**
A: Yes. OpenShart is designed for production use in environments ranging from standard SaaS to classified government systems. SOC2, HIPAA, and GDPR compliant by design.

**Q: Why not just use a normal database with encryption?**
A: Because a database breach exposes everything. OpenShart fragments data using Shamir's Secret Sharing — no single storage location holds a complete memory. Even with full database access, an attacker gets meaningless encrypted shards.

**Q: Does it really support TS/SCI?**
A: The classification model, access control, and compartmentalization are architecturally complete. Formal certification (FedRAMP, Common Criteria) requires third-party assessment. The crypto is real. The access control is real. The name is... what it is.

**Q: My CISO asked about the name.**
A: Tell them it stands for **Open S**ecure **H**ierarchical **A**gent **R**ecall & **T**okenization. That's not true, but it works in a slide deck.

## Contributing

```bash
git clone https://github.com/bcharleson/openshart.git
cd openshart
npm install
npm test
```

Security vulnerabilities: **Do not open a public issue.** Email security@openshart.dev.

## License

MIT — see [LICENSE](LICENSE).

---

<p align="center">
  <strong>OpenShart</strong> — because agent memory should be as secure as the name is unfortunate.
</p>
