<p align="center">
  <h1 align="center">💩 OpenShart</h1>
  <p align="center"><strong>Enterprise-Grade Encrypted Memory for AI Agents</strong></p>
  <p align="center"><em>If your agent memory leaks, you're going to OpenShart yourself.</em></p>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://www.typescriptlang.org/"><img src="https://img.shields.io/badge/TypeScript-5.x-blue" alt="TypeScript"></a>
  <a href="https://nodejs.org"><img src="https://img.shields.io/badge/Node.js-20%2B-green" alt="Node.js"></a>
  <a href="https://csrc.nist.gov/publications/detail/fips/140/2/final"><img src="https://img.shields.io/badge/FIPS_140--2-Algorithms_Used-yellowgreen" alt="FIPS Algorithms"></a>
  <a href="https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2"><img src="https://img.shields.io/badge/SOC2-Designed_For-blue" alt="SOC2"></a>
  <a href="https://www.hhs.gov/hipaa"><img src="https://img.shields.io/badge/HIPAA-Designed_For-blue" alt="HIPAA"></a>
  <img src="https://img.shields.io/badge/Bell--LaPadula-Implemented-red" alt="Bell-LaPadula">
  <img src="https://img.shields.io/badge/69_Tests-Passing-brightgreen" alt="Tests Passing">
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

## How It Works

When an AI agent stores a memory through OpenShart, the content never touches disk in readable form. Here is the exact pipeline:

```
"Patient John Doe, SSN 123-45-6789"
         │
         ▼
┌─── PII Detection ───┐
│ Scans for:           │
│ • SSN, credit cards  │
│ • Email, phone       │  ← auto-detects SSN as CRITICAL PII
│ • Financial, medical │
└──────────┬───────────┘
           ▼
┌─── Shamir Split ────┐
│ Breaks content into  │
│ K-of-N fragments     │  ← e.g., 3-of-5: any 3 can rebuild, but
│ using secret sharing │     1 or 2 fragments alone are random noise
└──────────┬───────────┘
           ▼
┌─── AES-256-GCM ─────┐
│ Each fragment gets    │
│ its own derived key   │  ← per-fragment HKDF key derivation
│ + authenticated enc.  │     cracking one fragment doesn't help with others
└──────────┬───────────┘
           ▼
┌─── HMAC Indexing ────┐
│ Search tokens built   │
│ from HMAC-SHA256      │  ← content searchable WITHOUT decryption
│ not plaintext         │     the index never contains readable content
└──────────┬───────────┘
           ▼
┌─── Audit Log ────────┐
│ Hash-chained entry    │
│ SHA-256 linked to     │  ← tamper-evident: altering any entry
│ previous entry        │     breaks the chain
└──────────┬───────────┘
           ▼
       Storage
   (SQLite / Postgres)
```

**Searching** works without decryption: the query is hashed into HMAC tokens and matched against the index. The search engine never sees plaintext.

**Recalling** reassembles the minimum threshold of fragments, decrypts each with its derived key, and reconstructs the original content. At government+ security levels, the ChainLock protocol enforces a timed sequence with breach detection.

**Forgetting** overwrites each fragment three times (zeros, ones, random bytes per DoD 5220.22-M) before deletion. The cryptographic erasure is verified and audit-logged.

## Why Not Just Encrypt a Database?

A traditional encrypted database (SQLCipher, AWS KMS + DynamoDB, etc.) stores complete records. If the encryption key leaks or the database is breached, every record is exposed at once. OpenShart is fundamentally different because no single storage location ever holds a complete memory.

| Approach | Search while encrypted? | Fragment-based? | PII-aware? | Built for AI agents? |
|---|---|---|---|---|
| Encrypted DB (SQLCipher) | No — must decrypt to query | No | No | No |
| Key-value vault (HashiCorp) | No — key/value only | No | No | No |
| Cloud KMS + DB (AWS/GCP) | No — envelope encryption | No | No | No |
| Confidential computing (SGX/SEV) | Yes, needs special hardware | No | No | No |
| **OpenShart** | **Yes** (HMAC tokens) | **Yes** (Shamir) | **Yes** (auto-detects) | **Yes** (plugin-native) |

The combination of Shamir's Secret Sharing, per-fragment AES-256-GCM, and HMAC-based searchable encryption in a single framework purpose-built for AI agent memory is what makes OpenShart distinct. Each technique is well-established individually; the novelty is composing them into an agent-native memory layer with automatic PII classification that adjusts fragmentation based on content sensitivity.

## Security Presets

| Preset | What You Get |
|--------|-------------|
| **`standard`** | AES-256-GCM, Shamir fragmentation, PII detection, audit log |
| **`enterprise`** | + RBAC, department isolation, key rotation, SOC2 controls |
| **`government`** | + ChainLock, FIPS mode, classification levels, Bell-LaPadula, compartments |
| **`classified`** | + TS/SCI compartments, increased fragmentation (5-of-8), Bell-LaPadula strict enforcement |

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

ChainLock is OpenShart's composite security layer for high-security recall operations. Fragments must be decrypted in a cryptographically random sequence, within strict time windows, with HMAC chain tokens linking each step. It combines known techniques (hash chains, temporal windows, breach detection) into a defense-in-depth layer over the core Shamir + AES-GCM pipeline.

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
- Stolen fragments are already **useless** without the master key (AES-256-GCM). ChainLock adds **API-level friction** against automated extraction by anyone with key access
- Automated attacks **detected** via timing analysis (uniform step durations = bot)
- Replay attacks **prevented** — sequence rotates after every successful recall
- Breach lockdown — configurable failure threshold triggers account lockdown

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

OpenShart supports the full US government classification hierarchy with policy-level enforcement (Bell-LaPadula MAC). Note: this provides application-level access control, not cryptographically-bound compartmentalization. Formal government certification (FedRAMP, Common Criteria) requires third-party assessment beyond this library.

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

| Threat | Mitigation | Strength |
|--------|-----------|----------|
| Database breach | Shamir's SSS + AES-256-GCM — no single fragment is usable | Strong (cryptographic) |
| Automated extraction | ChainLock timing analysis + breach lockdown | Moderate (API-level) |
| Replay attacks | ChainLock sequence rotates after every recall | Moderate (API-level) |
| Brute force | Exponential backoff + account lockdown | Moderate (rate limiting) |
| Insider threat | Bell-LaPadula MAC + department isolation | Moderate (policy-level) |
| Key compromise | Key rotation + Shamir escrow | Strong (re-encryption) |
| PII exposure | Auto-detection + increased fragmentation | Moderate (regex-based, US patterns) |

## Compliance

| Framework | Status | Notes |
|-----------|--------|-------|
| **SOC2 Type II** | 🟢 Designed for | Technical controls in place; organizational audit required for certification |
| **HIPAA** | 🟢 Designed for | PHI detection (regex-based, US patterns), encryption, audit logging; BAA and administrative controls not included |
| **GDPR** | 🟢 Designed for | Article 17 cryptographic erasure with verification; data residency controls not included |
| **FIPS 140-2** | 🟡 Algorithms used | AES-256-GCM, HMAC-SHA256, HKDF-SHA256 are FIPS-approved; Node.js `crypto` is not a FIPS-validated module |
| **NIST 800-53** | 🟡 Partial | AC, AU, SC, SI, MP families partially covered (~35%); see [SECURITY_AUDIT.md](SECURITY_AUDIT.md) |

> **Important:** Compliance frameworks like SOC2 and HIPAA are organizational obligations, not software properties. OpenShart provides the technical building blocks (encryption, access control, audit logging, erasure) but actual compliance requires organizational policies, third-party audits, and administrative controls beyond any library. See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for the full assessment.

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
A: Yes, for commercial/enterprise use cases. OpenShart uses standard, well-established cryptographic primitives (AES-256-GCM, Shamir's SSS, HKDF, HMAC-SHA256) and has 69 unit tests with CI. It is designed to support SOC2, HIPAA, and GDPR compliance requirements, though formal certification requires organizational controls beyond this library. Not certified for government classified systems.

**Q: Why not just use a normal database with encryption?**
A: Because a database breach exposes everything. OpenShart fragments data using Shamir's Secret Sharing — no single storage location holds a complete memory. Even with full database access, an attacker gets meaningless encrypted shards.

**Q: Does it really support TS/SCI?**
A: The classification model and Bell-LaPadula access control are implemented at the application layer. The crypto primitives are real and correctly implemented. However, actual government TS/SCI deployment requires FIPS-validated cryptographic modules, HSM-backed keys, formal 3PAO assessment, and organizational accreditation — none of which this library provides. Think of it as a solid foundation, not a finished government product.

**Q: My CISO asked about the name.**
A: Tell them it stands for **Open S**ecure **H**ierarchical **A**gent **R**ecall & **T**okenization. That's not true, but it works in a slide deck.

**Q: What happens if there's a security breach?**
A: The attacker gets useless encrypted fragments and you get to say "good thing we used OpenShart" in the incident report.

**Q: How do I explain this to my board of directors?**
A: "We've implemented enterprise-grade cryptographic memory fragmentation with temporal sequence locking." Then hope nobody Googles the npm package name.

**Q: Can I put this on my resume?**
A: "Led implementation of OpenShart across the organization" is technically accurate and a great conversation starter.

**Q: Our compliance team flagged the package name.**
A: Show them the Shamir's Secret Sharing implementation, the FIPS compliance mode, and the Bell-LaPadula access control. Then watch them slowly nod and pretend the name doesn't bother them.

**Q: Is there an enterprise version with a different name?**
A: No. The security is the same whether you call it OpenShart or "Open Secure Hierarchical Agent Recall & Tokenization." We just prefer honesty.

**Q: My PR adding OpenShart as a dependency was rejected.**
A: `npm install openshart` hits different in a code review. We recommend adding it on a Friday afternoon.

**Q: I ran `npm install openshart` and my coworker saw my screen.**
A: You're welcome. That's a core memory now.

## Testing

69 tests across 8 suites verify the full cryptographic pipeline. CI runs on Node 20 and 22.

```bash
npm test              # 69 unit tests (in-memory backend)
npm run validate      # Quick 13-check end-to-end validation
npm run test:pg       # Postgres integration (requires OPENSHART_PG_URL)
npm run test:distributed  # Multi-node distributed test (requires Postgres + shared key)
```

See [TESTING.md](TESTING.md) for the full testing guide including distributed multi-machine testing.

## Contributing

```bash
git clone https://github.com/bcharleson/openshart.git
cd openshart
npm install
npm test              # Should see 69 tests passing
```

Security vulnerabilities: **Do not open a public issue.** Email security@openshart.dev.

## License

MIT — see [LICENSE](LICENSE).

---

<p align="center">
  <strong>OpenShart</strong> — because agent memory should be as secure as the name is unfortunate.
</p>

## Webhook Handler (Strict Contracts)

The `WebhookHandler` wraps all OpenShart operations in a deterministic contract layer for production agent deployments. Every request and response follows a strict envelope format with traceability, validation, and explicit error branching.

```typescript
import { OpenShart, MemoryBackend, WebhookHandler } from 'openshart';
import { randomBytes } from 'node:crypto';

const shart = await OpenShart.init({
  storage: new MemoryBackend(),
  encryptionKey: randomBytes(32),
});

const handler = new WebhookHandler(shart, {
  logger: console,  // pluggable — any { info, warn, error } logger
});

const response = await handler.handle({
  action: 'memory_store',
  request_id: 'req-abc-123',
  idempotency_key: 'idem-xyz',
  params: {
    content: 'Sensitive project details here.',
    tags: ['project', 'confidential'],
  },
});

// Response is always a deterministic envelope:
// {
//   status: 'success',
//   code: 200,
//   message: 'Memory stored successfully',
//   request_id: 'req-abc-123',
//   idempotency_key: 'idem-xyz',
//   data: { id: 'mem_...', piiLevel: 'NONE', fragmentCount: 3, ... },
//   timing: {
//     total_ms: 12,
//     steps: [
//       { step: 'validate', duration_ms: 0 },
//       { step: 'tool:memory_store', duration_ms: 11 },
//       { step: 'parse_response', duration_ms: 0 }
//     ]
//   }
// }
```

**Actions:** `memory_store`, `memory_search`, `memory_get`, `memory_forget`

**Response branches:**

| Status | Code | When |
|--------|------|------|
| `success` | 200 | Operation completed, data returned |
| `no_result` | 204 | Search returned zero hits, or memory not found |
| `validation_error` | 400 | Missing or invalid fields in the request |
| `upstream_error` | 502 | OpenShart operation threw an unexpected error |

**Guarantees:**
- Input validated before any tool call executes
- `request_id` and `idempotency_key` propagated through every response and log entry
- Tool returns parsed as JSON string before field mapping (no raw object passthrough)
- Per-step latency tracked in `timing.steps[]`
- Raw tool errors surfaced in `data.raw_error` for debugging
- Handler never throws — all errors are captured in the response envelope

## OpenClaw Plugin Integration

OpenClaw integration is supported by:

- `openclaw.extensions` in `package.json` (inside `openclaw`) set to `["./dist/openclaw-plugin.js"]`
- `openclaw.plugin.json` at the package root
- `dist/openclaw-plugin.js` as the plugin entry point for OpenClaw

For tested install commands and failure-mode notes, see [INSTALL.md](INSTALL.md).
