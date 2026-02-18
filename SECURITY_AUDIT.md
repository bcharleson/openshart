# OpenShart Security Audit — Government/Military Hardening Assessment

**Date:** 2026-02-17 (initial), 2026-02-18 (post-hardening update)
**Auditor:** OpenClaw Security Analysis
**Classification:** UNCLASSIFIED // FOR OFFICIAL USE ONLY
**Version:** 2.0

---

## Executive Summary

OpenShart is an encrypted memory framework for AI agents featuring Shamir's Secret Sharing over GF(2^8), AES-256-GCM encryption, HMAC-based searchable encryption, hierarchical access control, Bell-LaPadula mandatory access control, ChainLock temporal sequence locks, and tamper-evident audit logging. The architecture is sound for commercial enterprise use and has been hardened with government-oriented features, though formal certification for government/military deployment has not been pursued.

**Overall Rating: 8/10 for enterprise. 4/10 for government.**

**What changed since v1.0 of this audit (2026-02-17):**

| Finding | v1.0 Status | v2.0 Status | Resolution |
|---------|------------|------------|------------|
| Access control not enforced in core API | CRITICAL | **RESOLVED** | Wired into `recall()`, `search()`, `store()` |
| SQL injection via schema interpolation | CRITICAL | **RESOLVED** | Schema name validated against `[a-z_]+` allowlist |
| Empty HKDF salt for search/tag keys | HIGH | **RESOLVED** | Non-empty application-specific salts added |
| No entropy validation on encryption key | MEDIUM | **RESOLVED** | Rejects all-zero, single-byte-repeated, and low-entropy keys |
| Single overwrite pass for deletion | HIGH | **RESOLVED** | DoD 5220.22-M 3-pass overwrite implemented |
| No classification levels | CRITICAL | **RESOLVED** | Full hierarchy: UNCLASSIFIED → CUI → CONFIDENTIAL → SECRET → TOP_SECRET → TS/SCI |
| No mandatory access control | CRITICAL | **RESOLVED** | Bell-LaPadula (no read up, no write down) enforced |
| No rate limiting | HIGH | **RESOLVED** | ChainLock breach detection with exponential backoff and lockdown |
| No key rotation | HIGH | **RESOLVED** | `KeyRotationManager` with versioned re-encryption |
| No key escrow | HIGH | **RESOLVED** | Shamir-based M-of-N key escrow |
| No key destruction protocol | HIGH | **RESOLVED** | 3-pass secure destruction in `src/keys/destruction.ts` |
| No FIPS mode | HIGH | **RESOLVED** | Algorithm policy enforcement via `src/crypto/fips.ts` |
| GF(2^8) lookup table bug (generator order) | — | **RESOLVED** | Generator changed from element 2 (order 51) to element 3 (order 255) |
| No test suite | — | **RESOLVED** | 64 unit tests across 7 suites, CI on Node 20+22 |

**Remaining gaps:** No FIPS-validated cryptographic module (Node.js `crypto` is not FIPS 140-2 certified), master key held in plain V8 heap memory, no real HSM integration (software fallback only), grants/delegated keys still in-memory (lost on restart), no share integrity verification (HMAC on Shamir shares), metadata stored in plaintext in storage backends, PII detection is regex-only and US-centric, JavaScript string immutability prevents secure zeroing of reconstructed plaintext.

---

## Section 1: Current State Assessment

### 1.1 Per-Module Findings

#### `src/fragments/encrypt.ts` — Encryption Module

**What's solid:**
- AES-256-GCM with authenticated encryption (AEAD) — good algorithm choice
- HKDF-SHA256 for key derivation — industry standard
- Per-fragment unique keys via HKDF — prevents cross-fragment correlation
- 96-bit random IVs for GCM — correct size per NIST SP 800-38D

**Remaining weaknesses:**
1. **No FIPS validation** — Uses Node.js `crypto` (OpenSSL), which is NOT a FIPS 140-2/3 validated module. Government systems require FIPS-validated cryptographic modules. *(FIPS algorithm policy enforcement added in `src/crypto/fips.ts`, but this is application-layer validation, not a validated module boundary.)*
2. ~~**Empty salt for search key derivation**~~ — **RESOLVED in v0.1.0.** Proper non-empty application-specific salts (`openshart-search-key-salt-v1`, `openshart-tag-key-salt-v1`) now used.
3. ~~**Empty salt for tag key derivation**~~ — **RESOLVED in v0.1.0.** See above.
4. ~~**No key versioning**~~ — **RESOLVED.** `KeyRotationManager` added in `src/keys/rotation.ts` with versioned re-encryption.
5. **Master key held in-memory as `Buffer`** — No protection against heap inspection, core dumps, or swap. V8's GC may leave copies in freed memory. `SecureBuffer` wrapper added for explicit zeroing, but cannot guarantee V8 doesn't retain copies.
6. **No constant-time comparisons** — Auth tag verification relies on OpenSSL internals (likely safe), but no explicit guarantee.
7. **Department key uses department name as salt** — Predictable salt. Not catastrophic (HKDF salt need not be secret), but reduces security margin.

#### `src/fragments/shard.ts` — Shamir's Secret Sharing

**What's solid:**
- Correct GF(2^8) arithmetic with AES polynomial (0x11B) using generator 3 (order 255, full field coverage)
- Precomputed log/exp tables for performance — **verified by 17 crypto unit tests**
- Proper Lagrange interpolation at x=0
- Information-theoretic security (k-1 shares reveal nothing)
- Input validation (k ≥ 2, n ≥ k, n ≤ 255)
- **Bug fix (v0.1.0):** EXP/LOG table generation previously used `x = x ^ gf256MulNoTable(x, 3)` which computed powers of element 2 (order 51), generating only 51 of 255 non-zero field elements. Changed to `x = gf256MulNoTable(x, 3)` (powers of generator 3, order 255). This was a critical correctness bug that silently corrupted all Shamir reconstruction.

**Weaknesses:**
1. **No verification shares** — Cannot detect corrupted shares before reconstruction. A single bit-flip in a share produces silent wrong output.
2. **Share indices are sequential (1..n)** — Predictable x-coordinates. While not a cryptographic weakness for Shamir, randomized indices would prevent share ordering attacks.
3. **No share authentication** — Shares are encrypted downstream, but the Shamir layer itself has no integrity checks. If encryption is ever bypassed or weakened, shares are malleable.
4. **Buffer operations may leave residue** — `randomBytes(k-1)` for polynomial coefficients — the random buffer is not zeroed after use.
5. **Max 255 shares** — GF(2^8) limitation. Acceptable for current use but limits future scalability.

#### `src/core/openshart.ts` — Main API

**What's solid:**
- Clean pipeline: PII detect → classify → fragment → encrypt → store → index → audit
- Expiry enforcement on recall
- Cryptographic erasure on forget (overwrite then delete)
- Audit logging for all operations

**Remaining weaknesses:**
1. ~~**Access control not enforced in core API**~~ — **RESOLVED in v0.1.0.** `AccessController.checkAccess()` now wired into `recall()`, `search()`, `store()`. Bell-LaPadula MAC enforced for classified operations.
2. ~~**Encryption key validation is length-only**~~ — **RESOLVED in v0.1.0.** Key entropy validation now rejects all-zero keys, single-byte-repeated keys, and keys with fewer than 8 unique bytes.
3. ~~**`forget()` single overwrite pass**~~ — **RESOLVED in v0.1.0.** DoD 5220.22-M 3-pass overwrite (zeros, ones, random) implemented in `src/keys/destruction.ts`. *Note: In a JavaScript runtime, Buffer overwrites are best-effort — V8's GC may retain copies, and the OS/storage layer cannot be controlled.*
4. ~~**No rate limiting**~~ — **RESOLVED.** ChainLock breach detection provides exponential backoff and lockdown after configurable failure threshold.
5. **Content reconstructed as plaintext string in memory** — After `reconstructContent()`, the full plaintext exists in V8 heap with no way to zero it. JavaScript strings are immutable — cannot be securely wiped. *This is a fundamental language limitation.*
6. **No re-authentication on sensitive operations** — `forget()` (destructive) requires no additional auth beyond the master key.
7. **Race condition in `forget()`** — Between `getFragments()` and `deleteFragments()`, new fragments could theoretically be inserted.

#### `src/hierarchy/access-control.ts` — Access Control

**What's solid:**
- Role-based clearance hierarchy
- Department isolation with explicit cross-department grants
- Time-limited delegated keys
- Bi-directional flow control (push-down with redaction, bubble-up with anonymization)

**Partially resolved / remaining weaknesses:**
1. ~~**Discretionary Access Control (DAC) only**~~ — **PARTIALLY RESOLVED.** Bell-LaPadula MAC (no read up, no write down) now enforced via `src/hierarchy/classification.ts`. However, MAC enforcement is policy-based (function calls), not cryptographic — a caller with the master key can still bypass by not invoking the checks.
2. **No multi-party authorization** — Single-person can grant, delegate, and access. TPI (Two-Person Integrity) interfaces are defined but not fully enforced at runtime.
3. **Grants stored in memory only** — `DepartmentManager` uses `Map<>` — grants are lost on restart. No persistent grant storage.
4. **No formal access request/approval workflow** — Grants are programmatic. Government requires documented request → review → approve → audit trail.
5. **Role clearance is numeric comparison** — Trivially bypassable by constructing a fake role. No cryptographic binding between role claims and capabilities.
6. **No time-of-check/time-of-use (TOCTOU) protection** — Access is checked but not enforced at the cryptographic level. Checking `hasClearance()` then proceeding to decrypt is a two-step process with no binding.

#### `src/hierarchy/key-chain.ts` — Key Hierarchy

**What's solid:**
- Hierarchical key derivation (master → department → role → agent)
- Time-limited delegated keys
- Scope-limited delegation
- **Key rotation** via `KeyRotationManager` (`src/keys/rotation.ts`) — versioned re-encryption of all fragments
- **Key escrow** via Shamir-based M-of-N split (`src/keys/escrow.ts`) — master key recoverable from threshold of custodian shares
- **Key destruction** via 3-pass secure overwrite (`src/keys/destruction.ts`)
- **HSM interface** defined (`src/keys/hsm.ts`) — pluggable `HSMProvider` with `SoftwareHSMProvider` fallback (clearly labeled "NOT suitable for production government use")

**Remaining weaknesses:**
1. ~~**No key rotation mechanism**~~ — **RESOLVED.** `KeyRotationManager` added. However, rotation requires re-encrypting all fragments, which is an expensive operation.
2. ~~**No key escrow**~~ — **RESOLVED.** Shamir-based M-of-N escrow added.
3. ~~**No key destruction protocol**~~ — **RESOLVED.** 3-pass secure overwrite added. *Same JavaScript runtime caveat applies — V8 may retain copies.*
4. **Delegated keys stored in memory Map** — Lost on restart. No persistence.
5. **No real HSM integration** — `HSMProvider` interface exists with a software fallback, but no integration with actual hardware (AWS CloudHSM, Thales Luna, YubiHSM, etc.). Master key still lives in application memory for all practical deployments.
6. **Single master key** — All security depends on one 32-byte secret. Escrow allows recovery but does not eliminate single-point-of-failure during runtime.

#### `src/search/tokens.ts` — Searchable Encryption

**What's solid:**
- HMAC-SHA256 based search tokens — deterministic, one-way
- Stop word removal to reduce token count
- Tag prefix separation to prevent collisions

**Weaknesses:**
1. **Deterministic tokens enable frequency analysis** — Same word always produces same token. Attacker with storage access can do frequency analysis to infer content.
2. **No padding/blinding** — Token count reveals approximate content length and vocabulary size.
3. **Query tokens identical to index tokens** — Enables known-plaintext attacks. If attacker knows a search was performed for "password", they can identify all memories containing "password."
4. **Lowercase normalization before HMAC** — Reduces keyspace. Search for "API" and "api" produce identical tokens.
5. **No forward secrecy** — Compromised search key compromises all past and future searches.
6. **Bigrams/trigrams not supported** — Only single-word tokens. Phrase search is approximate.

#### `src/audit/logger.ts` & `src/audit/chain.ts` — Audit System

**What's solid:**
- SHA-256 hash chain for tamper evidence
- Genesis hash initialization
- Full chain verification capability
- JSON deterministic serialization for hash computation

**Weaknesses:**
1. **Hash chain, not a Merkle tree** — Linear chain. Verification requires reading ALL entries. Government systems need efficient random-access verification.
2. **No digital signatures** — Hash chain proves ordering but not authorship. Any process with storage access can append fake entries with valid hashes.
3. **No timestamping authority** — Timestamps are self-reported. No trusted third-party timestamp (RFC 3161).
4. **Audit log is appendable but also deletable** — Storage backend `appendAuditLog` is append-only by convention, not enforcement. SQLite/Postgres backends allow direct deletion.
5. **Chain verification loads all entries into memory** — `limit: 1_000_000` — will OOM on large audit logs.
6. **No log forwarding** — Government requires real-time SIEM integration (Splunk, etc.).
7. **`readAuditLog({ limit: 1 })` for init** — Gets newest entry only. If the newest entry was tampered with, init trusts the wrong hash.
8. **No separation between audit writer and audit reader** — Same process that generates events also controls the audit log.

#### `src/storage/sqlite.ts` — SQLite Backend

**Weaknesses:**
1. **Database file is unencrypted on disk** — Fragment ciphertext is encrypted, but metadata (tags, PII levels, agent IDs, department names, timestamps) is plaintext.
2. **No database-level encryption** — Should use SQLCipher for defense-in-depth.
3. **`require('better-sqlite3')` — dynamic require** — Could be hijacked via module path manipulation.
4. **SQL injection via schema interpolation in Postgres** — `${schema}` is interpolated directly into SQL strings. Not parameterized.
5. **WAL mode journal persists data** — WAL files may contain fragments of unencrypted metadata.
6. **Tags stored as JSON in TEXT column** — `tags_json LIKE ?` search is SQL injection adjacent with crafted tags.
7. **No connection encryption** — No TLS for Postgres connections.
8. **No database access logging** — Operations are logged at the application level, but direct database access is unaudited.

#### `src/storage/postgres.ts` — PostgreSQL Backend

**Remaining weaknesses:**
1. ~~**SQL injection via schema interpolation**~~ — **RESOLVED in v0.1.0.** Schema name now validated against `[a-z_]+` allowlist before interpolation.
2. **Connection string may contain credentials in plaintext** — No credential rotation or vault integration.
3. **No TLS enforcement** — `connectionString` doesn't mandate `sslmode=require`.
4. **No row-level security** — All data accessible to the database user.
5. **Postgres backend has been integration-tested** — 6 tests verify full pipeline (store/recall/search/forget/PII/key-isolation) against real Postgres. Previously listed as stub quality; now functional with verified BYTEA round-trips.

#### `src/pii/detector.ts` — PII Detection

**What's solid:**
- Regex-based detection for common PII types
- Luhn validation for credit cards
- IP address range validation
- Position-aware detection for targeted redaction

**Weaknesses:**
1. **Regex-only detection** — No NLP/ML-based detection. Will miss context-dependent PII (names without patterns, free-text medical conditions).
2. **US-centric patterns** — No international phone numbers, national IDs, or non-US address formats.
3. **No false positive management** — "123 Main St" in a coding example would be flagged as an address.
4. **PII detection results include the actual PII value** — `PIIDetection.value` contains the matched sensitive data. If detection results are logged or leaked, PII is exposed.
5. **Redaction is string replacement** — Original content exists in memory. JavaScript string immutability means `content` parameter persists.

#### `src/compliance/hipaa.ts`, `soc2.ts`, `gdpr.ts` — Compliance Modules

**What's solid:**
- HIPAA PHI detection with Safe Harbor patterns
- Minimum necessary standard enforcement
- GDPR Article 17 cryptographic erasure with verification
- SOC2 control checks with hash chain verification

**Weaknesses:**
1. **Compliance checks are advisory, not enforcing** — `runSOC2Checks()` reports but doesn't prevent non-compliant operations.
2. **CC8.1 check is hardcoded PASS** — "All stored data is encrypted" is assumed, not verified. If encryption failed, this still passes.
3. **No BAA tracking** — HIPAA requires Business Associate Agreements. No tracking mechanism.
4. **No data residency controls** — GDPR requires data localization. No geographic constraints.
5. **GDPR erasure doesn't verify underlying storage media** — `verifyErasure()` checks application-level deletion but not whether the database engine has truly purged data from disk (vacuum, page reuse, etc.).

---

## Section 2: Critical Fixes (Must Do)

### P0 — Security Vulnerabilities

| # | Finding | Severity | Module | Status |
|---|---------|----------|--------|--------|
| 1 | **Access control not enforced in core API** | CRITICAL | `openshart.ts` | **RESOLVED** — `AccessController.checkAccess()` wired into `recall()`, `search()`, `store()`. Bell-LaPadula enforced for classified operations. |
| 2 | **SQL injection via schema interpolation** | CRITICAL | `postgres.ts` | **RESOLVED** — Schema name validated against `[a-z_]+` allowlist. |
| 3 | **Master key in plain memory** | HIGH | `encrypt.ts`, `openshart.ts` | **OPEN** — `SecureBuffer` wrapper added for explicit zeroing, but V8 GC may retain copies. No `mlock()` / `mprotect()` integration. |
| 4 | **Empty HKDF salt for search/tag keys** | HIGH | `encrypt.ts` | **RESOLVED** — Non-empty application-specific salts added. |
| 5 | **Single overwrite pass for deletion** | HIGH | `openshart.ts`, `gdpr.ts` | **RESOLVED** — DoD 5220.22-M 3-pass overwrite (zeros, ones, random) implemented. *Caveat: best-effort in JS runtime.* |
| 6 | **Grants/delegated keys lost on restart** | HIGH | `departments.ts`, `key-chain.ts` | **OPEN** — Not yet persisted to storage backend. |
| 7 | **No share integrity verification** | MEDIUM | `shard.ts` | **OPEN** — No HMAC on individual Shamir shares. Corrupted share produces silent wrong output. |
| 8 | **Audit chain loads all entries to verify** | MEDIUM | `chain.ts` | **OPEN** — Still linear chain with `limit: 1_000_000`. No Merkle tree or checkpoints. |
| 9 | **Metadata stored in plaintext** | MEDIUM | `sqlite.ts`, `postgres.ts` | **OPEN** — Tags, department names, agent IDs, timestamps visible in storage. Fragment ciphertext is encrypted. |
| 10 | **No entropy validation on encryption key** | MEDIUM | `config.ts` | **RESOLVED** — Rejects all-zero, single-byte-repeated, and keys with fewer than 8 unique bytes. |

### P1 — Implementation Gaps

| # | Finding | Module | Fix |
|---|---------|--------|-----|
| 11 | Reconstructed plaintext cannot be zeroed (JS string immutability) | `openshart.ts` | Return `Buffer` instead of `string`, zero after use. Document that callers must zero buffers. |
| 12 | No rate limiting on operations | `openshart.ts` | Add configurable rate limiter per agent/operation. |
| 13 | PII detection results contain actual PII values | `detector.ts` | Redact values in detection results; store only type + position. |
| 14 | No database connection encryption | `postgres.ts` | Require `sslmode=verify-full` by default. |
| 15 | SOC2 CC8.1 hardcoded PASS | `soc2.ts` | Actually verify encryption by attempting to read raw fragment and confirming it's ciphertext. |

---

## Section 3: Government Hardening Roadmap

### 3.1 FIPS 140-2/3 Compliance

**Current state:** Non-compliant. Uses Node.js OpenSSL which is not FIPS-validated.

**Required changes:**

| Priority | Requirement | Implementation |
|----------|-------------|----------------|
| P0 | **Use FIPS-validated crypto module** | Build Node.js with `--openssl-is-fips` flag using a FIPS-validated OpenSSL module (e.g., OpenSSL 3.x FIPS provider). Alternatively, use AWS-LC FIPS or BoringCrypto via N-API binding. |
| P0 | **FIPS-approved algorithms only** | Already using AES-256-GCM (approved) and HMAC-SHA256 (approved) and HKDF-SHA256 (approved per SP 800-56C). Verify no non-approved algorithms are used. |
| P0 | **Cryptographic module boundary** | Define clear module boundary. All crypto operations must go through the validated module. No `crypto.createHash()` outside the boundary. |
| P1 | **Key management per FIPS 140-2 §4.7** | Keys must be generated by approved DRBG (NIST SP 800-90A). Verify `randomBytes()` uses FIPS DRBG. |
| P1 | **Self-tests on module load** | Implement known-answer tests (KAT) for AES-GCM, HMAC-SHA256, and HKDF on startup. |
| P2 | **Physical security (Level 2+)** | HSM integration for master key storage. Tamper-evident seals on HSM. |
| P2 | **Conditional self-tests** | Run crypto self-tests on algorithm first use, not just startup. |

### 3.2 NIST 800-53 Rev 5 — Security Control Families

| Family | ID | Control | Current State | Required Implementation |
|--------|-----|---------|---------------|------------------------|
| Access Control | AC-2 | Account Management | ❌ No user/agent lifecycle | Agent provisioning, deprovisioning, periodic review |
| | AC-3 | Access Enforcement | ✅ Enforced in core API | Access control wired into `recall()`, `search()`, `store()` with Bell-LaPadula MAC |
| | AC-4 | Information Flow Enforcement | ⚠️ Bell-LaPadula NRU/NWD | Policy-level enforcement; not cryptographically bound |
| | AC-5 | Separation of Duties | ❌ Missing | Admin ≠ operator ≠ auditor roles |
| | AC-6 | Least Privilege | ⚠️ Role-based but coarse | Fine-grained permissions per operation type |
| | AC-17 | Remote Access | ❌ No controls | mTLS, VPN requirements, session management |
| Audit | AU-2 | Event Logging | ✅ Comprehensive | Add failed attempt logging |
| | AU-3 | Content of Audit Records | ✅ Good | Add source IP, session ID |
| | AU-6 | Audit Review/Analysis | ❌ Manual only | Automated anomaly detection, SIEM integration |
| | AU-9 | Protection of Audit Information | ❌ No protection | Sign audit entries, write-once storage |
| | AU-10 | Non-repudiation | ❌ No signatures | Digital signatures on audit entries |
| | AU-11 | Audit Record Retention | ❌ No policy | Configurable retention with secure archival |
| CM | CM-3 | Configuration Change Control | ❌ Missing | Config versioning, change approval workflow |
| Crypto | SC-12 | Cryptographic Key Establishment | ⚠️ HKDF + key rotation + escrow | HSM integration for production government use |
| | SC-13 | Cryptographic Protection | ⚠️ FIPS algorithm policy enforced | FIPS-validated module required for certification |
| | SC-28 | Protection of Information at Rest | ⚠️ Fragments encrypted | Metadata also needs encryption |
| IA | IA-2 | Identification and Authentication | ❌ No authentication | Add agent authentication (certificates, tokens) |
| | IA-5 | Authenticator Management | ❌ Missing | Key lifecycle management |
| IR | IR-4 | Incident Handling | ❌ Missing | Incident detection, alerting, response procedures |
| | IR-5 | Incident Monitoring | ❌ Missing | Real-time monitoring, anomaly detection |
| MP | MP-6 | Media Sanitization | ✅ DoD 5220.22-M 3-pass | Best-effort in JS runtime; storage media verification not possible |
| PE | PE-3 | Physical Access Control | N/A (software) | HSM physical security requirements |
| SA | SA-10 | Developer Security Testing | ⚠️ 64 unit tests + CI | SAST, DAST, fuzz testing, pen testing still needed |
| SI | SI-7 | Software/Information Integrity | ⚠️ Hash chain | Code signing, SBOM, supply chain verification |
| | SI-10 | Information Input Validation | ⚠️ Basic | Comprehensive input validation framework |

### 3.3 FedRAMP Requirements

| Requirement | Current State | Implementation |
|-------------|---------------|----------------|
| **FedRAMP Moderate baseline** | ❌ | Implement all NIST 800-53 Moderate controls (325 controls) |
| **Continuous monitoring** | ❌ | ConMon dashboard, monthly vulnerability scans, annual pen tests |
| **Boundary definition** | ❌ | System Security Plan (SSP) with data flow diagrams |
| **Incident response** | ❌ | US-CERT reporting within 1 hour for significant incidents |
| **Data sovereignty** | ❌ | Data must reside in authorized facilities within US borders |
| **Personnel security** | ❌ | Background checks for all personnel with system access |
| **3PAO assessment** | ❌ | Third-party assessment organization audit |
| **POA&M tracking** | ❌ | Plan of Action & Milestones for all findings |

### 3.4 ITAR/EAR Export Control

| Requirement | Implementation |
|-------------|----------------|
| **Encryption classification** | AES-256 is Category 5 Part 2 of the Commerce Control List. Requires EAR review. |
| **ITAR data handling** | If storing defense article data, must implement ITAR access controls — US persons only |
| **Geographic restrictions** | Prevent deployment/access from embargoed countries |
| **Access logging for export compliance** | Log all access with nationality/citizenship verification |
| **Technology transfer controls** | Prevent source code access by non-US persons for ITAR-controlled implementations |
| **Deemed export controls** | In-person access by foreign nationals = deemed export |

### 3.5 Common Criteria (EAL4+)

| Requirement | Implementation |
|-------------|----------------|
| **Security Target (ST)** | Formal document specifying security claims and threat model |
| **Functional specification** | Formal specification of all security functions |
| **High-level design** | Architecture documentation showing security boundary |
| **Implementation representation** | Source code review by evaluation lab |
| **Vulnerability analysis** | Independent penetration testing by certified lab |
| **Testing** | Comprehensive test suite covering all security functions |
| **Configuration management** | Formal CM process with labeled configurations |
| **Delivery procedures** | Secure delivery with integrity verification |

### 3.6 Zero Trust Architecture (NIST 800-207)

| Principle | Current State | Implementation |
|-----------|---------------|----------------|
| **Never trust, always verify** | ❌ Trust based on possession of master key | Per-request authentication and authorization |
| **Least privilege access** | ⚠️ Role-based | Dynamic, context-aware access decisions |
| **Assume breach** | ❌ | Microsegmentation, blast radius containment |
| **Verify explicitly** | ❌ | Continuous verification of agent identity and posture |
| **Device/workload identity** | ❌ | Certificate-based agent identity (SPIFFE/SPIRE) |
| **Micro-segmentation** | ⚠️ Department isolation | Per-memory, per-fragment access policies |
| **Real-time risk scoring** | ❌ | Behavioral analytics on access patterns |

---

## Section 4: Advanced Security Features

### 4.1 Post-Quantum Cryptography

**Threat:** Harvest-now-decrypt-later attacks. Encrypted memories captured today could be decrypted by quantum computers in 10-15 years.

**Implementation plan:**

```
Phase 1: Hybrid encryption (AES-256-GCM + ML-KEM-1024)
- Wrap fragment keys with both classical and PQ KEM
- Either algorithm's security is sufficient
- Use NIST PQC standards (FIPS 203, 204, 205)

Phase 2: PQ key derivation
- Replace HKDF-SHA256 with HKDF-SHA3-256 (quantum-resistant hash)
- Increase HMAC key sizes to 512 bits

Phase 3: PQ search tokens
- Replace HMAC-SHA256 search tokens with lattice-based PRF
- Or use HMAC-SHA3-256 as interim measure

Algorithms:
- Key encapsulation: ML-KEM-1024 (FIPS 203)
- Digital signatures: ML-DSA-87 (FIPS 204) for audit entries
- Hash-based signatures: SLH-DSA (FIPS 205) for long-term audit integrity
```

### 4.2 HSM Integration

```typescript
interface HSMProvider {
  // Key lifecycle
  generateKey(algorithm: string, label: string): Promise<KeyHandle>;
  importKey(material: Buffer, label: string): Promise<KeyHandle>;
  destroyKey(handle: KeyHandle): Promise<void>;

  // Cryptographic operations (key never leaves HSM)
  encrypt(handle: KeyHandle, plaintext: Buffer, iv: Buffer): Promise<Buffer>;
  decrypt(handle: KeyHandle, ciphertext: Buffer, iv: Buffer): Promise<Buffer>;
  sign(handle: KeyHandle, data: Buffer): Promise<Buffer>;
  verify(handle: KeyHandle, data: Buffer, signature: Buffer): Promise<boolean>;

  // Key wrapping for export/backup
  wrapKey(wrappingHandle: KeyHandle, targetHandle: KeyHandle): Promise<Buffer>;
  unwrapKey(wrappingHandle: KeyHandle, wrappedKey: Buffer): Promise<KeyHandle>;

  // Attestation
  attest(handle: KeyHandle): Promise<AttestationResult>;
}

// Supported HSMs:
// - AWS CloudHSM (FIPS 140-2 Level 3)
// - Azure Dedicated HSM (FIPS 140-2 Level 3)
// - Thales Luna (FIPS 140-2 Level 3)
// - YubiHSM 2 (FIPS 140-2 Level 3)
// - PKCS#11 generic interface
```

### 4.3 Canary Tokens / Honeypot Memories

```typescript
interface CanaryMemory {
  id: MemoryId;
  // Looks like real sensitive data
  baitContent: string;
  // Classification to attract unauthorized access
  baitClassification: ClassificationLevel;
  // Alert channels
  alertWebhook: string;
  alertEmail: string;
  // Tracking
  accessCount: number;
  lastAccessBy: string;
  lastAccessAt: string;
  // Fingerprinting
  uniqueMarker: string; // Embedded steganographic marker
}

// Deployment strategy:
// - Place canaries at every classification level
// - Include department-specific canaries
// - Monitor for access by agents without need-to-know
// - Trigger incident response on unauthorized access
// - Embed unique markers to trace data exfiltration
```

### 4.4 Air-Gap Operation Mode

```typescript
interface AirGapConfig {
  mode: 'air-gapped' | 'connected';
  // All data local — no network calls
  storageBackend: 'sqlite'; // Only SQLite in air-gap mode
  // Key loading via physical media (USB HSM, smart card)
  keySource: 'hsm-usb' | 'smart-card' | 'manual-entry';
  // Audit export via physical media
  auditExport: 'usb' | 'serial' | 'printed';
  // No DNS, no NTP — use local time source
  timeSource: 'local' | 'gps' | 'radio-clock';
  // Disable all network-dependent features
  disableFeatures: ['postgres', 'siem-forwarding', 'remote-audit'];
}

// Air-gap requirements:
// 1. No network sockets opened
// 2. No DNS resolution
// 3. All dependencies vendored/bundled
// 4. HSM via USB/serial only
// 5. Audit logs exported via physical media with crypto verification
// 6. Manual key ceremony (split knowledge, 2+ custodians)
```

### 4.5 Two-Person Integrity (TPI)

```typescript
interface TPIPolicy {
  // Operations requiring two-person authorization
  requiredFor: ('KEY_ROTATION' | 'FORGET' | 'EXPORT' | 'GRANT_TS_SCI' | 'DECLASSIFY')[];
  // Minimum authorizers
  minAuthorizers: 2;
  // Authorizers must be from different departments
  crossDepartment: boolean;
  // Maximum time between first and second authorization
  maxApprovalWindowMs: number; // e.g., 3600000 (1 hour)
  // Require different authentication methods
  diverseAuth: boolean; // e.g., one smart card + one biometric
}

interface TPIRequest {
  id: string;
  operation: string;
  requestedBy: string;
  requestedAt: string;
  approvals: TPIApproval[];
  status: 'pending' | 'approved' | 'denied' | 'expired';
}

interface TPIApproval {
  approverId: string;
  approverRole: Role;
  approverDepartment: string;
  approvedAt: string;
  authMethod: 'smart-card' | 'biometric' | 'password' | 'hsm-token';
  signature: Buffer; // Digital signature of the request
}
```

### 4.6 Insider Threat Detection

```typescript
interface InsiderThreatEngine {
  // Behavioral baselines per agent
  baselineAccess(agentId: string): Promise<AccessBaseline>;

  // Real-time anomaly detection
  detectAnomalies(event: AuditEntry): Promise<ThreatIndicator[]>;

  // Indicators:
  // - Access outside normal hours
  // - Bulk recall operations (data exfiltration pattern)
  // - Access to memories outside normal department scope
  // - Rapid succession of search queries (reconnaissance)
  // - Access to canary memories
  // - Privilege escalation attempts
  // - Access from unusual locations/IPs
  // - Pattern changes after personnel actions (termination, demotion)

  // Response actions
  quarantineAgent(agentId: string): Promise<void>;
  revokeAllKeys(agentId: string): Promise<void>;
  alertSecurityTeam(indicator: ThreatIndicator): Promise<void>;
  preserveEvidence(agentId: string, timeRange: DateRange): Promise<EvidencePackage>;
}
```

### 4.7 Cross-Domain Guards

```typescript
interface CrossDomainGuard {
  // Controlled information flow between classification levels
  // e.g., UNCLASSIFIED ↔ SECRET requires a guard

  validateTransfer(
    source: ClassificationLevel,
    destination: ClassificationLevel,
    content: string,
  ): Promise<TransferDecision>;

  // Guard checks:
  // 1. Classification label verification
  // 2. Content inspection for classification markers
  // 3. PII/sensitive data stripping
  // 4. Downgrade authorization verification (requires TPI)
  // 5. Audit logging of all cross-domain transfers
  // 6. Rate limiting on transfers
  // 7. Dirty word filtering (classification-specific terms)

  // Transfer types:
  // HIGH → LOW: Requires declassification review + TPI
  // LOW → HIGH: Allowed with proper marking
  // LATERAL (same level, different compartments): Requires compartment access grant
}
```

---

## Section 5: Updated Classification System

### 5.1 Expanded Classification Levels

Replace the current 5-role enterprise hierarchy with a dual-axis system:

**Axis 1: Classification Level (mandatory, hierarchical)**

```typescript
enum ClassificationLevel {
  UNCLASSIFIED = 'UNCLASSIFIED',           // Clearance: 0
  CUI = 'CUI',                               // Controlled Unclassified Information
  CONFIDENTIAL = 'CONFIDENTIAL',             // Clearance: 40
  SECRET = 'SECRET',                          // Clearance: 60
  TOP_SECRET = 'TOP_SECRET',                  // Clearance: 80
  TS_SCI = 'TS_SCI',                          // Clearance: 100 + compartment access
}
```

**Axis 2: Organizational Role (maps to clearance ceiling)**

```typescript
enum OrganizationalRole {
  EXECUTIVE = 'EXECUTIVE',       // Max: TS/SCI (with compartment access)
  DIRECTOR = 'DIRECTOR',         // Max: TOP_SECRET
  MANAGER = 'MANAGER',           // Max: SECRET
  CONTRIBUTOR = 'CONTRIBUTOR',   // Max: CONFIDENTIAL
  AGENT = 'AGENT',               // Max: CUI (default), upgradeable via grant
}
```

**Access rule:** `agent.clearanceLevel >= memory.classificationLevel AND agent.hasCompartmentAccess(memory.compartments)`

### 5.2 SCI Compartmentalization Model

```typescript
interface SCICompartment {
  id: string;                    // e.g., 'GAMMA', 'HCS', 'SI', 'TK'
  name: string;                  // Human-readable name
  parentCompartment?: string;    // Sub-compartments
  encryptionKey: KeyHandle;      // Compartment-specific key (in HSM)
  accessList: string[];          // Agent IDs with access
  controlOfficer: string;        // Compartment control officer
  created: string;
  reviewDate: string;            // Periodic access review
}

interface CompartmentAccess {
  agentId: string;
  compartmentId: string;
  grantedBy: string;             // Must be control officer
  grantedAt: string;
  expiresAt: string;
  justification: string;         // Documented need-to-know
  approvedBy: string[];          // TPI — at least 2 approvers
  polygraphDate?: string;        // For certain compartments
  readOnDate: string;            // When agent was read into compartment
}

// Memory marking:
interface ClassifiedMemoryMeta extends MemoryMeta {
  classification: ClassificationLevel;
  compartments: string[];         // e.g., ['GAMMA', 'TK']
  disseminationControls: string[]; // e.g., ['NOFORN', 'ORCON', 'REL TO USA, GBR']
  declassifyOn: string;           // Auto-declassification date
  classifiedBy: string;           // Original classification authority
  derivedFrom: string;            // If derivatively classified
  portionMarking: string;         // e.g., '(TS//SI//NF)'
}
```

### 5.3 Need-to-Know Enforcement at Cryptographic Level

```
Classification + Compartment → Unique encryption key

Master Key
  └── Classification Level Key (via HKDF)
        └── Compartment Key (via HKDF with compartment salt)
              └── Memory Key (via HKDF with memory ID)

Access path:
1. Agent authenticates (certificate/smart card)
2. Agent's clearance verified against classification
3. Agent's compartment access verified
4. Compartment key unwrapped from HSM using agent's credential
5. Memory key derived from compartment key
6. Fragments decrypted

Without compartment access, agent cannot derive the compartment key,
and therefore cannot derive any memory keys within that compartment.
This is cryptographic enforcement — not just policy enforcement.
```

### 5.4 Mandatory Access Control (MAC)

```typescript
interface MACPolicy {
  // Bell-LaPadula (confidentiality)
  noReadUp: boolean;    // Agent cannot read above their clearance
  noWriteDown: boolean; // Agent cannot write below their clearance (prevent leaks)

  // Biba (integrity)
  noReadDown: boolean;  // Agent cannot read from less trusted sources
  noWriteUp: boolean;   // Agent cannot write to more trusted stores

  // Combined: Strict * policy
  // Agents can only read at their level and write at their level
  // Cross-level transfers require Cross-Domain Guard
}
```

---

## Section 6: Implementation Priority

### Phase 1: Critical Foundation (Weeks 1-4, ~160 hours)

| Task | Effort | Priority | Status |
|------|--------|----------|--------|
| Wire access control into core API (`recall`, `search`, `store`) | 16h | P0 | **DONE** |
| Fix SQL injection in Postgres backend | 4h | P0 | **DONE** |
| Fix empty HKDF salts | 4h | P0 | **DONE** |
| Add share integrity verification (HMAC) | 8h | P0 | Open |
| Persist grants and delegated keys to storage | 16h | P0 | Open |
| Implement 3-pass secure deletion (DoD 5220.22-M) | 8h | P0 | **DONE** |
| Encrypt metadata at rest (SQLCipher / column encryption) | 16h | P0 | Open |
| Add entropy validation for encryption keys | 4h | P0 | **DONE** |
| Implement rate limiting | 8h | P1 | **DONE** (ChainLock breach detection) |
| Add agent authentication (certificate-based) | 24h | P1 | Open |
| Secure memory handling (Buffer returns, mlock) | 16h | P1 | Partial (`SecureBuffer` added, no `mlock`) |
| Redact PII values from detection results | 4h | P1 | Open |
| Require TLS for Postgres connections | 4h | P1 | Open |
| Add failed operation logging | 8h | P1 | Open |
| Add FIPS crypto self-tests | 16h | P1 | **DONE** (`src/crypto/fips.ts`) |

**Phase 1 progress: ~60% complete (7 of 15 tasks done, 1 partial)**

### Phase 2: Classification & MAC (Weeks 5-10, ~240 hours)

| Task | Effort | Priority | Status |
|------|--------|----------|--------|
| Implement classification levels (UNCLASSIFIED → TS/SCI) | 32h | P0 | **DONE** (`src/hierarchy/classification.ts`) |
| Implement Mandatory Access Control (Bell-LaPadula + Biba) | 40h | P0 | **DONE** (Bell-LaPadula; Biba not implemented) |
| SCI compartment model with per-compartment encryption | 40h | P0 | Partial (compartment labels exist; per-compartment encryption not enforced) |
| Need-to-know cryptographic enforcement | 32h | P0 | Partial (policy enforcement, not cryptographic) |
| Two-Person Integrity (TPI) framework | 32h | P0 | Interfaces defined, not enforced at runtime |
| Key rotation mechanism with versioned wrapping | 24h | P1 | **DONE** (`src/keys/rotation.ts`) |
| Key ceremony tooling (split knowledge, M-of-N) | 16h | P1 | **DONE** (`src/keys/escrow.ts`) |
| Digital signatures on audit entries (non-repudiation) | 16h | P1 | Open |
| Cross-domain guard (basic) | 24h | P1 | Open |

**Phase 2 progress: ~40% complete (4 of 9 tasks done, 3 partial)**

### Phase 3: Government Infrastructure (Weeks 11-18, ~320 hours)

| Task | Effort | Priority | Status |
|------|--------|----------|--------|
| HSM integration (PKCS#11 + cloud HSM providers) | 60h | P0 | Partial (`HSMProvider` interface + `SoftwareHSMProvider` fallback; no real HSM) |
| FIPS 140-2/3 validated crypto module integration | 40h | P0 | Open (requires FIPS-validated OpenSSL build) |
| SIEM integration (syslog, Splunk, Elastic) | 24h | P1 | Open |
| Insider threat detection engine | 40h | P1 | Partial (ChainLock timing anomaly detection) |
| Canary tokens / honeypot memories | 24h | P1 | Interfaces defined, not implemented |
| Air-gap operation mode | 40h | P1 | Interfaces defined, not implemented |
| Key escrow / recovery system | 32h | P1 | **DONE** (`src/keys/escrow.ts`) |
| Secure key destruction (DoD 5220.22-M for keys) | 16h | P1 | **DONE** (`src/keys/destruction.ts`) |
| Post-quantum hybrid encryption (ML-KEM-1024) | 40h | P2 | Open |
| Merkle tree audit log | 24h | P2 | Open |

**Phase 3 progress: ~20% complete (2 of 10 tasks done, 3 partial)**

### Phase 4: Compliance Certification Prep (Weeks 19-26, ~200 hours)

| Task | Effort | Priority |
|------|--------|----------|
| NIST 800-53 full control implementation & documentation | 60h | P0 |
| System Security Plan (SSP) for FedRAMP | 40h | P0 |
| Common Criteria Security Target document | 40h | P1 |
| Formal verification of crypto module boundary | 24h | P1 |
| ITAR/EAR export classification & controls | 16h | P1 |
| Penetration testing (3PAO engagement) | 20h | P1 |
| Supply chain security (SBOM, dependency audit) | 16h | P2 |
| Continuous monitoring (ConMon) dashboard | 24h | P2 |

### Total Estimated Effort

| Phase | Hours | Timeline |
|-------|-------|----------|
| Phase 1: Critical Foundation | ~160h | Weeks 1-4 |
| Phase 2: Classification & MAC | ~240h | Weeks 5-10 |
| Phase 3: Government Infrastructure | ~320h | Weeks 11-18 |
| Phase 4: Compliance Certification | ~200h | Weeks 19-26 |
| **Total** | **~920h** | **~6 months with 2 engineers** |

---

## Appendix A: Compliance Matrix Summary

| Framework | Pre-Hardening (v1.0) | Current (v2.0, post-hardening) | After Full Phase 2 | After Phase 4 |
|-----------|---------------------|-------------------------------|--------------------|--------------|
| SOC2 Type II | ~60% | ~80% | ~95% | ~98% |
| HIPAA | ~50% | ~70% | ~90% | ~95% |
| GDPR | ~70% | ~85% | ~95% | ~98% |
| FIPS 140-2/3 | 0% | ~25% (algorithm policy only) | ~50% | ~90% |
| NIST 800-53 Moderate | ~15% | ~35% | ~65% | ~90% |
| FedRAMP Moderate | ~10% | ~25% | ~55% | ~85% |
| Common Criteria EAL4+ | ~5% | ~15% | ~45% | ~75% |
| ITAR | 0% | ~10% | ~50% | ~80% |

*Note: SOC2, HIPAA, and GDPR compliance are organizational obligations, not purely software properties. The percentages above reflect technical control coverage only. Actual compliance requires organizational policies, third-party audits, and administrative controls beyond this library.*

## Appendix B: Threat Model Summary

| Threat Actor | Capability | Current Mitigation | Required Mitigation |
|-------------|-----------|--------------------|--------------------|
| External attacker (network) | Remote code execution, DB access | Encryption at rest | TLS everywhere, WAF, IDS |
| Malicious insider (agent) | Valid credentials, authorized access | Role-based access | MAC, TPI, insider threat detection, canaries |
| Compromised agent (AI) | Full API access within scope | Department isolation | Cryptographic compartmentalization, behavioral analytics |
| Nation-state (APT) | Supply chain, side-channel, quantum | AES-256-GCM | HSM, PQ crypto, air-gap mode, formal verification |
| Physical access | Storage media theft, cold boot | Fragment encryption | Full disk encryption, HSM, memory protection, secure boot |
| Insider (administrator) | Database access, key access | Audit logging | TPI for key access, HSM-bound keys, signed audit logs |

---

*This audit was initially generated for OpenShart pre-v0.1.0 (2026-02-17) and updated post-hardening (2026-02-18) to reflect resolved findings. The v0.1.0 release includes the GF(2^8) bug fix, all resolved P0 items above, ChainLock, FIPS mode, key management, classification system, Bell-LaPadula MAC, and 64 unit tests with CI. Findings should be re-assessed after each implementation phase.*
