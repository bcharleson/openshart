/**
 * Engram — Enterprise-grade encrypted memory framework for AI agents.
 *
 * @packageDocumentation
 *
 * @example
 * ```typescript
 * import { Engram, MemoryBackend, PIILevel, Role } from 'engram';
 * import { randomBytes } from 'node:crypto';
 *
 * const engram = await Engram.init({
 *   storage: new MemoryBackend(),
 *   encryptionKey: randomBytes(32),
 * });
 *
 * const { id } = await engram.store('Sensitive data here', { tags: ['test'] });
 * const results = await engram.search('sensitive');
 * const memory = await engram.recall(id);
 * await engram.forget(id);
 * await engram.close();
 * ```
 */

// Core
export { Engram, EngramNotFoundError, EngramExpiredError, EngramReconstructionError, EngramAccessDeniedError } from './core/engram.js';
export type {
  EngramOptions,
  MemoryId,
  FragmentId,
  EncryptedFragment,
  MemoryMeta,
  Memory,
  FragmentConfig,
  PIIConfig,
  PIIPattern,
  AuditConfig,
  StoreOptions,
  StoreResult,
  SearchOptions,
  SearchResult,
  ListFilters,
  ForgetResult,
  AuditEntry,
  AuditFilters,
  StorageBackend,
  Department,
  AccessGrant,
  DelegatedKey,
  PIIDetection,
} from './core/types.js';
export { PIILevel, AuditOperation, Role, ROLE_CLEARANCE, memoryId, fragmentId } from './core/types.js';
export { resolveFragmentConfig, resolveTTL, validateOptions, hasRoleClearance } from './core/config.js';

// Storage Backends
export { MemoryBackend } from './storage/memory.js';
export { SQLiteBackend } from './storage/sqlite.js';
export type { SQLiteOptions } from './storage/sqlite.js';

// PII
export { detectPII, redactPII, BUILTIN_PATTERNS } from './pii/detector.js';
export { classifyPIILevel, classifyContent, comparePIILevels, isAtLeast } from './pii/classifier.js';

// Fragments
export { split, reconstruct } from './fragments/shard.js';
export { aesEncrypt, aesDecrypt, deriveFragmentKey, deriveSearchKey } from './fragments/encrypt.js';
export { fragmentContent, reconstructContent } from './fragments/fragment-engine.js';

// Search
export { generateSearchToken, generateTagToken, tokenizeContent, generateContentTokens } from './search/tokens.js';
export { SearchIndex } from './search/index.js';
export { executeSearch } from './search/query.js';

// Audit
export { AuditLogger, computeEntryHash } from './audit/logger.js';
export { verifyAuditChain } from './audit/chain.js';
export { generateComplianceReport, exportAsCSV, exportAsJSONL } from './audit/compliance.js';

// Hierarchy
export { ROLE_DEFINITIONS, canDelegate, hasClearance, getAccessibleRoles } from './hierarchy/roles.js';
export { DepartmentManager } from './hierarchy/departments.js';
export { AccessController } from './hierarchy/access-control.js';
export { KeyChain } from './hierarchy/key-chain.js';
export { ContextFlowManager } from './hierarchy/context-flow.js';

// Compliance
export { cryptographicErase, verifyErasure } from './compliance/gdpr.js';
export { detectPHI, enforceMinimumNecessary, containsPHI, PHI_PATTERNS } from './compliance/hipaa.js';
export { runSOC2Checks, generateSOC2Report } from './compliance/soc2.js';
