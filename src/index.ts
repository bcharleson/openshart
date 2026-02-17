/**
 * Engram — Enterprise-grade encrypted memory framework for AI agents.
 *
 * @packageDocumentation
 */

// Core
export {
  Engram,
  EngramNotFoundError,
  EngramExpiredError,
  EngramReconstructionError,
  EngramAccessDeniedError,
} from './core/engram.js';
export type {
  SecurityLevel,
  EngramInitOptions,
  ClassifiedStoreOptions,
} from './core/engram.js';
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

// Classification (Government)
export {
  Classification,
  CLASSIFICATION_LEVEL,
  KNOWN_COMPARTMENTS,
  hasClearanceFor,
  hasCompartmentAccess,
  bellLaPadulaReadCheck,
  bellLaPadulaWriteCheck,
  checkClassifiedAccess,
  generatePortionMarking,
} from './hierarchy/classification.js';
export type {
  SCICompartment,
  CompartmentAccess,
  ClassifiedMemoryMeta,
  ClearanceProfile,
} from './hierarchy/classification.js';

// ChainLock
export {
  ChainLockProtocol,
  ChainLockError,
  generateSequence,
  encryptSequence,
  decryptSequence,
  validateSequence,
  rotateSequence,
  BreachDetector,
  BreachEventType,
  generateSessionNonce,
  produceChainToken,
  verifyChainToken,
  wipeChainToken,
  wipeSessionNonce,
  createTemporalConfig,
  signTimestamp,
  verifyTimestamp,
  checkStepWindow,
  checkTotalCeiling,
} from './chainlock/index.js';
export type {
  ChainLockConfig,
  ChainLockRecallResult,
  EncryptedSequence,
  TemporalConfig,
  SignedTimestamp,
  WindowCheckResult,
  ChainToken,
  BreachEvent,
  BreachDetectionConfig,
} from './chainlock/index.js';

// Crypto (FIPS)
export {
  enableFIPS,
  disableFIPS,
  isFIPSEnabled,
  validateKeyEntropy,
  fipsEncrypt,
  fipsDecrypt,
  fipsHmac,
  fipsHkdf,
  fipsRandomBytes,
  runSelfTests,
  FIPSError,
} from './crypto/index.js';

// Key Management
export {
  KeyRotationManager,
  createEscrow,
  recoverFromEscrow,
  secureDestroy,
  verifyDestruction,
  secureDestroyAll,
  SecureBuffer,
  SoftwareHSMProvider,
} from './keys/index.js';
export type {
  RotationEvent,
  KeyVersion,
  EscrowShare,
  EscrowConfig,
  DestructionVerification,
  HSMProvider,
  KeyHandle,
  AttestationResult,
} from './keys/index.js';

// Compliance
export { cryptographicErase, verifyErasure } from './compliance/gdpr.js';
export { detectPHI, enforceMinimumNecessary, containsPHI, PHI_PATTERNS } from './compliance/hipaa.js';
export { runSOC2Checks, generateSOC2Report } from './compliance/soc2.js';
