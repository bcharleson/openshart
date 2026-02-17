/**
 * @module types
 * Core type definitions for OpenShart — the encrypted memory framework for AI agents.
 */

// ─── Branded ID Types ─────────────────────────────────────────

/** Unique identifier for a stored memory */
export type MemoryId = string & { readonly __brand: 'MemoryId' };

/** Unique identifier for a fragment */
export type FragmentId = string & { readonly __brand: 'FragmentId' };

/** Create a branded MemoryId */
export function memoryId(id: string): MemoryId {
  return id as MemoryId;
}

/** Create a branded FragmentId */
export function fragmentId(id: string): FragmentId {
  return id as FragmentId;
}

// ─── Enums ────────────────────────────────────────────────────

/** Sensitivity classification for stored content */
export enum PIILevel {
  NONE = 'NONE',
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

/** Audit log operation types */
export enum AuditOperation {
  STORE = 'STORE',
  SEARCH = 'SEARCH',
  RECALL = 'RECALL',
  FORGET = 'FORGET',
  EXPORT = 'EXPORT',
  KEY_DELEGATION = 'KEY_DELEGATION',
  ACCESS_GRANT = 'ACCESS_GRANT',
  ACCESS_REVOKE = 'ACCESS_REVOKE',
  CONTEXT_PUSH_DOWN = 'CONTEXT_PUSH_DOWN',
  CONTEXT_BUBBLE_UP = 'CONTEXT_BUBBLE_UP',
  LATERAL_GRANT = 'LATERAL_GRANT',
}

/** Enterprise hierarchy roles */
export enum Role {
  EXECUTIVE = 'EXECUTIVE',
  DIRECTOR = 'DIRECTOR',
  MANAGER = 'MANAGER',
  CONTRIBUTOR = 'CONTRIBUTOR',
  AGENT = 'AGENT',
}

/** Clearance levels mapped to roles (higher = more access) */
export const ROLE_CLEARANCE: Record<Role, number> = {
  [Role.EXECUTIVE]: 100,
  [Role.DIRECTOR]: 80,
  [Role.MANAGER]: 60,
  [Role.CONTRIBUTOR]: 40,
  [Role.AGENT]: 20,
};

// ─── Fragment Types ───────────────────────────────────────────

/** Encrypted fragment stored in backend */
export interface EncryptedFragment {
  id: FragmentId;
  memoryId: MemoryId;
  /** Fragment index (1-based) */
  index: number;
  /** Total fragments for this memory */
  total: number;
  /** AES-256-GCM encrypted Shamir share */
  ciphertext: Buffer;
  /** GCM initialization vector */
  iv: Buffer;
  /** GCM authentication tag */
  authTag: Buffer;
  /** Storage slot identifier */
  slot: string;
  /** ISO 8601 creation timestamp */
  createdAt: string;
}

/** Memory metadata (never includes content) */
export interface MemoryMeta {
  id: MemoryId;
  tags: string[];
  piiLevel: PIILevel;
  fragmentCount: number;
  threshold: number;
  createdAt: string;
  updatedAt: string;
  expiresAt: string | null;
  contentLength: number;
  /** Agent ID that owns this memory */
  agentId?: string;
  /** Department scope */
  department?: string;
  /** Access level required */
  accessLevel?: Role;
}

/** Reconstructed memory */
export interface Memory {
  id: MemoryId;
  content: string;
  tags: string[];
  piiLevel: PIILevel;
  createdAt: string;
  updatedAt: string;
}

// ─── Configuration Types ──────────────────────────────────────

/** Fragment engine configuration */
export interface FragmentConfig {
  threshold?: number;
  totalShares?: number;
  slots?: number;
}

/** Custom PII detection pattern */
export interface PIIPattern {
  name: string;
  regex: RegExp;
  level: PIILevel;
}

/** PII detection configuration */
export interface PIIConfig {
  enabled?: boolean;
  customPatterns?: PIIPattern[];
  fragmentOverrides?: Partial<Record<PIILevel, FragmentConfig>>;
  ttlOverrides?: Partial<Record<PIILevel, number | null>>;
}

/** Audit configuration */
export interface AuditConfig {
  enabled?: boolean;
  maxEntries?: number;
}

/** OpenShart initialization options */
export interface OpenShartOptions {
  storage: StorageBackend;
  encryptionKey: Buffer;
  fragment?: FragmentConfig;
  pii?: PIIConfig;
  audit?: AuditConfig;
  /** Agent identity for hierarchy-aware operations */
  agentId?: string;
  /** Agent's role for access control */
  role?: Role;
  /** Agent's department */
  department?: string;
}

// ─── Operation Types ──────────────────────────────────────────

export interface StoreOptions {
  tags?: string[];
  piiLevel?: PIILevel;
  ttl?: number | null;
  fragment?: FragmentConfig;
  metadata?: Record<string, unknown>;
  /** Restrict access to this role level and above */
  accessLevel?: Role;
}

export interface StoreResult {
  id: MemoryId;
  piiLevel: PIILevel;
  fragmentCount: number;
  threshold: number;
  detectedPII: string[];
  auditId: string;
}

export interface SearchOptions {
  limit?: number;
  tags?: string[];
  maxPIILevel?: PIILevel;
  after?: Date;
  before?: Date;
}

export interface SearchResult {
  memories: MemoryMeta[];
  total: number;
  encrypted: true;
}

export interface ListFilters {
  tags?: string[];
  piiLevel?: PIILevel;
  after?: Date;
  before?: Date;
  limit?: number;
  offset?: number;
}

export interface ForgetResult {
  memoryId: MemoryId;
  fragmentsDestroyed: number;
  searchTokensPurged: number;
  auditId: string;
}

// ─── Audit Types ──────────────────────────────────────────────

export interface AuditEntry {
  id: string;
  operation: AuditOperation;
  memoryId: MemoryId | null;
  agentId: string;
  accessLevel: Role | null;
  timestamp: string;
  previousHash: string;
  hash: string;
  details: Record<string, unknown>;
}

export interface AuditFilters {
  operation?: AuditOperation;
  memoryId?: MemoryId;
  after?: Date;
  before?: Date;
  limit?: number;
}

// ─── Storage Backend Interface ────────────────────────────────

export interface StorageBackend {
  putFragment(fragment: EncryptedFragment): Promise<void>;
  getFragment(id: FragmentId): Promise<EncryptedFragment | null>;
  getFragments(memoryId: MemoryId): Promise<EncryptedFragment[]>;
  deleteFragments(memoryId: MemoryId): Promise<number>;
  putMeta(meta: MemoryMeta): Promise<void>;
  getMeta(memoryId: MemoryId): Promise<MemoryMeta | null>;
  deleteMeta(memoryId: MemoryId): Promise<void>;
  listMeta(filters: ListFilters): Promise<MemoryMeta[]>;
  putSearchToken(token: string, memoryId: MemoryId): Promise<void>;
  lookupSearchToken(token: string): Promise<MemoryId[]>;
  deleteSearchTokens(memoryId: MemoryId): Promise<void>;
  appendAuditLog(entry: AuditEntry): Promise<void>;
  readAuditLog(filters: AuditFilters): Promise<AuditEntry[]>;
  close(): Promise<void>;
}

// ─── Hierarchy Types ──────────────────────────────────────────

/** Department definition */
export interface Department {
  id: string;
  name: string;
  parentId?: string;
  encryptionNamespace: string;
}

/** Access grant for cross-department or delegated access */
export interface AccessGrant {
  id: string;
  fromAgentId: string;
  toAgentId: string;
  fromDepartment?: string;
  toDepartment?: string;
  scope: string[];
  role: Role;
  createdAt: string;
  expiresAt: string;
}

/** Delegated access key */
export interface DelegatedKey {
  id: string;
  issuedBy: string;
  issuedTo: string;
  derivedKey: Buffer;
  scope: string[];
  maxRole: Role;
  createdAt: string;
  expiresAt: string;
}

/** PII detection result */
export interface PIIDetection {
  type: string;
  level: PIILevel;
  /** Character offset in source text */
  start: number;
  end: number;
  /** The matched value (for redaction) */
  value: string;
}
