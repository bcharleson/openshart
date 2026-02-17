/**
 * @module engram
 * Main Engram class — the public API for storing, searching, recalling, and forgetting memories.
 * Now with ChainLock, government classification, FIPS compliance, and security presets.
 */

import { randomUUID, randomBytes } from 'node:crypto';
import type {
  EngramOptions,
  StorageBackend,
  StoreOptions,
  StoreResult,
  SearchOptions,
  SearchResult,
  Memory,
  MemoryId,
  MemoryMeta,
  ForgetResult,
  ListFilters,
  AuditFilters,
  AuditEntry,
} from './types.js';
import { AuditOperation, memoryId } from './types.js';
import { validateOptions, resolveFragmentConfig, resolveTTL } from './config.js';
import { detectPII } from '../pii/detector.js';
import { classifyContent } from '../pii/classifier.js';
import { fragmentContent, reconstructContent } from '../fragments/fragment-engine.js';
import { deriveSearchKey } from '../fragments/encrypt.js';
import { SearchIndex } from '../search/index.js';
import { executeSearch } from '../search/query.js';
import { AuditLogger } from '../audit/logger.js';
import { verifyAuditChain, type ChainVerificationResult } from '../audit/chain.js';
import { ChainLockProtocol, type ChainLockConfig } from '../chainlock/protocol.js';
import { AccessController } from '../hierarchy/access-control.js';
import { DepartmentManager } from '../hierarchy/departments.js';
import {
  Classification,
  CLASSIFICATION_LEVEL,
  bellLaPadulaWriteCheck,
  type ClearanceProfile,
} from '../hierarchy/classification.js';
import { enableFIPS, isFIPSEnabled, validateKeyEntropy } from '../crypto/fips.js';

/** Security preset levels */
export type SecurityLevel = 'standard' | 'enterprise' | 'government' | 'classified';

/** Extended options with security presets */
export interface EngramInitOptions extends EngramOptions {
  /** Security preset: 'standard' | 'enterprise' | 'government' | 'classified' */
  securityLevel?: SecurityLevel;
  /** ChainLock configuration (auto-enabled at 'government'+) */
  chainLock?: ChainLockConfig;
  /** Agent's clearance profile for classified operations */
  clearance?: ClearanceProfile;
}

/** Extended store options with classification */
export interface ClassifiedStoreOptions extends StoreOptions {
  /** Government classification level */
  classification?: Classification;
  /** SCI compartments */
  compartments?: string[];
  /** Dissemination controls (e.g., 'NOFORN', 'ORCON') */
  disseminationControls?: string[];
  /** Original classification authority */
  classifiedBy?: string;
}

/**
 * Engram — the encrypted memory framework for AI agents.
 *
 * @example
 * ```typescript
 * const engram = await Engram.init({
 *   storage: new MemoryBackend(),
 *   encryptionKey: randomBytes(32),
 *   securityLevel: 'government',
 * });
 *
 * await engram.store("Patient John Doe, SSN 123-45-6789", {
 *   classification: Classification.SECRET,
 *   compartments: ['MEDICAL'],
 * });
 *
 * const memory = await engram.recall(id);
 * ```
 */
export class Engram {
  private readonly storage: StorageBackend;
  private readonly encryptionKey: Buffer;
  private readonly options: EngramInitOptions;
  private readonly securityLevel: SecurityLevel;
  private readonly chainLock: ChainLockProtocol;
  private readonly accessController: AccessController;
  private readonly departments: DepartmentManager;
  private readonly clearance?: ClearanceProfile;
  private searchIndex!: SearchIndex;
  private auditLogger!: AuditLogger;

  private constructor(options: EngramInitOptions) {
    this.storage = options.storage;
    this.encryptionKey = options.encryptionKey;
    this.options = options;
    this.securityLevel = options.securityLevel ?? 'standard';
    this.clearance = options.clearance;

    // Initialize departments and access control
    this.departments = new DepartmentManager();
    this.accessController = new AccessController(this.departments);

    // Initialize ChainLock based on security level
    const chainLockEnabled = this.securityLevel === 'government' || this.securityLevel === 'classified';
    this.chainLock = new ChainLockProtocol({
      enabled: chainLockEnabled,
      ...options.chainLock,
    });
  }

  /**
   * Initialize an Engram instance with security presets.
   */
  static async init(options: EngramInitOptions): Promise<Engram> {
    validateOptions(options);

    const level = options.securityLevel ?? 'standard';

    // FIPS mode for government+
    if ((level === 'government' || level === 'classified') && !isFIPSEnabled()) {
      enableFIPS();
    }

    // Validate key entropy for enterprise+
    if (level !== 'standard') {
      validateKeyEntropy(options.encryptionKey);
    }

    const instance = new Engram(options);

    // Derive search key from master key
    const searchKey = await deriveSearchKey(options.encryptionKey);
    instance.searchIndex = new SearchIndex(options.storage, searchKey);

    // Initialize audit logger
    instance.auditLogger = new AuditLogger(
      options.storage,
      options.agentId ?? 'system',
      options.audit?.enabled ?? true,
    );
    await instance.auditLogger.init();

    return instance;
  }

  /**
   * Store a memory with optional classification.
   * PII detection, fragmentation, encryption, classification — all automatic.
   */
  async store(content: string, options: ClassifiedStoreOptions = {}): Promise<StoreResult> {
    // P0 fix: Enforce access control — check write permission
    if (options.classification && this.clearance) {
      const writeCheck = bellLaPadulaWriteCheck(
        this.clearance.maxClassification,
        options.classification,
      );
      if (!writeCheck.allowed) {
        throw new EngramAccessDeniedError(writeCheck.reason);
      }
    }

    // PII detection
    const piiEnabled = this.options.pii?.enabled ?? true;
    const detections = piiEnabled
      ? detectPII(content, this.options.pii?.customPatterns)
      : [];
    const classification = classifyContent(detections);

    const piiLevel = options.piiLevel ?? classification.level;
    const fragmentConfig = resolveFragmentConfig(
      piiLevel,
      options.fragment ?? this.options.fragment,
      this.options.pii?.fragmentOverrides,
    );

    // Increase fragmentation for classified content
    if (options.classification && CLASSIFICATION_LEVEL[options.classification] >= CLASSIFICATION_LEVEL[Classification.SECRET]) {
      fragmentConfig.threshold = Math.max(fragmentConfig.threshold, 5);
      fragmentConfig.totalShares = Math.max(fragmentConfig.totalShares, 8);
      fragmentConfig.slots = Math.max(fragmentConfig.slots, 8);
    }

    const id = memoryId(`mem_${randomUUID().replace(/-/g, '').slice(0, 16)}`);

    const fragments = await fragmentContent(
      content,
      id,
      this.encryptionKey,
      fragmentConfig,
    );

    for (const fragment of fragments) {
      await this.storage.putFragment(fragment);
    }

    const ttl = resolveTTL(piiLevel, options.ttl, this.options.pii?.ttlOverrides);
    const now = new Date();
    const expiresAt = ttl ? new Date(now.getTime() + ttl).toISOString() : null;

    const tags = options.tags ?? [];
    const meta: MemoryMeta = {
      id,
      tags,
      piiLevel,
      fragmentCount: fragments.length,
      threshold: fragmentConfig.threshold,
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      expiresAt,
      contentLength: Buffer.byteLength(content, 'utf-8'),
      agentId: this.options.agentId,
      department: this.options.department,
      accessLevel: options.accessLevel,
    };
    await this.storage.putMeta(meta);

    // Initialize ChainLock sequence for government+
    if (this.securityLevel === 'government' || this.securityLevel === 'classified') {
      await this.chainLock.initializeSequence(id, fragments.length, this.encryptionKey);
    }

    await this.searchIndex.indexMemory(id, content, tags);

    const auditId = await this.auditLogger.log(
      AuditOperation.STORE,
      id,
      {
        piiLevel,
        fragmentCount: fragments.length,
        threshold: fragmentConfig.threshold,
        detectedPII: classification.detectedTypes,
        tags,
        contentLength: meta.contentLength,
        hasExpiry: expiresAt !== null,
        classification: options.classification,
        compartments: options.compartments,
        securityLevel: this.securityLevel,
      },
    );

    return {
      id,
      piiLevel,
      fragmentCount: fragments.length,
      threshold: fragmentConfig.threshold,
      detectedPII: classification.detectedTypes,
      auditId,
    };
  }

  /**
   * Search memories without decrypting content.
   * P0 fix: Enforces access control before returning results.
   */
  async search(query: string, options: SearchOptions = {}): Promise<SearchResult> {
    const result = await executeSearch(
      this.searchIndex,
      this.storage,
      query,
      options,
    );

    // P0 fix: Filter results by access control
    if (this.options.role && this.options.department) {
      result.memories = result.memories.filter(meta => {
        const decision = this.accessController.checkAccess(
          this.options.agentId ?? 'system',
          this.options.role!,
          this.options.department!,
          meta,
        );
        return decision.allowed;
      });
      result.total = result.memories.length;
    }

    await this.auditLogger.log(
      AuditOperation.SEARCH,
      null,
      {
        resultCount: result.total,
        hasTagFilter: !!(options.tags?.length),
        hasPIIFilter: !!options.maxPIILevel,
      },
    );

    return result;
  }

  /**
   * Recall a specific memory.
   * P0 fix: Enforces access control before decryption.
   * Uses ChainLock protocol at government+ security levels.
   */
  async recall(id: MemoryId): Promise<Memory> {
    const meta = await this.storage.getMeta(id);
    if (!meta) {
      throw new EngramNotFoundError(id);
    }

    // Check expiry
    if (meta.expiresAt && new Date(meta.expiresAt) < new Date()) {
      throw new EngramExpiredError(id);
    }

    // P0 fix: Enforce access control
    if (this.options.role && this.options.department) {
      const decision = this.accessController.checkAccess(
        this.options.agentId ?? 'system',
        this.options.role,
        this.options.department,
        meta,
      );
      if (!decision.allowed) {
        await this.auditLogger.log(
          AuditOperation.RECALL,
          id,
          { denied: true, reason: decision.reason },
        );
        throw new EngramAccessDeniedError(decision.reason);
      }
    }

    // Fetch fragments
    const fragments = await this.storage.getFragments(id);
    if (fragments.length < meta.threshold) {
      throw new EngramReconstructionError(id, fragments.length, meta.threshold);
    }

    let content: string;

    // Use ChainLock for government+ security
    if (this.securityLevel === 'government' || this.securityLevel === 'classified') {
      const result = await this.chainLock.recall(
        id,
        fragments,
        this.encryptionKey,
        this.options.agentId ?? 'system',
        meta.threshold,
      );
      content = result.content;
    } else {
      const selectedFragments = fragments.slice(0, meta.threshold);
      content = await reconstructContent(selectedFragments, this.encryptionKey);
    }

    await this.auditLogger.log(
      AuditOperation.RECALL,
      id,
      {
        fragmentsUsed: meta.threshold,
        threshold: meta.threshold,
        chainLock: this.securityLevel === 'government' || this.securityLevel === 'classified',
      },
    );

    return {
      id,
      content,
      tags: meta.tags,
      piiLevel: meta.piiLevel,
      createdAt: meta.createdAt,
      updatedAt: meta.updatedAt,
    };
  }

  /**
   * Cryptographically destroy a memory.
   * P0 fix: Multi-pass overwrite (DoD 5220.22-M — 3 passes).
   */
  async forget(id: MemoryId): Promise<ForgetResult> {
    const meta = await this.storage.getMeta(id);
    if (!meta) {
      throw new EngramNotFoundError(id);
    }

    const fragments = await this.storage.getFragments(id);

    // P0 fix: 3-pass overwrite (zeros, ones, random) per DoD 5220.22-M
    for (const fragment of fragments) {
      for (let pass = 0; pass < 3; pass++) {
        if (pass === 0) {
          fragment.ciphertext = Buffer.alloc(fragment.ciphertext.length, 0x00);
          fragment.iv = Buffer.alloc(fragment.iv.length, 0x00);
          fragment.authTag = Buffer.alloc(fragment.authTag.length, 0x00);
        } else if (pass === 1) {
          fragment.ciphertext = Buffer.alloc(fragment.ciphertext.length, 0xff);
          fragment.iv = Buffer.alloc(fragment.iv.length, 0xff);
          fragment.authTag = Buffer.alloc(fragment.authTag.length, 0xff);
        } else {
          fragment.ciphertext = randomBytes(fragment.ciphertext.length);
          fragment.iv = randomBytes(fragment.iv.length);
          fragment.authTag = randomBytes(fragment.authTag.length);
        }
        await this.storage.putFragment(fragment);
      }
    }

    const fragmentsDestroyed = await this.storage.deleteFragments(id);
    await this.searchIndex.removeMemory(id);
    await this.storage.deleteMeta(id);

    // Clean up ChainLock sequence
    this.chainLock.clearSequence(id);

    const auditId = await this.auditLogger.log(
      AuditOperation.FORGET,
      id,
      {
        fragmentsDestroyed,
        method: 'dod_5220_22m_3pass',
        gdprArticle17: true,
        passes: 3,
      },
    );

    return {
      memoryId: id,
      fragmentsDestroyed,
      searchTokensPurged: fragmentsDestroyed,
      auditId,
    };
  }

  /**
   * List memory metadata. Never returns content.
   */
  async list(filters: ListFilters = {}): Promise<MemoryMeta[]> {
    return this.storage.listMeta(filters);
  }

  /**
   * Export audit log for compliance reporting.
   */
  async export(filters: AuditFilters = {}): Promise<AuditEntry[]> {
    const entries = await this.storage.readAuditLog(filters);

    await this.auditLogger.log(
      AuditOperation.EXPORT,
      null,
      {
        entriesExported: entries.length,
        filters: {
          operation: filters.operation,
          hasDateRange: !!(filters.after || filters.before),
        },
      },
    );

    return entries;
  }

  /**
   * Verify the integrity of the audit log hash chain.
   */
  async verifyAuditChain(): Promise<ChainVerificationResult> {
    return verifyAuditChain(this.storage);
  }

  /**
   * Get the ChainLock protocol instance (for lockdown management, breach events).
   */
  getChainLock(): ChainLockProtocol {
    return this.chainLock;
  }

  /**
   * Get the current security level.
   */
  getSecurityLevel(): SecurityLevel {
    return this.securityLevel;
  }

  /**
   * Gracefully close storage connections.
   */
  async close(): Promise<void> {
    await this.storage.close();
  }
}

// ─── Error Classes ────────────────────────────────────────────

export class EngramNotFoundError extends Error {
  constructor(public readonly memoryId: MemoryId) {
    super(`Memory not found: ${memoryId}`);
    this.name = 'EngramNotFoundError';
  }
}

export class EngramExpiredError extends Error {
  constructor(public readonly memoryId: MemoryId) {
    super(`Memory has expired: ${memoryId}`);
    this.name = 'EngramExpiredError';
  }
}

export class EngramReconstructionError extends Error {
  constructor(
    public readonly memoryId: MemoryId,
    public readonly available: number,
    public readonly required: number,
  ) {
    super(`Insufficient fragments for ${memoryId}: ${available} available, ${required} required`);
    this.name = 'EngramReconstructionError';
  }
}

export class EngramAccessDeniedError extends Error {
  constructor(reason: string) {
    super(`Access denied: ${reason}`);
    this.name = 'EngramAccessDeniedError';
  }
}
