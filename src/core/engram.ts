/**
 * @module engram
 * Main Engram class — the public API for storing, searching, recalling, and forgetting memories.
 */

import { randomUUID } from 'node:crypto';
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

/**
 * Engram — the encrypted memory framework for AI agents.
 *
 * @example
 * ```typescript
 * const engram = await Engram.init({
 *   storage: new MemoryBackend(),
 *   encryptionKey: randomBytes(32),
 * });
 *
 * const { id } = await engram.store('User prefers dark mode', { tags: ['preferences'] });
 * const results = await engram.search('dark mode');
 * const memory = await engram.recall(id);
 * await engram.forget(id);
 * await engram.close();
 * ```
 */
export class Engram {
  private readonly storage: StorageBackend;
  private readonly encryptionKey: Buffer;
  private readonly options: EngramOptions;
  private searchIndex!: SearchIndex;
  private auditLogger!: AuditLogger;

  private constructor(options: EngramOptions) {
    this.storage = options.storage;
    this.encryptionKey = options.encryptionKey;
    this.options = options;
  }

  /**
   * Initialize an Engram instance.
   * Validates options, derives keys, and sets up the audit logger.
   */
  static async init(options: EngramOptions): Promise<Engram> {
    validateOptions(options);

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
   * Store a memory. Content is PII-scanned, fragmented, encrypted, indexed, and audited.
   */
  async store(content: string, options: StoreOptions = {}): Promise<StoreResult> {
    // PII detection
    const piiEnabled = this.options.pii?.enabled ?? true;
    const detections = piiEnabled
      ? detectPII(content, this.options.pii?.customPatterns)
      : [];
    const classification = classifyContent(detections);

    // Use explicit PII level if provided, otherwise auto-detected
    const piiLevel = options.piiLevel ?? classification.level;

    // Resolve fragment configuration
    const fragmentConfig = resolveFragmentConfig(
      piiLevel,
      options.fragment ?? this.options.fragment,
      this.options.pii?.fragmentOverrides,
    );

    // Generate memory ID
    const id = memoryId(`mem_${randomUUID().replace(/-/g, '').slice(0, 16)}`);

    // Fragment and encrypt content
    const fragments = await fragmentContent(
      content,
      id,
      this.encryptionKey,
      fragmentConfig,
    );

    // Store fragments
    for (const fragment of fragments) {
      await this.storage.putFragment(fragment);
    }

    // Resolve TTL
    const ttl = resolveTTL(piiLevel, options.ttl, this.options.pii?.ttlOverrides);
    const now = new Date();
    const expiresAt = ttl ? new Date(now.getTime() + ttl).toISOString() : null;

    // Store metadata
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

    // Index for search
    await this.searchIndex.indexMemory(id, content, tags);

    // Audit
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
   * Search memories without decrypting content. Returns metadata only.
   */
  async search(query: string, options: SearchOptions = {}): Promise<SearchResult> {
    const result = await executeSearch(
      this.searchIndex,
      this.storage,
      query,
      options,
    );

    // Audit the search
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
   * Recall a specific memory. Reconstructs plaintext in-memory only.
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

    // Fetch fragments
    const fragments = await this.storage.getFragments(id);
    if (fragments.length < meta.threshold) {
      throw new EngramReconstructionError(
        id,
        fragments.length,
        meta.threshold,
      );
    }

    // Use only threshold number of fragments for reconstruction
    const selectedFragments = fragments.slice(0, meta.threshold);
    const content = await reconstructContent(selectedFragments, this.encryptionKey);

    // Audit the recall
    await this.auditLogger.log(
      AuditOperation.RECALL,
      id,
      {
        fragmentsUsed: selectedFragments.length,
        threshold: meta.threshold,
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
   * Cryptographically destroy a memory. GDPR Article 17 compliant.
   */
  async forget(id: MemoryId): Promise<ForgetResult> {
    const meta = await this.storage.getMeta(id);
    if (!meta) {
      throw new EngramNotFoundError(id);
    }

    // Overwrite fragments with random data, then delete
    const { randomBytes } = await import('node:crypto');
    const fragments = await this.storage.getFragments(id);

    for (const fragment of fragments) {
      fragment.ciphertext = randomBytes(fragment.ciphertext.length);
      fragment.iv = randomBytes(fragment.iv.length);
      fragment.authTag = randomBytes(fragment.authTag.length);
      await this.storage.putFragment(fragment);
    }

    const fragmentsDestroyed = await this.storage.deleteFragments(id);
    await this.searchIndex.removeMemory(id);
    await this.storage.deleteMeta(id);

    const auditId = await this.auditLogger.log(
      AuditOperation.FORGET,
      id,
      {
        fragmentsDestroyed,
        method: 'cryptographic_erase',
        gdprArticle17: true,
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
