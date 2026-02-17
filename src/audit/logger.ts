/**
 * @module audit/logger
 * Audit logger with tamper-evident hash chain.
 * Every operation is logged with a cryptographic link to the previous entry.
 */

import { createHash, randomUUID } from 'node:crypto';
import type {
  StorageBackend,
  AuditEntry,
  AuditOperation,
  MemoryId,
  Role,
} from '../core/types.js';

/** The genesis hash (first entry's previousHash) */
const GENESIS_HASH = '0'.repeat(64);

/**
 * Compute the SHA-256 hash of an audit entry (excluding the hash field itself).
 */
export function computeEntryHash(entry: Omit<AuditEntry, 'hash'>): string {
  const data = JSON.stringify({
    id: entry.id,
    operation: entry.operation,
    memoryId: entry.memoryId,
    agentId: entry.agentId,
    accessLevel: entry.accessLevel,
    timestamp: entry.timestamp,
    previousHash: entry.previousHash,
    details: entry.details,
  });
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Audit logger that maintains a hash chain for tamper evidence.
 */
export class AuditLogger {
  private lastHash: string = GENESIS_HASH;
  private enabled: boolean;

  constructor(
    private readonly storage: StorageBackend,
    private readonly agentId: string = 'system',
    enabled = true,
  ) {
    this.enabled = enabled;
  }

  /** Initialize by loading the last hash from storage */
  async init(): Promise<void> {
    if (!this.enabled) return;

    const entries = await this.storage.readAuditLog({ limit: 1 });
    if (entries.length > 0) {
      this.lastHash = entries[0]!.hash;
    }
  }

  /**
   * Log an operation to the audit chain.
   *
   * @returns The audit entry ID, or empty string if logging is disabled
   */
  async log(
    operation: AuditOperation,
    memoryId: MemoryId | null,
    details: Record<string, unknown>,
    accessLevel?: Role | null,
  ): Promise<string> {
    if (!this.enabled) return '';

    const id = `aud_${randomUUID().replace(/-/g, '').slice(0, 12)}`;
    const timestamp = new Date().toISOString();

    const entryWithoutHash = {
      id,
      operation,
      memoryId,
      agentId: this.agentId,
      accessLevel: accessLevel ?? null,
      timestamp,
      previousHash: this.lastHash,
      details,
    };

    const hash = computeEntryHash(entryWithoutHash);
    const entry: AuditEntry = { ...entryWithoutHash, hash };

    await this.storage.appendAuditLog(entry);
    this.lastHash = hash;

    return id;
  }

  /** Get the current chain head hash */
  getLastHash(): string {
    return this.lastHash;
  }
}
