/**
 * @module storage/memory
 * In-memory storage backend for testing. All data is lost when the process exits.
 */

import type {
  StorageBackend,
  EncryptedFragment,
  FragmentId,
  MemoryId,
  MemoryMeta,
  AuditEntry,
  AuditFilters,
  ListFilters,
} from '../core/types.js';

export class MemoryBackend implements StorageBackend {
  private fragments = new Map<string, EncryptedFragment>();
  private metas = new Map<string, MemoryMeta>();
  private searchIndex = new Map<string, Set<MemoryId>>();
  private auditLog: AuditEntry[] = [];

  async putFragment(fragment: EncryptedFragment): Promise<void> {
    this.fragments.set(fragment.id, fragment);
  }

  async getFragment(id: FragmentId): Promise<EncryptedFragment | null> {
    return this.fragments.get(id) ?? null;
  }

  async getFragments(memoryId: MemoryId): Promise<EncryptedFragment[]> {
    const results: EncryptedFragment[] = [];
    for (const frag of this.fragments.values()) {
      if (frag.memoryId === memoryId) results.push(frag);
    }
    return results.sort((a, b) => a.index - b.index);
  }

  async deleteFragments(memoryId: MemoryId): Promise<number> {
    let count = 0;
    for (const [id, frag] of this.fragments) {
      if (frag.memoryId === memoryId) {
        this.fragments.delete(id);
        count++;
      }
    }
    return count;
  }

  async putMeta(meta: MemoryMeta): Promise<void> {
    this.metas.set(meta.id, meta);
  }

  async getMeta(memoryId: MemoryId): Promise<MemoryMeta | null> {
    return this.metas.get(memoryId) ?? null;
  }

  async deleteMeta(memoryId: MemoryId): Promise<void> {
    this.metas.delete(memoryId);
  }

  async listMeta(filters: ListFilters): Promise<MemoryMeta[]> {
    let results = [...this.metas.values()];

    if (filters.tags?.length) {
      results = results.filter(m =>
        filters.tags!.some(t => m.tags.includes(t))
      );
    }
    if (filters.piiLevel) {
      results = results.filter(m => m.piiLevel === filters.piiLevel);
    }
    if (filters.after) {
      results = results.filter(m => new Date(m.createdAt) >= filters.after!);
    }
    if (filters.before) {
      results = results.filter(m => new Date(m.createdAt) <= filters.before!);
    }

    // Filter expired
    results = results.filter(m => !m.expiresAt || new Date(m.expiresAt) > new Date());

    results.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    const offset = filters.offset ?? 0;
    const limit = filters.limit ?? 100;
    return results.slice(offset, offset + limit);
  }

  async putSearchToken(token: string, memoryId: MemoryId): Promise<void> {
    if (!this.searchIndex.has(token)) {
      this.searchIndex.set(token, new Set());
    }
    this.searchIndex.get(token)!.add(memoryId);
  }

  async lookupSearchToken(token: string): Promise<MemoryId[]> {
    const set = this.searchIndex.get(token);
    return set ? [...set] : [];
  }

  async deleteSearchTokens(memoryId: MemoryId): Promise<void> {
    for (const [token, ids] of this.searchIndex) {
      ids.delete(memoryId);
      if (ids.size === 0) this.searchIndex.delete(token);
    }
  }

  async appendAuditLog(entry: AuditEntry): Promise<void> {
    this.auditLog.push(entry);
  }

  async readAuditLog(filters: AuditFilters): Promise<AuditEntry[]> {
    let results = [...this.auditLog];

    if (filters.operation) {
      results = results.filter(e => e.operation === filters.operation);
    }
    if (filters.memoryId) {
      results = results.filter(e => e.memoryId === filters.memoryId);
    }
    if (filters.after) {
      results = results.filter(e => new Date(e.timestamp) >= filters.after!);
    }
    if (filters.before) {
      results = results.filter(e => new Date(e.timestamp) <= filters.before!);
    }

    results.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    if (filters.limit) {
      results = results.slice(0, filters.limit);
    }

    return results;
  }

  async close(): Promise<void> {
    this.fragments.clear();
    this.metas.clear();
    this.searchIndex.clear();
    this.auditLog = [];
  }
}
