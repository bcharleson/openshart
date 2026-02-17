/**
 * @module storage/sqlite
 * SQLite storage backend using better-sqlite3.
 * Zero-config local storage with full schema for fragments, search index, audit log, and access keys.
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
import { PIILevel, memoryId } from '../core/types.js';

export interface SQLiteOptions {
  /** Database file path. Default: './openshart.db' */
  path?: string;
  /** Enable WAL mode. Default: true */
  wal?: boolean;
  /** Run PRAGMA optimize on close. Default: true */
  optimize?: boolean;
}

/**
 * SQLite storage backend.
 * Requires `better-sqlite3` as a peer dependency.
 */
export class SQLiteBackend implements StorageBackend {
  private db: any; // better-sqlite3 Database instance
  private readonly options: Required<SQLiteOptions>;

  constructor(options: SQLiteOptions = {}) {
    this.options = {
      path: options.path ?? './openshart.db',
      wal: options.wal ?? true,
      optimize: options.optimize ?? true,
    };
  }

  /** Initialize the database (called automatically on first operation) */
  private ensureDb(): any {
    if (this.db) return this.db;

    // Dynamic import of better-sqlite3
    let Database: any;
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      Database = require('better-sqlite3');
    } catch {
      throw new Error(
        'better-sqlite3 is required for SQLiteBackend. Install it: npm install better-sqlite3'
      );
    }

    this.db = new Database(this.options.path);

    if (this.options.wal) {
      this.db.pragma('journal_mode = WAL');
    }
    this.db.pragma('foreign_keys = ON');

    this.createTables();
    return this.db;
  }

  private createTables(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS fragments (
        id TEXT PRIMARY KEY,
        memory_id TEXT NOT NULL,
        idx INTEGER NOT NULL,
        total INTEGER NOT NULL,
        ciphertext BLOB NOT NULL,
        iv BLOB NOT NULL,
        auth_tag BLOB NOT NULL,
        slot TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS memory_meta (
        id TEXT PRIMARY KEY,
        tags_json TEXT NOT NULL DEFAULT '[]',
        pii_level TEXT NOT NULL,
        fragment_count INTEGER NOT NULL,
        threshold INTEGER NOT NULL,
        content_length INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        expires_at TEXT,
        agent_id TEXT,
        department TEXT,
        access_level TEXT
      );

      CREATE TABLE IF NOT EXISTS search_index (
        token TEXT NOT NULL,
        memory_id TEXT NOT NULL,
        PRIMARY KEY (token, memory_id)
      );

      CREATE TABLE IF NOT EXISTS audit_log (
        id TEXT PRIMARY KEY,
        operation TEXT NOT NULL,
        memory_id TEXT,
        agent_id TEXT NOT NULL DEFAULT 'system',
        access_level TEXT,
        timestamp TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        hash TEXT NOT NULL,
        details TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS access_keys (
        id TEXT PRIMARY KEY,
        issued_by TEXT NOT NULL,
        issued_to TEXT NOT NULL,
        derived_key BLOB NOT NULL,
        scope TEXT NOT NULL,
        max_role TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_fragments_memory ON fragments(memory_id);
      CREATE INDEX IF NOT EXISTS idx_meta_pii ON memory_meta(pii_level);
      CREATE INDEX IF NOT EXISTS idx_meta_expires ON memory_meta(expires_at);
      CREATE INDEX IF NOT EXISTS idx_search_token ON search_index(token);
      CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp);
      CREATE INDEX IF NOT EXISTS idx_audit_memory ON audit_log(memory_id);
      CREATE INDEX IF NOT EXISTS idx_access_keys_to ON access_keys(issued_to);
    `);
  }

  async putFragment(fragment: EncryptedFragment): Promise<void> {
    const db = this.ensureDb();
    db.prepare(`
      INSERT OR REPLACE INTO fragments (id, memory_id, idx, total, ciphertext, iv, auth_tag, slot, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      fragment.id,
      fragment.memoryId,
      fragment.index,
      fragment.total,
      fragment.ciphertext,
      fragment.iv,
      fragment.authTag,
      fragment.slot,
      fragment.createdAt,
    );
  }

  async getFragment(id: FragmentId): Promise<EncryptedFragment | null> {
    const db = this.ensureDb();
    const row = db.prepare('SELECT * FROM fragments WHERE id = ?').get(id) as any;
    return row ? this.rowToFragment(row) : null;
  }

  async getFragments(mid: MemoryId): Promise<EncryptedFragment[]> {
    const db = this.ensureDb();
    const rows = db.prepare('SELECT * FROM fragments WHERE memory_id = ? ORDER BY idx').all(mid) as any[];
    return rows.map(r => this.rowToFragment(r));
  }

  async deleteFragments(mid: MemoryId): Promise<number> {
    const db = this.ensureDb();
    const result = db.prepare('DELETE FROM fragments WHERE memory_id = ?').run(mid);
    return result.changes;
  }

  async putMeta(meta: MemoryMeta): Promise<void> {
    const db = this.ensureDb();
    db.prepare(`
      INSERT OR REPLACE INTO memory_meta
        (id, tags_json, pii_level, fragment_count, threshold, content_length, created_at, updated_at, expires_at, agent_id, department, access_level)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      meta.id,
      JSON.stringify(meta.tags),
      meta.piiLevel,
      meta.fragmentCount,
      meta.threshold,
      meta.contentLength,
      meta.createdAt,
      meta.updatedAt,
      meta.expiresAt,
      meta.agentId ?? null,
      meta.department ?? null,
      meta.accessLevel ?? null,
    );
  }

  async getMeta(mid: MemoryId): Promise<MemoryMeta | null> {
    const db = this.ensureDb();
    const row = db.prepare('SELECT * FROM memory_meta WHERE id = ?').get(mid) as any;
    return row ? this.rowToMeta(row) : null;
  }

  async deleteMeta(mid: MemoryId): Promise<void> {
    const db = this.ensureDb();
    db.prepare('DELETE FROM memory_meta WHERE id = ?').run(mid);
  }

  async listMeta(filters: ListFilters): Promise<MemoryMeta[]> {
    const db = this.ensureDb();
    const conditions: string[] = [];
    const params: any[] = [];

    if (filters.tags?.length) {
      // Check if any tag matches (JSON array search)
      const tagConditions = filters.tags.map(() => "tags_json LIKE ?");
      conditions.push(`(${tagConditions.join(' OR ')})`);
      for (const tag of filters.tags) {
        params.push(`%"${tag}"%`);
      }
    }
    if (filters.piiLevel) {
      conditions.push('pii_level = ?');
      params.push(filters.piiLevel);
    }
    if (filters.after) {
      conditions.push('created_at >= ?');
      params.push(filters.after.toISOString());
    }
    if (filters.before) {
      conditions.push('created_at <= ?');
      params.push(filters.before.toISOString());
    }

    // Exclude expired
    conditions.push('(expires_at IS NULL OR expires_at > ?)');
    params.push(new Date().toISOString());

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = filters.limit ?? 100;
    const offset = filters.offset ?? 0;

    const rows = db.prepare(
      `SELECT * FROM memory_meta ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`
    ).all(...params, limit, offset) as any[];

    return rows.map(r => this.rowToMeta(r));
  }

  async putSearchToken(token: string, mid: MemoryId): Promise<void> {
    const db = this.ensureDb();
    db.prepare('INSERT OR IGNORE INTO search_index (token, memory_id) VALUES (?, ?)').run(token, mid);
  }

  async lookupSearchToken(token: string): Promise<MemoryId[]> {
    const db = this.ensureDb();
    const rows = db.prepare('SELECT memory_id FROM search_index WHERE token = ?').all(token) as any[];
    return rows.map(r => memoryId(r.memory_id));
  }

  async deleteSearchTokens(mid: MemoryId): Promise<void> {
    const db = this.ensureDb();
    db.prepare('DELETE FROM search_index WHERE memory_id = ?').run(mid);
  }

  async appendAuditLog(entry: AuditEntry): Promise<void> {
    const db = this.ensureDb();
    db.prepare(`
      INSERT INTO audit_log (id, operation, memory_id, agent_id, access_level, timestamp, previous_hash, hash, details)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      entry.id,
      entry.operation,
      entry.memoryId,
      entry.agentId,
      entry.accessLevel,
      entry.timestamp,
      entry.previousHash,
      entry.hash,
      JSON.stringify(entry.details),
    );
  }

  async readAuditLog(filters: AuditFilters): Promise<AuditEntry[]> {
    const db = this.ensureDb();
    const conditions: string[] = [];
    const params: any[] = [];

    if (filters.operation) {
      conditions.push('operation = ?');
      params.push(filters.operation);
    }
    if (filters.memoryId) {
      conditions.push('memory_id = ?');
      params.push(filters.memoryId);
    }
    if (filters.after) {
      conditions.push('timestamp >= ?');
      params.push(filters.after.toISOString());
    }
    if (filters.before) {
      conditions.push('timestamp <= ?');
      params.push(filters.before.toISOString());
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = filters.limit ?? 1000;

    const rows = db.prepare(
      `SELECT * FROM audit_log ${where} ORDER BY timestamp DESC LIMIT ?`
    ).all(...params, limit) as any[];

    return rows.map(r => this.rowToAuditEntry(r));
  }

  async close(): Promise<void> {
    if (this.db) {
      if (this.options.optimize) {
        this.db.pragma('optimize');
      }
      this.db.close();
      this.db = null;
    }
  }

  // ─── Row Mapping ────────────────────────────────────────────

  private rowToFragment(row: any): EncryptedFragment {
    return {
      id: row.id,
      memoryId: row.memory_id,
      index: row.idx,
      total: row.total,
      ciphertext: Buffer.from(row.ciphertext),
      iv: Buffer.from(row.iv),
      authTag: Buffer.from(row.auth_tag),
      slot: row.slot,
      createdAt: row.created_at,
    };
  }

  private rowToMeta(row: any): MemoryMeta {
    return {
      id: memoryId(row.id),
      tags: JSON.parse(row.tags_json),
      piiLevel: row.pii_level as PIILevel,
      fragmentCount: row.fragment_count,
      threshold: row.threshold,
      contentLength: row.content_length,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      expiresAt: row.expires_at ?? null,
      agentId: row.agent_id ?? undefined,
      department: row.department ?? undefined,
      accessLevel: row.access_level ?? undefined,
    };
  }

  private rowToAuditEntry(row: any): AuditEntry {
    return {
      id: row.id,
      operation: row.operation,
      memoryId: row.memory_id ? memoryId(row.memory_id) : null,
      agentId: row.agent_id,
      accessLevel: row.access_level ?? null,
      timestamp: row.timestamp,
      previousHash: row.previous_hash,
      hash: row.hash,
      details: JSON.parse(row.details),
    };
  }
}
