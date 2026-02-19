import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { OpenShart, type OpenShartInitOptions } from './core/openshart.js';
import { MemoryBackend } from './storage/memory.js';
import { SQLiteBackend } from './storage/sqlite.js';
import { type SecurityLevel } from './core/openshart.js';
import { memoryId } from './core/types.js';
import type { SearchResult } from './core/types.js';

export interface OpenClawPluginConfig {
  /** Base64 or hex key string (hex by default). */
  encryptionKey?: string;
  /** Encryption key encoding when a key is provided as string. */
  encryptionKeyEncoding?: 'hex' | 'base64';
  /** Security preset passed through to OpenShart.init. */
  securityLevel?: SecurityLevel;
  /** Optional SQLite file path when useSQLite is enabled. */
  storagePath?: string;
  /** Use SQLiteBackend instead of MemoryBackend. */
  useSQLite?: boolean;
  /** Optional path or plugin-defined agent identifier. */
  agentId?: string;
  /** Optional department value for hierarchical context. */
  department?: string;
  /** Optional metadata tags to apply to all stored entries. */
  tags?: string[];
}

export interface OpenClawSearchItem {
  id: string;
  content: string;
  score: number;
}

export interface OpenClawMemoryProvider {
  init(config: OpenClawPluginConfig): Promise<void>;
  store(content: string, metadata?: Record<string, unknown>): Promise<string>;
  get(id: string): Promise<string>;
  search(query: string, limit?: number): Promise<OpenClawSearchItem[]>;
  forget(id: string): Promise<void>;
  close(): Promise<void>;
}

const OPENCLAW_KEY_ENV = 'OPENSHART_ENCRYPTION_KEY';

function parseConfigEncryptionKey(config: OpenClawPluginConfig): Buffer {
  const raw = config.encryptionKey ?? process.env[OPENCLAW_KEY_ENV];
  if (!raw) {
    if (config.useSQLite || typeof config.storagePath === 'string') {
      throw new Error(
        'OpenShart OpenClaw plugin requires encryptionKey when persistence is enabled. ' +
          'Set config.encryptionKey or OPENSHART_ENCRYPTION_KEY in the environment.',
      );
    }

    return randomBytes(32);
  }

  if (config.encryptionKeyEncoding === 'base64') {
    const parsed = Buffer.from(raw, 'base64');
    if (parsed.length !== 32) {
      throw new Error('OpenShart encryption key must decode to exactly 32 bytes.');
    }
    return parsed;
  }

  const parsed = Buffer.from(raw, 'hex');
  if (parsed.length !== 32) {
    throw new Error('OpenShart encryption key must be exactly 64 hex characters.');
  }
  return parsed;
}

export class OpenShartMemoryProvider implements OpenClawMemoryProvider {
  private openshart?: OpenShart;

  async init(config: OpenClawPluginConfig = {}): Promise<void> {
    const key = parseConfigEncryptionKey(config);
    const backend = config.useSQLite
      ? new SQLiteBackend({ path: join(config.storagePath || '', 'openshart.db') })
      : new MemoryBackend();

    const options: OpenShartInitOptions = {
      storage: backend,
      encryptionKey: key,
      securityLevel: config.securityLevel,
      agentId: config.agentId,
      department: config.department,
    };

    this.openshart = await OpenShart.init(options);
  }

  async store(content: string, metadata?: Record<string, unknown>): Promise<string> {
    if (!this.openshart) {
      throw new Error('OpenShartMemoryProvider not initialized. Call init(config) first.');
    }

    const tags = this.toStringArray(metadata?.tags);
    const result = await this.openshart.store(content, { tags });
    return result.id;
  }

  async search(query: string, limit = 10): Promise<OpenClawSearchItem[]> {
    if (!this.openshart) {
      throw new Error('OpenShartMemoryProvider not initialized. Call init(config) first.');
    }

    const searchResult: SearchResult = await this.openshart.search(query, {
      limit,
    });

    return Promise.all(
      searchResult.memories.map(async (meta) => {
        const memory = await this.openshart!.recall(meta.id);
        return {
          id: meta.id,
          content: memory.content,
          score: 1,
        };
      }),
    );
  }

  async forget(id: string): Promise<void> {
    if (!this.openshart) {
      throw new Error('OpenShartMemoryProvider not initialized. Call init(config) first.');
    }

    await this.openshart.forget(memoryId(id));
  }

  async get(id: string): Promise<string> {
    if (!this.openshart) {
      throw new Error('OpenShartMemoryProvider not initialized. Call init(config) first.');
    }

    const memory = await this.openshart.recall(memoryId(id));
    return memory.content;
  }

  async close(): Promise<void> {
    await this.openshart?.close();
    this.openshart = undefined;
  }

  private toStringArray(value: unknown): string[] {
    if (!Array.isArray(value)) {
      return [];
    }

    return value.filter((item): item is string => typeof item === 'string');
  }
}

const plugin = {
  id: 'openshart',
  name: 'OpenShart Encrypted Memory',
  version: '0.1.0',
  kind: 'memory',
  register: (api: any): void => {
    const provider = new OpenShartMemoryProvider();
    const config = (api?.pluginConfig ?? {}) as OpenClawPluginConfig;
    let initialized: Promise<void> | null = null;

    const ensureInit = (): Promise<void> => {
      if (!initialized) {
        initialized = provider.init(config);
      }
      return initialized;
    };

    api.registerTool(
      () => ({
        name: 'memory_search',
        label: 'Memory Search (OpenShart)',
        description: 'Search encrypted agent memory using HMAC tokens.',
        parameters: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query',
            },
            maxResults: {
              type: 'number',
              description: 'Max results to return',
            },
          },
          required: ['query'],
        },
        execute: async (_toolCallId: string, params: Record<string, unknown>): Promise<string> => {
          await ensureInit();
          const query = typeof params.query === 'string' ? params.query : '';
          const maxResults =
            typeof params.maxResults === 'number' && Number.isFinite(params.maxResults) && params.maxResults > 0
              ? Math.floor(params.maxResults)
              : 10;

          const result = await provider.search(query, maxResults);
          return JSON.stringify({
            results: result,
            provider: 'openshart',
            encrypted: true,
          });
        },
      }),
      { names: ['memory_search'] },
    );

    api.registerTool(
      () => ({
        name: 'memory_get',
        label: 'Memory Get (OpenShart)',
        description: 'Retrieve decrypted memory content by memory id.',
        parameters: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'Memory id',
            },
          },
          required: ['id'],
        },
        execute: async (_toolCallId: string, params: Record<string, unknown>): Promise<string> => {
          await ensureInit();
          const id = typeof params.id === 'string' ? params.id : '';
          if (!id) {
            throw new Error('memory_get requires id');
          }

          const content = await provider.get(id);
          if (!content) {
            throw new Error(`Memory not found: ${id}`);
          }
          return JSON.stringify({ id, content });
        },
      }),
      { names: ['memory_get'] },
    );

    api.registerTool(
      () => ({
        name: 'memory_store',
        label: 'Memory Store (OpenShart)',
        description: 'Store content in encrypted memory.',
        parameters: {
          type: 'object',
          properties: {
            content: {
              type: 'string',
              description: 'Raw content to store',
            },
            metadata: {
              type: 'object',
              description: 'Optional metadata',
            },
          },
          required: ['content'],
        },
        execute: async (_toolCallId: string, params: Record<string, unknown>): Promise<string> => {
          await ensureInit();
          const content = typeof params.content === 'string' ? params.content : '';
          const metadata =
            typeof params.metadata === 'object' && params.metadata !== null
              ? (params.metadata as Record<string, unknown>)
              : undefined;
          const memoryId = await provider.store(content, metadata);
          return JSON.stringify({ id: memoryId });
        },
      }),
      { names: ['memory_store'] },
    );

    api.registerTool(
      () => ({
        name: 'memory_forget',
        label: 'Memory Forget (OpenShart)',
        description: 'Forget and erase memory content by id.',
        parameters: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'Memory id',
            },
          },
          required: ['id'],
        },
        execute: async (_toolCallId: string, params: Record<string, unknown>): Promise<string> => {
          await ensureInit();
          const id = typeof params.id === 'string' ? params.id : '';
          if (!id) {
            throw new Error('memory_forget requires id');
          }

          await provider.forget(id);
          return JSON.stringify({ success: true, id });
        },
      }),
      { names: ['memory_forget'] },
    );

    api.on?.('gateway_stop', async () => {
      if (initialized) {
        await initialized;
        await provider.close();
      }
    });
  },
};

export default plugin;
