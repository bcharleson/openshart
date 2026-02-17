/**
 * @module search/index
 * Searchable encrypted index — stores and queries HMAC token → memoryId mappings.
 */

import type { StorageBackend, MemoryId } from '../core/types.js';
import { generateContentTokens, generateSearchToken, generateTagToken } from './tokens.js';

/**
 * Manages the searchable encrypted index.
 * Tokens are HMAC-SHA256 hashes — the index never sees plaintext.
 */
export class SearchIndex {
  constructor(
    private readonly storage: StorageBackend,
    private readonly searchKey: Buffer,
  ) {}

  /**
   * Index a memory's content and tags.
   * Generates HMAC tokens and stores token→memoryId mappings.
   *
   * @returns Number of tokens indexed
   */
  async indexMemory(
    memoryId: MemoryId,
    content: string,
    tags: string[] = [],
  ): Promise<number> {
    const tokens = generateContentTokens(this.searchKey, content, tags);
    const unique = [...new Set(tokens)];

    for (const token of unique) {
      await this.storage.putSearchToken(token, memoryId);
    }

    return unique.length;
  }

  /**
   * Remove all search tokens for a memory.
   */
  async removeMemory(memoryId: MemoryId): Promise<void> {
    await this.storage.deleteSearchTokens(memoryId);
  }

  /**
   * Query the index with a search string.
   * Returns memory IDs that match ALL query terms (intersection).
   */
  async query(
    queryText: string,
    tags: string[] = [],
  ): Promise<MemoryId[]> {
    const tokens: string[] = [];

    // Generate tokens for query words
    const words = queryText
      .toLowerCase()
      .replace(/[^a-z0-9\s]/g, ' ')
      .split(/\s+/)
      .filter(w => w.length >= 2);

    for (const word of words) {
      tokens.push(generateSearchToken(this.searchKey, word));
    }

    // Generate tokens for tag filters
    for (const tag of tags) {
      tokens.push(generateTagToken(this.searchKey, tag));
    }

    if (tokens.length === 0) return [];

    // Intersect: memory must match all tokens
    let resultSet: Set<MemoryId> | null = null;

    for (const token of tokens) {
      const memoryIds = await this.storage.lookupSearchToken(token);
      const idSet = new Set(memoryIds);

      if (resultSet === null) {
        resultSet = idSet;
      } else {
        // Intersect
        for (const id of resultSet) {
          if (!idSet.has(id)) resultSet.delete(id);
        }
      }

      // Early exit if empty
      if (resultSet.size === 0) return [];
    }

    return resultSet ? [...resultSet] : [];
  }
}
