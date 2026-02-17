/**
 * @module query
 * Query processing — encrypt query terms, match against index, return results.
 */

import type { MemoryMeta, SearchOptions, SearchResult, StorageBackend } from '../core/types.js';
import { PIILevel } from '../core/types.js';
import { SearchIndex } from './index.js';

/** PII level ordering for filtering */
const PII_ORDER: Record<PIILevel, number> = {
  [PIILevel.NONE]: 0,
  [PIILevel.LOW]: 1,
  [PIILevel.MEDIUM]: 2,
  [PIILevel.HIGH]: 3,
  [PIILevel.CRITICAL]: 4,
};

/**
 * Execute a search query against the encrypted index.
 *
 * @param searchIndex - The search index to query
 * @param storage - Storage backend for metadata retrieval
 * @param query - Search query text
 * @param options - Search options (limit, tag filters, PII level filter, date range)
 * @returns Search results with metadata (never content)
 */
export async function executeSearch(
  searchIndex: SearchIndex,
  storage: StorageBackend,
  query: string,
  options: SearchOptions = {},
): Promise<SearchResult> {
  const { limit = 10, tags, maxPIILevel, after, before } = options;

  // Query the encrypted index
  const matchingIds = await searchIndex.query(query, tags);

  // Fetch metadata for matches and apply filters
  const memories: MemoryMeta[] = [];

  for (const id of matchingIds) {
    const meta = await storage.getMeta(id);
    if (!meta) continue;

    // Filter by PII level
    if (maxPIILevel && PII_ORDER[meta.piiLevel] > PII_ORDER[maxPIILevel]) {
      continue;
    }

    // Filter by date range
    if (after && new Date(meta.createdAt) < after) continue;
    if (before && new Date(meta.createdAt) > before) continue;

    // Filter expired memories
    if (meta.expiresAt && new Date(meta.expiresAt) < new Date()) continue;

    memories.push(meta);
  }

  // Sort by creation date descending
  memories.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

  return {
    memories: memories.slice(0, limit),
    total: memories.length,
    encrypted: true,
  };
}
