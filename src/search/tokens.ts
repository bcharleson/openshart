/**
 * @module tokens
 * HMAC-SHA256 based search token generation for searchable symmetric encryption.
 */

import { createHmac } from 'node:crypto';

/**
 * Generate an HMAC-SHA256 search token from a term.
 * Deterministic: same key + term always produces the same token.
 * One-way: knowing the token reveals nothing about the term.
 */
export function generateSearchToken(searchKey: Buffer, term: string): string {
  return createHmac('sha256', searchKey)
    .update(term.toLowerCase().trim())
    .digest('hex');
}

/**
 * Generate a search token for a tag.
 * Tags are prefixed to avoid collisions with content tokens.
 */
export function generateTagToken(searchKey: Buffer, tag: string): string {
  return createHmac('sha256', searchKey)
    .update(`tag:${tag.toLowerCase().trim()}`)
    .digest('hex');
}

/**
 * Tokenize content into searchable terms.
 * Extracts individual words, lowercased, with stop words removed.
 */
export function tokenizeContent(content: string): string[] {
  const STOP_WORDS = new Set([
    'a', 'an', 'the', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
    'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'shall',
    'should', 'may', 'might', 'must', 'can', 'could', 'of', 'in', 'to',
    'for', 'with', 'on', 'at', 'by', 'from', 'as', 'into', 'through',
    'and', 'but', 'or', 'nor', 'not', 'so', 'yet', 'both', 'either',
    'neither', 'each', 'every', 'all', 'any', 'few', 'more', 'most',
    'other', 'some', 'such', 'no', 'only', 'own', 'same', 'than',
    'too', 'very', 'just', 'it', 'its', 'this', 'that', 'these', 'those',
  ]);

  return content
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter(word => word.length >= 2 && !STOP_WORDS.has(word));
}

/**
 * Generate all search tokens for a piece of content.
 * Returns unique tokens derived from content words and tags.
 */
export function generateContentTokens(
  searchKey: Buffer,
  content: string,
  tags: string[] = [],
): string[] {
  const words = tokenizeContent(content);
  const uniqueWords = [...new Set(words)];

  const tokens: string[] = [];

  // Content tokens
  for (const word of uniqueWords) {
    tokens.push(generateSearchToken(searchKey, word));
  }

  // Tag tokens
  for (const tag of tags) {
    tokens.push(generateTagToken(searchKey, tag));
  }

  return tokens;
}
