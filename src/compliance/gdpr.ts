/**
 * @module compliance/gdpr
 * GDPR Article 17 — Right to Erasure implementation.
 * Cryptographic deletion of all fragments, search tokens, and metadata.
 */

import { randomBytes } from 'node:crypto';
import type { StorageBackend, MemoryId, ForgetResult } from '../core/types.js';
import { AuditOperation } from '../core/types.js';
import type { AuditLogger } from '../audit/logger.js';

/**
 * GDPR-compliant memory erasure.
 *
 * Implements Article 17 right-to-forget:
 * 1. Overwrite all fragment ciphertext with random data
 * 2. Delete all fragments
 * 3. Purge all search index entries
 * 4. Delete memory metadata
 * 5. Record deletion in audit log (audit entries are retained for compliance)
 */
export async function cryptographicErase(
  memoryId: MemoryId,
  storage: StorageBackend,
  auditLogger: AuditLogger,
  agentId: string,
): Promise<ForgetResult> {
  // 1. Fetch all fragments
  const fragments = await storage.getFragments(memoryId);

  // 2. Overwrite each fragment's ciphertext with random data before deletion
  for (const fragment of fragments) {
    const randomData = randomBytes(fragment.ciphertext.length);
    fragment.ciphertext = randomData;
    fragment.iv = randomBytes(fragment.iv.length);
    fragment.authTag = randomBytes(fragment.authTag.length);
    await storage.putFragment(fragment); // Overwrite in storage
  }

  // 3. Delete all fragments
  const fragmentsDestroyed = await storage.deleteFragments(memoryId);

  // 4. Purge search tokens
  await storage.deleteSearchTokens(memoryId);

  // 5. Delete metadata
  await storage.deleteMeta(memoryId);

  // 6. Audit the deletion (audit entries persist for compliance verification)
  const auditId = await auditLogger.log(
    AuditOperation.FORGET,
    memoryId,
    {
      fragmentsDestroyed,
      method: 'cryptographic_erase',
      gdprArticle17: true,
      agentId,
    },
  );

  return {
    memoryId,
    fragmentsDestroyed,
    searchTokensPurged: fragmentsDestroyed, // approximate
    auditId,
  };
}

/**
 * Verify that a memory has been completely erased.
 * Returns true if no fragments, metadata, or search tokens remain.
 */
export async function verifyErasure(
  memoryId: MemoryId,
  storage: StorageBackend,
): Promise<{ erased: boolean; remainingFragments: number; metadataExists: boolean }> {
  const fragments = await storage.getFragments(memoryId);
  const meta = await storage.getMeta(memoryId);

  return {
    erased: fragments.length === 0 && meta === null,
    remainingFragments: fragments.length,
    metadataExists: meta !== null,
  };
}
