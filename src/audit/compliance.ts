/**
 * @module audit/compliance
 * Export audit logs in formats needed for SOC2/HIPAA compliance audits.
 */

import type { StorageBackend, AuditEntry, AuditFilters } from '../core/types.js';
import { AuditOperation } from '../core/types.js';
import { verifyAuditChain, type ChainVerificationResult } from './chain.js';

/** Compliance report structure */
export interface ComplianceReport {
  generatedAt: string;
  period: { from: string; to: string };
  chainIntegrity: ChainVerificationResult;
  summary: {
    totalOperations: number;
    storeCount: number;
    searchCount: number;
    recallCount: number;
    forgetCount: number;
  };
  entries: AuditEntry[];
}

/**
 * Generate a compliance report for the given period.
 * Includes chain integrity verification and operation summary.
 */
export async function generateComplianceReport(
  storage: StorageBackend,
  filters: AuditFilters = {},
): Promise<ComplianceReport> {
  const entries = await storage.readAuditLog(filters);
  const chainIntegrity = await verifyAuditChain(storage);

  const summary = {
    totalOperations: entries.length,
    storeCount: entries.filter(e => e.operation === AuditOperation.STORE).length,
    searchCount: entries.filter(e => e.operation === AuditOperation.SEARCH).length,
    recallCount: entries.filter(e => e.operation === AuditOperation.RECALL).length,
    forgetCount: entries.filter(e => e.operation === AuditOperation.FORGET).length,
  };

  return {
    generatedAt: new Date().toISOString(),
    period: {
      from: filters.after?.toISOString() ?? 'beginning',
      to: filters.before?.toISOString() ?? 'now',
    },
    chainIntegrity,
    summary,
    entries,
  };
}

/**
 * Export audit entries as CSV for external audit tools.
 */
export function exportAsCSV(entries: AuditEntry[]): string {
  const header = 'id,operation,memory_id,agent_id,access_level,timestamp,previous_hash,hash';
  const rows = entries.map(e =>
    [e.id, e.operation, e.memoryId ?? '', e.agentId, e.accessLevel ?? '', e.timestamp, e.previousHash, e.hash].join(',')
  );
  return [header, ...rows].join('\n');
}

/**
 * Export audit entries as JSON Lines format.
 */
export function exportAsJSONL(entries: AuditEntry[]): string {
  return entries.map(e => JSON.stringify(e)).join('\n');
}
