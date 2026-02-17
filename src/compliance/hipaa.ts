/**
 * @module compliance/hipaa
 * HIPAA compliance — PHI detection, minimum necessary standard enforcement.
 */

import { PIILevel } from '../core/types.js';
import type { PIIPattern, PIIDetection } from '../core/types.js';
import { detectPII, redactPII } from '../pii/detector.js';

/** Protected Health Information (PHI) patterns per HIPAA Safe Harbor */
export const PHI_PATTERNS: PIIPattern[] = [
  // Medical Record Numbers
  { name: 'MEDICAL_RECORD_NUMBER', regex: /\bMRN[-:]?\s?\d{6,10}\b/gi, level: PIILevel.CRITICAL },

  // Health plan beneficiary numbers
  { name: 'HEALTH_PLAN_ID', regex: /\bHP[-:]?\s?\d{8,12}\b/gi, level: PIILevel.CRITICAL },

  // Drug/medication names with dosage (proxy for health conditions)
  { name: 'MEDICATION', regex: /\b\d+\s?mg\b/gi, level: PIILevel.HIGH },

  // ICD-10 codes
  { name: 'ICD10_CODE', regex: /\b[A-Z]\d{2}(?:\.\d{1,4})?\b/g, level: PIILevel.CRITICAL },

  // Lab values with units
  { name: 'LAB_VALUE', regex: /\b\d+(?:\.\d+)?\s?(?:mg\/dL|mmol\/L|g\/dL|mL\/min|U\/L)\b/gi, level: PIILevel.HIGH },

  // Diagnosis keywords
  { name: 'DIAGNOSIS', regex: /\b(?:diagnosed with|diagnosis of|treatment for|history of)\s+[\w\s]+/gi, level: PIILevel.CRITICAL },
];

/**
 * Detect PHI (Protected Health Information) in content.
 * Combines standard PII patterns with HIPAA-specific patterns.
 */
export function detectPHI(content: string): PIIDetection[] {
  // Standard PII detection
  const standardDetections = detectPII(content);

  // Additional PHI-specific detection
  const phiDetections = detectPII(content, PHI_PATTERNS);

  // Merge and deduplicate by position
  const all = [...standardDetections, ...phiDetections];
  const unique = new Map<string, PIIDetection>();
  for (const d of all) {
    const key = `${d.start}:${d.end}`;
    const existing = unique.get(key);
    if (!existing || d.level === PIILevel.CRITICAL) {
      unique.set(key, d);
    }
  }

  return [...unique.values()].sort((a, b) => a.start - b.start);
}

/**
 * Enforce minimum necessary standard.
 * Strips all PHI that isn't strictly required for the stated purpose.
 *
 * @param content - Content that may contain PHI
 * @param allowedTypes - PHI types that are permitted for this use case
 * @returns Content with non-essential PHI redacted
 */
export function enforceMinimumNecessary(
  content: string,
  allowedTypes: string[] = [],
): { content: string; redactedCount: number } {
  const detections = detectPHI(content);

  // Filter to only redact types NOT in the allowed list
  const toRedact = detections.filter(d => !allowedTypes.includes(d.type));

  if (toRedact.length === 0) {
    return { content, redactedCount: 0 };
  }

  return {
    content: redactPII(content, toRedact),
    redactedCount: toRedact.length,
  };
}

/**
 * Check if content contains any PHI.
 */
export function containsPHI(content: string): boolean {
  return detectPHI(content).some(d => d.level === PIILevel.CRITICAL);
}
