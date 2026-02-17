/**
 * @module detector
 * PII detection engine — scans content for personally identifiable information.
 */

import { PIILevel } from '../core/types.js';
import type { PIIPattern, PIIDetection } from '../core/types.js';

/** Built-in PII detection patterns */
export const BUILTIN_PATTERNS: PIIPattern[] = [
  // Email addresses
  { name: 'EMAIL', regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, level: PIILevel.HIGH },

  // US phone numbers
  { name: 'PHONE_US', regex: /(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g, level: PIILevel.HIGH },

  // US Social Security Numbers
  { name: 'SSN', regex: /\b\d{3}-\d{2}-\d{4}\b/g, level: PIILevel.CRITICAL },

  // Credit card numbers (basic pattern — Luhn validation done separately)
  { name: 'CREDIT_CARD', regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g, level: PIILevel.CRITICAL },

  // Financial amounts
  { name: 'FINANCIAL', regex: /\$\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?(?:\s?[kKmMbB])?/g, level: PIILevel.CRITICAL },

  // IP addresses
  { name: 'IP_ADDRESS', regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, level: PIILevel.MEDIUM },

  // Dates of birth (MM/DD/YYYY, MM-DD-YYYY)
  { name: 'DOB', regex: /\b(?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b/g, level: PIILevel.HIGH },

  // US addresses (simplified)
  { name: 'ADDRESS', regex: /\b\d{1,5}\s+[\w\s]+(?:St|Ave|Blvd|Dr|Rd|Ln|Way|Ct|Pl)\.?\b/gi, level: PIILevel.HIGH },

  // Medical Record Numbers (MRN pattern)
  { name: 'MEDICAL_RECORD', regex: /\bMRN[-:]?\s?\d{6,10}\b/gi, level: PIILevel.CRITICAL },
];

/**
 * Luhn algorithm validation for credit card numbers.
 */
function isValidLuhn(digits: string): boolean {
  const nums = digits.replace(/\D/g, '');
  if (nums.length < 13 || nums.length > 19) return false;

  let sum = 0;
  let alternate = false;
  for (let i = nums.length - 1; i >= 0; i--) {
    let n = parseInt(nums[i]!, 10);
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

/**
 * Detect PII in content using pattern matching.
 *
 * @param content - Text to scan
 * @param customPatterns - Additional patterns to match
 * @returns Array of PII detections with type, level, and position
 */
export function detectPII(
  content: string,
  customPatterns: PIIPattern[] = [],
): PIIDetection[] {
  const detections: PIIDetection[] = [];
  const allPatterns = [...BUILTIN_PATTERNS, ...customPatterns];

  for (const pattern of allPatterns) {
    // Reset regex state (important for /g patterns)
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(content)) !== null) {
      const value = match[0];

      // For credit cards, validate with Luhn
      if (pattern.name === 'CREDIT_CARD' && !isValidLuhn(value)) {
        continue;
      }

      // For IP addresses, validate ranges
      if (pattern.name === 'IP_ADDRESS') {
        const parts = value.split('.');
        if (parts.some(p => parseInt(p!, 10) > 255)) continue;
      }

      detections.push({
        type: pattern.name,
        level: pattern.level,
        start: match.index,
        end: match.index + value.length,
        value,
      });
    }
  }

  return detections;
}

/**
 * Redact PII from content, replacing detected values with placeholders.
 *
 * @param content - Text to redact
 * @param detections - PII detections to redact
 * @returns Redacted content
 */
export function redactPII(content: string, detections: PIIDetection[]): string {
  // Sort by position descending so we can replace without offset issues
  const sorted = [...detections].sort((a, b) => b.start - a.start);
  let result = content;
  for (const detection of sorted) {
    const placeholder = `[${detection.type}_REDACTED]`;
    result = result.slice(0, detection.start) + placeholder + result.slice(detection.end);
  }
  return result;
}
