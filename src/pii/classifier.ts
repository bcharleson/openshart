/**
 * @module classifier
 * PII level classification — determines the overall sensitivity of content
 * and auto-adjusts fragment parameters accordingly.
 */

import { PIILevel } from '../core/types.js';
import type { PIIDetection, FragmentConfig } from '../core/types.js';
import { DEFAULT_FRAGMENT_CONFIG, DEFAULT_TTL } from '../core/config.js';

/** PII level ordering for comparison */
const PII_LEVEL_ORDER: Record<PIILevel, number> = {
  [PIILevel.NONE]: 0,
  [PIILevel.LOW]: 1,
  [PIILevel.MEDIUM]: 2,
  [PIILevel.HIGH]: 3,
  [PIILevel.CRITICAL]: 4,
};

/**
 * Classify the overall PII level from a set of detections.
 * Returns the highest level detected, or NONE if no PII found.
 */
export function classifyPIILevel(detections: PIIDetection[]): PIILevel {
  if (detections.length === 0) return PIILevel.NONE;

  let maxLevel = PIILevel.NONE;
  for (const detection of detections) {
    if (PII_LEVEL_ORDER[detection.level] > PII_LEVEL_ORDER[maxLevel]) {
      maxLevel = detection.level;
    }
  }
  return maxLevel;
}

/**
 * Compare two PII levels.
 * @returns negative if a < b, 0 if equal, positive if a > b
 */
export function comparePIILevels(a: PIILevel, b: PIILevel): number {
  return PII_LEVEL_ORDER[a] - PII_LEVEL_ORDER[b];
}

/**
 * Check if a PII level is at or above a threshold.
 */
export function isAtLeast(level: PIILevel, threshold: PIILevel): boolean {
  return PII_LEVEL_ORDER[level] >= PII_LEVEL_ORDER[threshold];
}

/**
 * Get recommended fragment configuration for a PII level.
 * Higher PII levels get more fragments and stricter thresholds.
 */
export function getFragmentConfigForLevel(level: PIILevel): Required<FragmentConfig> {
  return { ...DEFAULT_FRAGMENT_CONFIG[level] };
}

/**
 * Get recommended TTL for a PII level (milliseconds, null = no expiry).
 */
export function getTTLForLevel(level: PIILevel): number | null {
  return DEFAULT_TTL[level];
}

/** Summary of PII classification */
export interface PIIClassification {
  level: PIILevel;
  detectedTypes: string[];
  fragmentConfig: Required<FragmentConfig>;
  recommendedTTL: number | null;
}

/**
 * Full PII classification: level, detected types, recommended fragment config and TTL.
 */
export function classifyContent(detections: PIIDetection[]): PIIClassification {
  const level = classifyPIILevel(detections);
  const detectedTypes = [...new Set(detections.map(d => d.type))];

  return {
    level,
    detectedTypes,
    fragmentConfig: getFragmentConfigForLevel(level),
    recommendedTTL: getTTLForLevel(level),
  };
}
