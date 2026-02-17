/**
 * @module config
 * Configuration management with sensible defaults for OpenShart.
 */

import { PIILevel, Role, ROLE_CLEARANCE } from './types.js';
import type { FragmentConfig, OpenShartOptions } from './types.js';

/** Default fragment configuration by PII level */
export const DEFAULT_FRAGMENT_CONFIG: Record<PIILevel, Required<FragmentConfig>> = {
  [PIILevel.NONE]: { threshold: 2, totalShares: 3, slots: 3 },
  [PIILevel.LOW]: { threshold: 2, totalShares: 3, slots: 3 },
  [PIILevel.MEDIUM]: { threshold: 3, totalShares: 5, slots: 5 },
  [PIILevel.HIGH]: { threshold: 4, totalShares: 7, slots: 7 },
  [PIILevel.CRITICAL]: { threshold: 5, totalShares: 8, slots: 8 },
};

/** Default TTL by PII level (milliseconds, null = no expiry) */
export const DEFAULT_TTL: Record<PIILevel, number | null> = {
  [PIILevel.NONE]: null,
  [PIILevel.LOW]: null,
  [PIILevel.MEDIUM]: 365 * 24 * 60 * 60 * 1000,   // 1 year
  [PIILevel.HIGH]: 180 * 24 * 60 * 60 * 1000,      // 180 days
  [PIILevel.CRITICAL]: 90 * 24 * 60 * 60 * 1000,   // 90 days
};

/** Resolve fragment config for a given PII level, merging user overrides */
export function resolveFragmentConfig(
  piiLevel: PIILevel,
  userConfig?: FragmentConfig,
  piiOverrides?: Partial<Record<PIILevel, FragmentConfig>>,
): Required<FragmentConfig> {
  const base = DEFAULT_FRAGMENT_CONFIG[piiLevel];
  const override = piiOverrides?.[piiLevel];
  return {
    threshold: userConfig?.threshold ?? override?.threshold ?? base.threshold,
    totalShares: userConfig?.totalShares ?? override?.totalShares ?? base.totalShares,
    slots: userConfig?.slots ?? override?.slots ?? base.slots,
  };
}

/** Resolve TTL for a given PII level */
export function resolveTTL(
  piiLevel: PIILevel,
  userTTL?: number | null,
  piiOverrides?: Partial<Record<PIILevel, number | null>>,
): number | null {
  if (userTTL !== undefined) return userTTL;
  if (piiOverrides?.[piiLevel] !== undefined) return piiOverrides[piiLevel]!;
  return DEFAULT_TTL[piiLevel];
}

/** Validate OpenShartOptions */
export function validateOptions(options: OpenShartOptions): void {
  if (!options.storage) {
    throw new Error('OpenShart: storage backend is required');
  }
  if (!options.encryptionKey || options.encryptionKey.length !== 32) {
    throw new Error('OpenShart: encryptionKey must be exactly 32 bytes (256 bits)');
  }

  // P0 fix: Validate key entropy — reject obviously weak keys
  const key = options.encryptionKey;
  if (key.every(b => b === 0)) {
    throw new Error('OpenShart: encryption key has zero entropy (all zeros)');
  }
  if (key.every(b => b === key[0])) {
    throw new Error('OpenShart: encryption key has minimal entropy (all same byte)');
  }
  const uniqueBytes = new Set(key).size;
  if (uniqueBytes < 8) {
    throw new Error(`OpenShart: encryption key has insufficient entropy (only ${uniqueBytes} unique bytes)`);
  }
}

/** Role hierarchy check: does `actor` have at least `required` clearance? */
export function hasRoleClearance(actor: Role, required: Role): boolean {
  return ROLE_CLEARANCE[actor] >= ROLE_CLEARANCE[required];
}
