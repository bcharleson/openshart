/**
 * @module chainlock/temporal
 * Time window enforcement for ChainLock protocol.
 * Each decryption step must complete within a configurable time window.
 */

import { createHmac } from 'node:crypto';

/** Configuration for temporal enforcement */
export interface TemporalConfig {
  /** Maximum duration per step in milliseconds (default: 2000) */
  stepWindowMs: number;
  /** Maximum total reconstruction time in milliseconds (default: 30000) */
  totalCeilingMs: number;
  /** HMAC key for signing timestamps */
  hmacKey: Buffer;
}

/** A cryptographically signed timestamp */
export interface SignedTimestamp {
  /** ISO 8601 timestamp */
  timestamp: string;
  /** High-resolution monotonic time (nanoseconds) */
  hrtime: bigint;
  /** HMAC-SHA256 signature */
  signature: string;
}

/** Result of a time window check */
export interface WindowCheckResult {
  valid: boolean;
  elapsedMs: number;
  reason?: string;
}

const DEFAULT_STEP_WINDOW_MS = 2000;
const DEFAULT_TOTAL_CEILING_MS = 30000;

/**
 * Create a default temporal config with sensible defaults.
 */
export function createTemporalConfig(
  hmacKey: Buffer,
  stepWindowMs = DEFAULT_STEP_WINDOW_MS,
  totalCeilingMs = DEFAULT_TOTAL_CEILING_MS,
): TemporalConfig {
  return { stepWindowMs, totalCeilingMs, hmacKey };
}

/**
 * Create a cryptographically signed timestamp.
 * The signature prevents timestamp forgery.
 */
export function signTimestamp(config: TemporalConfig): SignedTimestamp {
  const timestamp = new Date().toISOString();
  const hrtime = process.hrtime.bigint();

  const signature = createHmac('sha256', config.hmacKey)
    .update(`${timestamp}:${hrtime.toString()}`)
    .digest('hex');

  return { timestamp, hrtime, signature };
}

/**
 * Verify a signed timestamp has not been tampered with.
 */
export function verifyTimestamp(
  signed: SignedTimestamp,
  config: TemporalConfig,
): boolean {
  const expected = createHmac('sha256', config.hmacKey)
    .update(`${signed.timestamp}:${signed.hrtime.toString()}`)
    .digest('hex');

  // Constant-time comparison via buffer
  if (expected.length !== signed.signature.length) return false;
  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(signed.signature, 'hex');
  if (a.length !== b.length) return false;

  // Manual constant-time comparison
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

/**
 * Check if a step completed within its time window.
 *
 * @param stepStart - When this step began (signed timestamp from previous step completion)
 * @param config - Temporal configuration
 * @returns Whether the step is within the allowed window
 */
export function checkStepWindow(
  stepStart: SignedTimestamp,
  config: TemporalConfig,
): WindowCheckResult {
  const now = process.hrtime.bigint();
  const elapsedNs = now - stepStart.hrtime;
  const elapsedMs = Number(elapsedNs / 1_000_000n);

  if (elapsedMs > config.stepWindowMs) {
    return {
      valid: false,
      elapsedMs,
      reason: `Step exceeded window: ${elapsedMs}ms > ${config.stepWindowMs}ms`,
    };
  }

  return { valid: true, elapsedMs };
}

/**
 * Check if the total reconstruction time is within the ceiling.
 *
 * @param protocolStart - When the entire ChainLock protocol began
 * @param config - Temporal configuration
 * @returns Whether total time is within ceiling
 */
export function checkTotalCeiling(
  protocolStart: SignedTimestamp,
  config: TemporalConfig,
): WindowCheckResult {
  const now = process.hrtime.bigint();
  const elapsedNs = now - protocolStart.hrtime;
  const elapsedMs = Number(elapsedNs / 1_000_000n);

  if (elapsedMs > config.totalCeilingMs) {
    return {
      valid: false,
      elapsedMs,
      reason: `Total time exceeded ceiling: ${elapsedMs}ms > ${config.totalCeilingMs}ms`,
    };
  }

  return { valid: true, elapsedMs };
}
