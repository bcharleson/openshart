/**
 * @module chainlock/protocol
 * The full ChainLock protocol — temporal sequence lock for fragment decryption.
 *
 * Protocol flow:
 * 1. Agent requests recall → generate sequence + session nonce
 * 2. For each step i in sequence:
 *    - Decrypt fragment[seq[i]] within time window
 *    - Produce chain_token_i from fragment content + metadata + previous token
 *    - Validate step timing
 * 3. All fragments decrypted + valid chain → reconstruct memory
 * 4. Rotate sequence for next recall
 * 5. Wipe all ephemeral data
 */

import type { EncryptedFragment, MemoryId } from '../core/types.js';
import { aesDecrypt, deriveFragmentKey } from '../fragments/encrypt.js';
import { reconstruct, type Share } from '../fragments/shard.js';
import {
  generateSequence,
  encryptSequence,
  decryptSequence,
  rotateSequence,
  type EncryptedSequence,
} from './sequence.js';
import {
  createTemporalConfig,
  signTimestamp,
  checkStepWindow,
  checkTotalCeiling,
} from './temporal.js';
import {
  generateSessionNonce,
  produceChainToken,
  wipeChainToken,
  wipeSessionNonce,
  type ChainToken,
} from './chain-token.js';
import {
  BreachDetector,
  BreachEventType,
} from './breach-detection.js';

/** ChainLock protocol configuration */
export interface ChainLockConfig {
  /** Max time per decryption step in ms (default: 2000) */
  stepWindowMs?: number;
  /** Max total reconstruction time in ms (default: 30000) */
  totalCeilingMs?: number;
  /** Max failed attempts before lockdown (default: 3) */
  maxFailedAttempts?: number;
  /** Whether ChainLock is enabled (default: true) */
  enabled?: boolean;
}

/** Result of a ChainLock recall */
export interface ChainLockRecallResult {
  /** Reconstructed plaintext content */
  content: string;
  /** Step timings in ms (for diagnostics) */
  stepTimings: number[];
  /** Total reconstruction time in ms */
  totalTimeMs: number;
  /** New encrypted sequence (for storage after rotation) */
  rotatedSequence: EncryptedSequence;
}

/** In-memory sequence store (per protocol instance) */
const sequenceStore = new Map<string, EncryptedSequence>();

/**
 * The ChainLock protocol engine.
 * Orchestrates temporal sequence-locked fragment decryption.
 */
export class ChainLockProtocol {
  private readonly breachDetector: BreachDetector;
  private readonly config: Required<ChainLockConfig>;

  constructor(config: ChainLockConfig = {}) {
    this.config = {
      stepWindowMs: config.stepWindowMs ?? 2000,
      totalCeilingMs: config.totalCeilingMs ?? 30000,
      maxFailedAttempts: config.maxFailedAttempts ?? 3,
      enabled: config.enabled ?? true,
    };

    this.breachDetector = new BreachDetector({
      maxFailedAttempts: this.config.maxFailedAttempts,
    });
  }

  /**
   * Get the breach detector for event listening.
   */
  getBreachDetector(): BreachDetector {
    return this.breachDetector;
  }

  /**
   * Initialize a sequence for a memory (called on first store or when missing).
   */
  async initializeSequence(
    memoryId: MemoryId,
    fragmentCount: number,
    masterKey: Buffer,
  ): Promise<EncryptedSequence> {
    const sequence = generateSequence(fragmentCount);
    const encrypted = await encryptSequence(sequence, masterKey, memoryId, 1);
    sequenceStore.set(memoryId, encrypted);
    return encrypted;
  }

  /**
   * Execute the full ChainLock recall protocol.
   *
   * @param memoryId - Memory to recall
   * @param fragments - All encrypted fragments for this memory
   * @param masterKey - Master encryption key
   * @param agentId - Requesting agent ID
   * @param threshold - Minimum fragments needed for reconstruction
   * @returns Reconstructed content with diagnostics
   * @throws On any protocol violation (timing, sequence, token, lockdown)
   */
  async recall(
    memoryId: MemoryId,
    fragments: EncryptedFragment[],
    masterKey: Buffer,
    agentId: string,
    threshold: number,
  ): Promise<ChainLockRecallResult> {
    if (!this.config.enabled) {
      // Bypass — just do normal decryption
      return this.bypassRecall(fragments, masterKey, threshold);
    }

    // Check lockdown
    if (this.breachDetector.isLockedDown(memoryId)) {
      throw new ChainLockError('LOCKDOWN', `Memory ${memoryId} is in lockdown`);
    }

    // Check cooldown
    if (!this.breachDetector.canRetry(memoryId)) {
      const cooldown = this.breachDetector.getCooldownMs(memoryId);
      throw new ChainLockError('COOLDOWN', `Retry cooldown active: wait ${cooldown}ms`);
    }

    // Set up temporal config
    const temporalConfig = createTemporalConfig(
      masterKey,
      this.config.stepWindowMs,
      this.config.totalCeilingMs,
    );

    // Get or create sequence
    let encryptedSeq = sequenceStore.get(memoryId);
    if (!encryptedSeq) {
      encryptedSeq = await this.initializeSequence(memoryId, fragments.length, masterKey);
    }

    // Decrypt the sequence
    let sequence: number[];
    try {
      sequence = await decryptSequence(encryptedSeq, masterKey, memoryId);
    } catch {
      this.breachDetector.recordFailure(memoryId, agentId, BreachEventType.SEQUENCE_FAILURE, {
        reason: 'Failed to decrypt sequence',
      });
      throw new ChainLockError('SEQUENCE', 'Failed to decrypt sequence');
    }

    // Generate session nonce
    const sessionNonce = generateSessionNonce();
    const protocolStart = signTimestamp(temporalConfig);
    const stepTimings: number[] = [];
    const chainTokens: ChainToken[] = [];
    const shares: Share[] = [];

    try {
      // Use only threshold number of fragments
      const stepsToExecute = Math.min(threshold, sequence.length);
      let previousTokenValue = sessionNonce; // First step seeded from nonce

      for (let step = 0; step < stepsToExecute; step++) {
        const stepStart = signTimestamp(temporalConfig);
        const fragmentIndex = sequence[step]!;
        const fragment = fragments[fragmentIndex];

        if (!fragment) {
          this.breachDetector.recordFailure(memoryId, agentId, BreachEventType.SEQUENCE_FAILURE, {
            step,
            fragmentIndex,
            reason: 'Fragment not found at sequence index',
          });
          throw new ChainLockError('SEQUENCE', `Fragment at sequence index ${fragmentIndex} not found`);
        }

        // Decrypt fragment
        const key = await deriveFragmentKey(masterKey, fragment.memoryId, fragment.index);
        let shareBuffer: Buffer;
        try {
          shareBuffer = aesDecrypt(fragment.ciphertext, key, fragment.iv, fragment.authTag);
        } catch {
          this.breachDetector.recordFailure(memoryId, agentId, BreachEventType.TOKEN_MISMATCH, {
            step,
            reason: 'Fragment decryption failed',
          });
          throw new ChainLockError('DECRYPTION', `Fragment decryption failed at step ${step}`);
        }

        // Produce chain token
        const now = process.hrtime.bigint();
        const chainToken = produceChainToken(
          shareBuffer,
          step,
          now,
          previousTokenValue,
          sessionNonce,
        );
        chainTokens.push(chainToken);
        previousTokenValue = chainToken.value;

        // Extract share
        shares.push({
          x: shareBuffer[0]!,
          y: shareBuffer.subarray(1),
        });

        // Check step timing
        const stepCheck = checkStepWindow(stepStart, temporalConfig);
        stepTimings.push(stepCheck.elapsedMs);

        if (!stepCheck.valid) {
          this.breachDetector.recordFailure(memoryId, agentId, BreachEventType.TEMPORAL_VIOLATION, {
            step,
            elapsedMs: stepCheck.elapsedMs,
            windowMs: this.config.stepWindowMs,
          });
          throw new ChainLockError('TEMPORAL', stepCheck.reason!);
        }

        // Check total ceiling
        const totalCheck = checkTotalCeiling(protocolStart, temporalConfig);
        if (!totalCheck.valid) {
          this.breachDetector.recordFailure(memoryId, agentId, BreachEventType.TEMPORAL_VIOLATION, {
            step,
            totalElapsedMs: totalCheck.elapsedMs,
            ceilingMs: this.config.totalCeilingMs,
          });
          throw new ChainLockError('TEMPORAL', totalCheck.reason!);
        }
      }

      // Check for timing anomalies (automated attack detection)
      if (this.breachDetector.detectTimingAnomaly(stepTimings)) {
        this.breachDetector.recordFailure(memoryId, agentId, BreachEventType.TIMING_ANOMALY, {
          stepTimings,
          reason: 'Suspiciously uniform step timings detected',
        });
        // Warning only — don't abort (could be fast local access)
      }

      // Reconstruct via Shamir
      const plainBuffer = reconstruct(shares);
      const content = plainBuffer.toString('utf-8');

      // Rotate sequence for next recall
      const rotatedSequence = await rotateSequence(
        fragments.length,
        masterKey,
        memoryId,
        encryptedSeq.version,
      );
      sequenceStore.set(memoryId, rotatedSequence);

      // Calculate total time
      const totalEnd = process.hrtime.bigint();
      const totalTimeMs = Number((totalEnd - protocolStart.hrtime) / 1_000_000n);

      return { content, stepTimings, totalTimeMs, rotatedSequence };
    } finally {
      // Wipe all ephemeral data
      for (const token of chainTokens) {
        wipeChainToken(token);
      }
      wipeSessionNonce(sessionNonce);
    }
  }

  /**
   * Bypass ChainLock for non-government security levels.
   * Performs standard decryption without temporal/sequence enforcement.
   */
  private async bypassRecall(
    fragments: EncryptedFragment[],
    masterKey: Buffer,
    threshold: number,
  ): Promise<ChainLockRecallResult> {
    const selected = fragments.slice(0, threshold);
    const shares: Share[] = [];

    for (const fragment of selected) {
      const key = await deriveFragmentKey(masterKey, fragment.memoryId, fragment.index);
      const shareBuffer = aesDecrypt(fragment.ciphertext, key, fragment.iv, fragment.authTag);
      shares.push({ x: shareBuffer[0]!, y: shareBuffer.subarray(1) });
    }

    const plainBuffer = reconstruct(shares);
    const dummySeq = await encryptSequence([], masterKey, 'bypass', 0);

    return {
      content: plainBuffer.toString('utf-8'),
      stepTimings: [],
      totalTimeMs: 0,
      rotatedSequence: dummySeq,
    };
  }

  /**
   * Release a lockdown on a memory (admin action).
   */
  releaseLockdown(memoryId: string, adminId: string): boolean {
    return this.breachDetector.releaseLockdown(memoryId, adminId);
  }

  /**
   * Remove stored sequence for a memory (on forget/delete).
   */
  clearSequence(memoryId: string): void {
    sequenceStore.delete(memoryId);
  }
}

/**
 * ChainLock protocol error with typed reason codes.
 */
export class ChainLockError extends Error {
  constructor(
    public readonly code: 'LOCKDOWN' | 'COOLDOWN' | 'SEQUENCE' | 'TEMPORAL' | 'DECRYPTION' | 'TOKEN',
    message: string,
  ) {
    super(`ChainLock violation [${code}]: ${message}`);
    this.name = 'ChainLockError';
  }
}
