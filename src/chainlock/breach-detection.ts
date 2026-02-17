/**
 * @module chainlock/breach-detection
 * Detects and responds to ChainLock protocol violations.
 * Tracks failed attempts, detects automated attacks via timing analysis,
 * and implements lockdown with exponential backoff.
 */

import { EventEmitter } from 'node:events';

/** Breach event types */
export enum BreachEventType {
  SEQUENCE_FAILURE = 'SEQUENCE_FAILURE',
  TEMPORAL_VIOLATION = 'TEMPORAL_VIOLATION',
  TOKEN_MISMATCH = 'TOKEN_MISMATCH',
  TIMING_ANOMALY = 'TIMING_ANOMALY',
  LOCKDOWN_TRIGGERED = 'LOCKDOWN_TRIGGERED',
  LOCKDOWN_RELEASED = 'LOCKDOWN_RELEASED',
}

/** A recorded breach event */
export interface BreachEvent {
  type: BreachEventType;
  memoryId: string;
  agentId: string;
  timestamp: string;
  details: Record<string, unknown>;
}

/** Breach detection configuration */
export interface BreachDetectionConfig {
  /** Max failed attempts before lockdown (default: 3) */
  maxFailedAttempts: number;
  /** Base cooldown between retries in ms (default: 1000) */
  baseCooldownMs: number;
  /** Maximum cooldown cap in ms (default: 60000) */
  maxCooldownMs: number;
  /** Minimum timing variance (ms) for natural agent behavior (default: 50) */
  minTimingVarianceMs: number;
  /** Window for counting failed attempts in ms (default: 300000 = 5 min) */
  failureWindowMs: number;
}

const DEFAULT_CONFIG: BreachDetectionConfig = {
  maxFailedAttempts: 3,
  baseCooldownMs: 1000,
  maxCooldownMs: 60000,
  minTimingVarianceMs: 50,
  failureWindowMs: 300000,
};

/** Tracks per-memory lockdown state */
interface LockdownState {
  locked: boolean;
  failedAttempts: number;
  firstFailureAt: number;
  lastFailureAt: number;
  lockedAt?: number;
}

/**
 * Breach detection and response engine for ChainLock.
 * Emits events for integration with alerting/SIEM systems.
 */
export class BreachDetector extends EventEmitter {
  private readonly config: BreachDetectionConfig;
  private readonly lockdowns = new Map<string, LockdownState>();
  private readonly events: BreachEvent[] = [];

  constructor(config: Partial<BreachDetectionConfig> = {}) {
    super();
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Record a failed ChainLock attempt.
   * May trigger lockdown if threshold is exceeded.
   */
  recordFailure(
    memoryId: string,
    agentId: string,
    type: BreachEventType,
    details: Record<string, unknown> = {},
  ): void {
    const event: BreachEvent = {
      type,
      memoryId,
      agentId,
      timestamp: new Date().toISOString(),
      details,
    };

    this.events.push(event);
    this.emit('breach', event);

    const now = Date.now();
    let state = this.lockdowns.get(memoryId);

    if (!state) {
      state = { locked: false, failedAttempts: 0, firstFailureAt: now, lastFailureAt: now };
      this.lockdowns.set(memoryId, state);
    }

    // Reset window if failures are outside the window
    if (now - state.firstFailureAt > this.config.failureWindowMs) {
      state.failedAttempts = 0;
      state.firstFailureAt = now;
    }

    state.failedAttempts++;
    state.lastFailureAt = now;

    if (state.failedAttempts >= this.config.maxFailedAttempts && !state.locked) {
      state.locked = true;
      state.lockedAt = now;

      const lockdownEvent: BreachEvent = {
        type: BreachEventType.LOCKDOWN_TRIGGERED,
        memoryId,
        agentId,
        timestamp: new Date().toISOString(),
        details: { failedAttempts: state.failedAttempts, ...details },
      };
      this.events.push(lockdownEvent);
      this.emit('lockdown', lockdownEvent);
    }
  }

  /**
   * Check if a memory is locked down.
   */
  isLockedDown(memoryId: string): boolean {
    return this.lockdowns.get(memoryId)?.locked ?? false;
  }

  /**
   * Get the required cooldown before next retry attempt.
   * Implements exponential backoff: base * 2^(failures-1), capped at maxCooldown.
   */
  getCooldownMs(memoryId: string): number {
    const state = this.lockdowns.get(memoryId);
    if (!state || state.failedAttempts === 0) return 0;

    const backoff = this.config.baseCooldownMs * Math.pow(2, state.failedAttempts - 1);
    return Math.min(backoff, this.config.maxCooldownMs);
  }

  /**
   * Check if enough time has passed since last failure for a retry.
   */
  canRetry(memoryId: string): boolean {
    const state = this.lockdowns.get(memoryId);
    if (!state) return true;
    if (state.locked) return false;

    const cooldown = this.getCooldownMs(memoryId);
    return Date.now() - state.lastFailureAt >= cooldown;
  }

  /**
   * Detect automated attack patterns via timing analysis.
   * Natural agents have variable step timing; automated attacks tend to be uniform.
   *
   * @param stepTimings - Array of step durations in ms
   * @returns Whether the timing pattern looks automated
   */
  detectTimingAnomaly(stepTimings: number[]): boolean {
    if (stepTimings.length < 3) return false;

    // Calculate variance of step timings
    const mean = stepTimings.reduce((a, b) => a + b, 0) / stepTimings.length;
    const variance = stepTimings.reduce((sum, t) => sum + Math.pow(t - mean, 2), 0) / stepTimings.length;
    const stdDev = Math.sqrt(variance);

    // If standard deviation is below threshold, timings are suspiciously uniform
    return stdDev < this.config.minTimingVarianceMs;
  }

  /**
   * Release a lockdown (requires admin/executive action).
   */
  releaseLockdown(memoryId: string, adminId: string): boolean {
    const state = this.lockdowns.get(memoryId);
    if (!state?.locked) return false;

    state.locked = false;
    state.failedAttempts = 0;

    const event: BreachEvent = {
      type: BreachEventType.LOCKDOWN_RELEASED,
      memoryId,
      agentId: adminId,
      timestamp: new Date().toISOString(),
      details: { releasedBy: adminId },
    };
    this.events.push(event);
    this.emit('lockdown-released', event);

    return true;
  }

  /**
   * Get all breach events for a memory.
   */
  getEvents(memoryId?: string): BreachEvent[] {
    if (memoryId) return this.events.filter(e => e.memoryId === memoryId);
    return [...this.events];
  }

  /**
   * Get failure count for a memory within the current window.
   */
  getFailureCount(memoryId: string): number {
    return this.lockdowns.get(memoryId)?.failedAttempts ?? 0;
  }
}
