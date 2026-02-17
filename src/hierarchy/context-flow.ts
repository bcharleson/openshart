/**
 * @module hierarchy/context-flow
 * Manages the flow of context up and down the enterprise hierarchy.
 *
 * - pushDown: share context downward with optional redaction
 * - bubbleUp: aggregate and anonymize intelligence upward
 * - grantLateral: temporary cross-department access
 */

import { randomUUID } from 'node:crypto';
import { Role } from '../core/types.js';
import type { AccessGrant } from '../core/types.js';
import { AccessController } from './access-control.js';
import { DepartmentManager } from './departments.js';
import { detectPII, redactPII } from '../pii/detector.js';

/** Result of a downward context push */
export interface PushDownResult {
  allowed: boolean;
  reason: string;
  /** Redacted content (if redaction was applied) */
  content?: string;
  /** PII types that were redacted */
  redactedPII?: string[];
}

/** Result of upward intelligence bubble */
export interface BubbleUpResult {
  allowed: boolean;
  reason: string;
  /** De-identified content */
  content?: string;
  /** Number of PII instances stripped */
  piiStripped?: number;
}

/** Result of lateral access grant */
export interface LateralGrantResult {
  allowed: boolean;
  reason: string;
  grant?: AccessGrant;
}

/**
 * Context flow manager — controls how information moves through the hierarchy.
 */
export class ContextFlowManager {
  private readonly accessController: AccessController;

  constructor(private readonly departments: DepartmentManager) {
    this.accessController = new AccessController(departments);
  }

  /**
   * Push context downward from a higher role to a lower role.
   * Automatically redacts PII that the target role shouldn't see.
   *
   * @param content - Context to share
   * @param fromRole - Sender's role
   * @param toRole - Recipient's role
   * @param scope - Departments/areas the context applies to
   * @param redact - Whether to strip PII (default: true for roles below MANAGER)
   */
  pushDown(
    content: string,
    fromRole: Role,
    toRole: Role,
    _scope: string[] = [],
    redact?: boolean,
  ): PushDownResult {
    const decision = this.accessController.canPushDown(fromRole, toRole);
    if (!decision.allowed) {
      return { allowed: false, reason: decision.reason };
    }

    // Auto-redact PII for lower roles unless explicitly disabled
    const shouldRedact = redact ?? (toRole === Role.CONTRIBUTOR || toRole === Role.AGENT);

    if (shouldRedact) {
      const detections = detectPII(content);
      if (detections.length > 0) {
        const redacted = redactPII(content, detections);
        return {
          allowed: true,
          reason: 'Context shared with PII redaction',
          content: redacted,
          redactedPII: [...new Set(detections.map(d => d.type))],
        };
      }
    }

    return {
      allowed: true,
      reason: 'Context shared without redaction',
      content,
      redactedPII: [],
    };
  }

  /**
   * Bubble intelligence upward from a lower role to a higher role.
   * PII is always stripped for upward flow to protect individual privacy.
   *
   * @param intelligence - Raw intelligence/insights from the lower level
   * @param fromRole - Source role
   * @param toRole - Target higher role
   * @param redactAllPII - Strip all PII (default: true)
   */
  bubbleUp(
    intelligence: string,
    fromRole: Role,
    toRole: Role,
    redactAllPII = true,
  ): BubbleUpResult {
    const decision = this.accessController.canBubbleUp(fromRole, toRole);
    if (!decision.allowed) {
      return { allowed: false, reason: decision.reason };
    }

    if (redactAllPII) {
      const detections = detectPII(intelligence);
      const content = detections.length > 0
        ? redactPII(intelligence, detections)
        : intelligence;

      return {
        allowed: true,
        reason: 'Intelligence aggregated with PII stripped',
        content,
        piiStripped: detections.length,
      };
    }

    return {
      allowed: true,
      reason: 'Intelligence passed up without PII stripping',
      content: intelligence,
      piiStripped: 0,
    };
  }

  /**
   * Grant temporary lateral (cross-department) access.
   *
   * @param fromAgentId - Agent granting access
   * @param toAgentId - Agent receiving access
   * @param fromDept - Source department
   * @param toDept - Target department
   * @param scope - Access scope (e.g., specific tags or memory types)
   * @param ttlMs - Time-to-live in milliseconds
   */
  grantLateral(
    fromAgentId: string,
    toAgentId: string,
    fromDept: string,
    toDept: string,
    scope: string[] = [],
    ttlMs: number = 24 * 60 * 60 * 1000, // default 24h
  ): LateralGrantResult {
    // Verify both departments exist
    if (!this.departments.getDepartment(fromDept)) {
      return { allowed: false, reason: `Source department ${fromDept} not found` };
    }
    if (!this.departments.getDepartment(toDept)) {
      return { allowed: false, reason: `Target department ${toDept} not found` };
    }

    const now = new Date();
    const grant: AccessGrant = {
      id: `grant_${randomUUID().replace(/-/g, '').slice(0, 16)}`,
      fromAgentId,
      toAgentId,
      fromDepartment: fromDept,
      toDepartment: toDept,
      scope,
      role: Role.CONTRIBUTOR, // Lateral grants are contributor-level by default
      createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
    };

    this.departments.grantAccess(grant);

    return {
      allowed: true,
      reason: `Lateral access granted from ${fromDept} to ${toDept} for ${ttlMs}ms`,
      grant,
    };
  }
}
