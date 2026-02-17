/**
 * @module hierarchy/access-control
 * Hierarchical access control rules.
 *
 * - Downward flow: leadership shares context down with optional redaction
 * - Upward flow: IC intelligence bubbles up as aggregated, de-identified data
 * - Lateral isolation: departments can't read each other without explicit grants
 * - Key delegation: time-limited, scope-limited access keys
 */

import { Role, ROLE_CLEARANCE } from '../core/types.js';
import type { DelegatedKey, MemoryMeta } from '../core/types.js';
import { hasClearance, canDelegate } from './roles.js';
import { DepartmentManager } from './departments.js';

/** Access decision result */
export interface AccessDecision {
  allowed: boolean;
  reason: string;
}

/**
 * Hierarchical access control engine.
 */
export class AccessController {
  constructor(private readonly departments: DepartmentManager) {}

  /**
   * Check if an agent can access a specific memory.
   *
   * Rules:
   * 1. Agent must have sufficient role clearance for the memory's access level
   * 2. Agent must be in the same department (or have a cross-department grant)
   * 3. Delegated keys extend access within their scope
   */
  checkAccess(
    agentId: string,
    agentRole: Role,
    agentDepartment: string,
    memory: MemoryMeta,
    delegatedKeys: DelegatedKey[] = [],
  ): AccessDecision {
    // Check role clearance
    const requiredRole = memory.accessLevel ?? Role.AGENT;
    if (!hasClearance(agentRole, requiredRole)) {
      return {
        allowed: false,
        reason: `Insufficient clearance: ${agentRole} (${ROLE_CLEARANCE[agentRole]}) < ${requiredRole} (${ROLE_CLEARANCE[requiredRole]})`,
      };
    }

    // Check department access
    const memoryDept = memory.department;
    if (memoryDept && memoryDept !== agentDepartment) {
      // Check cross-department grants
      if (!this.departments.hasAccess(agentId, agentDepartment, memoryDept)) {
        // Check delegated keys for department access
        const hasDelegatedAccess = delegatedKeys.some(
          key =>
            key.issuedTo === agentId &&
            new Date(key.expiresAt) > new Date() &&
            key.scope.includes(memoryDept),
        );

        if (!hasDelegatedAccess) {
          return {
            allowed: false,
            reason: `No access to department ${memoryDept} from ${agentDepartment}`,
          };
        }
      }
    }

    return { allowed: true, reason: 'Access granted' };
  }

  /**
   * Check if an agent can share context downward.
   * The sharing agent must have higher clearance than the target role.
   */
  canPushDown(fromRole: Role, toRole: Role): AccessDecision {
    if (!hasClearance(fromRole, toRole)) {
      return {
        allowed: false,
        reason: `Cannot push down: ${fromRole} does not have clearance over ${toRole}`,
      };
    }
    if (ROLE_CLEARANCE[fromRole] <= ROLE_CLEARANCE[toRole]) {
      return {
        allowed: false,
        reason: `Cannot push down to same or higher level: ${fromRole} → ${toRole}`,
      };
    }
    return { allowed: true, reason: 'Downward context sharing allowed' };
  }

  /**
   * Check if intelligence can bubble up from a lower role.
   * Any role can bubble up to a higher role (intelligence flows up naturally).
   */
  canBubbleUp(fromRole: Role, toRole: Role): AccessDecision {
    if (ROLE_CLEARANCE[fromRole] >= ROLE_CLEARANCE[toRole]) {
      return {
        allowed: false,
        reason: `Cannot bubble up to same or lower level: ${fromRole} → ${toRole}`,
      };
    }
    return { allowed: true, reason: 'Upward intelligence flow allowed' };
  }

  /**
   * Validate a key delegation request.
   * The issuer must be able to delegate to the target role.
   */
  canDelegateKey(
    issuerRole: Role,
    targetRole: Role,
    _scope: string[],
    ttlMs: number,
  ): AccessDecision {
    if (!canDelegate(issuerRole, targetRole)) {
      return {
        allowed: false,
        reason: `${issuerRole} cannot delegate to ${targetRole}`,
      };
    }

    // Maximum TTL enforcement by role
    const MAX_TTL: Record<Role, number> = {
      [Role.EXECUTIVE]: 365 * 24 * 60 * 60 * 1000,  // 1 year
      [Role.DIRECTOR]: 90 * 24 * 60 * 60 * 1000,    // 90 days
      [Role.MANAGER]: 30 * 24 * 60 * 60 * 1000,     // 30 days
      [Role.CONTRIBUTOR]: 7 * 24 * 60 * 60 * 1000,   // 7 days
      [Role.AGENT]: 0,                                 // Cannot delegate
    };

    if (ttlMs > MAX_TTL[issuerRole]) {
      return {
        allowed: false,
        reason: `TTL exceeds maximum for ${issuerRole}: ${ttlMs}ms > ${MAX_TTL[issuerRole]}ms`,
      };
    }

    return { allowed: true, reason: 'Key delegation allowed' };
  }
}
