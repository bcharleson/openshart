/**
 * @module hierarchy/departments
 * Department isolation with per-department encryption namespaces.
 * Each department operates in its own encryption context.
 * Cross-department access requires explicit grants.
 */

import type { Department, AccessGrant } from '../core/types.js';


/**
 * Manages department isolation and cross-department access grants.
 */
export class DepartmentManager {
  private departments = new Map<string, Department>();
  private grants = new Map<string, AccessGrant>();

  /**
   * Register a department with its encryption namespace.
   */
  registerDepartment(dept: Department): void {
    this.departments.set(dept.id, dept);
  }

  /**
   * Get a department by ID.
   */
  getDepartment(id: string): Department | undefined {
    return this.departments.get(id);
  }

  /**
   * List all registered departments.
   */
  listDepartments(): Department[] {
    return [...this.departments.values()];
  }

  /**
   * Get the encryption namespace for a department.
   * Used as salt/context in key derivation to ensure department-level isolation.
   */
  getEncryptionNamespace(departmentId: string): string {
    const dept = this.departments.get(departmentId);
    if (!dept) throw new Error(`Department ${departmentId} not found`);
    return dept.encryptionNamespace;
  }

  /**
   * Grant cross-department access.
   * The granting agent must have sufficient role clearance.
   */
  grantAccess(grant: AccessGrant): void {
    this.grants.set(grant.id, grant);
  }

  /**
   * Revoke a cross-department access grant.
   */
  revokeAccess(grantId: string): boolean {
    return this.grants.delete(grantId);
  }

  /**
   * Check if an agent has access to a target department.
   * Access is granted if:
   * 1. Agent is in the same department, OR
   * 2. There's a valid (non-expired) access grant
   */
  hasAccess(
    agentId: string,
    agentDepartment: string,
    targetDepartment: string,
  ): boolean {
    // Same department = access
    if (agentDepartment === targetDepartment) return true;

    // Check for valid grants
    const now = new Date();
    for (const grant of this.grants.values()) {
      if (
        grant.toAgentId === agentId &&
        grant.toDepartment === targetDepartment &&
        new Date(grant.expiresAt) > now
      ) {
        return true;
      }
    }

    return false;
  }

  /**
   * Get all active grants for an agent.
   */
  getGrantsForAgent(agentId: string): AccessGrant[] {
    const now = new Date();
    return [...this.grants.values()].filter(
      g => g.toAgentId === agentId && new Date(g.expiresAt) > now,
    );
  }

  /**
   * Clean up expired grants.
   * @returns Number of grants removed
   */
  purgeExpiredGrants(): number {
    const now = new Date();
    let removed = 0;
    for (const [id, grant] of this.grants) {
      if (new Date(grant.expiresAt) <= now) {
        this.grants.delete(id);
        removed++;
      }
    }
    return removed;
  }
}
