/**
 * @module hierarchy/key-chain
 * Hierarchical key derivation.
 * Master key → department keys → team keys → agent keys.
 * Each level can only decrypt its level and below (with proper grants).
 */

import { randomUUID } from 'node:crypto';
import {
  deriveHierarchyKey,
  deriveDepartmentKey,
} from '../fragments/encrypt.js';
import { Role } from '../core/types.js';
import type { DelegatedKey } from '../core/types.js';

/**
 * Hierarchical key chain — derives scoped encryption keys for each level
 * of the organization hierarchy.
 */
export class KeyChain {
  private delegatedKeys = new Map<string, DelegatedKey>();

  constructor(private readonly masterKey: Buffer) {}

  /**
   * Derive a department-scoped encryption key.
   * Used as the root key for all operations within a department.
   */
  async getDepartmentKey(department: string): Promise<Buffer> {
    return deriveDepartmentKey(this.masterKey, department);
  }

  /**
   * Derive a role+department-scoped key.
   * Different roles within the same department get different keys.
   */
  async getRoleKey(department: string, role: Role): Promise<Buffer> {
    return deriveHierarchyKey(this.masterKey, department, role);
  }

  /**
   * Derive an agent-specific key.
   * Most granular key — unique per agent within a department.
   */
  async getAgentKey(department: string, agentId: string): Promise<Buffer> {
    return deriveHierarchyKey(this.masterKey, department, `agent:${agentId}`);
  }

  /**
   * Issue a time-limited, scope-limited delegated key.
   * The delegated key is derived from the issuer's scope but with a unique salt.
   *
   * @param issuedBy - Agent ID of the issuer
   * @param issuedTo - Agent ID of the recipient
   * @param scope - Departments/scopes the key grants access to
   * @param maxRole - Maximum role level the key can operate at
   * @param ttlMs - Time-to-live in milliseconds
   */
  async issueKey(
    issuedBy: string,
    issuedTo: string,
    scope: string[],
    maxRole: Role,
    ttlMs: number,
  ): Promise<DelegatedKey> {
    const id = `dkey_${randomUUID().replace(/-/g, '').slice(0, 16)}`;
    const now = new Date();

    // Derive a unique key for this delegation
    const scopeStr = scope.sort().join(':');
    const derivedKey = await deriveHierarchyKey(
      this.masterKey,
      scopeStr,
      `delegation:${id}`,
    );

    const key: DelegatedKey = {
      id,
      issuedBy,
      issuedTo,
      derivedKey,
      scope,
      maxRole,
      createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
    };

    this.delegatedKeys.set(id, key);
    return key;
  }

  /**
   * Revoke a delegated key.
   */
  revokeKey(keyId: string): boolean {
    return this.delegatedKeys.delete(keyId);
  }

  /**
   * Get all active delegated keys for an agent.
   */
  getKeysForAgent(agentId: string): DelegatedKey[] {
    const now = new Date();
    return [...this.delegatedKeys.values()].filter(
      k => k.issuedTo === agentId && new Date(k.expiresAt) > now,
    );
  }

  /**
   * Validate a delegated key is still active and within scope.
   */
  validateKey(keyId: string, requiredScope: string): boolean {
    const key = this.delegatedKeys.get(keyId);
    if (!key) return false;
    if (new Date(key.expiresAt) <= new Date()) return false;
    return key.scope.includes(requiredScope);
  }

  /**
   * Purge all expired delegated keys.
   * @returns Number of keys purged
   */
  purgeExpiredKeys(): number {
    const now = new Date();
    let count = 0;
    for (const [id, key] of this.delegatedKeys) {
      if (new Date(key.expiresAt) <= now) {
        this.delegatedKeys.delete(id);
        count++;
      }
    }
    return count;
  }
}
