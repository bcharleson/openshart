/**
 * @module hierarchy/roles
 * Enterprise role definitions with clearance levels.
 */

import { Role, ROLE_CLEARANCE } from '../core/types.js';

/** Role metadata */
export interface RoleDefinition {
  role: Role;
  clearance: number;
  label: string;
  description: string;
  canDelegateToRoles: Role[];
}

/** Full role definitions with delegation rules */
export const ROLE_DEFINITIONS: Record<Role, RoleDefinition> = {
  [Role.EXECUTIVE]: {
    role: Role.EXECUTIVE,
    clearance: ROLE_CLEARANCE[Role.EXECUTIVE],
    label: 'Executive',
    description: 'C-suite / VP level. Full access to organizational context. Can delegate to all lower roles.',
    canDelegateToRoles: [Role.DIRECTOR, Role.MANAGER, Role.CONTRIBUTOR, Role.AGENT],
  },
  [Role.DIRECTOR]: {
    role: Role.DIRECTOR,
    clearance: ROLE_CLEARANCE[Role.DIRECTOR],
    label: 'Director',
    description: 'Department head. Full access within department. Can delegate to managers and below.',
    canDelegateToRoles: [Role.MANAGER, Role.CONTRIBUTOR, Role.AGENT],
  },
  [Role.MANAGER]: {
    role: Role.MANAGER,
    clearance: ROLE_CLEARANCE[Role.MANAGER],
    label: 'Manager',
    description: 'Team lead. Access within team scope. Can delegate to contributors and agents.',
    canDelegateToRoles: [Role.CONTRIBUTOR, Role.AGENT],
  },
  [Role.CONTRIBUTOR]: {
    role: Role.CONTRIBUTOR,
    clearance: ROLE_CLEARANCE[Role.CONTRIBUTOR],
    label: 'Contributor',
    description: 'Individual contributor. Access to own work and shared team context.',
    canDelegateToRoles: [Role.AGENT],
  },
  [Role.AGENT]: {
    role: Role.AGENT,
    clearance: ROLE_CLEARANCE[Role.AGENT],
    label: 'Agent',
    description: 'AI agent. Scoped access to assigned tasks and delegated context only.',
    canDelegateToRoles: [],
  },
};

/**
 * Check if a role can delegate access to another role.
 */
export function canDelegate(from: Role, to: Role): boolean {
  return ROLE_DEFINITIONS[from].canDelegateToRoles.includes(to);
}

/**
 * Check if a role has sufficient clearance for an access level.
 */
export function hasClearance(actorRole: Role, requiredRole: Role): boolean {
  return ROLE_CLEARANCE[actorRole] >= ROLE_CLEARANCE[requiredRole];
}

/**
 * Get all roles that a given role can access (same level and below).
 */
export function getAccessibleRoles(role: Role): Role[] {
  const clearance = ROLE_CLEARANCE[role];
  return Object.values(Role).filter(r => ROLE_CLEARANCE[r] <= clearance);
}
