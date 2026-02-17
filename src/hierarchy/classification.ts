/**
 * @module hierarchy/classification
 * Government classification system — UNCLASSIFIED through TS/SCI.
 * Implements Bell-LaPadula (no read up, no write down) and compartmentalization.
 */



/** Government classification levels (hierarchical) */
export enum Classification {
  UNCLASSIFIED = 'UNCLASSIFIED',
  CUI = 'CUI',
  CONFIDENTIAL = 'CONFIDENTIAL',
  SECRET = 'SECRET',
  TOP_SECRET = 'TOP_SECRET',
  TS_SCI = 'TS_SCI',
}

/** Numeric ordering for classification levels */
export const CLASSIFICATION_LEVEL: Record<Classification, number> = {
  [Classification.UNCLASSIFIED]: 0,
  [Classification.CUI]: 10,
  [Classification.CONFIDENTIAL]: 40,
  [Classification.SECRET]: 60,
  [Classification.TOP_SECRET]: 80,
  [Classification.TS_SCI]: 100,
};

/** Common SCI compartment codes */
export const KNOWN_COMPARTMENTS = [
  'GAMMA',  // Signals intelligence
  'HCS',    // HUMINT Control System
  'SI',     // Special Intelligence
  'TK',     // TALENT KEYHOLE (satellite imagery)
  'ORCON',  // Originator Controlled
  'NOFORN', // No Foreign Nationals
  'REL TO', // Releasable To (specific countries)
] as const;

/** SCI Compartment definition */
export interface SCICompartment {
  id: string;
  name: string;
  parentCompartment?: string;
  accessList: string[];      // Agent IDs with access
  controlOfficer: string;
  created: string;
  reviewDate: string;
}

/** Compartment access record */
export interface CompartmentAccess {
  agentId: string;
  compartmentId: string;
  grantedBy: string;
  grantedAt: string;
  expiresAt: string;
  justification: string;
  approvedBy: string[];      // TPI — at least 2 approvers for TS/SCI
  readOnDate: string;
}

/** Classification metadata for a memory */
export interface ClassifiedMemoryMeta {
  classification: Classification;
  compartments: string[];
  disseminationControls: string[];
  declassifyOn?: string;
  classifiedBy: string;
  derivedFrom?: string;
  portionMarking: string;
}

/** Agent's clearance profile */
export interface ClearanceProfile {
  agentId: string;
  maxClassification: Classification;
  compartments: string[];
  needToKnow: Map<string, string[]>; // memoryId/scope → granted compartments
}

/**
 * Check if an agent's clearance is sufficient for a classification level.
 */
export function hasClearanceFor(
  agentClearance: Classification,
  requiredClassification: Classification,
): boolean {
  return CLASSIFICATION_LEVEL[agentClearance] >= CLASSIFICATION_LEVEL[requiredClassification];
}

/**
 * Check if an agent has access to all required compartments.
 */
export function hasCompartmentAccess(
  agentCompartments: string[],
  requiredCompartments: string[],
): boolean {
  return requiredCompartments.every(c => agentCompartments.includes(c));
}

/**
 * Bell-LaPadula: No Read Up — agent cannot read above their clearance.
 */
export function bellLaPadulaReadCheck(
  agentClearance: Classification,
  memoryClassification: Classification,
): { allowed: boolean; reason: string } {
  if (CLASSIFICATION_LEVEL[agentClearance] < CLASSIFICATION_LEVEL[memoryClassification]) {
    return {
      allowed: false,
      reason: `Bell-LaPadula NRU violation: ${agentClearance} cannot read ${memoryClassification}`,
    };
  }
  return { allowed: true, reason: 'Read permitted' };
}

/**
 * Bell-LaPadula: No Write Down — agent cannot write below their clearance.
 * Prevents data leakage from high to low classification.
 */
export function bellLaPadulaWriteCheck(
  agentClearance: Classification,
  targetClassification: Classification,
): { allowed: boolean; reason: string } {
  if (CLASSIFICATION_LEVEL[agentClearance] > CLASSIFICATION_LEVEL[targetClassification]) {
    return {
      allowed: false,
      reason: `Bell-LaPadula NWD violation: ${agentClearance} cannot write to ${targetClassification}`,
    };
  }
  return { allowed: true, reason: 'Write permitted' };
}

/**
 * Full access check: clearance + compartments + need-to-know.
 */
export function checkClassifiedAccess(
  profile: ClearanceProfile,
  memoryMeta: ClassifiedMemoryMeta,
  memoryId: string,
): { allowed: boolean; reason: string } {
  // 1. Classification level check (Bell-LaPadula NRU)
  const readCheck = bellLaPadulaReadCheck(profile.maxClassification, memoryMeta.classification);
  if (!readCheck.allowed) return readCheck;

  // 2. Compartment access check
  if (memoryMeta.compartments.length > 0) {
    if (!hasCompartmentAccess(profile.compartments, memoryMeta.compartments)) {
      const missing = memoryMeta.compartments.filter(c => !profile.compartments.includes(c));
      return {
        allowed: false,
        reason: `Missing compartment access: ${missing.join(', ')}`,
      };
    }
  }

  // 3. Need-to-know check (for SECRET and above)
  if (CLASSIFICATION_LEVEL[memoryMeta.classification] >= CLASSIFICATION_LEVEL[Classification.SECRET]) {
    const ntkGrants = profile.needToKnow.get(memoryId) ?? profile.needToKnow.get('*');
    if (!ntkGrants) {
      return {
        allowed: false,
        reason: `Need-to-know not established for ${memoryId}`,
      };
    }
    // Verify NTK covers required compartments
    if (memoryMeta.compartments.length > 0) {
      const ntkCovers = memoryMeta.compartments.every(c => ntkGrants.includes(c) || ntkGrants.includes('*'));
      if (!ntkCovers) {
        return {
          allowed: false,
          reason: `Need-to-know does not cover all compartments for ${memoryId}`,
        };
      }
    }
  }

  return { allowed: true, reason: 'Full classified access granted' };
}

/**
 * Generate a portion marking string (e.g., "(TS//SI//NF)").
 */
export function generatePortionMarking(meta: ClassifiedMemoryMeta): string {
  const parts: string[] = [];

  // Classification abbreviation
  const abbrevs: Record<Classification, string> = {
    [Classification.UNCLASSIFIED]: 'U',
    [Classification.CUI]: 'CUI',
    [Classification.CONFIDENTIAL]: 'C',
    [Classification.SECRET]: 'S',
    [Classification.TOP_SECRET]: 'TS',
    [Classification.TS_SCI]: 'TS',
  };
  parts.push(abbrevs[meta.classification]);

  // Compartments
  parts.push(...meta.compartments);

  // Dissemination controls
  parts.push(...meta.disseminationControls);

  return `(${parts.join('//')})`;
}
