/**
 * Parses the vector to a number score
 *
 * @returns {Number} Calculated  Score
 */
export function getScore(vector: any): number;
/**
 * Parses the vector to the temporal score
 *
 * @returns {Number} Temporal  Score
 */
export function getTemporalScore(vector: any): number;
/**
 * Parses the vector to the environmental score
 *
 * @returns {Number} Environmental  Score
 */
export function getEnvironmentalScore(vector: any): number;
/**
 * Returns an Exploitability sub score
 *
 * 8.22 x AttackVector x AttackComplexity x PrivilegeRequired x UserInteraction
 *
 * @param {String} vector
 * @returns {Number} Exploitability sub score
 */
export function getExploitabilitySubScore(vector: any): number;
/**
 * Returns an Impact sub score
 *
 * ISCBase = 1 − [(1 − ImpactConf) × (1 − ImpactInteg) × (1 − ImpactAvail)]
 *
 * Scope Unchanged 6.42 × ISCBase
 * Scope Changed 7.52 × [ISCBase − 0.029] − 3.25 × [ISCBase - 0.02]15
 *
 * @param {String} vector
 * @returns {Number} Impact sub score
 */
export function getImpactSubScore(vector: any): number;
