/**
 * @param {Number} num The number to round
 *
 * @returns The rounded number
 */
export function roundUpExact(num: number): number;
/**
 * @param {Number} num The number to round
 * @param {Number} precision The number of decimal places to preserve
 *
 * @returns The rounded number
 */
export function roundUpApprox(num: number, precision: number): number;
/**
 * Retrieves an object of vector's metrics
 *
 * @param {String} vector
 * @returns {Object} Abbreviations & Vector Value pair
 */
export function getVectorObject(vector: string): any;
/**
 * Retrieves an object of vector's metrics
 *
 * @param {String} vector
 * @returns {Object} Abbreviations & Vectors Detailed Values
 */
export function getDetailedVectorObject(vector: string): any;
/**
 * Finds the vector's metric by it's abbreviation
 *
 * @param {String} abbr
 */
export function findMetric(abbr: string): any;
/**
 * Finds the vector's value for a specific metric
 *
 * @param {String} abbr
 * @param {Object} vectorObject
 */
export function findMetricValue(abbr: string, vectorObject: any): any;
/**
 * Calculates the rating of the given vector
 *
 * @param Score calculated score from getScore() in cvss.js
 * @returns {String} returns one of the five possible ratings
 */
export function getRating(score: any): string;
/**
 * Checks whether the vector passed is valid
 *
 * @param {String} vector
 * @returns {Boolean} result with whether the vector is valid or not
 */
export function isVectorValid(vector: string): boolean;
/**
 * This transforms an object in the format of getVectorObject()
 * and parses it to a CVSS comaptible string
 *
 * @param {Object} obj
 */
export function parseVectorObjectToString(obj: any): string;
/**
 * Retrives the version from the vector string
 *
 * @return {String} returns the version number
 */
export function getVersion(vector: any): string;
/**
 * Returns a vector without undefined values
 *
 * @param {String} vector
 * @returns {String} Vector without undefined values
 */
export function getCleanVectorString(vector: string): string;
