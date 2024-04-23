import { CvssVectorObject } from "./types";
import { util } from "./util";
import { score } from "./score";

/**
 * Creates a new CVSS object
 *
 * @param {string | CvssVectorObject} cvss
 */
export function CVSS(cvss: string | CvssVectorObject) {
  const vector = util.parseVectorObjectToString(cvss);

  /**
   * Retrieves an object of vector's metrics
   * Calls a function from util.js
   *
   * @returns {CvssVectorObject} Abbreviations & Vector Value pair
   */
  function getVectorObject() {
    return util.getVectorObject(vector);
  }

  /**
   * Retrieves an object of vector's metrics
   * Calls a function from util.js
   *
   * @returns {DetailedVectorObject} Abbreviations & Vectors Detailed Values
   */
  function getDetailedVectorObject() {
    return util.getDetailedVectorObject(vector);
  }

  /**
   * Calculates the Base Rating of the given vector
   * Calls a function from util.js
   *
   * @returns {string} returns one of the five possible ratings
   */
  function getRating() {
    return util.getRating(getScore());
  }

  /**
   * Calculates the Temporal Rating of the given vector
   * Calls a function from util.js
   *
   * @returns {string} returns one of the five possible ratings
   */
  function getTemporalRating() {
    return util.getRating(getTemporalScore());
  }

  /**
   * Calculates the Environmental Rating of the given vector
   * Calls a function from util.js
   *
   * @returns {string} returns one of the five possible ratings
   */
  function getEnvironmentalRating() {
    return util.getRating(getEnvironmentalScore());
  }

  /**
   * Checks if the given vector is valid
   * Calls a function from util.js
   *
   * @returns {boolean} valid = true ; not valid = false
   */
  const isVectorValid = function () {
    return util.isVectorValid(vector);
  };

  /**
   * Retrives the version from the vector string
   *
   * @return {string} returns the version number
   */
  function getVersion() {
    return util.getVersion(vector);
  }

  /**
   * Parses the vector to a number score
   *
   * @returns {number} Calculated  Score
   */
  function getScore() {
    return score.getScore(vector);
  }

  /**
   * Parses the vector to the temporal score
   *
   * @returns {number} Temporal  Score
   */
  function getTemporalScore() {
    return score.getTemporalScore(vector);
  }

  /**
   * Parses the vector to the environmental score
   *
   * @returns {number} Environmental  Score
   */
  function getEnvironmentalScore() {
    return score.getEnvironmentalScore(vector);
  }

  /**
   * Returns a vector without undefined values
   *
   * @returns {string} Vector without undefined values
   */
  function getCleanVectorString() {
    return util.getCleanVectorString(vector);
  }

  /**
   * Updates a vector's metric by a specific value
   *
   * @param {string} metric
   * @param {string} value
   *
   * @returns {string} Vector with updated value
   */
  function updateVectorValue(metric: string, value: string) {
    return util.updateVectorValue(vector, metric, value);
  }

  /**
   * Returns an Impact sub score
   *
   * ISCBase = 1 − [(1 − ImpactConf) × (1 − ImpactInteg) × (1 − ImpactAvail)]
   *
   * Scope Unchanged 6.42 × ISCBase
   * Scope Changed 7.52 × [ISCBase − 0.029] − 3.25 × [ISCBase - 0.02]15
   *   *
   * @returns {number} Impact sub score
   */
  function getImpactSubScore() {
    return score.getImpactSubScore(vector);
  }

  /**
   * Returns an Exploitability sub score
   *
   * 8.22 x AttackVector x AttackComplexity x PrivilegeRequired x UserInteraction
   *
   * @returns {number} Exploitability sub score
   */
  function getExploitabilitySubScore() {
    return score.getExploitabilitySubScore(vector);
  }

  //Check if vector version is valid
  const isVersionValid = getVersion();
  if (isVersionValid === "Error") {
    throw new Error("The vector version is not valid");
  }

  //Check if vector format is valid
  const isValid = isVectorValid();
  if (!isValid) {
    throw new Error("The vector format is not valid!");
  }

  return {
    vector,
    getScore,
    getTemporalScore,
    getEnvironmentalScore,
    getRating,
    getTemporalRating,
    getEnvironmentalRating,
    getVectorObject,
    getDetailedVectorObject,
    getVersion,
    getCleanVectorString,
    updateVectorValue,
    getImpactSubScore,
    getExploitabilitySubScore,
    isVersionValid,
    isValid
  };
}
