import { CvssVectorObject } from "./types";
import { util } from "./util";
import { score as score3_0 } from "./score_3_0";
import { score as score4_0 } from "./score_4_0";

/**
 * Creates a new CVSS object
 */
export function CVSS(cvss: string | CvssVectorObject) {
  const vector = util.parseVectorObjectToString(cvss);
  const score = util.getVersion(vector) === "4.0" ? score4_0 : score3_0;
  /**
   * Retrieves an object of vector's metrics
   * Calls a function from util.js
   */
  function getVectorObject() {
    return util.getVectorObject(vector);
  }

  /**
   * Retrieves an object of vector's metrics
   * Calls a function from util.js
   */
  function getDetailedVectorObject() {
    return util.getDetailedVectorObject(vector);
  }

  /**
   * Calculates the Base Rating of the given vector
   * Calls a function from util.js
   */
  function getRating() {
    return util.getRating(getScore());
  }

  /**
   * Calculates the Temporal Rating of the given vector
   * Calls a function from util.js
   *
   * Only available for cvss 3.0 and 3.1
   */
  function getTemporalRating() {
    return util.getRating(getTemporalScore());
  }

  /**
   * Calculates the Environmental Rating of the given vector
   * Calls a function from util.js
   *
   * Only available for cvss 3.0 and 3.1
   */
  function getEnvironmentalRating() {
    return util.getRating(getEnvironmentalScore());
  }

  /**
   * Checks if the given vector is valid
   * Calls a function from util.js
   */
  function isVectorValid() {
    return util.isVectorValid(vector);
  }

  /**
   * Retrives the version from the vector string
   */
  function getVersion() {
    return util.getVersion(vector);
  }

  /**
   * Parses the vector to a number score
   */
  function getScore() {
    return score.getScore(vector);
  }

  /**
   * Parses the vector to the temporal score
   * Only available for cvss 3.0 and 3.1
   */
  function getTemporalScore() {
    return score.getTemporalScore(vector);
  }

  /**
   * Parses the vector to the environmental score
   * Only available for cvss 3.0 and 3.1
   */
  function getEnvironmentalScore() {
    return score.getEnvironmentalScore(vector);
  }

  /**
   * Returns a vector without undefined values
   */
  function getCleanVectorString() {
    return util.getCleanVectorString(vector);
  }

  /**
   * Updates a vector's metric by a specific value
   */
  function updateVectorValue(metric: keyof CvssVectorObject, value: string) {
    return util.updateVectorValue(vector, metric, value);
  }

  /**
   * Returns an Impact sub score
   *
   * ISCBase = 1 − [(1 − ImpactConf) × (1 − ImpactInteg) × (1 − ImpactAvail)]
   *
   * Scope Unchanged 6.42 × ISCBase
   * Scope Changed 7.52 × [ISCBase − 0.029] − 3.25 × [ISCBase - 0.02]15
   *
   * Only available for cvss 3.0 and 3.1
   */
  function getImpactSubScore() {
    return score.getImpactSubScore(vector);
  }

  /**
   * Returns an Exploitability sub score
   *
   * 8.22 x AttackVector x AttackComplexity x PrivilegeRequired x UserInteraction
   *
   * Only available for cvss 3.0 and 3.1
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
    isValid,
  };
}
