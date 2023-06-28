const util = require("./util");
const score = require("./score");

/**
 * Creates a new CVSS object
 *
 * @param {String} vector
 */
function CVSS(vector) {
  /**
   * Retrieves an object of vector's metrics
   * Calls a function from util.js
   *
   * @returns {Object} Abbreviations & Vector Value pair
   */
  function getVectorObject() {
    return util.getVectorObject(vector);
  }

  /**
   * Retrieves an object of vector's metrics
   * Calls a function from util.js
   *
   * @returns {Object} Abbreviations & Vectors Detailed Values
   */
  function getDetailedVectorObject() {
    return util.getDetailedVectorObject(vector);
  }

  /**
   * Calculates the Base Rating of the given vector
   * Calls a function from util.js
   *
   * @returns {String} returns one of the five possible ratings
   */
  function getRating() {
    return util.getRating(getScore());
  }

  /**
   * Calculates the Temporal Rating of the given vector
   * Calls a function from util.js
   *
   * @returns {String} returns one of the five possible ratings
   */
  function getTemporalRating() {
    return util.getRating(getTemporalScore());
  }

  /**
   * Calculates the Environmental Rating of the given vector
   * Calls a function from util.js
   *
   * @returns {String} returns one of the five possible ratings
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
   * Converts an object into a vector string
   * Calls a function from util.js
   *
   * @param {*} obj
   * @returns {String} returns the vectorstring
   */
  function parseVectorObjectToString(obj) {
    return util.parseVectorObjectToString(obj);
  }

  /**
   * Retrives the version from the vector string
   *
   * @return {String} returns the version number
   */
  function getVersion() {
    return util.getVersion(vector);
  }

  /**
   * Parses the vector to a number score
   *
   * @returns {Number} Calculated  Score
   */
  function getScore() {
    return score.getScore(vector);
  }

  /**
   * Parses the vector to the temporal score
   *
   * @returns {Number} Temporal  Score
   */
  function getTemporalScore() {
    return score.getTemporalScore(vector);
  }

  /**
   * Parses the vector to the environmental score
   *
   * @returns {Number} Environmental  Score
   */
  function getEnvironmentalScore() {
    return score.getEnvironmentalScore(vector);
  }

  /**
   * Returns a vector without undefined values
   *
   * @param {String} vector
   * @returns {String} Vector without undefined values
   */
  function getCleanVectorString() {
    return util.getCleanVectorString(vector);
  }

  /**
   * Updates a vector's metric by a specific value
   *
   * @param {String} vector
   * @param {String} metric
   * @param {String} value
   * @returns {String} Vector with updated value
   */
  function updateVectorValue(metric, value) {
    return util.updateVectorValue(vector, metric, value);
  }

  vector = parseVectorObjectToString(vector);

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
  function getImpactSubScore() {
    return score.getImpactSubScore(vector);
  }

  /**
   * Returns an Exploitability sub score
   *
   * 8.22 x AttackVector x AttackComplexity x PrivilegeRequired x UserInteraction
   *
   * @param {String} vector
   * @returns {Number} Exploitability sub score
   */
  function getExploitabilitySubScore() {
    return score.getExploitabilitySubScore(vector);
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
    isValid,
    getImpactSubScore,
    getExploitabilitySubScore,
  };
}

module.exports = CVSS;
