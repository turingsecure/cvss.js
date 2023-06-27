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
   * Returns a Impact sub score
   *
   * 𝐼𝑆𝐶𝐵𝑎𝑠𝑒 = 1 − [(1 − 𝐼𝑚𝑝𝑎𝑐𝑡𝐶𝑜𝑛𝑓) × (1 − 𝐼𝑚𝑝𝑎𝑐𝑡𝐼𝑛𝑡𝑒𝑔) × (1 − 𝐼𝑚𝑝𝑎𝑐𝑡𝐴𝑣𝑎𝑖𝑙)]
   *
   * Scope Unchanged 6.42 × 𝐼𝑆𝐶Base
   * Scope Changed 7.52 × [𝐼𝑆𝐶𝐵𝑎𝑠𝑒 − 0.029] − 3.25 × [𝐼𝑆𝐶𝐵𝑎𝑠𝑒 − 0.02]15
   *
   * @param {String} vector
   * @returns {Number} Impact sub score
   */
  function getImpactSubScore() {
    const vectorObject = util.getVectorObject(vector);
    const C = util.findMetricValue("C", vectorObject).numerical;
    const I = util.findMetricValue("I", vectorObject).numerical;
    const A = util.findMetricValue("A", vectorObject).numerical;
    const {S} = vectorObject;

    // Calculate the impact using the formula from the CVSS v3.0 Specification Document
    const impact = 1 - (1 - C) * (1 - I) * (1 - A);

    // Check if the impact equal 0
    if (impact === 0) return impact;

    // If unchanged scope, multiply the impact by 6.42
    let result = (6.42 * impact).toFixed(1);


    // Check if the scope is changed
    if (S === "C") {
      // Scope Changed 7.52 × [𝐼𝑆𝐶𝐵𝑎𝑠𝑒 − 0.029] − 3.25 × [𝐼𝑆𝐶𝐵𝑎𝑠𝑒 − 0.02] ** 15
      result = (7.52 * (impact - 0.029) - 3.25 * (impact - 0.02) ** 15).toFixed(1);
    }

    return Number(result);
  }

  /**
   * Returns a Exploitability sub score
   *
   * 8.22 × 𝐴𝑡𝑡𝑎𝑐𝑘𝑉𝑒𝑐𝑡𝑜𝑟 × 𝐴𝑡𝑡𝑎𝑐𝑘𝐶𝑜𝑚𝑝𝑙𝑒𝑥𝑖𝑡𝑦 × 𝑃𝑟𝑖𝑣𝑖𝑙𝑒𝑔𝑒𝑅𝑒𝑞𝑢𝑖𝑟𝑒𝑑 × 𝑈𝑠𝑒𝑟𝐼𝑛𝑡𝑒𝑟𝑎𝑐𝑡𝑖𝑜𝑛
   *
   * @param {String} vector
   * @returns {Number} Impact sub score
   */
  function getExploitabilitySubScore() {
    const vectorObject = util.getVectorObject(vector);
    const AV = util.findMetricValue("AV", vectorObject).numerical;
    const AC = util.findMetricValue("AC", vectorObject).numerical;
    const UI = util.findMetricValue("UI", vectorObject).numerical;
    const PRObj = util.findMetricValue("PR", vectorObject).numerical;
    const { S } = vectorObject;

    let PR = PRObj.changed;

    // check if scope unchanged
    if (S === "U") PR = PRObj.unchanged;

    const result = (8.22 * AV * AC * PR * UI).toFixed(1);

    return Number(result);
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
