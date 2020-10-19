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
  function getVersion(){
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
    isValid
  };
}

module.exports = CVSS;