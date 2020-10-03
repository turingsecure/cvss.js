const definitions = require("./cvss_3_0.json");
const { roundUp } = require("./util");

/**
 * Creates a new CVSS object
 *
 * @param {String} vector
 */
function CVSS(vector) {
  /**
   * Retrieves an object of vector's metrics
   *
   * @returns {Object} Abbreviations & Vector Value pair
   */
  function getVectorObject() {
    const vectorArray = vector.split("/");
    const vectorObject = {};

    for (const entry of vectorArray) {
      const values = entry.split(":");
      vectorObject[values[0]] = values[1];
    }
    return vectorObject;
  }

  /**
   * Parses the vector to a number score
   *
   * @returns {Number} Calculated  Score
   */
  function getScore() {
    const vectorObject = getVectorObject();

    const scopeChanged = vectorObject.S === "C";
    const ISCBase = calculateISCBase(vectorObject);
    const ISC = calculateISC(ISCBase, scopeChanged);

    if (ISC <= 0) return 0;

    const exploitability = calculateExploitability(vectorObject, scopeChanged);

    if (scopeChanged) {
      return roundUp(Math.min(1.08 * (ISC + exploitability), 10), 1);
    }

    return roundUp(Math.min(ISC + exploitability, 10), 1);
  }

  /**
   * Parses the vector to a rating
   *
   * @returns {String} Rating value
   */
  function getRating() {
    const score = getScore();
    let rating = "None";

    if (score === 0) {
      rating = "None";
    } else if (score <= 3.9) {
      rating = "Low";
    } else if (score <= 6.9) {
      rating = "Medium";
    } else if (score <= 8.9) {
      rating = "High";
    } else {
      rating = "Critical";
    }
    return rating;
  }

  /**
   * Parses the vector to a number score
   *
   * @returns {Number} Temporal  Score
   */
  function getTemporalScore() {
    const vectorArray = vector.split("/");
    const vectorObject = {};

    for (const entry of vectorArray) {
      const values = entry.split(":");
      vectorObject[values[0]] = values[1];
    }

    const score = getScore();

    const eDef = findMetric("E");
    const rlDef = findMetric("RL");
    const rcDef = findMetric("RC");

    const exploitCodeMaturity = eDef.metrics.find(
      (metric) => metric.abbr === (vectorObject.E ? vectorObject.E : "X")
    ).numerical;
    const remediationLevel = rlDef.metrics.find(
      (metric) => metric.abbr === (vectorObject.RL ? vectorObject.RL : "X")
    ).numerical;
    const reportConfidence = rcDef.metrics.find(
      (metric) => metric.abbr === (vectorObject.RC ? vectorObject.RC : "X")
    ).numerical;

    return roundUp(score * exploitCodeMaturity * remediationLevel * reportConfidence, 1);
  }

  const calculateISCBase = function (vectorObject) {
    const cDef = findMetric("C");
    const iDef = findMetric("I");
    const aDef = findMetric("A");

    const cValue = cDef.metrics.find((metric) => metric.abbr === vectorObject.C).numerical;
    const iValue = iDef.metrics.find((metric) => metric.abbr === vectorObject.I).numerical;
    const aValue = aDef.metrics.find((metric) => metric.abbr === vectorObject.A).numerical;

    return 1 - (1 - cValue) * (1 - iValue) * (1 - aValue);
  };

  const calculateISC = function (iscBase, scopeChanged) {
    if (!scopeChanged) return 6.42 * iscBase;

    return 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
  };

  const calculateExploitability = function (vectorObject, scopeChanged) {
    const avDef = findMetric("AV");
    const acDef = findMetric("AC");
    const prDef = findMetric("PR");
    const uiDef = findMetric("UI");

    const avValue = avDef.metrics.find((metric) => metric.abbr === vectorObject.AV).numerical;
    const acValue = acDef.metrics.find((metric) => metric.abbr === vectorObject.AC).numerical;
    const uiValue = uiDef.metrics.find((metric) => metric.abbr === vectorObject.UI).numerical;

    const prMetrics = prDef.metrics.find((metric) => metric.abbr === vectorObject.PR).numerical;
    const prValue = scopeChanged ? prMetrics.changed : prMetrics.unchanged;

    return 8.22 * avValue * acValue * prValue * uiValue;
  };

  const findMetric = function (abbr) {
    return definitions.definitions.find((def) => def.abbr === abbr);
  };

  const checkVector = function (vector) {
    const inicial = /^CVSS:3\.0\/(AV:[NALP]){1}\/(AC:[LH]){1}\/(PR:[NLH]){1}\/(UI:[NR]){1}\/(S:[UC]){1}\/(C:[NLW]){1}\/(I:[NLW]){1}\/(A:[NLW]){1}$/
    const AV = /AV:[NALP]/
    const AC = /AC:[LH]/
    const PR = /PR:[NLH]/
    const UI = /UI:[NR]/
    const S = /S:[UC]/
    const C = /C:[NLW]/
    const I = /I:[NLW]/
    const A = /A:[NLW]/
  }

  return { vector, getScore, getRating, getVectorObject, getTemporalScore };
}

module.exports = CVSS;
