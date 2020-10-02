const definitions = require("./cvss_3_0.json");
const { roundUp } = require("./util");

/**
 * Creates a new CVSS object
 *
 * @param {String} vector
 */
function CVSS(vector) {
  /**
   * Parses the vector to a number score
   *
   * @returns {Number} Calculated  Score
   */
  function getScore() {
    const vectorArray = vector.split("/");
    const vectorObject = {};

    for (const entry of vectorArray) {
      const values = entry.split(":");
      vectorObject[values[0]] = values[1];
    }

    const scopeChanged = vectorObject.S === "C";
    const ISCBase = calculateISCBase(vectorObject);
    const ISC = calculateISC(ISCBase, scopeChanged);

    if (ISC <= 0) return 0;

    const exploitability = calculateExploitability(vectorObject, scopeChanged);

    if (scopeChanged) {
      return roundUp(Math.min(1.08 * (ISC + exploitability - 0.1), 10), 1);
    }

    return roundUp(Math.min(ISC + exploitability - 0.1, 10), 1);
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

    return 8.92 * avValue * acValue * prValue * uiValue;
  };

  const findMetric = function (abbr) {
    return definitions.definitions.find((def) => def.abbr === abbr);
  };

  return { vector, getScore };
}

module.exports = CVSS;
