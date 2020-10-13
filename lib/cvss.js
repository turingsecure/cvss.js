const util = require("./util");

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
  function getVectorObject (){
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
   * Calculates the Rating of the given vector
   * Calls a function from util.js
   * 
   * @returns {String} returns one of the five possible ratings
   */
  function getRating() {
    return util.getRating(getScore());
  }

  /**
   * Checks if the given vector is valid
   * Calls a function from util.js
   * 
   * @returns {boolean} valid = true ; not valid = false
   */
  const isVectorValid = function() {
    return util.isVectorValid(vector);
  };

  /**
   * Converts an object into a vectorstring
   * Calls a function from util.js
   * 
   * @param {*} obj 
   * @returns {String} returns the vectorstring
   */
  function parseVectorObjectToString(obj){
    return util.parseVectorObjectToString(obj);
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
      return util.roundUp(Math.min(1.08 * (ISC + exploitability), 10), 1);
    }

    return util.roundUp(Math.min(ISC + exploitability, 10), 1);
  }

  /**
   * Parses the vector to the temporal score
   *
   * @returns {Number} Temporal  Score
   */
  function getTemporalScore() {
    const vectorObject = getVectorObject();

    const baseScore = getScore();

    const eDef = util.findMetric("E");
    const rlDef = util.findMetric("RL");
    const rcDef = util.findMetric("RC");

    const exploitCodeMaturity = eDef.metrics.find(
      (metric) => metric.abbr === (vectorObject.E ? vectorObject.E : "X")
    ).numerical;
    const remediationLevel = rlDef.metrics.find(
      (metric) => metric.abbr === (vectorObject.RL ? vectorObject.RL : "X")
    ).numerical;
    const reportConfidence = rcDef.metrics.find(
      (metric) => metric.abbr === (vectorObject.RC ? vectorObject.RC : "X")
    ).numerical;

    return util.roundUp(baseScore * exploitCodeMaturity * remediationLevel * reportConfidence, 1);
  }

  /**
   * Parses the vector to the environmental score
   *
   * @returns {Number} Environmental  Score
   */
  function getEnvironmentalScore() {
    const vectorObject = getVectorObject();
    const scopeChanged = vectorObject.MS === "C";
    const modifiedISCBase = calculateISCModifiedBase(vectorObject);
    const modifiedExploitability = calculateModifiedExploitability(vectorObject, scopeChanged);
    const modifiedISC = calculateISC(modifiedISCBase, scopeChanged);

    if (modifiedISC <= 0) return 0;

    const eDef = util.findMetric("E");
    const rlDef = util.findMetric("RL");
    const rcDef = util.findMetric("RC");

    const e = eDef.metrics.find((metric) => metric.abbr === vectorObject.E);
    const eValue = e ? e.numerical : 1;
    const rl = rlDef.metrics.find((metric) => metric.abbr === vectorObject.RL);
    const rlValue = rl ? rl.numerical : 1;
    const rc = rcDef.metrics.find((metric) => metric.abbr === vectorObject.RC);
    const rcValue = rc ? rc.numerical : 1;

    if (!scopeChanged) {
      return util.roundUp(
        util.roundUp(Math.min(modifiedISC + modifiedExploitability, 10), 1) * eValue * rlValue * rcValue,
        1
      );
    }
    return util.roundUp(
      util.roundUp(Math.min(1.08 * (modifiedISC + modifiedExploitability), 10), 1) *
        eValue *
        rlValue *
        rcValue,
      1
    );
  }


  const calculateISCBase = function (vectorObject) {
    const cDef = util.findMetric("C");
    const iDef = util.findMetric("I");
    const aDef = util.findMetric("A");

    const cValue = cDef.metrics.find((metric) => metric.abbr === vectorObject.C).numerical;
    const iValue = iDef.metrics.find((metric) => metric.abbr === vectorObject.I).numerical;
    const aValue = aDef.metrics.find((metric) => metric.abbr === vectorObject.A).numerical;

    return 1 - (1 - cValue) * (1 - iValue) * (1 - aValue);
  };

  const calculateISC = function (iscBase, scopeChanged) {
    if (!scopeChanged) return 6.42 * iscBase;

    return 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
  };

  function calculateISCModifiedBase(vectorObject) {
    const mcDef = util.findMetric("MC");
    const miDef = util.findMetric("MI");
    const maDef = util.findMetric("MA");
    const crDef = util.findMetric("CR");
    const irDef = util.findMetric("IR");
    const arDef = util.findMetric("AR");

    const mcValue = mcDef.metrics.find((metric) => metric.abbr === vectorObject.MC).numerical;
    const miValue = miDef.metrics.find((metric) => metric.abbr === vectorObject.MI).numerical;
    const maValue = maDef.metrics.find((metric) => metric.abbr === vectorObject.MA).numerical;
    const crValue = crDef.metrics.find((metric) => metric.abbr === vectorObject.CR).numerical;
    const irValue = irDef.metrics.find((metric) => metric.abbr === vectorObject.IR).numerical;
    const arValue = arDef.metrics.find((metric) => metric.abbr === vectorObject.AR).numerical;

    return Math.min(
      1 - (1 - mcValue * crValue) * (1 - miValue * irValue) * (1 - maValue * arValue),
      0.915
    );
  }

  const calculateExploitability = function (vectorObject, scopeChanged) {
    const avDef = util.findMetric("AV");
    const acDef = util.findMetric("AC");
    const prDef = util.findMetric("PR");
    const uiDef = util.findMetric("UI");

    const avValue = avDef.metrics.find((metric) => metric.abbr === vectorObject.AV).numerical;
    const acValue = acDef.metrics.find((metric) => metric.abbr === vectorObject.AC).numerical;
    const uiValue = uiDef.metrics.find((metric) => metric.abbr === vectorObject.UI).numerical;

    const prMetrics = prDef.metrics.find((metric) => metric.abbr === vectorObject.PR).numerical;
    const prValue = scopeChanged ? prMetrics.changed : prMetrics.unchanged;

    return 8.22 * avValue * acValue * prValue * uiValue;
  };

  const calculateModifiedExploitability = function (vectorObject, scopeChanged) {
    const mavDef = util.findMetric("MAV");
    const macDef = util.findMetric("MAC");
    const mprDef = util.findMetric("MPR");
    const muiDef = util.findMetric("MUI");
    const mavValue = mavDef.metrics.find((metric) => metric.abbr === vectorObject.MAV).numerical;
    const macValue = macDef.metrics.find((metric) => metric.abbr === vectorObject.MAC).numerical;
    const muiValue = muiDef.metrics.find((metric) => metric.abbr === vectorObject.MUI).numerical;

    const mprMetrics = mprDef.metrics.find((metric) => metric.abbr === vectorObject.MPR).numerical;
    const mprValue = scopeChanged ? mprMetrics.changed : mprMetrics.unchanged;

    return 8.22 * mavValue * macValue * mprValue * muiValue;
  };

  vector = parseVectorObjectToString(vector);

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
    getVectorObject,
    getDetailedVectorObject,
    isValid
  };
}

module.exports = CVSS;
