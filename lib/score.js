const util = require("./util");

/**
 * Parses the vector to a number score
 *
 * @returns {Number} Calculated  Score
 */
function getScore(vector) {
  const vectorObject = util.getVectorObject(vector);

  const scopeChanged = vectorObject.S === "C";
  const ISCBase = calculateISCBase(vectorObject);
  const ISC = calculateISC(ISCBase, scopeChanged, vector);

  if (ISC <= 0) return 0;

  const exploitability = calculateExploitability(vectorObject, scopeChanged);

  if (scopeChanged) {
    return roundUp(Math.min(1.08 * (ISC + exploitability), 10), 1, vector);
  }

  return roundUp(Math.min(ISC + exploitability, 10), 1, vector);
}

/**
 * Parses the vector to the temporal score
 *
 * @returns {Number} Temporal  Score
 */
function getTemporalScore(vector) {
  const vectorObject = util.getVectorObject(vector);

  const baseScore = getScore(vector);

  const eMetric = util.findMetricValue("E", vectorObject);
  const exploitCodeMaturity = eMetric ? eMetric.numerical : 1;
  const rMetric = util.findMetricValue("RL", vectorObject);
  const remediationLevel = rMetric ? rMetric.numerical : 1;
  const rcMetric = util.findMetricValue("RC", vectorObject);
  const reportConfidence = rcMetric ? rcMetric.numerical : 1;

  return roundUp(baseScore * exploitCodeMaturity * remediationLevel * reportConfidence, 1, vector);
}

const calculateISCBase = function (vectorObject) {
  const cValue = util.findMetricValue("C", vectorObject).numerical;
  const iValue = util.findMetricValue("I", vectorObject).numerical;
  const aValue = util.findMetricValue("A", vectorObject).numerical;

  return 1 - (1 - cValue) * (1 - iValue) * (1 - aValue);
};

/**
 * Parses the vector to the environmental score
 *
 * @returns {Number} Environmental  Score
 */
function getEnvironmentalScore(vector) {
  const vectorObject = util.getVectorObject(vector);
  const scopeChanged = vectorObject.MS === "X" ? vectorObject.S === "C" : vectorObject.MS === "C";
  const modifiedISCBase = calculateISCModifiedBase(vectorObject);
  const modifiedExploitability = calculateModifiedExploitability(vectorObject, scopeChanged);
  const modifiedISC = calculateISC(modifiedISCBase, scopeChanged, vector);

  if (modifiedISC <= 0) return 0;

  const e = util.findMetricValue("E", vectorObject);
  const rl = util.findMetricValue("RL", vectorObject);
  const rc = util.findMetricValue("RC", vectorObject);
  const eValue = e ? e.numerical : 1;
  const rlValue = rl ? rl.numerical : 1;
  const rcValue = rc ? rc.numerical : 1;

  if (!scopeChanged) {
    return roundUp(
      roundUp(Math.min(modifiedISC + modifiedExploitability, 10), 1, vector) *
        eValue *
        rlValue *
        rcValue,
      1,
      vector
    );
  }
  return roundUp(
    roundUp(Math.min(1.08 * (modifiedISC + modifiedExploitability), 10), 1, vector) *
      eValue *
      rlValue *
      rcValue,
    1,
    vector
  );
}

const calculateISC = function (iscBase, scopeChanged, vector) {
  if (!scopeChanged) return 6.42 * iscBase;
  if (util.getVersion(vector) === "3.0") {
    return 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
  } else if (util.getVersion(vector) === "3.1") {
    return 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase * 0.9731 - 0.02, 13);
  }
};

const calculateExploitability = function (vectorObject, scopeChanged) {
  const avValue = util.findMetricValue("AV", vectorObject).numerical;
  const acValue = util.findMetricValue("AC", vectorObject).numerical;
  const prMetrics = util.findMetricValue("PR", vectorObject).numerical;
  const uiValue = util.findMetricValue("UI", vectorObject).numerical;

  const prValue = scopeChanged ? prMetrics.changed : prMetrics.unchanged;

  return 8.22 * avValue * acValue * prValue * uiValue;
};

function calculateISCModifiedBase(vectorObject) {
  let mcValue = util.findMetricValue("MC", vectorObject);
  let miValue = util.findMetricValue("MI", vectorObject);
  let maValue = util.findMetricValue("MA", vectorObject);
  const crValue = util.findMetricValue("CR", vectorObject).numerical;
  const irValue = util.findMetricValue("IR", vectorObject).numerical;
  const arValue = util.findMetricValue("AR", vectorObject).numerical;

  if (!mcValue || mcValue.abbr === "X") mcValue = util.findMetricValue("C", vectorObject);
  if (!miValue || miValue.abbr === "X") miValue = util.findMetricValue("I", vectorObject);
  if (!maValue || maValue.abbr === "X") maValue = util.findMetricValue("A", vectorObject);

  return Math.min(
    1 -
      (1 - mcValue.numerical * crValue) *
        (1 - miValue.numerical * irValue) *
        (1 - maValue.numerical * arValue),
    0.915
  );
}

const calculateModifiedExploitability = function (vectorObject, scopeChanged) {
  let mavValue = util.findMetricValue("MAV", vectorObject);
  let macValue = util.findMetricValue("MAC", vectorObject);
  let mprMetrics = util.findMetricValue("MPR", vectorObject);
  let muiValue = util.findMetricValue("MUI", vectorObject);

  if (!mavValue || mavValue.abbr === "X") mavValue = util.findMetricValue("AV", vectorObject);
  if (!macValue || macValue.abbr === "X") macValue = util.findMetricValue("AC", vectorObject);
  if (!mprMetrics || mprMetrics.abbr === "X") mprMetrics = util.findMetricValue("PR", vectorObject);
  if (!muiValue || muiValue.abbr === "X") muiValue = util.findMetricValue("UI", vectorObject);

  const mprValue = scopeChanged ? mprMetrics.numerical.changed : mprMetrics.numerical.unchanged;

  return 8.22 * mavValue.numerical * macValue.numerical * mprValue * muiValue.numerical;
};

/**
 * Chooses the correct way to round numbers depending on the CVSS version number
 *
 * @param {Number} num The number to round
 * @param {Number} precision The number of decimal places to preserve (only affects CVSS 3.0)
 * @param {String} vector The vector currently being parsed
 *
 * @returns {num} The rounded number
 */
function roundUp(num, precision, vector) {
  if (util.getVersion(vector) === "3.0") {
    return util.roundUpApprox(num, precision);
  } else if (util.getVersion(vector) === "3.1") {
    return util.roundUpExact(num);
  }
}

module.exports = {
  getScore,
  getTemporalScore,
  getEnvironmentalScore
};
