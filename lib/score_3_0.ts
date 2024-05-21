import { CvssVectorObject, MetricPrivilegesRequired, Metric } from "./types";
import { util } from "./util";

/**
 * Parses the vector to a number score
 *
 * @param {string} vector The vector string
 *
 * @returns {number} Calculated Score
 */
function getScore(vector: string) {
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
 * @param {string} vector The vector string
 *
 * @returns {number} Temporal Score
 */
function getTemporalScore(vector: string) {
  const vectorObject = util.getVectorObject(vector);

  const baseScore = getScore(vector);

  const eMetric = util.findMetricValue<Metric>("E", vectorObject);
  const exploitCodeMaturity = eMetric ? eMetric.numerical : 1;
  const rMetric = util.findMetricValue<Metric>("RL", vectorObject);
  const remediationLevel = rMetric ? rMetric.numerical : 1;
  const rcMetric = util.findMetricValue<Metric>("RC", vectorObject);
  const reportConfidence = rcMetric ? rcMetric.numerical : 1;

  return roundUp(baseScore * exploitCodeMaturity * remediationLevel * reportConfidence, 1, vector);
}

/**
 * Calculate the ISC base based on the cvss vector object
 *
 * @param {CvssVectorObject} vectorObject The cvss vector object
 *
 * @returns {number} ISC base
 */
const calculateISCBase = function (vectorObject: CvssVectorObject) {
  const cValue = util.findMetricValue<Metric>("C", vectorObject).numerical;
  const iValue = util.findMetricValue<Metric>("I", vectorObject).numerical;
  const aValue = util.findMetricValue<Metric>("A", vectorObject).numerical;

  return 1 - (1 - cValue) * (1 - iValue) * (1 - aValue);
};

/**
 * Parses the vector to the environmental score
 *
 * @param {string} vector The vector string
 *
 * @returns {number} Environmental Score
 */
function getEnvironmentalScore(vector: string) {
  const vectorObject = util.getVectorObject(vector);
  const scopeChanged = vectorObject.MS === "X" ? vectorObject.S === "C" : vectorObject.MS === "C";
  const modifiedISCBase = calculateISCModifiedBase(vectorObject);
  const modifiedExploitability = calculateModifiedExploitability(vectorObject, scopeChanged);
  const modifiedISC = calculateModifiedISC(modifiedISCBase, scopeChanged, vector);

  if (modifiedISC <= 0) return 0;

  const e = util.findMetricValue<Metric>("E", vectorObject);
  const rl = util.findMetricValue<Metric>("RL", vectorObject);
  const rc = util.findMetricValue<Metric>("RC", vectorObject);
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

/**
 * Calculates the ISC value based on the ISC base, whether the scope has changed and the vector string
 *
 * @param {number} iscBase Value of the ISC base
 * @param {boolean} scopeChanged Boolean value whether the scope has changed
 * @param {string} vector The vector string
 *
 * @returns {number} ISC value
 */
const calculateISC = function (iscBase: number, scopeChanged: boolean, vector: string) {
  if (!scopeChanged) return 6.42 * iscBase;
  if (util.getVersion(vector) === "3.0") {
    return 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
  } else if (util.getVersion(vector) === "3.1") {
    return 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
  }
};

/**
 * Calculates the modified ISC value based on the ISC base, whether the scope has changed and the vector string
 *
 * @param {number} iscBase Value of the ISC base
 * @param {boolean} scopeChanged Boolean value whether the scope has changed
 * @param {string} vector The vector string
 *
 * @returns {number} Modified ISC value
 */
const calculateModifiedISC = function (iscBase: number, scopeChanged: boolean, vector: string) {
  if (!scopeChanged) return 6.42 * iscBase;
  if (util.getVersion(vector) === "3.0") {
    return 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
  } else if (util.getVersion(vector) === "3.1") {
    return 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase * 0.9731 - 0.02, 13);
  }
};

/**
 * Calculates the exploitability value based on the cvss vector object and whether the scope has changed
 *
 * @param {CvssVectorObject} vectorObject Cvss vector object
 * @param {boolean} scopeChanged Boolean value whether the scope has changed
 *
 * @returns {number} Exploitability value
 */
const calculateExploitability = function (vectorObject: CvssVectorObject, scopeChanged: boolean) {
  const avValue = util.findMetricValue<Metric>("AV", vectorObject).numerical;
  const acValue = util.findMetricValue<Metric>("AC", vectorObject).numerical;
  const prMetrics = util.findMetricValue<MetricPrivilegesRequired>("PR", vectorObject).numerical;
  const uiValue = util.findMetricValue<Metric>("UI", vectorObject).numerical;

  const prValue = scopeChanged ? prMetrics.changed : prMetrics.unchanged;

  return 8.22 * avValue * acValue * prValue * uiValue;
};

/**
 * Calculates the ISC modified base value based on the cvss vector object
 *
 * @param {CvssVectorObject} vectorObject Cvss vector object
 *
 * @returns {number} ISC modified base value
 */
const calculateISCModifiedBase = function (vectorObject: CvssVectorObject) {
  let mcValue = util.findMetricValue<Metric>("MC", vectorObject);
  let miValue = util.findMetricValue<Metric>("MI", vectorObject);
  let maValue = util.findMetricValue<Metric>("MA", vectorObject);
  const crValue = util.findMetricValue<Metric>("CR", vectorObject).numerical;
  const irValue = util.findMetricValue<Metric>("IR", vectorObject).numerical;
  const arValue = util.findMetricValue<Metric>("AR", vectorObject).numerical;

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
};

const calculateModifiedExploitability = function (
  vectorObject: CvssVectorObject,
  scopeChanged: boolean
) {
  let mavValue = util.findMetricValue<Metric>("MAV", vectorObject);
  let macValue = util.findMetricValue<Metric>("MAC", vectorObject);
  let mprMetrics = util.findMetricValue<MetricPrivilegesRequired>("MPR", vectorObject);
  let muiValue = util.findMetricValue<Metric>("MUI", vectorObject);

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
 * @param {number} num The number to round
 * @param {number} precision The number of decimal places to preserve (only affects CVSS 3.0)
 * @param {string} vector The vector string currently being parsed
 *
 * @returns {number} The rounded number
 */
function roundUp(num: number, precision: number, vector: string) {
  if (util.getVersion(vector) === "3.0") {
    return util.roundUpApprox(num, precision);
  } else if (util.getVersion(vector) === "3.1") {
    return util.roundUpExact(num);
  }
}

/**
 * Returns an Impact sub score
 *
 * ISCBase = 1 − [(1 − ImpactConf) × (1 − ImpactInteg) × (1 − ImpactAvail)]
 *
 * Scope Unchanged 6.42 × ISCBase
 * Scope Changed 7.52 × [ISCBase − 0.029] − 3.25 × [ISCBase - 0.02]15
 *
 * @param {string} vector The vector string currently being parsed
 *
 * @returns {number} Impact sub score
 */
function getImpactSubScore(vector: string) {
  const vectorObject = util.getVectorObject(vector);
  const { S } = vectorObject;

  const ISCBase = calculateISCBase(vectorObject);

  return Number(calculateISC(ISCBase, S === "C", vector).toFixed(1));
}

/**
 * Returns an Exploitability sub score
 *
 * 8.22 x AttackVector x AttackComplexity x PrivilegeRequired x UserInteraction
 *
 * @param {string} vector The vector string currently being parsed
 *
 * @returns {number} Exploitability sub score
 */
function getExploitabilitySubScore(vector: string) {
  const vectorObject = util.getVectorObject(vector);
  const { S } = vectorObject;

  return Number(calculateExploitability(vectorObject, S === "C").toFixed(1));
}

export const score = {
  getScore,
  getTemporalScore,
  getEnvironmentalScore,
  getImpactSubScore,
  getExploitabilitySubScore
};
