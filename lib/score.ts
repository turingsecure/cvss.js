import {
  CvssVectorObject,
  MetricPrivilegesRequired,
  Metric,
  MetricScope,
  MetricUnion
} from "./types";
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

// testing 4.0 score calc
//
//
//
//
//
//
//
//

import { definitions, cvssLookup_global, maxComposed, maxSeverity } from "./cvss_4_0";

const findMetric4_0 = function (abbr: string) {
  return definitions.definitions.find((def) => def.abbr === abbr);
};

const findMetricValue = function <T extends MetricUnion>(
  abbr: string,
  vectorObject: CvssVectorObject
) {
  const definition = findMetric4_0(abbr);
  const value = definition.metrics.find((metric) => metric.abbr === vectorObject[definition.abbr]);

  return value as T;
};

function getVectorObject(vector: string) {
  const vectorArray = vector.split("/");
  const vectorObject = definitions.definitions
    .map((definition) => definition.abbr)
    .reduce((acc, curr) => {
      acc[curr] = "X";
      return acc;
    }, {} as CvssVectorObject);

  for (const entry of vectorArray) {
    const values = entry.split(":");
    vectorObject[values[0]] = values[1];
  }
  return vectorObject;
}

function cvss4_0scoring(vector: string) {
  const vectorObj = getVectorObject(vector);

  // EQ1
  const AVmetric = findMetricValue<Metric>("AV", vectorObj);
  const PRmetric = findMetricValue<Metric>("PR", vectorObj);
  const UImetric = findMetricValue<Metric>("UI", vectorObj);

  // EQ2
  const ACmetric = findMetricValue<Metric>("AC", vectorObj);
  const ATmetric = findMetricValue<Metric>("AT", vectorObj);

  // EQ3 + half of EQ6
  const VCmetric = findMetricValue<Metric>("VC", vectorObj);
  const VImetric = findMetricValue<Metric>("VI", vectorObj);
  const VAmetric = findMetricValue<Metric>("VA", vectorObj);

  // EQ4
  const SCmetric = findMetricValue<Metric>("SC", vectorObj);
  const SImetric = findMetricValue<Metric>("SI", vectorObj);
  const SAmetric = findMetricValue<Metric>("SA", vectorObj);
  const MSImetric = findMetricValue<MetricScope>("MSI", vectorObj);
  const MSAmetric = findMetricValue<MetricScope>("MSA", vectorObj);

  // EQ5
  const Emetric = findMetricValue<Metric>("E", vectorObj);

  // half of EQ6
  const CRmetric = findMetricValue<Metric>("CR", vectorObj);
  const IRmetric = findMetricValue<Metric>("IR", vectorObj);
  const ARmetric = findMetricValue<Metric>("AR", vectorObj);

  // calculate EQ levels
  let eq1 = "0";
  let eq2 = "0";
  let eq3 = "0";
  let eq4 = "0";
  let eq5 = "0";
  let eq6 = "0";

  // EQ1
  // 0	AV:N and PR:N and UI:N
  // 1	(AV:N or PR:N or UI:N) and not (AV:N and PR:N and UI:N) and not AV:P
  // 2	AV:P or not(AV:N or PR:N or UI:N)
  if (AVmetric.abbr === "N" && PRmetric.abbr === "N" && UImetric.abbr === "N") eq1 = "0";
  else if (
    (AVmetric.abbr === "N" || PRmetric.abbr === "N" || UImetric.abbr === "N") &&
    !(AVmetric.abbr === "N" && PRmetric.abbr === "N" && UImetric.abbr === "N") &&
    !(AVmetric.abbr = "P")
  )
    eq1 = "1";
  else if (
    AVmetric.abbr === "P" ||
    !(AVmetric.abbr === "N" || PRmetric.abbr === "N" || UImetric.abbr === "N")
  )
    eq1 = "2";

  // EQ2
  // 0	AC:L and AT:N
  // 1	not (AC:L and AT:N)
  if (ACmetric.abbr === "L" && ATmetric.abbr === "N") eq2 = "0";
  else if (!(ACmetric.abbr === "L" && ATmetric.abbr === "N")) eq2 = "1";

  // EQ3
  // 0	VC:H and VI:H
  // 1	not (VC:H and VI:H) and (VC:H or VI:H or VA:H)
  // 2	not (VC:H or VI:H or VA:H)
  if (VCmetric.abbr === "H" && VImetric.abbr === "H") eq3 = "0";
  else if (
    !(VCmetric.abbr === "H" && VImetric.abbr === "H") &&
    (VCmetric.abbr === "H" || VImetric.abbr === "H" || VAmetric.abbr === "H")
  )
    eq3 = "1";
  else if (!(VCmetric.abbr === "H" || VImetric.abbr === "H" || VAmetric.abbr === "H")) eq3 = "2";

  // EQ4
  // 0	MSI:S or MSA:S
  // 1	not (MSI:S or MSA:S) and (SC:H or SI:H or SA:H)
  // 2	not (MSI:S or MSA:S) and not (SC:H or SI:H or SA:H)
  // If MSI=X or MSA=X they will default to the corresponding value of SI and SA according to the rules of Modified Base Metrics in section 4.2 (See Table 15).
  // So if there are no modified base metrics, the highest value that EQ4 can reach is 1.
  if (MSImetric.abbr === "S" || MSAmetric.abbr === "S") eq4 = "0";
  else if (
    !(MSImetric.abbr === "S" || MSAmetric.abbr === "S") &&
    (SCmetric.abbr === "H" || SImetric.abbr === "H" || SAmetric.abbr === "H")
  )
    eq4 = "1";
  else if (
    !(
      MSImetric.abbr === "S" ||
      MSImetric.abbr === "X" ||
      MSAmetric.abbr === "S" ||
      MSAmetric.abbr === "X"
    ) &&
    !(SCmetric.abbr === "H" || SImetric.abbr === "H" || SAmetric.abbr === "H")
  )
    eq4 = "2";

  // EQ5
  // 0	E:A
  // 1	E:P
  // 2	E:U
  // If E=X it will default to the worst case (i.e., E=A).
  if (Emetric.abbr === "A" || Emetric.abbr === "X") eq5 = "0";
  else if (Emetric.abbr === "P") eq5 = "1";
  else if (Emetric.abbr === "U") eq5 = "2";

  // EQ6
  // 0	(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)
  // 1	not (CR:H and VC:H) and not (IR:H and VI:H) and not (AR:H and VA:H)
  // If CR=X, IR=X or AR=X they will default to the worst case (i.e., CR=H, IR=H and AR=H).
  if (
    ((CRmetric.abbr === "H" || CRmetric.abbr === "X") && VCmetric.abbr === "H") ||
    ((IRmetric.abbr === "H" || IRmetric.abbr === "X") && VImetric.abbr === "H") ||
    ((ARmetric.abbr === "H" || ARmetric.abbr === "X") && VAmetric.abbr === "H")
  )
    eq6 = "0";
  else if (
    !((CRmetric.abbr === "H" || CRmetric.abbr === "X") && VCmetric.abbr === "H") &&
    !((IRmetric.abbr === "H" || IRmetric.abbr === "X") && VImetric.abbr === "H") &&
    !((ARmetric.abbr === "H" || ARmetric.abbr === "X") && VAmetric.abbr === "H")
  )
    eq6 = "1";

  // For each of the EQs
  // The maximal scoring difference is determined as the difference between the current MacroVector and the lower MacroVector
  // there is no lower MacroVector the available distance is set to NaN and then ignored in the further calculations
  // The scores of each MacroVector can be found in the cvssLookup table

  const eq1NextLowerMarcoVectorScore =
    cvssLookup_global["".concat("" + (parseInt(eq1) + 1), eq2, eq3, eq4, eq5, eq6)];
  const eq2NextLowerMarcoVectorScore =
    cvssLookup_global["".concat(eq1, "" + (parseInt(eq2) + 1), eq3, eq4, eq5, eq6)];
  const eq4NextLowerMarcoVectorScore =
    cvssLookup_global["".concat(eq1, eq2, eq3, "" + (parseInt(eq4) + 1), eq5, eq6)];
  const eq5NextLowerMarcoVectorScore =
    cvssLookup_global["".concat(eq1, eq2, eq3, eq4, "" + (parseInt(eq5) + 1), eq6)];

  // // EQ3 and EQ6 are joint see Table 30, an if case represents an change in level constraint f.e 11 -> 21
  let eq3eq6NextLowerMarcoVector = 0;
  let eq3eq6NextLowerLeftMarcoVector = 0;
  let eq3eq6NextLowerRightMarcoVector = 0;
  if (eq3 === "1" && eq6 === "1") {
    eq3eq6NextLowerMarcoVector =
      cvssLookup_global["".concat(eq1, eq2, "" + (parseInt(eq3) + 1), eq4, eq5, eq6)];
  } else if (eq3 === "1" && eq6 === "0") {
    eq3eq6NextLowerMarcoVector =
      cvssLookup_global["".concat(eq1, eq2, eq3, eq4, eq5, "" + (parseInt(eq6) + 1))];
  } else if (eq3 === "0" && eq6 === "1") {
    eq3eq6NextLowerMarcoVector =
      cvssLookup_global["".concat(eq1, eq2, "" + (parseInt(eq3) + 1), eq4, eq5, eq6)];
  } else if (eq3 === "0" && eq6 === "0") {
    eq3eq6NextLowerLeftMarcoVector =
      cvssLookup_global["".concat(eq1, eq2, eq3, eq4, eq5, "" + (parseInt(eq6) + 1))];
    eq3eq6NextLowerRightMarcoVector =
      cvssLookup_global["".concat(eq1, eq2, "" + (parseInt(eq3) + 1), eq4, eq5, eq6)];
  } // cannot exist path
  else
    eq3eq6NextLowerMarcoVector =
      cvssLookup_global[
        "".concat(eq1, eq2, "" + (parseInt(eq3) + 1), eq4, eq5, "" + (parseInt(eq6) + 1))
      ];

  // The severity distance of the to-be scored vector from a highest severity vector in the same MacroVector is determined
  const eq1Maxima = maxComposed["eq1"][eq1];
  const eq2Maxima = maxComposed["eq2"][eq2];
  const eq3eq6Maxima = maxComposed["eq3"][eq3][eq6];
  const eq4Maxima = maxComposed["eq4"][eq4];
  const eq5Maxima = maxComposed["eq5"][eq5];

  // combine all vector maximas to create all possible maximums
  const possibleMaximumVectorString = [];
  for (const eq1Max of eq1Maxima) {
    for (const eq2Max of eq2Maxima) {
      for (const eq3eq6Max of eq3eq6Maxima) {
        for (const eq4Max of eq4Maxima) {
          for (const eq5Max of eq5Maxima) {
            possibleMaximumVectorString.push(eq1Max + eq2Max + eq3eq6Max + eq4Max + eq5Max);
          }
        }
      }
    }
  }

  let max = "";
  for (let i = 0; i < possibleMaximumVectorString.length; i++) {
    max = possibleMaximumVectorString[i];
    console.log(max);
    const maxVectorObj = getVectorObject(max);

    const severity_distance_AV =
      AVmetric.numerical - findMetricValue<Metric>("AV", maxVectorObj).numerical;
    const severity_distance_PR =
      PRmetric.numerical - findMetricValue<Metric>("PR", maxVectorObj).numerical;
    const severity_distance_UI =
      UImetric.numerical - findMetricValue<Metric>("UI", maxVectorObj).numerical;

    const severity_distance_AC =
      ACmetric.numerical - findMetricValue<Metric>("AC", maxVectorObj).numerical;
    const severity_distance_AT =
      ATmetric.numerical - findMetricValue<Metric>("AT", maxVectorObj).numerical;

    const severity_distance_VC =
      VCmetric.numerical - findMetricValue<Metric>("VC", maxVectorObj).numerical;
    const severity_distance_VI =
      VImetric.numerical - findMetricValue<Metric>("VI", maxVectorObj).numerical;
    const severity_distance_VA =
      VAmetric.numerical - findMetricValue<Metric>("VA", maxVectorObj).numerical;

    const severity_distance_SC =
      SCmetric.numerical - findMetricValue<Metric>("SC", maxVectorObj).numerical;
    const severity_distance_SI =
      SImetric.numerical - findMetricValue<Metric>("SI", maxVectorObj).numerical;
    const severity_distance_SA =
      SAmetric.numerical - findMetricValue<Metric>("SA", maxVectorObj).numerical;

    const severity_distance_CR =
      CRmetric.numerical - findMetricValue<Metric>("CR", maxVectorObj).numerical;
    const severity_distance_IR =
      IRmetric.numerical - findMetricValue<Metric>("IR", maxVectorObj).numerical;
    const severity_distance_AR =
      ARmetric.numerical - findMetricValue<Metric>("AR", maxVectorObj).numerical;

    if (
      [
        severity_distance_AV,
        severity_distance_PR,
        severity_distance_UI,
        severity_distance_AC,
        severity_distance_AT,
        severity_distance_VC,
        severity_distance_VI,
        severity_distance_VA,
        severity_distance_SC,
        severity_distance_SI,
        severity_distance_SA,
        severity_distance_CR,
        severity_distance_IR,
        severity_distance_AR
      ].some((met) => met < 0)
    ) {
      continue;
    }
    break;
  }
  console.log(max);

  // TODO :  https://www.first.org/cvss/v4.0/specification-document#New-Scoring-System-Development step 1.3
}

export const score = {
  getScore,
  getTemporalScore,
  getEnvironmentalScore,
  getImpactSubScore,
  getExploitabilitySubScore,
  cvss4_0scoring
};
