import { CvssVectorObject, Metric, MetricScope, MetricUnion } from "./types";

import { definitions, cvssLookup_global, maxComposed, maxSeverity } from "./cvss_4_0";

const findMetric4_0 = function (abbr: string) {
  return definitions.definitions.find((def) => def.abbr === abbr);
};

const findMetricValue = function <T extends MetricUnion>(
  abbr: string,
  vectorObject: CvssVectorObject
) {
  const definition = findMetric4_0(abbr);
  let value = definition.metrics.find((metric) => metric.abbr === vectorObject[definition.abbr]);

  if (vectorObject.CVSS === "4.0") {
    // If E=X it will default to the worst case i.e. E=A
    if (abbr == "E" && vectorObject["E"] == "X") {
      return definition.metrics.find((metric) => metric.abbr === "A") as T;
    }
    // If CR=X, IR=X or AR=X they will default to the worst case i.e. CR=H, IR=H and AR=H
    if (abbr == "CR" && vectorObject["CR"] == "X") {
      return definition.metrics.find((metric) => metric.abbr === "H") as T;
    }
    // IR:X is the same as IR:H
    if (abbr == "IR" && vectorObject["IR"] == "X") {
      return definition.metrics.find((metric) => metric.abbr === "H") as T;
    }
    // AR:X is the same as AR:H
    if (abbr == "AR" && vectorObject["AR"] == "X") {
      return definition.metrics.find((metric) => metric.abbr === "H") as T;
    }
    // All other environmental metrics just overwrite base score values,
    // so if they’re not defined just use the base score value.
    if (vectorObject["M" + abbr] !== undefined && vectorObject["M" + abbr] !== "X") {
      const modifiedDefinition = findMetric4_0("M" + abbr);
      value = definition.metrics.find(
        (metric) => metric.abbr === vectorObject[modifiedDefinition.abbr]
      );
    }
  }

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

  // EQ1 (equivalent classes)
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
    !(AVmetric.abbr === "P")
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
    !(MSImetric.abbr === "S" || MSAmetric.abbr === "S") &&
    !(SCmetric.abbr === "H" || SImetric.abbr === "H" || SAmetric.abbr === "H")
  )
    eq4 = "2";

  // EQ5
  // 0	E:A
  // 1	E:P
  // 2	E:U
  // If E=X it will default to the worst case (i.e., E=A).
  if (Emetric.abbr === "A") eq5 = "0";
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

  const macroVector = eq1 + eq2 + eq3 + eq4 + eq5 + eq6;

  // 1. For each of the EQs
  // 1.1 The maximal scoring difference is determined as the difference between the current MacroVector and the lower MacroVector
  // 1.1.1 there is no lower MacroVector the available distance is set to NaN and then ignored in the further calculations
  // The scores of each MacroVector can be found in the cvssLookup table

  const eq1NextLowerMarcoVectorScore =
    cvssLookup_global["".concat("" + (parseInt(eq1) + 1), eq2, eq3, eq4, eq5, eq6)];
  const eq2NextLowerMarcoVectorScore =
    cvssLookup_global["".concat(eq1, "" + (parseInt(eq2) + 1), eq3, eq4, eq5, eq6)];
  const eq4NextLowerMarcoVectorScore =
    cvssLookup_global["".concat(eq1, eq2, eq3, "" + (parseInt(eq4) + 1), eq5, eq6)];
  const eq5NextLowerMarcoVectorScore =
    cvssLookup_global["".concat(eq1, eq2, eq3, eq4, "" + (parseInt(eq5) + 1), eq6)];

  // EQ3 and EQ6 are joint see Table 30, an if case represents an change in level constraint f.e 11 -> 21
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
    eq3eq6NextLowerMarcoVector =
      eq3eq6NextLowerLeftMarcoVector > eq3eq6NextLowerRightMarcoVector
        ? eq3eq6NextLowerLeftMarcoVector
        : eq3eq6NextLowerRightMarcoVector;
  } // cannot exist path
  else
    eq3eq6NextLowerMarcoVector =
      cvssLookup_global[
        "".concat(eq1, eq2, "" + (parseInt(eq3) + 1), eq4, eq5, "" + (parseInt(eq6) + 1))
      ];

  // 1.2. The severity distance of the to-be scored vector from a highest severity vector in the same MacroVector is determined
  const eq1Maxima = maxComposed["eq1"][parseInt(eq1)];
  const eq2Maxima = maxComposed["eq2"][parseInt(eq2)];
  const eq3eq6Maxima = maxComposed["eq3"][parseInt(eq3)][parseInt(eq6)];
  const eq4Maxima = maxComposed["eq4"][parseInt(eq4)];
  const eq5Maxima = maxComposed["eq5"][parseInt(eq5)];

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
  let eq1Distance = 0;
  let eq2Distance = 0;
  let eq3eq6Distance = 0;
  let eq4Distance = 0;
  let eq5Distance = 0;

  for (let i = 0; i < possibleMaximumVectorString.length; i++) {
    max = possibleMaximumVectorString[i];
    const maxVectorObj = getVectorObject(max);

    // distance of the to-be scored vector from a highest severity vector
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

    // if any of the values is negative, a greater max vector can be found
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

    // add the severity distance of the metric groups to calculate the serverity distance of the equivalent class
    eq1Distance = severity_distance_AV + severity_distance_PR + severity_distance_UI;
    eq2Distance = severity_distance_AC + severity_distance_AT;
    eq3eq6Distance =
      severity_distance_VC +
      severity_distance_VI +
      severity_distance_VA +
      severity_distance_CR +
      severity_distance_IR +
      severity_distance_AR;
    eq4Distance = severity_distance_SC + severity_distance_SI + severity_distance_SA;
    eq5Distance = 0;

    break;
  }

  // calculate maximal scoring difference
  const currentMacroVectorValue = cvssLookup_global[macroVector];

  let eq1MSD = currentMacroVectorValue - eq1NextLowerMarcoVectorScore;
  let eq2MSD = currentMacroVectorValue - eq2NextLowerMarcoVectorScore;
  let eq3eq6MSD = currentMacroVectorValue - eq3eq6NextLowerMarcoVector;
  let eq4MSD = currentMacroVectorValue - eq4NextLowerMarcoVectorScore;
  let eq5MSD = currentMacroVectorValue - eq5NextLowerMarcoVectorScore;

  const step = 0.1;

  const eq1MaxSevertity = maxSeverity["eq1"][parseInt(eq1)] * step;
  const eq2MaxSevertity = maxSeverity["eq2"][parseInt(eq2)] * step;
  const eq3eq6MaxSevertity = maxSeverity["eq3eq6"][parseInt(eq3)][parseInt(eq6)] * step;
  const eq4MaxSevertity = maxSeverity["eq4"][parseInt(eq4)] * step;
  const eq5MaxSevertity = maxSeverity["eq5"][parseInt(eq5)] * step;

  // 1.1.1 if there is no lower MacroVector the available distance is set to NaN and then ignored in the further calculations
  // 1.3 The proportion of the distance is determined by dividing the severity distance of the to-be-scored vector by the depth of the MacroVector
  // 1.4 The maximal scoring difference is multiplied by the proportion of distance
  let count = 0;

  if (!isNaN(eq1MSD)) {
    count++;
    eq1MSD = eq1MSD * (eq1Distance / eq1MaxSevertity);
  } else {
    eq1MSD = 0;
  }
  if (!isNaN(eq2MSD)) {
    count++;
    eq2MSD = eq2MSD * (eq2Distance / eq2MaxSevertity);
  } else {
    eq2MSD = 0;
  }
  if (!isNaN(eq3eq6MSD)) {
    count++;
    eq3eq6MSD = eq3eq6MSD * (eq3eq6Distance / eq3eq6MaxSevertity);
  } else {
    eq3eq6MSD = 0;
  }
  if (!isNaN(eq4MSD)) {
    count++;
    eq4MSD = eq4MSD * (eq4Distance / eq4MaxSevertity);
  } else {
    eq4MSD = 0;
  }
  if (!isNaN(eq5MSD)) {
    count++;
    eq5MSD = 0;
  } else {
    eq5MSD = 0;
  }

  // 2. The mean of the above computed proportional distances is computed
  let mean = 0;
  if (!isNaN(eq1MSD) || !isNaN(eq1MSD) || !isNaN(eq1MSD) || !isNaN(eq1MSD) || !isNaN(eq1MSD)) {
    mean = (eq1MSD + eq2MSD + eq3eq6MSD + eq4MSD + eq5MSD) / count;
  }

  // normalized_severity_eq1 0.44999999999999996
  // normalized_severity_eq2 0
  // normalized_severity_eq3eq6 0.6749999999999997
  // normalized_severity_eq4 1.2666666666666662
  // normalized_severity_eq5 0
  // value 7.6
  // mean_distance 0.5979166666666664

  // 3. The score of the vector is the score of the MacroVector (i.e. the score of the highest severity vector) minus the mean distance so computed.
  // This score is rounded to one decimal place.
  let vectorScore = currentMacroVectorValue - mean;
  if (vectorScore < 0) {
    vectorScore = 0.0;
  }
  if (vectorScore > 10) {
    vectorScore = 10.0;
  }
  return vectorScore.toFixed(1);
}

export const score = {
  cvss4_0scoring
};
