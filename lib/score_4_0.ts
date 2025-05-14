import { CvssVectorObject, Metric, MetricUnion } from "./types";

import { cvssLookup_global, maxComposed, maxSeverity } from "./cvss_4_0";
import { util } from "./util";

/**
 * Finds the vector's value for a specific metric and checks for additional scoring rules.
 */
function parseMetric<T extends MetricUnion>(
  abbr: string,
  vectorObject: CvssVectorObject
) {
  const definition = util.findMetric(abbr, vectorObject.CVSS);
  let value = util.findMetricValue<T>(abbr, vectorObject);

  if (vectorObject.CVSS === "4.0") {
    // If E=X it will default to the worst case i.e. E=A
    if (abbr == "E" && vectorObject["E"] == "X") {
      return definition?.metrics.find((metric) => metric.abbr === "A") as T;
    }
    // If CR=X, IR=X or AR=X they will default to the worst case i.e. CR=H, IR=H and AR=H
    if (abbr == "CR" && vectorObject["CR"] == "X") {
      return definition?.metrics.find((metric) => metric.abbr === "H") as T;
    }
    // IR:X is the same as IR:H
    if (abbr == "IR" && vectorObject["IR"] == "X") {
      return definition?.metrics.find((metric) => metric.abbr === "H") as T;
    }
    // AR:X is the same as AR:H
    if (abbr == "AR" && vectorObject["AR"] == "X") {
      return definition?.metrics.find((metric) => metric.abbr === "H") as T;
    }
    // All other environmental metrics just overwrite base score values if they are defined, when not defined use base score
    if (
      // @ts-expect-error
      vectorObject["M" + abbr] !== undefined &&
      // @ts-expect-error
      vectorObject["M" + abbr] !== "X"
    ) {
      const modifiedDefinition = util.findMetric("M" + abbr, vectorObject.CVSS);
      value = definition?.metrics.find(
        // @ts-expect-error
        (metric) => metric.abbr === vectorObject[modifiedDefinition.abbr]
      ) as T;
    }
  }
  return value;
}

function eq3eq6CalculateLowerMacroVector(eqLevels: any) {
  if (eqLevels.eq3 === "1" && eqLevels.eq6 === "1") {
    return cvssLookup_global[
      `${eqLevels.eq1}${eqLevels.eq2}${parseInt(eqLevels.eq3) + 1}${
        eqLevels.eq4
      }${eqLevels.eq5}${eqLevels.eq6}`
    ];
  }
  if (eqLevels.eq3 === "1" && eqLevels.eq6 === "0") {
    return cvssLookup_global[
      `${eqLevels.eq1}${eqLevels.eq2}${eqLevels.eq3}${eqLevels.eq4}${
        eqLevels.eq5
      }${parseInt(eqLevels.eq6) + 1}`
    ];
  }
  if (eqLevels.eq3 === "0" && eqLevels.eq6 === "1") {
    return cvssLookup_global[
      `${eqLevels.eq1}${eqLevels.eq2}${parseInt(eqLevels.eq3) + 1}${
        eqLevels.eq4
      }${eqLevels.eq5}${eqLevels.eq6}`
    ];
  }
  if (eqLevels.eq3 === "0" && eqLevels.eq6 === "0") {
    const eq3eq6NextLowerLeftMarcoVector =
      cvssLookup_global[
        `${eqLevels.eq1}${eqLevels.eq2}${eqLevels.eq3}${eqLevels.eq4}${
          eqLevels.eq5
        }${parseInt(eqLevels.eq6) + 1}`
      ];
    const eq3eq6NextLowerRightMarcoVector =
      cvssLookup_global[
        `${eqLevels.eq1}${eqLevels.eq2}${parseInt(eqLevels.eq3) + 1}${
          eqLevels.eq4
        }${eqLevels.eq5}${eqLevels.eq6}`
      ];
    return eq3eq6NextLowerLeftMarcoVector > eq3eq6NextLowerRightMarcoVector
      ? eq3eq6NextLowerLeftMarcoVector
      : eq3eq6NextLowerRightMarcoVector;
  }

  return cvssLookup_global[
    `${eqLevels.eq1}${eqLevels.eq2}${parseInt(eqLevels.eq3) + 1}${
      eqLevels.eq4
    }${eqLevels.eq5}${parseInt(eqLevels.eq6) + 1}`
  ];
}

/**
 * Parses the vector to a number score
 */
function getScore(vector: string) {
  const vectorObj = util.getVectorObject(vector);

  // Special case: if all metrics are N, return 0.0
  const allMetrics = ['VC', 'VI', 'VA', 'SC', 'SI', 'SA'] as const;
  const allMetricsAreN = allMetrics.every(metric => vectorObj[metric as keyof CvssVectorObject] === 'N');
  if (allMetricsAreN) {
    const score = 0.0;
    return parseFloat(score.toFixed(1));
  }

  const metrics = {
    AV: {} as Metric, // EQ1
    PR: {} as Metric, // EQ1
    UI: {} as Metric, // EQ1
    AC: {} as Metric, // EQ2
    AT: {} as Metric, // EQ2
    VC: {} as Metric, // EQ3 + EQ6
    VI: {} as Metric, // EQ3 + EQ6
    VA: {} as Metric, // EQ3 + EQ6
    SC: {} as Metric, // EQ4
    SI: {} as Metric, // EQ4
    SA: {} as Metric, // EQ4
    MSI: {} as Metric, // EQ4
    MSA: {} as Metric, // EQ4
    E: {} as Metric, // EQ5
    CR: {} as Metric, // EQ6
    IR: {} as Metric, // EQ6
    AR: {} as Metric, // EQ6
  };

  for (let [key] of Object.entries(metrics)) {
    // @ts-expect-error
    metrics[key] = parseMetric<Metric>(key, vectorObj);
  }

  // calculate EQ levels
  const eqLevels = {
    eq1: "0",
    eq2: "0",
    eq3: "0",
    eq4: "0",
    eq5: "0",
    eq6: "0",
  };

  // EQ1
  // 0	AV:N and PR:N and UI:N
  // 1	(AV:N or PR:N or UI:N) and not (AV:N and PR:N and UI:N) and not AV:P
  // 2	AV:P or not(AV:N or PR:N or UI:N)
  if (
    metrics.AV.abbr === "N" &&
    metrics.PR.abbr === "N" &&
    metrics.UI.abbr === "N"
  )
    eqLevels.eq1 = "0";
  if (
    (metrics.AV.abbr === "N" ||
      metrics.PR.abbr === "N" ||
      metrics.UI.abbr === "N") &&
    !(
      metrics.AV.abbr === "N" &&
      metrics.PR.abbr === "N" &&
      metrics.UI.abbr === "N"
    ) &&
    !(metrics.AV.abbr === "P")
  )
    eqLevels.eq1 = "1";
  if (
    metrics.AV.abbr === "P" ||
    !(
      metrics.AV.abbr === "N" ||
      metrics.PR.abbr === "N" ||
      metrics.UI.abbr === "N"
    )
  )
    eqLevels.eq1 = "2";

  // EQ2
  // 0	AC:L and AT:N
  // 1	not (AC:L and AT:N)
  if (metrics.AC.abbr === "L" && metrics.AT.abbr === "N") eqLevels.eq2 = "0";
  if (!(metrics.AC.abbr === "L" && metrics.AT.abbr === "N")) eqLevels.eq2 = "1";

  // EQ3
  // 0	VC:H and VI:H
  // 1	not (VC:H and VI:H) and (VC:H or VI:H or VA:H)
  // 2	not (VC:H or VI:H or VA:H)
  if (metrics.VC.abbr === "H" && metrics.VI.abbr === "H") eqLevels.eq3 = "0";
  if (
    !(metrics.VC.abbr === "H" && metrics.VI.abbr === "H") &&
    (metrics.VC.abbr === "H" ||
      metrics.VI.abbr === "H" ||
      metrics.VA.abbr === "H")
  )
    eqLevels.eq3 = "1";
  if (
    !(
      metrics.VC.abbr === "H" ||
      metrics.VI.abbr === "H" ||
      metrics.VA.abbr === "H"
    )
  )
    eqLevels.eq3 = "2";

  // EQ4
  // 0	MSI:S or MSA:S
  // 1	not (MSI:S or MSA:S) and (SC:H or SI:H or SA:H)
  // 2	not (MSI:S or MSA:S) and not (SC:H or SI:H or SA:H)
  // If MSI=X or MSA=X they will default to the corresponding value of SI and SA according to the rules of Modified Base Metrics in section 4.2 (See Table 15).
  // So if there are no modified base metrics, the highest value that EQ4 can reach is 1.
  if (metrics.MSI.abbr === "S" || metrics.MSA.abbr === "S") eqLevels.eq4 = "0";
  if (
    !(metrics.MSI.abbr === "S" || metrics.MSA.abbr === "S") &&
    (metrics.SC.abbr === "H" ||
      metrics.SI.abbr === "H" ||
      metrics.SA.abbr === "H")
  )
    eqLevels.eq4 = "1";
  if (
    !(metrics.MSI.abbr === "S" || metrics.MSA.abbr === "S") &&
    !(
      metrics.SC.abbr === "H" ||
      metrics.SI.abbr === "H" ||
      metrics.SA.abbr === "H"
    )
  )
    eqLevels.eq4 = "2";

  // EQ5
  // 0	E:A
  // 1	E:P
  // 2	E:U
  // If E=X it will default to the worst case (i.e., E=A).
  if (metrics.E.abbr === "A") eqLevels.eq5 = "0";
  if (metrics.E.abbr === "P") eqLevels.eq5 = "1";
  if (metrics.E.abbr === "U") eqLevels.eq5 = "2";

  // EQ6
  // 0	(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)
  // 1	not (CR:H and VC:H) and not (IR:H and VI:H) and not (AR:H and VA:H)
  // If CR=X, IR=X or AR=X they will default to the worst case (i.e., CR=H, IR=H and AR=H).
  if (
    ((metrics.CR.abbr === "H" || metrics.CR.abbr === "X") &&
      metrics.VC.abbr === "H") ||
    ((metrics.IR.abbr === "H" || metrics.IR.abbr === "X") &&
      metrics.VI.abbr === "H") ||
    ((metrics.AR.abbr === "H" || metrics.AR.abbr === "X") &&
      metrics.VA.abbr === "H")
  )
    eqLevels.eq6 = "0";
  if (
    !(
      (metrics.CR.abbr === "H" || metrics.CR.abbr === "X") &&
      metrics.VC.abbr === "H"
    ) &&
    !(
      (metrics.IR.abbr === "H" || metrics.IR.abbr === "X") &&
      metrics.VI.abbr === "H"
    ) &&
    !(
      (metrics.AR.abbr === "H" || metrics.AR.abbr === "X") &&
      metrics.VA.abbr === "H"
    )
  )
    eqLevels.eq6 = "1";

  const macroVector =
    eqLevels.eq1 +
    eqLevels.eq2 +
    eqLevels.eq3 +
    eqLevels.eq4 +
    eqLevels.eq5 +
    eqLevels.eq6;

  // 1. For each of the EQs
  // 1.1 The maximal scoring difference is determined as the difference between the current MacroVector and the lower MacroVector
  // 1.1.1 there is no lower MacroVector the available distance is set to NaN and then ignored in the further calculations
  // The scores of each MacroVector can be found in the cvssLookup table
  const eq1NextLowerMarcoVectorScore =
    cvssLookup_global[
      `${parseInt(eqLevels.eq1) + 1}${eqLevels.eq2}${eqLevels.eq3}${
        eqLevels.eq4
      }${eqLevels.eq5}${eqLevels.eq6}`
    ];
  const eq2NextLowerMarcoVectorScore =
    cvssLookup_global[
      `${eqLevels.eq1}${parseInt(eqLevels.eq2) + 1}${eqLevels.eq3}${
        eqLevels.eq4
      }${eqLevels.eq5}${eqLevels.eq6}`
    ];
  const eq4NextLowerMarcoVectorScore =
    cvssLookup_global[
      `${eqLevels.eq1}${eqLevels.eq2}${eqLevels.eq3}${
        parseInt(eqLevels.eq4) + 1
      }${eqLevels.eq5}${eqLevels.eq6}`
    ];
  const eq5NextLowerMarcoVectorScore =
    cvssLookup_global[
      `${eqLevels.eq1}${eqLevels.eq2}${eqLevels.eq3}${eqLevels.eq4}${
        parseInt(eqLevels.eq5) + 1
      }${eqLevels.eq6}`
    ];

  // EQ3 and EQ6 are joint see Table 30, an if case represents an change in level constraint f.e 11 -> 21
  let eq3eq6NextLowerMarcoVector = eq3eq6CalculateLowerMacroVector(eqLevels);

  // 1.2. The severity distance of the to-be scored vector from a highest severity vector in the same MacroVector is determined
  const maxima = {
    eq1: maxComposed["eq1"][parseInt(eqLevels.eq1)],
    eq2: maxComposed["eq2"][parseInt(eqLevels.eq2)],
    eq3eq6: maxComposed["eq3"][parseInt(eqLevels.eq3)][parseInt(eqLevels.eq6)],
    eq4: maxComposed["eq4"][parseInt(eqLevels.eq4)],
    eq5: maxComposed["eq5"][parseInt(eqLevels.eq5)],
  };

  // combine all vector maximas to create all possible maximums
  const possibleMaximumVectorStrings: string[] = [];
  for (const eq1Max of maxima.eq1) {
    for (const eq2Max of maxima.eq2) {
      for (const eq3eq6Max of maxima.eq3eq6) {
        for (const eq4Max of maxima.eq4) {
          for (const eq5Max of maxima.eq5) {
            possibleMaximumVectorStrings.push(
              "CVSS:4.0/" + eq1Max + eq2Max + eq3eq6Max + eq4Max + eq5Max
            );
          }
        }
      }
    }
  }

  const eqDistance = { eq1: 0, eq2: 0, eq3eq6: 0, eq4: 0, eq5: 0 };

  outerLoop: for (let i = 0; i < possibleMaximumVectorStrings.length; i++) {
    const max = possibleMaximumVectorStrings[i];
    const maxVectorObj = util.getVectorObject(max);
    // distance of the to-be scored vector from a highest severity vector
    const severityDistance = {
      AV: 0,
      PR: 0,
      UI: 0,
      AC: 0,
      AT: 0,
      VC: 0,
      VI: 0,
      VA: 0,
      SC: 0,
      SI: 0,
      SA: 0,
      CR: 0,
      IR: 0,
      AR: 0,
    };

    innerLoop: for (let [key] of Object.entries(severityDistance)) {
      // @ts-expect-error
      severityDistance[key] =
        // @ts-expect-error
        metrics[key].numerical -
        parseMetric<Metric>(key, maxVectorObj).numerical;

      // if any of the values is negative, a greater max vector can be found
      // @ts-expect-error
      if (severityDistance[key] < 0) {
        continue outerLoop;
      }
    }

    // add the severity distance of the metric groups to calculate the serverity distance of the equivalent class
    eqDistance.eq1 =
      severityDistance.AV + severityDistance.PR + severityDistance.UI;
    eqDistance.eq2 = severityDistance.AC + severityDistance.AT;
    eqDistance.eq3eq6 =
      severityDistance.VC +
      severityDistance.VI +
      severityDistance.VA +
      severityDistance.CR +
      severityDistance.IR +
      severityDistance.AR;
    eqDistance.eq4 =
      severityDistance.SC + severityDistance.SI + severityDistance.SA;
    eqDistance.eq5 = 0;

    break;
  }

  // calculate maximal scoring difference (msd)
  const currentMacroVectorValue = cvssLookup_global[macroVector];
  const msd = {
    eq1: currentMacroVectorValue - eq1NextLowerMarcoVectorScore,
    eq2: currentMacroVectorValue - eq2NextLowerMarcoVectorScore,
    eq3eq6: currentMacroVectorValue - eq3eq6NextLowerMarcoVector,
    eq4: currentMacroVectorValue - eq4NextLowerMarcoVectorScore,
    eq5: currentMacroVectorValue - eq5NextLowerMarcoVectorScore,
  };

  const step = 0.1;
  const maxSeverityNormalized = {
    eq1: maxSeverity["eq1"][parseInt(eqLevels.eq1)] * step,
    eq2: maxSeverity["eq2"][parseInt(eqLevels.eq2)] * step,
    eq3eq6:
      maxSeverity["eq3eq6"][parseInt(eqLevels.eq3)][parseInt(eqLevels.eq6)] *
      step,
    eq4: maxSeverity["eq4"][parseInt(eqLevels.eq4)] * step,
    eq5: maxSeverity["eq5"][parseInt(eqLevels.eq5)] * step,
  };

  // 1.1.1 if there is no lower MacroVector the available distance is set to NaN and then ignored in the further calculations
  // 1.3 The proportion of the distance is determined by dividing the severity distance of the to-be-scored vector by the depth of the MacroVector
  // 1.4 The maximal scoring difference is multiplied by the proportion of distance
  let count = 0;
  if (!isNaN(msd.eq1)) {
    count++;
    msd.eq1 = msd.eq1 * (eqDistance.eq1 / maxSeverityNormalized.eq1);
  } else {
    msd.eq1 = 0;
  }
  if (!isNaN(msd.eq2)) {
    count++;
    msd.eq2 = msd.eq2 * (eqDistance.eq2 / maxSeverityNormalized.eq2);
  } else {
    msd.eq2 = 0;
  }
  if (!isNaN(msd.eq3eq6)) {
    count++;
    msd.eq3eq6 =
      msd.eq3eq6 * (eqDistance.eq3eq6 / maxSeverityNormalized.eq3eq6);
  } else {
    msd.eq3eq6 = 0;
  }
  if (!isNaN(msd.eq4)) {
    count++;
    msd.eq4 = msd.eq4 * (eqDistance.eq4 / maxSeverityNormalized.eq4);
  } else {
    msd.eq4 = 0;
  }
  if (!isNaN(msd.eq5)) {
    count++;
    msd.eq5 = 0;
  } else {
    msd.eq5 = 0;
  }

  // 2. The mean of the above computed proportional distances is computed
  let mean = 0;
  if (
    !isNaN(msd.eq1) ||
    !isNaN(msd.eq2) ||
    !isNaN(msd.eq3eq6) ||
    !isNaN(msd.eq4) ||
    !isNaN(msd.eq5)
  ) {
    mean = (msd.eq1 + msd.eq2 + msd.eq3eq6 + msd.eq4 + msd.eq5) / count;
  }

  // 3. The score of the vector is the score of the MacroVector (i.e. the score of the highest severity vector) minus the mean distance so computed.
  // This score is rounded to one decimal place.
  let vectorScore = currentMacroVectorValue - mean;
  if (vectorScore < 0) {
    vectorScore = 0.0;
  }
  if (vectorScore > 10) {
    vectorScore = 10.0;
  }
  return parseFloat(vectorScore.toFixed(1));
}

/**
 * Error function for unsupport function
 */
function getTemporalScore(vector: string) {
  throw new Error("This function is not supported for this cvss version");
  return 0;
}

/**
 * Error function for unsupport function
 */
function getEnvironmentalScore(vector: string) {
  throw new Error("This function is not supported for this cvss version");
  return 0;
}

/**
 * Error function for unsupport function
 */
function getImpactSubScore(vector: string) {
  throw new Error("This function is not supported for this cvss version");
}

/**
 * Error function for unsupport function
 */
function getExploitabilitySubScore(vector: string) {
  throw new Error("This function is not supported for this cvss version");
}

export const score = {
  getScore,
  getTemporalScore,
  getEnvironmentalScore,
  getImpactSubScore,
  getExploitabilitySubScore,
};
