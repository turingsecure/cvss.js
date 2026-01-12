import { CvssVectorObject, CvssVersionDefinition, DetailedVectorObject, MetricUnion } from "./types";
import { definitions as definitions3_0, metricMap as metricMap3_0, metricValueMap as metricValueMap3_0 } from "./cvss_3_0";
import { definitions as definitions4_0, metricMap as metricMap4_0, metricValueMap as metricValueMap4_0 } from "./cvss_4_0";

function buildValidationData(defs: CvssVersionDefinition) {
  const mandatoryMetrics = new Set<string>();
  for (const def of defs.definitions) {
    if (def.mandatory) {
      mandatoryMetrics.add(def.abbr);
    }
  }
  return { mandatoryMetrics };
}

const validationData3x = buildValidationData(definitions3_0);
const validationData4x = buildValidationData(definitions4_0);

const defaultVectorObject3x: Record<string, string> = { CVSS: "3.0" };
const defaultVectorObject4x: Record<string, string> = { CVSS: "4.0" };

for (const def of definitions3_0.definitions) {
  defaultVectorObject3x[def.abbr] = "X";
}
for (const def of definitions4_0.definitions) {
  defaultVectorObject4x[def.abbr] = "X";
}

/**
 * Finds the vector's metric by it's abbreviation
 */
function findMetric(abbr: string, cvssVersion: string) {
  return cvssVersion === "4.0" ? metricMap4_0[abbr] : metricMap3_0[abbr];
}

/**
 * Finds the vector's value for a specific metric
 */
function findMetricValue<T extends MetricUnion>(
  abbr: string,
  vectorObject: CvssVectorObject
) {
  const valueMap = vectorObject.CVSS === "4.0" ? metricValueMap4_0 : metricValueMap3_0;
  const valueAbbr = vectorObject[abbr as keyof CvssVectorObject];
  return valueMap[abbr]?.[valueAbbr as string] as T;
}

function roundUpApprox(num: number, precision: number) {
  precision = Math.pow(10, precision);
  return Math.ceil(num * precision) / precision;
}

function roundUpExact(num: number) {
  const int_input = Math.round(num * 100000);

  if (int_input % 10000 === 0) {
    return int_input / 100000;
  } else {
    return (Math.floor(int_input / 10000) + 1) / 10;
  }
}

/**
 * Retrieves an object of vector's metrics
 */
function getVectorObject(vector: string) {
  const is4x = vector.includes("4.0");
  const vectorObject = is4x
    ? { ...defaultVectorObject4x }
    : { ...defaultVectorObject3x };

  const vectorArray = vector.split("/");
  for (const entry of vectorArray) {
    const colonPos = entry.indexOf(":");
    if (colonPos > 0) {
      vectorObject[entry.slice(0, colonPos)] = entry.slice(colonPos + 1);
    }
  }

  return vectorObject as CvssVectorObject;
}

/**
 * Returns a vector without undefined values
 */
function getCleanVectorString(vector: string) {
  const vectorArray = vector.split("/");
  const cleanVectorArray: string[] = [];
  for (const entry of vectorArray) {
    const values = entry.split(":");
    if (values[1] !== "X") cleanVectorArray.push(entry);
  }

  return cleanVectorArray.join("/");
}

/**
 * Retrieves an object of vector's metrics with detailed information
 */
function getDetailedVectorObject(vector: string) {
  const vectorArray = vector.split("/");
  const result: DetailedVectorObject = { metrics: {}, CVSS: "" };

  const versionPart = vectorArray[0];
  const colonPos = versionPart.indexOf(":");
  const cvssVersion = versionPart.slice(colonPos + 1);
  result.CVSS = cvssVersion;

  const valueMap = cvssVersion === "4.0" ? metricValueMap4_0 : metricValueMap3_0;

  for (let i = 1; i < vectorArray.length; i++) {
    const item = vectorArray[i];
    const itemColonPos = item.indexOf(":");
    const metricAbbr = item.slice(0, itemColonPos);
    const valueAbbr = item.slice(itemColonPos + 1);

    const vectorDef = findMetric(metricAbbr, cvssVersion);
    if (vectorDef) {
      const metricValue = valueMap[metricAbbr]?.[valueAbbr];

      result.metrics[metricAbbr] = {
        name: vectorDef.name,
        abbr: vectorDef.abbr,
        fullName: `${vectorDef.name} (${vectorDef.abbr})`,
        value: metricValue?.name,
        valueAbbr: valueAbbr,
      };
    }
  }

  return result;
}

/**
 * Calculates the rating of the given vector
 */
function getRating(score: number) {
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
 * Checks whether the vector passed is valid
 */
function isVectorValid(vector: string) {
  const version = getVersion(vector);
  if (version === "Error") return false;

  const is4x = version === "4.0";
  const metricMap = is4x ? metricMap4_0 : metricMap3_0;
  const metricValueMap = is4x ? metricValueMap4_0 : metricValueMap3_0;
  const { mandatoryMetrics } = is4x ? validationData4x : validationData3x;

  const parts = vector.split("/");

  // First part must be the version (already validated by getVersion)
  if (parts.length < 2) return false;

  const seenMetrics = new Set<string>();
  const foundMandatory = new Set<string>();

  // Validate each metric (skip the version prefix at index 0)
  for (let i = 1; i < parts.length; i++) {
    const part = parts[i];
    const colonPos = part.indexOf(":");
    if (colonPos <= 0) return false;

    const metricAbbr = part.slice(0, colonPos);
    const valueAbbr = part.slice(colonPos + 1);

    // Check if metric exists
    if (!metricMap[metricAbbr]) return false;

    // Check if value is valid for this metric
    if (!metricValueMap[metricAbbr]?.[valueAbbr]) return false;

    // Check for duplicates
    if (seenMetrics.has(metricAbbr)) return false;
    seenMetrics.add(metricAbbr);

    // Track mandatory metrics
    if (mandatoryMetrics.has(metricAbbr)) {
      foundMandatory.add(metricAbbr);
    }
  }

  // Check all mandatory metrics are present
  if (foundMandatory.size !== mandatoryMetrics.size) return false;

  return true;
}

/**
 * This transforms an object in the format of getVectorObject()
 * and parses it to a CVSS comaptible string
 */
function parseVectorObjectToString(cvssInput: string | CvssVectorObject) {
  if (typeof cvssInput === "string") {
    return cvssInput;
  }

  let vectorString = `CVSS:${cvssInput["CVSS"]}/`;

  const definitions =
    cvssInput.CVSS === "4.0" ? definitions4_0 : definitions3_0;
  for (const entry of definitions["definitions"]) {
    const metric = entry.abbr;
    if (Object.prototype.hasOwnProperty.call(cvssInput, metric)) {
      vectorString += `${metric}:${cvssInput[metric]}/`;
    }
  }

  vectorString = vectorString.slice(0, -1);

  return vectorString;
}

/**
 * Updates the value of a singular metric and returns the updated clean vector string
 */
function updateVectorValue(
  vector: string,
  metric: keyof CvssVectorObject,
  value: string
) {
  const vectorObject = getVectorObject(vector);
  // @ts-expect-error
  vectorObject[metric] = value;

  const vectorString = parseVectorObjectToString(vectorObject);

  return getCleanVectorString(vectorString);
}

/**
 * Retrives the version from the vector string
 */
function getVersion(vector: string) {
  if (vector.startsWith("CVSS:3.0/")) return "3.0";
  if (vector.startsWith("CVSS:3.1/")) return "3.1";
  if (vector.startsWith("CVSS:4.0/")) return "4.0";
  return "Error";
}

export const util = {
  roundUpExact,
  roundUpApprox,
  getVectorObject,
  getDetailedVectorObject,
  findMetric,
  findMetricValue,
  getRating,
  updateVectorValue,
  isVectorValid,
  parseVectorObjectToString,
  getVersion,
  getCleanVectorString,
};
