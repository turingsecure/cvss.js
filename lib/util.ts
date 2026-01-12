import { CvssVectorObject, CvssVersionDefinition, DetailedVectorObject, MetricUnion } from "./types";
import { definitions as definitions3_0, metricMap as metricMap3_0, metricValueMap as metricValueMap3_0 } from "./cvss_3_0";
import { definitions as definitions4_0, metricMap as metricMap4_0, metricValueMap as metricValueMap4_0 } from "./cvss_4_0";

// Pre-compiled regex patterns for validation (built once at module load)
function buildValidationRegex(defs: CvssVersionDefinition) {
  const expression = defs.definitions.reduce(
    (acc, def, index) => {
      const serializedAbbr = `${def.abbr}:[${def.metrics.map(m => m.abbr).join("")}]`;
      return index !== 0 ? `(${acc}|${serializedAbbr})` : serializedAbbr;
    },
    ""
  );

  return {
    main: new RegExp(`^CVSS:(3\\.(0|1)|4\\.0)(/${expression})+$`),
    duplicateChecks: defs.definitions.map(def =>
      new RegExp(`/${def.abbr}:[${def.metrics.map(m => m.abbr).join("")}]`, "g")
    ),
    mandatoryChecks: defs.definitions
      .filter(def => def.mandatory)
      .map(def => new RegExp(`/${def.abbr}:[${def.metrics.map(m => m.abbr).join("")}]`, "g")),
  };
}

const regexCache3x = buildValidationRegex(definitions3_0);
const regexCache4x = buildValidationRegex(definitions4_0);

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
  const vectorArray = vector.split("/");
  const definitions = vector.includes("4.0") ? definitions4_0 : definitions3_0;
  const vectorObject = definitions.definitions
    .map((definition) => definition.abbr)
    .reduce((acc, curr) => {
      // @ts-expect-error
      acc[curr] = "X";
      return acc;
    }, {} as CvssVectorObject);

  for (const entry of vectorArray) {
    const values = entry.split(":");
    // @ts-expect-error
    vectorObject[values[0]] = values[1];
  }
  return vectorObject;
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
 * Retrieves an object of vector's metrics
 */
function getDetailedVectorObject(vector: string) {
  const vectorArray = vector.split("/");
  const vectorObject = vectorArray.reduce(
    (vectorObjectAccumulator, vectorItem, index) => {
      const values = vectorItem.split(":");
      const metrics = { ...vectorObjectAccumulator.metrics };
      if (index) {
        const vectorDef = findMetric(values[0], vectorArray[0].split(":")[1]);
        const detailedVectorObject = {
          name: vectorDef?.name,
          abbr: vectorDef?.abbr,
          fullName: `${vectorDef?.name} (${vectorDef?.abbr})`,
          value: vectorDef?.metrics.find((def) => def.abbr === values[1])?.name,
          valueAbbr: values[1],
        };
        return Object.assign(vectorObjectAccumulator, {
          metrics: Object.assign(metrics, {
            [values[0].trim()]: detailedVectorObject,
          }),
        });
      } else {
        return Object.assign(vectorObjectAccumulator, {
          [values[0].trim()]: values[1],
        });
      }
    },
    { metrics: {}, CVSS: "" } as DetailedVectorObject
  );
  return vectorObject;
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

  const cache = version === "4.0" ? regexCache4x : regexCache3x;

  if (!cache.main.test(vector)) return false;

  for (const regex of cache.duplicateChecks) {
    if ((vector.match(regex) || []).length > 1) return false;
  }

  for (const regex of cache.mandatoryChecks) {
    if ((vector.match(regex) || []).length < 1) return false;
  }

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
