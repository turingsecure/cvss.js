type CvssVectorObject = {
  AV: "N" | "A" | "L" | "P";
  AC: "L" | "H";
  PR: "N" | "L" | "H";
  UI: "N" | "R";
  S: "U" | "C";
  C: "N" | "L" | "H";
  I: "N" | "L" | "H";
  A: "N" | "L" | "H";
  E: "X" | "H" | "F" | "P" | "U";
  RL: "X" | "U" | "W" | "T" | "O";
  RC: "X" | "C" | "R" | "U";
  CR: "X" | "H" | "M" | "L";
  IR: "X" | "H" | "M" | "L";
  AR: "X" | "H" | "M" | "L";
  MAV: "X" | "N" | "A" | "L" | "P";
  MAC: "X" | "L" | "H";
  MPR: "X" | "N" | "L" | "H";
  MUI: "X" | "N" | "R";
  MS: "X" | "U" | "C";
  MC: "X" | "N" | "L" | "H";
  MI: "X" | "N" | "L" | "H";
  MA: "X" | "N" | "L" | "H";
  CVSS: string;
};

type DetailedMetric = {
  name: string;
  abbr: string;
  fullName: string;
  value: string;
  valueAbbr: string;
};

type DetailedVectorObject = { metrics: DetailedMetric[]; CVSS: string };

type metric = {
  name: string;
  abbr: string;
  numerical: number;
};

type Definition = { name: string; abbr: string; metrics: metric[] };

type CvssVersionDefinition = {
  version: string;
  definitions: Definition[];
};

const definitions: CvssVersionDefinition = require("./cvss_3_0.json");

/**
 * Finds the vector's metric by it's abbreviation
 *
 * @param {string} abbr Abbreviation of the vector metric
 *
 * @returns {Definition} Definition of the vector metric matching the abbreviation
 */
const findMetric = function (abbr: string) {
  return definitions.definitions.find((def) => def.abbr === abbr);
};

/**
 * Finds the vector's value for a specific metric
 *
 * @param {string} abbr Abbreviation of the vector metric
 * @param {CvssVectorObject} vectorObject Vector object of interested
 *
 * @returns {metric | undefined} The metric matching to the given abbriviation or undefined if no match is found
 */
const findMetricValue = function (abbr: string, vectorObject: CvssVectorObject) {
  const definition = findMetric(abbr);
  const value = definition.metrics.find((metric) => metric.abbr === vectorObject[definition.abbr]);

  return value;
};

/**
 * @param {number} num The number to round
 * @param {number} precision The number of decimal places to preserve
 *
 * @returns {number} The rounded number
 */
function roundUpApprox(num: number, precision: number) {
  precision = Math.pow(10, precision);
  return Math.ceil(num * precision) / precision;
}

/**
 * @param {number} num The number to round
 *
 * @returns {number} The rounded number
 */
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
 *
 * @param {string} vector The vector string
 *
 * @returns {CvssVectorObject} Abbreviations & Vector Value pair
 */
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

/**
 * Returns a vector without undefined values
 *
 * @param {string} vector Vector with undefined values
 *
 * @returns {string} Vector without undefined values
 */
function getCleanVectorString(vector: string) {
  const vectorArray = vector.split("/");
  const cleanVectorArray = [];
  for (const entry of vectorArray) {
    const values = entry.split(":");
    if (values[1] !== "X") cleanVectorArray.push(entry);
  }

  return cleanVectorArray.join("/");
}

/**
 * Retrieves an object of vector's metrics
 *
 * @param {string} vector
 *
 * @returns {DetailedVectorObject} Abbreviations & Vectors Detailed Values
 */
function getDetailedVectorObject(vector: string) {
  const vectorArray = vector.split("/");
  const vectorObject = vectorArray.reduce(
    (vectorObjectAccumulator, vectorItem, index) => {
      const values = vectorItem.split(":");
      const metrics = { ...vectorObjectAccumulator.metrics };
      if (index) {
        const vectorDef = findMetric(values[0]);
        const detailedVectorObject = {
          name: vectorDef.name,
          abbr: vectorDef.abbr,
          fullName: `${vectorDef.name} (${vectorDef.abbr})`,
          value: vectorDef.metrics.find((def) => def.abbr === values[1]).name,
          valueAbbr: values[1]
        };
        return Object.assign(vectorObjectAccumulator, {
          metrics: Object.assign(metrics, {
            [values[0].trim()]: detailedVectorObject
          })
        });
      } else {
        return Object.assign(vectorObjectAccumulator, {
          [values[0].trim()]: values[1]
        });
      }
    },
    { metrics: {}, CVSS: "" } as DetailedVectorObject
  );
  return vectorObject;
}

/**
 * Calculates the rating of the given vector
 *
 * @param {number} Score calculated score from getScore() in cvss.js
 *
 * @returns {string} returns one of the five possible ratings
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
 *
 * @param {String} vector
 *
 * @returns {Boolean} result with whether the vector is valid or not
 */
const isVectorValid = function (vector) {
  /**
   * This function is used to scan the definitions file and join all
   * abbreviations in a format that RegExp understands.
   *
   * Exit example:
   * ((((((((((AV:[NALP]|AC:[LH])|PR:[NLH])|UI:[NR])|S:[UC])|C:[NLW])|I:[NLW])|A:[NLW])|E:[XUPFH])|RL:[XOTWU])|RC:[XURC])
   */
  const expression = definitions.definitions.reduce((accumulator, currentValue, index) => {
    const serializedAbbr = `${currentValue.abbr}:[${currentValue.metrics.reduce(
      (accumulator2, currentValue2) => {
        return accumulator2 + currentValue2.abbr;
      },
      ""
    )}]`;
    if (index !== 0) {
      return `(${accumulator}|${serializedAbbr})`;
    } else {
      return serializedAbbr;
    }
  }, "");

  const totalExpressionVector = new RegExp("^CVSS:3.(0|1)(/" + expression + ")+$");

  //Checks if the vector is in valid format
  if (!totalExpressionVector.test(vector)) {
    return false;
  }

  /**
   * Scans the definitions file and returns an array of each registered abbreviation
   * with its possible values.
   *
   * Exit example:
   * [/\/AV:[NALP]/g, /\/AC:[LH]/g, /\/PR:[NLH]/g, /\/UI:[NR]/g, /\/S:[UC]/g,]
   *
   * A / at the beginning serves for the algorithm not to confuse abbreviations as AC and C.
   */
  const allExpressions = definitions.definitions.map((currentValue) => {
    return new RegExp(
      `/${currentValue.abbr}:[${currentValue.metrics.reduce((accumulator2, currentValue2) => {
        return accumulator2 + currentValue2.abbr;
      }, "")}]`,
      "g"
    );
  });

  for (const regex of allExpressions) {
    if ((vector.match(regex) || []).length > 1) {
      return false;
    }
  }

  const mandatoryParams = [
    /\/AV:[NALP]/g,
    /\/AC:[LH]/g,
    /\/PR:[NLH]/g,
    /\/UI:[NR]/g,
    /\/S:[UC]/g,
    /\/C:[NLH]/g,
    /\/I:[NLH]/g,
    /\/A:[NLH]/g
  ];

  //Checks whether all mandatory parameters are present in the vector
  for (const regex of mandatoryParams) {
    if ((vector.match(regex) || []).length < 1) {
      return false;
    }
  }

  return true;
};

/**
 * This transforms an object in the format of getVectorObject()
 * and parses it to a CVSS comaptible string
 *
 * @param {CvssVectorObject} obj
 */
function parseVectorObjectToString(obj: CvssVectorObject) {
  if (typeof obj === "string") {
    return obj;
  }

  let vectorString = `CVSS:${obj["CVSS"]}/`;

  for (const entry of definitions["definitions"]) {
    const metric = entry["abbr"];
    if (Object.prototype.hasOwnProperty.call(obj, metric)) {
      vectorString += `${metric}:${obj[metric]}/`;
    }
  }

  vectorString = vectorString.slice(0, -1);

  return vectorString;
}

/**
 * Retrives the version from the vector string
 *
 * @param {string} vector
 * @param {string} metric
 * @param {string} value
 *
 * @return {string}
 */
function updateVectorValue(vector: string, metric: string, value: string) {
  const vectorObject = getVectorObject(vector);
  vectorObject[metric] = value;

  const vectorString = parseVectorObjectToString(vectorObject);

  return getCleanVectorString(vectorString);
}

/**
 * Retrives the version from the vector string
 *
 * @return {string} returns the version number
 */
function getVersion(vector: string) {
  const version = vector.split("/");
  if (version[0] === "CVSS:3.0") {
    return "3.0";
  } else if (version[0] === "CVSS:3.1") {
    return "3.1";
  } else {
    return "Error";
  }
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
  getCleanVectorString
};
