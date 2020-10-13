const definitions = require("./cvss_3_0.json");

/**
 * Finds the vector's metric by it's abbreviation
 *
 * @param {String} abbr
 */
const findMetric = function (abbr) {
  return definitions.definitions.find((def) => def.abbr === abbr);
};

/**
 * Finds the vector's value for a specific metric
 *
 * @param {String} abbr
 * @param {Object} vectorObject
 */
const findMetricValue = function (abbr, vectorObject) {
  const definition = findMetric(abbr);
  const value = definition.metrics.find((metric) => metric.abbr === vectorObject[definition.abbr]);

  return value;
};

/**
 * @param {Number} num The number to round
 * @param {Number} precision The number of decimal places to preserve
 *
 * @return The rounded number
 */
function roundUp(num, precision) {
  precision = Math.pow(10, precision);
  return Math.ceil(num * precision) / precision;
}

/**
 * Retrieves an object of vector's metrics
 *
 * @param {String} vector
 * @returns {Object} Abbreviations & Vector Value pair
 */
function getVectorObject(vector) {
  const vectorArray = vector.split("/");
  const vectorObject = {};
  definitions.definitions.forEach((definition) => (vectorObject[definition["abbr"]] = "X"));

  for (const entry of vectorArray) {
    const values = entry.split(":");
    vectorObject[values[0]] = values[1];
  }
  return vectorObject;
}

/**
 * Retrieves an object of vector's metrics
 *
 * @param {String} vector
 * @returns {Object} Abbreviations & Vectors Detailed Values
 */
function getDetailedVectorObject(vector) {
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
          metrics: Object.assign(metrics, { [values[0].trim()]: detailedVectorObject })
        });
      } else {
        return Object.assign(vectorObjectAccumulator, { [values[0].trim()]: values[1] });
      }
    },
    { metrics: {} }
  );
  return vectorObject;
}

/**
 * Calculates the rating of the given vector
 *
 * @param Score calculated score from getScore() in cvss.js
 * @returns {String} returns one of the five possible ratings
 */
function getRating(score) {
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

  const totalExpressionVector = new RegExp("^CVSS:3.0(/" + expression + ")+$");

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
 * @param {Object} obj
 */
function parseVectorObjectToString(obj) {
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

module.exports = {
  roundUp,
  getVectorObject,
  getDetailedVectorObject,
  findMetric,
  findMetricValue,
  getRating,
  isVectorValid,
  parseVectorObjectToString
};
