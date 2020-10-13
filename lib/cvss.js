const definitions = require("./cvss_3_0.json");
const { roundUp } = require("./util");

/**
 * Creates a new CVSS object
 *
 * @param {String} vector
 */
function CVSS(vector) {
  /**
   * Retrieves an object of vector's metrics
   *
   * @returns {Object} Abbreviations & Vector Value pair
   */
  function getVectorObject() {
    const vectorArray = vector.split("/");
    const vectorObject = {};
    definitions.definitions.forEach(definition => vectorObject[definition["abbr"]] = "X");

    for (const entry of vectorArray) {
      const values = entry.split(":");
      vectorObject[values[0]] = values[1];
    }
    return vectorObject;
  }

  /**
   * Retrieves an object of vector's metrics
   *
   * @returns {Object} Abbreviations & Vectors Detailed Values
   */
  function getDetailedVectorObject() {
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
      return roundUp(Math.min(1.08 * (ISC + exploitability), 10), 1);
    }

    return roundUp(Math.min(ISC + exploitability, 10), 1);
  }

  /**
   * Parses the vector to a rating
   *
   * @returns {String} Rating value
   */
  function getRating() {
    const score = getScore();
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
   * Parses the vector to the temporal score
   *
   * @returns {Number} Temporal  Score
   */
  function getTemporalScore() {
    const vectorObject = getVectorObject();

    const baseScore = getScore();

    const eMetric = findMetricValue("E", vectorObject);
    const exploitCodeMaturity = eMetric ? eMetric.numerical : 1;
    const rMetric = findMetricValue("RL", vectorObject);
    const remediationLevel = rMetric ? rMetric.numerical : 1;
    const rcMetric = findMetricValue("RC", vectorObject);
    const reportConfidence = rcMetric ? rcMetric.numerical : 1;

    return roundUp(baseScore * exploitCodeMaturity * remediationLevel * reportConfidence, 1);
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

    const e = findMetricValue("E", vectorObject);
    const rl = findMetricValue("RL", vectorObject);
    const rc = findMetricValue("RC", vectorObject);
    const eValue = e ? e.numerical : 1;
    const rlValue = rl ? rl.numerical : 1;
    const rcValue = rc ? rc.numerical : 1;

    if (!scopeChanged) {
      return roundUp(
        roundUp(Math.min(modifiedISC + modifiedExploitability, 10), 1) * eValue * rlValue * rcValue,
        1
      );
    }
    return roundUp(
      roundUp(Math.min(1.08 * (modifiedISC + modifiedExploitability), 10), 1) *
        eValue *
        rlValue *
        rcValue,
      1
    );
  }

  const calculateISCBase = function (vectorObject) {
    const cValue = findMetricValue("C", vectorObject).numerical;
    const iValue = findMetricValue("I", vectorObject).numerical;
    const aValue = findMetricValue("A", vectorObject).numerical;

    return 1 - (1 - cValue) * (1 - iValue) * (1 - aValue);
  };

  const calculateISC = function (iscBase, scopeChanged) {
    if (!scopeChanged) return 6.42 * iscBase;

    return 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
  };

  function calculateISCModifiedBase(vectorObject) {
    let mcValue = findMetricValue("MC", vectorObject);
    let miValue = findMetricValue("MI", vectorObject);
    let maValue = findMetricValue("MA", vectorObject);
    const crValue = findMetricValue("CR", vectorObject).numerical;
    const irValue = findMetricValue("IR", vectorObject).numerical;
    const arValue = findMetricValue("AR", vectorObject).numerical;

    if (!mcValue || mcValue.abbr === "X") mcValue = findMetricValue("C", vectorObject);
    if (!miValue || miValue.abbr === "X") miValue = findMetricValue("I", vectorObject);
    if (!maValue || maValue.abbr === "X") maValue = findMetricValue("A", vectorObject);

    return Math.min(
      1 -
        (1 - mcValue.numerical * crValue) *
          (1 - miValue.numerical * irValue) *
          (1 - maValue.numerical * arValue),
      0.915
    );
  }

  const calculateExploitability = function (vectorObject, scopeChanged) {
    const avValue = findMetricValue("AV", vectorObject).numerical;
    const acValue = findMetricValue("AC", vectorObject).numerical;
    const prMetrics = findMetricValue("PR", vectorObject).numerical;
    const uiValue = findMetricValue("UI", vectorObject).numerical;

    const prValue = scopeChanged ? prMetrics.changed : prMetrics.unchanged;

    return 8.22 * avValue * acValue * prValue * uiValue;
  };

  const calculateModifiedExploitability = function (vectorObject, scopeChanged) {
    let mavValue = findMetricValue("MAV", vectorObject);
    let macValue = findMetricValue("MAC", vectorObject);
    let mprMetrics = findMetricValue("MPR", vectorObject);
    let muiValue = findMetricValue("MUI", vectorObject);

    if (!mavValue || mavValue.abbr === "X") mavValue = findMetricValue("AV", vectorObject);
    if (!macValue || macValue.abbr === "X") macValue = findMetricValue("AC", vectorObject);
    if (!mprMetrics || mprMetrics.abbr === "X") mprMetrics = findMetricValue("PR", vectorObject);
    if (!muiValue || muiValue.abbr === "X") muiValue = findMetricValue("UI", vectorObject);

    const mprValue = scopeChanged ? mprMetrics.numerical.changed : mprMetrics.numerical.unchanged;

    return 8.22 * mavValue.numerical * macValue.numerical * mprValue * muiValue.numerical;
  };

  const findMetric = function (abbr) {
    return definitions.definitions.find((def) => def.abbr === abbr);
  };

  const findMetricValue = function (abbr, vectorObject) {
    const definition = findMetric(abbr);
    const value = definition.metrics.find(
      (metric) => metric.abbr === vectorObject[definition.abbr]
    );

    return value;
  };

  /**
   * Checks whether the vector passed is valid
   *
   * @returns {Boolean} result with whether the vector is valid or not
   */
  const isVectorValid = function () {
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
