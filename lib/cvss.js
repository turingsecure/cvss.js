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
    const vectorObject =  vectorArray.reduce((vectorObjectAccumulator , vectorItem, index) => {
      const values = vectorItem.split(":");
      const metrics = {...vectorObjectAccumulator.metrics};
      if(index){
        const vectorDef = findMetric(values[0]);
        const detailedVectorObject = {
          name: vectorDef.name,
          abbr: vectorDef.abbr,
          fullName: `${vectorDef.name} (${vectorDef.abbr})`,
          value: vectorDef.metrics.find(def => def.abbr === values[1]).name,
          valueAbbr: values[1]
        };
        return Object.assign(vectorObjectAccumulator , { metrics: Object.assign(metrics, { [values[0].trim()]: detailedVectorObject })});
      } else {
        return Object.assign(vectorObjectAccumulator , { [values[0].trim()]: values[1] });
      }
    }, { metrics: {} });
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
   * Parses the vector to a number score
   *
   * @returns {Number} Temporal  Score
   */
  function getTemporalScore() {
    const vectorObject = getVectorObject();

    const score = getScore();

    const eDef = findMetric("E");
    const rlDef = findMetric("RL");
    const rcDef = findMetric("RC");

    const exploitCodeMaturity = eDef.metrics.find(
      (metric) => metric.abbr === (vectorObject.E ? vectorObject.E : "X")
    ).numerical;
    const remediationLevel = rlDef.metrics.find(
      (metric) => metric.abbr === (vectorObject.RL ? vectorObject.RL : "X")
    ).numerical;
    const reportConfidence = rcDef.metrics.find(
      (metric) => metric.abbr === (vectorObject.RC ? vectorObject.RC : "X")
    ).numerical;

    return roundUp(score * exploitCodeMaturity * remediationLevel * reportConfidence, 1);
  }

  const calculateISCBase = function (vectorObject) {
    const cDef = findMetric("C");
    const iDef = findMetric("I");
    const aDef = findMetric("A");

    const cValue = cDef.metrics.find((metric) => metric.abbr === vectorObject.C).numerical;
    const iValue = iDef.metrics.find((metric) => metric.abbr === vectorObject.I).numerical;
    const aValue = aDef.metrics.find((metric) => metric.abbr === vectorObject.A).numerical;

    return 1 - (1 - cValue) * (1 - iValue) * (1 - aValue);
  };

  const calculateISC = function (iscBase, scopeChanged) {
    if (!scopeChanged) return 6.42 * iscBase;

    return 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
  };

  const calculateExploitability = function (vectorObject, scopeChanged) {
    const avDef = findMetric("AV");
    const acDef = findMetric("AC");
    const prDef = findMetric("PR");
    const uiDef = findMetric("UI");

    const avValue = avDef.metrics.find((metric) => metric.abbr === vectorObject.AV).numerical;
    const acValue = acDef.metrics.find((metric) => metric.abbr === vectorObject.AC).numerical;
    const uiValue = uiDef.metrics.find((metric) => metric.abbr === vectorObject.UI).numerical;

    const prMetrics = prDef.metrics.find((metric) => metric.abbr === vectorObject.PR).numerical;
    const prValue = scopeChanged ? prMetrics.changed : prMetrics.unchanged;

    return 8.22 * avValue * acValue * prValue * uiValue;
  };

  const findMetric = function (abbr) {
    return definitions.definitions.find((def) => def.abbr === abbr);
  };

  /**
   * Checks whether the vector passed is valid
   *
   * @returns {{message: string, isValid: boolean}} object with "message" and "isValid"
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
      const serializedAbbr = `${currentValue.abbr}:[${currentValue.metrics.reduce((accumulator2, currentValue2) => {
        return accumulator2 + currentValue2.abbr;
      }, "")}]`;
      if (index !== 0) {
        return `(${accumulator }|${serializedAbbr})`;
      } else {
        return serializedAbbr;
      }
    }, "");

    // eslint-disable-next-line
    const totalExpressionVector = new RegExp("^CVSS:3\.0(\/" + expression + ")+$");

    //Checks if the vector is in valid format
    if(!totalExpressionVector.test(vector)){
      return {
        message: "The vector is not in the correct format",
        isValid: false
      };
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
    const allExpressions = definitions.definitions.map(currentValue => {
      return new RegExp(`/${currentValue.abbr}:[${currentValue.metrics.reduce((accumulator2, currentValue2) => {
        return accumulator2 + currentValue2.abbr;
      }, "")}]`, "g");
    });

    for(const regex of allExpressions) {
      if((vector.match(regex) || []).length > 1) {
        return {
          message: "Each parameter can only be passed once",
          isValid: false
        };
      }
    }

    const mandatoryParams = [/AV:[NALP]/g, /AC:[LH]/g, /PR:[NLH]/g, /UI:[NR]/g, /S:[UC]/g, /C:[NLH]/g, /I:[NLH]/g, /A:[NLH]/g];

    //Checks whether all mandatory parameters are present in the vector
    for (const regex of mandatoryParams) {
      if((vector.match(regex) || []).length < 1) {
        return {
          message: "Pass all mandatory parameters",
          isValid: false
        };
      }
    }

    return {
      message: "This vector is valid",
      isValid: true
    };
  };

  return { vector, getScore, getRating, getVectorObject, getDetailedVectorObject, getTemporalScore, isVectorValid };
}

module.exports = CVSS;
