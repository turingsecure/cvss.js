var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var definitions = require("./cvss_3_0.json");
/**
 * Finds the vector's metric by it's abbreviation
 *
 * @param {string} abbr Abbreviation of the vector metric
 *
 * @returns {definition} Definition of the vector metric matching the abbreviation
 */
var findMetric = function (abbr) {
    return definitions.definitions.find(function (def) { return def.abbr === abbr; });
};
/**
 * Finds the vector's value for a specific metric
 *
 * @param {string} abbr Abbreviation of the vector metric
 * @param {cvssVectorObject} vectorObject Vector object of interested
 *
 * @returns {metric | undefined} The metric matching to the given abbriviation or undefined if no match is found
 */
var findMetricValue = function (abbr, vectorObject) {
    var definition = findMetric(abbr);
    var value = definition.metrics.find(function (metric) { return metric.abbr === vectorObject[definition.abbr]; });
    return value;
};
/**
 * @param {number} num The number to round
 * @param {number} precision The number of decimal places to preserve
 *
 * @returns {number} The rounded number
 */
function roundUpApprox(num, precision) {
    precision = Math.pow(10, precision);
    return Math.ceil(num * precision) / precision;
}
/**
 * @param {number} num The number to round
 *
 * @returns {number} The rounded number
 */
function roundUpExact(num) {
    var int_input = Math.round(num * 100000);
    if (int_input % 10000 === 0) {
        return int_input / 100000;
    }
    else {
        return (Math.floor(int_input / 10000) + 1) / 10;
    }
}
/**
 * Retrieves an object of vector's metrics
 *
 * @param {string} vector The vector string
 *
 * @returns {obejct} Abbreviations & Vector Value pair
 */
function getVectorObject(vector) {
    var vectorArray = vector.split("/");
    var vectorObject = {};
    definitions.definitions.forEach(function (definition) { return (vectorObject[definition["abbr"]] = "X"); });
    for (var _i = 0, vectorArray_1 = vectorArray; _i < vectorArray_1.length; _i++) {
        var entry = vectorArray_1[_i];
        var values = entry.split(":");
        vectorObject[values[0]] = values[1];
    }
    return vectorObject;
}
/**
 * Returns a vector without undefined values
 *
 * @param {String} vector
 * @returns {String} Vector without undefined values
 */
function getCleanVectorString(vector) {
    var vectorArray = vector.split("/");
    var cleanVectorArray = [];
    for (var _i = 0, vectorArray_2 = vectorArray; _i < vectorArray_2.length; _i++) {
        var entry = vectorArray_2[_i];
        var values = entry.split(":");
        if (values[1] !== "X")
            cleanVectorArray.push(entry);
    }
    return cleanVectorArray.join("/");
}
/**
 * Retrieves an object of vector's metrics
 *
 * @param {String} vector
 * @returns {Object} Abbreviations & Vectors Detailed Values
 */
function getDetailedVectorObject(vector) {
    var vectorArray = vector.split("/");
    var vectorObject = vectorArray.reduce(function (vectorObjectAccumulator, vectorItem, index) {
        var _a, _b;
        var values = vectorItem.split(":");
        var metrics = __assign({}, vectorObjectAccumulator.metrics);
        if (index) {
            var vectorDef = findMetric(values[0]);
            var detailedVectorObject = {
                name: vectorDef.name,
                abbr: vectorDef.abbr,
                fullName: vectorDef.name + " (" + vectorDef.abbr + ")",
                value: vectorDef.metrics.find(function (def) { return def.abbr === values[1]; }).name,
                valueAbbr: values[1]
            };
            return Object.assign(vectorObjectAccumulator, {
                metrics: Object.assign(metrics, (_a = {},
                    _a[values[0].trim()] = detailedVectorObject,
                    _a))
            });
        }
        else {
            return Object.assign(vectorObjectAccumulator, (_b = {},
                _b[values[0].trim()] = values[1],
                _b));
        }
    }, { metrics: {} });
    return vectorObject;
}
/**
 * Calculates the rating of the given vector
 *
 * @param Score calculated score from getScore() in cvss.js
 * @returns {String} returns one of the five possible ratings
 */
function getRating(score) {
    var rating = "None";
    if (score === 0) {
        rating = "None";
    }
    else if (score <= 3.9) {
        rating = "Low";
    }
    else if (score <= 6.9) {
        rating = "Medium";
    }
    else if (score <= 8.9) {
        rating = "High";
    }
    else {
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
var isVectorValid = function (vector) {
    /**
     * This function is used to scan the definitions file and join all
     * abbreviations in a format that RegExp understands.
     *
     * Exit example:
     * ((((((((((AV:[NALP]|AC:[LH])|PR:[NLH])|UI:[NR])|S:[UC])|C:[NLW])|I:[NLW])|A:[NLW])|E:[XUPFH])|RL:[XOTWU])|RC:[XURC])
     */
    var expression = definitions.definitions.reduce(function (accumulator, currentValue, index) {
        var serializedAbbr = currentValue.abbr + ":[" + currentValue.metrics.reduce(function (accumulator2, currentValue2) {
            return accumulator2 + currentValue2.abbr;
        }, "") + "]";
        if (index !== 0) {
            return "(" + accumulator + "|" + serializedAbbr + ")";
        }
        else {
            return serializedAbbr;
        }
    }, "");
    var totalExpressionVector = new RegExp("^CVSS:3.(0|1)(/" + expression + ")+$");
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
    var allExpressions = definitions.definitions.map(function (currentValue) {
        return new RegExp("/" + currentValue.abbr + ":[" + currentValue.metrics.reduce(function (accumulator2, currentValue2) {
            return accumulator2 + currentValue2.abbr;
        }, "") + "]", "g");
    });
    for (var _i = 0, allExpressions_1 = allExpressions; _i < allExpressions_1.length; _i++) {
        var regex = allExpressions_1[_i];
        if ((vector.match(regex) || []).length > 1) {
            return false;
        }
    }
    var mandatoryParams = [
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
    for (var _a = 0, mandatoryParams_1 = mandatoryParams; _a < mandatoryParams_1.length; _a++) {
        var regex = mandatoryParams_1[_a];
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
    var vectorString = "CVSS:" + obj["CVSS"] + "/";
    for (var _i = 0, _a = definitions["definitions"]; _i < _a.length; _i++) {
        var entry = _a[_i];
        var metric = entry["abbr"];
        if (Object.prototype.hasOwnProperty.call(obj, metric)) {
            vectorString += metric + ":" + obj[metric] + "/";
        }
    }
    vectorString = vectorString.slice(0, -1);
    return vectorString;
}
function updateVectorValue(vector, metric, value) {
    var vectorObject = getVectorObject(vector);
    vectorObject[metric] = value;
    var vectorString = parseVectorObjectToString(vectorObject);
    return getCleanVectorString(vectorString);
}
/**
 * Retrives the version from the vector string
 *
 * @return {String} returns the version number
 */
function getVersion(vector) {
    var version = vector.split("/");
    if (version[0] === "CVSS:3.0") {
        return "3.0";
    }
    else if (version[0] === "CVSS:3.1") {
        return "3.1";
    }
    else {
        return "Error";
    }
}
module.exports = {
    roundUpExact: roundUpExact,
    roundUpApprox: roundUpApprox,
    getVectorObject: getVectorObject,
    getDetailedVectorObject: getDetailedVectorObject,
    findMetric: findMetric,
    findMetricValue: findMetricValue,
    getRating: getRating,
    updateVectorValue: updateVectorValue,
    isVectorValid: isVectorValid,
    parseVectorObjectToString: parseVectorObjectToString,
    getVersion: getVersion,
    getCleanVectorString: getCleanVectorString
};
