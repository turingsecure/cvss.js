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
 * @param {String} vector The inicial vector CVSS
 *
 * @return The object containing all separate CVSS values 
 */
function getVectorObject(vector) {
  const vectorArray = vector.split("/");
  const vectorObject = {};

  for (const entry of vectorArray) {
    const values = entry.split(":");
    vectorObject[values[0]] = values[1];
  }

  return vectorObject;
}

module.exports = { roundUp, getVectorObject };
