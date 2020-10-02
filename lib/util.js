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


module.exports = { roundUp };
