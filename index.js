const CVSS = require("./lib/cvss.js");

const vector = CVSS("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:L");

console.log(vector.getScore());
console.log(vector.vector);

module.exports = CVSS;
