const CVSS = require("./lib/cvss.js");

const vector = CVSS("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R");
console.log(vector.isValid);

module.exports = CVSS;
