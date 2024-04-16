import { util } from "./util";

console.log("Test File delete before merge");

const vectorObject = util.getDetailedVectorObject(
  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X"
);

const test = util.findMetricValue("AV", {
  AV: "N",
  AC: "L",
  PR: "N",
  UI: "N",
  S: "U",
  C: "L",
  I: "H",
  A: "N",
  E: "X",
  RL: "X",
  RC: "X",
  CR: "X",
  IR: "X",
  AR: "X",
  MAV: "X",
  MAC: "X",
  MPR: "X",
  MUI: "X",
  MS: "X",
  MC: "X",
  MI: "X",
  MA: "X",
  CVSS: "3.0"
});

console.log(test);
