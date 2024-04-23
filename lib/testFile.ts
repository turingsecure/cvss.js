import { util } from "./util";
import { CVSS } from "../lib/cvss";
// TODO: delete this file
console.log("Test File delete before merge");

const testVector = CVSS(
  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X"
).getVersion();

console.log(testVector);
