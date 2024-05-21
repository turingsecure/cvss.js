import { score } from "./score_4_0";
import { CVSS } from "./cvss";
// TODO: delete this file

console.log(
  CVSS("CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N").getVectorObject()
);
const vector = CVSS("CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
vector.getTemporalScore();
