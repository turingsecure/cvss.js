const { getCleanVectorString } = require("../lib/util");
const util = require("../lib/util");

describe("roundUpExact Tests", () => {
  it("Should return the Number", () => {
    expect(util.roundUpExact(0.1+0.2)).toBe(0.3);

    expect(util.roundUpExact(0.6+0.2)).toBe(0.8);

    expect(util.roundUpExact(0.4+0.2)).toBe(0.6);

    expect(util.roundUpExact(0.8+0.2)).toBe(1);
  });
});

describe("getCleanVectorString Tests", () => {
  it("Should return the String", () => {
    const vectorObject = "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N/E:P/RL:W/RC:X/CR:X/IR:X/AR:M/MAV:A/MAC:X/MPR:X/MUI:N/MS:X/MC:X/MI:X/MA:X";

    expect(getCleanVectorString(vectorObject)).toBe("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N/E:P/RL:W/AR:M/MAV:A/MUI:N");

  });
});