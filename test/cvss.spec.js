const CVSS = require("../lib/cvss");

describe("Rating", () => {
  it("Should return the score", () => {
    const vector = CVSS("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:L");
    expect(vector.getScore()).toBe(4.4);
  });
});
