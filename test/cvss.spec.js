const CVSS = require("../lib/cvss");

describe("Rating", () => {
  it("Should return the score", () => {
    // These are just some example test cases.
    // TODO: clean this up and test more systematically.
    const vector = CVSS("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:L");
    expect(vector.getScore()).toBe(4.4);

    const vector2 = CVSS("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:L/A:N");
    expect(vector2.getScore()).toBe(4.0);

    const vector3 = CVSS("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:H");
    expect(vector3.getScore()).toBe(7.1);

    const vector4 = CVSS("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N");
    expect(vector4.getScore()).toBe(8.2);
  });
});
