const CVSS = require("../lib/cvss");

describe("Score Tests", () => {
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
  
    //Temporal score tests
    const vector5 = CVSS("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R");
    expect(vector5.getTemporalScore()).toBe(4.7);

    const vector6 = CVSS("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:F/RL:U/RC:X");
    expect(vector6.getTemporalScore()).toBe(5.4);
    
  });
});

describe("Rating Tests", () => {
  it("Should return 'None' if the vector's score is 0", () => {
    const vector = CVSS("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N");
    expect(vector.getScore()).toBe(0);
    expect(vector.getRating()).toBe("None");
  });

  it("Should return 'Low' if the vector's score is >= 0.1 and <= 3.9", () => {
    const vector = CVSS("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N");
    expect(vector.getScore()).toBe(2);
    expect(vector.getRating()).toBe("Low");
  });

  it("Should return 'Medium' if the vector's score is >= 4.0 and <= 6.9", () => {
    const vector = CVSS("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:N");
    expect(vector.getScore()).toBe(4.2);
    expect(vector.getRating()).toBe("Medium");
  });

  it("Should return 'High' if the vector's score is >= 7.0 and <= 8.9", () => {
    const vector = CVSS("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
    expect(vector.getScore()).toBe(8.8);
    expect(vector.getRating()).toBe("High");
  });

  it("Should return 'Critcal' if the vector's score is >= 9.0 and <= 10.0", () => {
    const vector = CVSS("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(vector.getScore()).toBe(9.8);
    expect(vector.getRating()).toBe("Critical");
  });
});
