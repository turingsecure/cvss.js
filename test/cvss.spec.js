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

    const vector5 = CVSS({
      A: "N",
      AC: "L",
      AV: "N",
      C: "L",
      CVSS: "3.0",
      E: "X",
      I: "H",
      PR: "N",
      RC: "X",
      RL: "X",
      S: "U",
      UI: "N"
    });
    expect(vector5.getScore()).toBe(8.2);
  });
});

describe("Version Tests", () => {
  it("Should return the Version", () => {
    const vector5 = CVSS("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R");
    expect(vector5.getVersion()).toBe("3.0");

    const vector6 = CVSS("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R");
    expect(vector6.getVersion()).toBe("3.1");

    const vector7 = () => {
      CVSS("CVSS:xyz/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R");
    };
    expect(vector7).toThrow("The vector version is not valid");

    const vector8 = () => {
      CVSS("CVSS:/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R");
    };
    expect(vector8).toThrow("The vector version is not valid");
  });
});

describe("Temporal Tests", () => {
  it("Should return the temporal score", () => {
    const vector5 = CVSS("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R");
    expect(vector5.getTemporalScore()).toBe(4.7);

    const vector6 = CVSS("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:F/RL:U/RC:X");
    expect(vector6.getTemporalScore()).toBe(5.4);

    const vector7 = CVSS({
      A: "N",
      AC: "L",
      AV: "N",
      C: "L",
      CVSS: "3.0",
      E: "X",
      I: "H",
      PR: "N",
      RC: "X",
      RL: "X",
      S: "U",
      UI: "N"
    });
    expect(vector7.getTemporalScore()).toBe(8.2);
  });
});

describe("Environmental score tests", () => {
  it("Should return the environmental score", () => {
    const vector = CVSS(
      "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N/CR:M/IR:H/AR:M/MAV:N/MAC:H/MPR:L/MUI:N/MS:C/MC:N/MI:L/MA:L"
    );
    expect(vector.getEnvironmentalScore()).toBe(5.6);

    const vector2 = CVSS(
      "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:L/E:P/RL:T/RC:U/CR:H/IR:M/AR:M/MAV:A/MAC:H/MPR:N/MUI:N/MS:U/MC:H/MI:H/MA:H"
    );
    expect(vector2.getEnvironmentalScore()).toBe(6.3);

    const vector3 = CVSS(
      "CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:H/E:H/RL:U/RC:R/CR:M/IR:M/AR:M/MAV:N/MAC:H/MPR:N/MUI:N/MS:C/MC:N/MI:N/MA:L"
    );
    expect(vector3.getEnvironmentalScore()).toBe(3.9);

    const vector4 = CVSS(
      "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H/RL:T/CR:L/IR:M/AR:H/MAV:N/MAC:L/MPR:N/MUI:R/MS:C/MC:H/MI:H/MA:H"
    );
    expect(vector4.getEnvironmentalScore()).toBe(9.3);

    const vector5 = CVSS(
      "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N/E:P/RL:O/IR:M/MAV:A/MPR:N/MI:L"
    );
    expect(vector5.getEnvironmentalScore()).toBe(4.9);

    const vector6 = CVSS(
      "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L/CR:H/IR:H/MS:C/MC:H/MI:H/MA:H"
    );
    expect(vector6.getEnvironmentalScore()).toBe(8.0);
    
    const vector7 = CVSS(
      "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L/CR:H/IR:H/MS:C/MC:H/MI:H/MA:H"
    );
    expect(vector7.getEnvironmentalScore()).toBe(8.1);
  });

  it("Should return base score when all environmental metrics are not defined", () => {
    const vector = CVSS(
      "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X"
    );

    expect(vector.getEnvironmentalScore()).toBe(vector.getScore());
  });
});

describe("Rating Tests", () => {
  it("Should return 'None' if the vector's score is 0", () => {
    const vector = CVSS("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N");
    expect(vector.getScore()).toBe(0);
    expect(vector.getRating()).toBe("None");
    expect(vector.getTemporalRating()).toBe("None");
    expect(vector.getEnvironmentalRating()).toBe("None");
  });

  it("Should return 'Low' if the vector's score is >= 0.1 and <= 3.9", () => {
    const vector = CVSS("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N");
    expect(vector.getScore()).toBe(2);
    expect(vector.getRating()).toBe("Low");
    expect(vector.getTemporalRating()).toBe("Low");
    expect(vector.getEnvironmentalRating()).toBe("Low");
  });

  it("Should return 'Medium' if the vector's score is >= 4.0 and <= 6.9", () => {
    const vector = CVSS("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:N");
    expect(vector.getScore()).toBe(4.2);
    expect(vector.getRating()).toBe("Medium");
    expect(vector.getTemporalRating()).toBe("Medium");
    expect(vector.getEnvironmentalRating()).toBe("Medium");
  });

  it("Should return 'High' if the vector's score is >= 7.0 and <= 8.9", () => {
    const vector = CVSS("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
    expect(vector.getScore()).toBe(8.8);
    expect(vector.getRating()).toBe("High");
    expect(vector.getTemporalRating()).toBe("High");
    expect(vector.getEnvironmentalRating()).toBe("High");
  });

  it("Should return 'Critical' if the vector's score is >= 9.0 and <= 10.0", () => {
    const vector = CVSS("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(vector.getScore()).toBe(9.8);
    expect(vector.getRating()).toBe("Critical");
    expect(vector.getTemporalRating()).toBe("Critical");
    expect(vector.getEnvironmentalRating()).toBe("Critical");
  });

  it("Should be able to discern individual ratings (base, temp, env) even if these don't match", () => {
    const vector = CVSS("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N/E:U/RL:O/RC:U/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:H/MI:H/MA:H");
    expect(vector.getScore()).toBe(4.3);
    expect(vector.getRating()).toBe("Medium");
    expect(vector.getTemporalScore()).toBe(3.5);
    expect(vector.getTemporalRating()).toBe("Low");
    expect(vector.getEnvironmentalScore()).toBe(7.8);
    expect(vector.getEnvironmentalRating()).toBe("High");
  });

});

describe("Vector Object Tests", () => {
  it("Should return vector object with same key-value pairs", () => {
    const vector = CVSS("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(vector.getScore()).toBe(9.8);
    expect(vector.getVectorObject()).toEqual({
      CVSS: "3.0",
      AV: "N",
      AC: "L",
      PR: "N",
      UI: "N",
      S: "U",
      C: "H",
      I: "H",
      A: "H",
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
      MA: "X"
    });
  });

  it("Should return vector object with same key-value pairs", () => {
    const vector = CVSS("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:N");
    expect(vector.getScore()).toBe(4.2);
    expect(vector.getVectorObject()).toEqual({
      CVSS: "3.0",
      AV: "N",
      AC: "H",
      PR: "H",
      UI: "R",
      S: "U",
      C: "H",
      I: "N",
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
      MA: "X"
    });
  });
});

describe("Check vector", () => {
  it("must return invalid format for the vector", () => {
    const t1 = () => {
      CVSS("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:TRC:R");
    };
    expect(t1).toThrow("The vector format is not valid!");

    const t2 = () => {
      CVSS("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:F/RL:U/RC:X/");
    };
    expect(t2).toThrow("The vector format is not valid!");

    const t3 = () => {
      CVSS("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:F/RL:U/RC:X/test");
    };
    expect(t3).toThrow("The vector format is not valid!");
  });

  it("must return repeated values in the vector", () => {
    const t1 = () => {
      CVSS("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R/RC:R");
    };
    expect(t1).toThrow("The vector format is not valid!");

    const t2 = () => {
      CVSS("CVSS:3.0/AV:N/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R");
    };
    expect(t2).toThrow("The vector format is not valid!");

    const t3 = () => {
      CVSS("CVSS:3.0/AV:N/AC:H/PR:L/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R");
    };
    expect(t3).toThrow("The vector format is not valid!");
  });

  it("checks if mandatory values have been passed", () => {
    const t1 = () => {
      CVSS("CVSS:3.0/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R");
    };
    expect(t1).toThrow("The vector format is not valid!");

    const t2 = () => {
      CVSS("CVSS:3.0/AV:N/AC:H/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R");
    };
    expect(t2).toThrow("The vector format is not valid!");

    const t3 = () => {
      CVSS("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/E:U/RL:T/RC:R");
    };
    expect(t3).toThrow("The vector format is not valid!");
  });

  it("all tests must have the vectors in valid format", () => {
    const vector = CVSS("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R");
    expect(vector.isValid).toBe(true);

    const vector2 = CVSS("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R");
    expect(vector2.isValid).toBe(true);

    const vector3 = CVSS("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:H/A:L/E:U/RL:T/RC:R");
    expect(vector3.isValid).toBe(true);
  });
});

describe("Detailed Vector Object Tests", () => {
  it("Should return detailed vector object with same key-value pairs and extra relevant values", () => {
    const vector = CVSS("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(vector.getScore()).toBe(9.8);
    expect(vector.getDetailedVectorObject()).toEqual({
      CVSS: "3.0",
      metrics: {
        AV: {
          name: "Attack Vector",
          abbr: "AV",
          fullName: "Attack Vector (AV)",
          value: "Network",
          valueAbbr: "N"
        },
        AC: {
          name: "Attack Complexity",
          abbr: "AC",
          fullName: "Attack Complexity (AC)",
          value: "Low",
          valueAbbr: "L"
        },
        PR: {
          name: "Privileges Required",
          abbr: "PR",
          fullName: "Privileges Required (PR)",
          value: "None",
          valueAbbr: "N"
        },
        UI: {
          name: "User Interaction",
          abbr: "UI",
          fullName: "User Interaction (UI)",
          value: "None",
          valueAbbr: "N"
        },
        S: {
          name: "Scope",
          abbr: "S",
          fullName: "Scope (S)",
          value: "Unchanged",
          valueAbbr: "U"
        },
        C: {
          name: "Confidentiality",
          abbr: "C",
          fullName: "Confidentiality (C)",
          value: "High",
          valueAbbr: "H"
        },
        I: {
          name: "Integrity",
          abbr: "I",
          fullName: "Integrity (I)",
          value: "High",
          valueAbbr: "H"
        },
        A: {
          name: "Availability",
          abbr: "A",
          fullName: "Availability (A)",
          value: "High",
          valueAbbr: "H"
        }
      }
    });
  });

  it("Should return detailed vector object with same key-value pairs and extra relevant values", () => {
    const vector = CVSS("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:N");
    expect(vector.getScore()).toBe(4.2);
    expect(vector.getDetailedVectorObject()).toEqual({
      CVSS: "3.0",
      metrics: {
        AV: {
          name: "Attack Vector",
          abbr: "AV",
          fullName: "Attack Vector (AV)",
          value: "Network",
          valueAbbr: "N"
        },
        AC: {
          name: "Attack Complexity",
          abbr: "AC",
          fullName: "Attack Complexity (AC)",
          value: "High",
          valueAbbr: "H"
        },
        PR: {
          name: "Privileges Required",
          abbr: "PR",
          fullName: "Privileges Required (PR)",
          value: "High",
          valueAbbr: "H"
        },
        UI: {
          name: "User Interaction",
          abbr: "UI",
          fullName: "User Interaction (UI)",
          value: "Required",
          valueAbbr: "R"
        },
        S: {
          name: "Scope",
          abbr: "S",
          fullName: "Scope (S)",
          value: "Unchanged",
          valueAbbr: "U"
        },
        C: {
          name: "Confidentiality",
          abbr: "C",
          fullName: "Confidentiality (C)",
          value: "High",
          valueAbbr: "H"
        },
        I: {
          name: "Integrity",
          abbr: "I",
          fullName: "Integrity (I)",
          value: "None",
          valueAbbr: "N"
        },
        A: {
          name: "Availability",
          abbr: "A",
          fullName: "Availability (A)",
          value: "None",
          valueAbbr: "N"
        }
      }
    });
  });
});

describe("Create vector from object", () => {
  it("Should return the vector as string", () => {
    const vectorObject = {
      CVSS: "3.0",
      AV: "N",
      AC: "H",
      PR: "H",
      UI: "R",
      S: "U",
      C: "H",
      I: "N",
      A: "N"
    };

    expect(CVSS(vectorObject).vector).toBe("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:N");

    const vectorObject1 = {
      A: "N",
      AC: "L",
      AV: "N",
      C: "L",
      CVSS: "3.0",
      E: "X",
      I: "H",
      PR: "N",
      RC: "X",
      RL: "X",
      S: "U",
      UI: "N"
    };

    expect(CVSS(vectorObject1).vector).toBe(
      "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N/E:X/RL:X/RC:X"
    );
  });

  it("Should calculate the correct scores", () => {
    const vectorObject = {
      CVSS: "3.0",
      AV: "N",
      AC: "H",
      PR: "L",
      UI: "R",
      S: "U",
      C: "H",
      I: "H",
      A: "H",
      RL: "T",
      CR: "L",
      IR: "M",
      AR: "H",
      MAV: "N",
      MAC: "L",
      MPR: "N",
      MUI: "R",
      MS: "C",
      MC: "H",
      MI: "H",
      MA: "H"
    };

    expect(CVSS(vectorObject).getScore()).toBe(7.1);
    expect(CVSS(vectorObject).getTemporalScore()).toBe(6.9);
    expect(CVSS(vectorObject).getEnvironmentalScore()).toBe(9.3);
  });
});

describe("Clean Vector String Test", () => {
  it("Should return the clean vector as string", () => {
    expect(CVSS("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N/E:P/RL:W/RC:X/CR:X/IR:X/AR:M/MAV:A/MAC:X/MPR:X/MUI:N/MS:X/MC:X/MI:X/MA:X").getCleanVectorString())
      .toBe("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N/E:P/RL:W/AR:M/MAV:A/MUI:N");

    expect(CVSS("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N/E:X/RL:X/RC:X").getCleanVectorString())
      .toBe("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N");

    expect(CVSS("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X").getCleanVectorString())
      .toBe("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N");
  });
});