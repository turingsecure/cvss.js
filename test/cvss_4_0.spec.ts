import { CVSS } from "../lib/cvss";

const examples = [
  { score: 7.3, vector: "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" },
  { score: 7.7, vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" },
  { score: 5.2, vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U" },
  { score: 8.3, vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N" },
  {
    score: 8.1,
    vector:
      "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/CR:H/IR:L/AR:L/MAV:N/MAC:H/MVC:H/MVI:L/MVA:L"
  },
  { score: 4.6, vector: "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N" },
  { score: 5.1, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N" },
  { score: 6.9, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N" },
  { score: 5.9, vector: "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N" },
  { score: 9.4, vector: "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H" },
  { score: 8.3, vector: "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N/S:P/V:D" },
  { score: 8.7, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A" },
  { score: 10, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A" },
  { score: 9.3, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A" },
  { score: 6.4, vector: "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:H/SI:N/SA:H" },
  { score: 9.3, vector: "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/R:I" },
  { score: 8.7, vector: "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/R:I" },
  { score: 8.6, vector: "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H" },
  { score: 7.1, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N" },
  { score: 8.2, vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N" },
  { score: 8.7, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L" },
  { score: 6.6, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L/E:U" },
  { score: 5.1, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N" },
  { score: 5.1, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N" },
  { score: 7.7, vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" },
  { score: 8.3, vector: "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N" },
  { score: 5.6, vector: "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:U" },
  { score: 8.5, vector: "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" },
  { score: 9.2, vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A" },
  { score: 5.4, vector: "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" },
  { score: 8.7, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N" },
  { score: 6.9, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N" },
  { score: 9.3, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" },
  { score: 6.9, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N" },
  { score: 8.5, vector: "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:P" },
  {
    score: 9.4,
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/S:P/AU:Y/V:C/RE:L"
  },
  {
    score: 7.0,
    vector:
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:L/IR:H/AR:L/MAV:L/MAC:H/MAT:N/MPR:N/MUI:N/MVC:N/MVI:H/MVA:L/MSC:N/MSI:S/MSA:L"
  },
  {
    score: 7.4,
    vector:
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAV:A/MAC:H/MAT:N/MPR:L/MUI:N/MVC:L/MVI:H/MVA:H/MSC:L/MSI:S/MSA:S/CR:L/IR:H/AR:H/E:P"
  },
  {
    score: 8.7,
    vector:
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:H/CR:M/IR:H/AR:M/E:P"
  },
  { score: 8.6, vector: "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/S:P" },
  {
    score: 9.7,
    vector: "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/MSI:S/S:P"
  },
  { score: 8.7, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/V:C" }
];

describe("Score Tests", () => {
  it("Should return the score", () => {
    // These are just some example test cases.
    for (const example of examples) {
      const vector = CVSS(example.vector);
      expect(vector.getScore()).toBe(example.score);
    }
  });
});

describe("Create vector from object", () => {
  it("Should return the vector as string with a valid vector object", () => {
    expect(
      CVSS({
        CVSS: "4.0",
        AV: "L",
        AC: "L",
        AT: "P",
        PR: "L",
        UI: "N",
        VC: "H",
        VI: "H",
        VA: "H",
        SC: "N",
        SI: "N",
        SA: "N"
      }).vector
    ).toBe("CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  });

  it("Should throw error with an invlaid vector object", () => {
    const fn = () => {
      expect(
        CVSS({
          A: "N",
          AC: "L",
          AV: "N",
          C: "L",
          CVSS: "4.0",
          E: "X",
          I: "H",
          PR: "N",
          RC: "X",
          RL: "X",
          S: "U",
          UI: "N"
        }).vector
      );
    };
    expect(fn).toThrow("The vector format is not valid!");
  });
});

describe("Version Tests", () => {
  it("Should return the correct version when calling getVersion", () => {
    const vector = CVSS("CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
    expect(vector.getVersion()).toBe("4.0");
  });
});

describe("Temporal Tests", () => {
  it("Should throw error when calling getTemporalScore", () => {
    const vector = CVSS("CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
    const fn = () => {
      vector.getTemporalScore();
    };
    expect(fn).toThrow("This function is not supported for this cvss version");
  });
});

describe("Environmental score tests", () => {
  it("Should throw error when calling getEnvironmentalScore", () => {
    const vector = CVSS("CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
    const fn = () => {
      vector.getEnvironmentalScore();
    };
    expect(fn).toThrow("This function is not supported for this cvss version");
  });
});

describe("ImpactSub score tests", () => {
  it("Should throw error when calling getImpactSubScore", () => {
    const vector = CVSS("CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
    const fn = () => {
      vector.getImpactSubScore();
    };
    expect(fn).toThrow("This function is not supported for this cvss version");
  });
});

describe("ExploitabilitySub score tests", () => {
  it("Should throw error when calling getExploitabilitySubScore", () => {
    const vector = CVSS("CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
    const fn = () => {
      vector.getExploitabilitySubScore();
    };
    expect(fn).toThrow("This function is not supported for this cvss version");
  });
});
