export const definitions = {
  version: "4.0",
  definitions: [
    {
      metricGroup: "Base",
      name: "Attack Vector",
      abbr: "AV",
      mandatory: true,
      metrics: [
        { name: "Network", abbr: "N", numerical: 0 },
        { name: "Adjacent", abbr: "A", numerical: 0.1 },
        { name: "Local", abbr: "L", numerical: 0.2 },
        { name: "Physical", abbr: "P", numerical: 0.3 }
      ]
    },
    {
      metricGroup: "Base",
      name: "Attack Complexity",
      abbr: "AC",
      mandatory: true,
      metrics: [
        { name: "Low", abbr: "L", numerical: 0 },
        { name: "High", abbr: "H", numerical: 0.1 }
      ]
    },
    {
      metricGroup: "Base",
      name: "Attack Requirements",
      abbr: "AT",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0 },
        { name: "Present", abbr: "P", numerical: 0.1 }
      ]
    },
    {
      metricGroup: "Base",
      name: "Privileges Required",
      abbr: "PR",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0.1 },
        { name: "High", abbr: "H", numerical: 0.2 }
      ]
    },
    {
      metricGroup: "Base",
      name: "User Interaction",
      abbr: "UI",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0 },
        { name: "Passive", abbr: "P", numerical: 0.1 },
        { name: "Active", abbr: "A", numerical: 0.2 }
      ]
    },
    {
      metricGroup: "Base",
      name: "Vulnerable System Confidentiality Impact",
      abbr: "VC",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0.2 },
        { name: "Low", abbr: "L", numerical: 0.1 },
        { name: "High", abbr: "H", numerical: 0 }
      ]
    },
    {
      metricGroup: "Base",
      name: "Vulnerable System Integrity Impact",
      abbr: "VI",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0.2 },
        { name: "Low", abbr: "L", numerical: 0.1 },
        { name: "High", abbr: "H", numerical: 0 }
      ]
    },
    {
      metricGroup: "Base",
      name: "Vulnerable System Availability Impact",
      abbr: "VA",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0.2 },
        { name: "Low", abbr: "L", numerical: 0.1 },
        { name: "High", abbr: "H", numerical: 0 }
      ]
    },
    {
      metricGroup: "Base",
      name: "Subsequent System Confidentiality Impact",
      abbr: "SC",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0.3 },
        { name: "Low", abbr: "L", numerical: 0.2 },
        { name: "High", abbr: "H", numerical: 0.1 }
      ]
    },
    {
      metricGroup: "Base",
      name: "Subsequent System Integrity Impact",
      abbr: "SI",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0.3 },
        { name: "Low", abbr: "L", numerical: 0.2 },
        { name: "High", abbr: "H", numerical: 0.1 },
        { name: "", abbr: "S", numerical: 0 } // no mentioned in the definitions but is in the max_composed.js
      ]
    },
    {
      metricGroup: "Base",
      name: "Subsequent System Availability Impact",
      abbr: "SA",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0.3 },
        { name: "Low", abbr: "L", numerical: 0.2 },
        { name: "High", abbr: "H", numerical: 0.1 },
        { name: "", abbr: "S", numerical: 0 } // no mentioned in the definitions but is in the max_composed.js
      ]
    },
    {
      metricGroup: "Threat",
      name: "Exploit Maturity",
      abbr: "E",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 0 },
        { name: "Attacked", abbr: "A", numerical: 0 },
        { name: "POC", abbr: "P", numerical: 0.1 },
        { name: "Unreported", abbr: "U", numerical: 0.2 }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Confidentiality Requirement",
      abbr: "CR",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 0 },
        { name: "High", abbr: "H", numerical: 0 },
        { name: "Medium", abbr: "M", numerical: 0.1 },
        { name: "Low", abbr: "L", numerical: 0.2 }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Integrity Requirement",
      abbr: "IR",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 0 },
        { name: "High", abbr: "H", numerical: 0 },
        { name: "Medium", abbr: "M", numerical: 0.1 },
        { name: "Low", abbr: "L", numerical: 0.2 }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Availability Requirement",
      abbr: "AR",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 0 },
        { name: "High", abbr: "H", numerical: 0 },
        { name: "Medium", abbr: "M", numerical: 0.1 },
        { name: "Low", abbr: "L", numerical: 0.2 }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Modified Attack Vector",
      abbr: "MAV",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X" },
        { name: "Network", abbr: "N" },
        { name: "Adjacent", abbr: "A" },
        { name: "Local", abbr: "L" },
        { name: "Physical", abbr: "P" }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Modified Attack Complexity",
      abbr: "MAC",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X" },
        { name: "High", abbr: "H" },
        { name: "Low", abbr: "L" }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Modified Attack Requirements ",
      abbr: "MAT",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X" },
        { name: "None", abbr: "N" },
        { name: "Present", abbr: "P" }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Modified Privileges Required",
      abbr: "MPR",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X" },
        { name: "High", abbr: "H" },
        { name: "Low", abbr: "L" },
        { name: "None", abbr: "N" }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Modified User Interaction",
      abbr: "MUI",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X" },
        { name: "None", abbr: "N" },
        { name: "Passive", abbr: "P" },
        { name: "Active", abbr: "A" }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Modified Vulnerable System Confidentiality",
      abbr: "MVC",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X" },
        { name: "High", abbr: "H" },
        { name: "Low", abbr: "L" },
        { name: "None", abbr: "N" }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Modified Vulnerable System Integrity",
      abbr: "MVI",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X" },
        { name: "High", abbr: "H" },
        { name: "Low", abbr: "L" },
        { name: "None", abbr: "N" }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Modified Vulnerable System Availability",
      abbr: "MVA",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X" },
        { name: "High", abbr: "H" },
        { name: "Low", abbr: "L" },
        { name: "None", abbr: "N" }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Modified Subsequent System Confidentiality",
      abbr: "MSC",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X" },
        { name: "High", abbr: "H" },
        { name: "Low", abbr: "L" },
        { name: "None", abbr: "N" }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Modified Subsequent System Integrity",
      abbr: "MSI",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X" },
        { name: "High", abbr: "H" },
        { name: "Low", abbr: "L" },
        { name: "Negligible", abbr: "N" },
        { name: "Safety", abbr: "S" }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Modified Subsequent System Availability",
      abbr: "MSA",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X" },
        { name: "High", abbr: "H" },
        { name: "Low", abbr: "L" },
        { name: "Negligible", abbr: "N" },
        { name: "Safety", abbr: "S" }
      ]
    },
    {
      metricGroup: "Supplemental",
      name: "Safety",
      abbr: "S",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X" },
        { name: "Negligible", abbr: "N" },
        { name: "Present", abbr: "P" }
      ]
    },
    {
      metricGroup: "Supplemental",
      name: "Automatable",
      abbr: "Au",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X" },
        { name: "No", abbr: "N" },
        { name: "Yes", abbr: "Y" }
      ]
    },
    {
      metricGroup: "Supplemental",
      name: "Recovery",
      abbr: "R",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X" },
        { name: "Automatic", abbr: "A" },
        { name: "User", abbr: "U" },
        { name: "Irrecoverable", abbr: "I" }
      ]
    },
    {
      metricGroup: "Supplemental",
      name: "Value Density",
      abbr: "V",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X" },
        { name: "Diffuse", abbr: "D" },
        { name: "Concentrated", abbr: "C" }
      ]
    },
    {
      metricGroup: "Supplemental",
      name: "Vulnerability Response Effort",
      abbr: "RE",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X" },
        { name: "Low", abbr: "L" },
        { name: "Moderate", abbr: "M" },
        { name: "High", abbr: "H" }
      ]
    },
    {
      metricGroup: "Supplemental",
      name: "Provider Urgency",
      abbr: "U",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X" },
        { name: "Clear", abbr: "Clear" },
        { name: "Green", abbr: "Green" },
        { name: "Amber", abbr: "Amber" },
        { name: "Red", abbr: "Red" }
      ]
    }
  ]
};

export const cvssLookup_global = {
  "000000": 10,
  "000001": 9.9,
  "000010": 9.8,
  "000011": 9.5,
  "000020": 9.5,
  "000021": 9.2,
  "000100": 10,
  "000101": 9.6,
  "000110": 9.3,
  "000111": 8.7,
  "000120": 9.1,
  "000121": 8.1,
  "000200": 9.3,
  "000201": 9,
  "000210": 8.9,
  "000211": 8,
  "000220": 8.1,
  "000221": 6.8,
  "001000": 9.8,
  "001001": 9.5,
  "001010": 9.5,
  "001011": 9.2,
  "001020": 9,
  "001021": 8.4,
  "001100": 9.3,
  "001101": 9.2,
  "001110": 8.9,
  "001111": 8.1,
  "001120": 8.1,
  "001121": 6.5,
  "001200": 8.8,
  "001201": 8,
  "001210": 7.8,
  "001211": 7,
  "001220": 6.9,
  "001221": 4.8,
  "002001": 9.2,
  "002011": 8.2,
  "002021": 7.2,
  "002101": 7.9,
  "002111": 6.9,
  "002121": 5,
  "002201": 6.9,
  "002211": 5.5,
  "002221": 2.7,
  "010000": 9.9,
  "010001": 9.7,
  "010010": 9.5,
  "010011": 9.2,
  "010020": 9.2,
  "010021": 8.5,
  "010100": 9.5,
  "010101": 9.1,
  "010110": 9,
  "010111": 8.3,
  "010120": 8.4,
  "010121": 7.1,
  "010200": 9.2,
  "010201": 8.1,
  "010210": 8.2,
  "010211": 7.1,
  "010220": 7.2,
  "010221": 5.3,
  "011000": 9.5,
  "011001": 9.3,
  "011010": 9.2,
  "011011": 8.5,
  "011020": 8.5,
  "011021": 7.3,
  "011100": 9.2,
  "011101": 8.2,
  "011110": 8,
  "011111": 7.2,
  "011120": 7,
  "011121": 5.9,
  "011200": 8.4,
  "011201": 7,
  "011210": 7.1,
  "011211": 5.2,
  "011220": 5,
  "011221": 3,
  "012001": 8.6,
  "012011": 7.5,
  "012021": 5.2,
  "012101": 7.1,
  "012111": 5.2,
  "012121": 2.9,
  "012201": 6.3,
  "012211": 2.9,
  "012221": 1.7,
  "100000": 9.8,
  "100001": 9.5,
  "100010": 9.4,
  "100011": 8.7,
  "100020": 9.1,
  "100021": 8.1,
  "100100": 9.4,
  "100101": 8.9,
  "100110": 8.6,
  "100111": 7.4,
  "100120": 7.7,
  "100121": 6.4,
  "100200": 8.7,
  "100201": 7.5,
  "100210": 7.4,
  "100211": 6.3,
  "100220": 6.3,
  "100221": 4.9,
  "101000": 9.4,
  "101001": 8.9,
  "101010": 8.8,
  "101011": 7.7,
  "101020": 7.6,
  "101021": 6.7,
  "101100": 8.6,
  "101101": 7.6,
  "101110": 7.4,
  "101111": 5.8,
  "101120": 5.9,
  "101121": 5,
  "101200": 7.2,
  "101201": 5.7,
  "101210": 5.7,
  "101211": 5.2,
  "101220": 5.2,
  "101221": 2.5,
  "102001": 8.3,
  "102011": 7,
  "102021": 5.4,
  "102101": 6.5,
  "102111": 5.8,
  "102121": 2.6,
  "102201": 5.3,
  "102211": 2.1,
  "102221": 1.3,
  "110000": 9.5,
  "110001": 9,
  "110010": 8.8,
  "110011": 7.6,
  "110020": 7.6,
  "110021": 7,
  "110100": 9,
  "110101": 7.7,
  "110110": 7.5,
  "110111": 6.2,
  "110120": 6.1,
  "110121": 5.3,
  "110200": 7.7,
  "110201": 6.6,
  "110210": 6.8,
  "110211": 5.9,
  "110220": 5.2,
  "110221": 3,
  "111000": 8.9,
  "111001": 7.8,
  "111010": 7.6,
  "111011": 6.7,
  "111020": 6.2,
  "111021": 5.8,
  "111100": 7.4,
  "111101": 5.9,
  "111110": 5.7,
  "111111": 5.7,
  "111120": 4.7,
  "111121": 2.3,
  "111200": 6.1,
  "111201": 5.2,
  "111210": 5.7,
  "111211": 2.9,
  "111220": 2.4,
  "111221": 1.6,
  "112001": 7.1,
  "112011": 5.9,
  "112021": 3,
  "112101": 5.8,
  "112111": 2.6,
  "112121": 1.5,
  "112201": 2.3,
  "112211": 1.3,
  "112221": 0.6,
  "200000": 9.3,
  "200001": 8.7,
  "200010": 8.6,
  "200011": 7.2,
  "200020": 7.5,
  "200021": 5.8,
  "200100": 8.6,
  "200101": 7.4,
  "200110": 7.4,
  "200111": 6.1,
  "200120": 5.6,
  "200121": 3.4,
  "200200": 7,
  "200201": 5.4,
  "200210": 5.2,
  "200211": 4,
  "200220": 4,
  "200221": 2.2,
  "201000": 8.5,
  "201001": 7.5,
  "201010": 7.4,
  "201011": 5.5,
  "201020": 6.2,
  "201021": 5.1,
  "201100": 7.2,
  "201101": 5.7,
  "201110": 5.5,
  "201111": 4.1,
  "201120": 4.6,
  "201121": 1.9,
  "201200": 5.3,
  "201201": 3.6,
  "201210": 3.4,
  "201211": 1.9,
  "201220": 1.9,
  "201221": 0.8,
  "202001": 6.4,
  "202011": 5.1,
  "202021": 2,
  "202101": 4.7,
  "202111": 2.1,
  "202121": 1.1,
  "202201": 2.4,
  "202211": 0.9,
  "202221": 0.4,
  "210000": 8.8,
  "210001": 7.5,
  "210010": 7.3,
  "210011": 5.3,
  "210020": 6,
  "210021": 5,
  "210100": 7.3,
  "210101": 5.5,
  "210110": 5.9,
  "210111": 4,
  "210120": 4.1,
  "210121": 2,
  "210200": 5.4,
  "210201": 4.3,
  "210210": 4.5,
  "210211": 2.2,
  "210220": 2,
  "210221": 1.1,
  "211000": 7.5,
  "211001": 5.5,
  "211010": 5.8,
  "211011": 4.5,
  "211020": 4,
  "211021": 2.1,
  "211100": 6.1,
  "211101": 5.1,
  "211110": 4.8,
  "211111": 1.8,
  "211120": 2,
  "211121": 0.9,
  "211200": 4.6,
  "211201": 1.8,
  "211210": 1.7,
  "211211": 0.7,
  "211220": 0.8,
  "211221": 0.2,
  "212001": 5.3,
  "212011": 2.4,
  "212021": 1.4,
  "212101": 2.4,
  "212111": 1.2,
  "212121": 0.5,
  "212201": 1,
  "212211": 0.3,
  "212221": 0.1
};

export const maxComposed = {
  // EQ1
  eq1: {
    0: ["AV:N/PR:N/UI:N/"],
    1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
    2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"]
  },
  // EQ2
  eq2: {
    0: ["AC:L/AT:N/"],
    1: ["AC:H/AT:N/", "AC:L/AT:P/"]
  },
  // EQ3+EQ6
  eq3: {
    0: {
      "0": ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
      "1": ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"]
    },
    1: {
      "0": ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
      "1": [
        "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
        "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
        "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
        "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
        "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"
      ]
    },
    2: { "1": ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"] }
  },
  // EQ4
  eq4: {
    0: ["SC:H/SI:S/SA:S/"],
    1: ["SC:H/SI:H/SA:H/"],
    2: ["SC:L/SI:L/SA:L/"]
  },
  // EQ5
  eq5: {
    0: ["E:A/"],
    1: ["E:P/"],
    2: ["E:U/"]
  }
};

export const maxSeverity = {
  eq1: {
    0: 1,
    1: 4,
    2: 5
  },
  eq2: {
    0: 1,
    1: 2
  },
  eq3eq6: {
    0: { 0: 7, 1: 6 },
    1: { 0: 8, 1: 8 },
    2: { 1: 10 }
  },
  eq4: {
    0: 6,
    1: 5,
    2: 4
  },
  eq5: {
    0: 1,
    1: 1,
    2: 1
  }
};
