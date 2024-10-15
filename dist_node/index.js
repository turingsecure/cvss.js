// lib/cvss_3_0.ts
var definitions = {
  version: "3.0",
  definitions: [
    {
      name: "Attack Vector",
      abbr: "AV",
      mandatory: true,
      metrics: [
        { name: "Network", abbr: "N", numerical: 0.85 },
        { name: "Adjacent", abbr: "A", numerical: 0.62 },
        { name: "Local", abbr: "L", numerical: 0.55 },
        { name: "Physical", abbr: "P", numerical: 0.2 }
      ]
    },
    {
      name: "Attack Complexity",
      abbr: "AC",
      mandatory: true,
      metrics: [
        { name: "Low", abbr: "L", numerical: 0.77 },
        { name: "High", abbr: "H", numerical: 0.44 }
      ]
    },
    {
      name: "Privileges Required",
      abbr: "PR",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: { changed: 0.85, unchanged: 0.85 } },
        { name: "Low", abbr: "L", numerical: { changed: 0.68, unchanged: 0.62 } },
        { name: "High", abbr: "H", numerical: { changed: 0.5, unchanged: 0.27 } }
      ]
    },
    {
      name: "User Interaction",
      abbr: "UI",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0.85 },
        { name: "Required", abbr: "R", numerical: 0.62 }
      ]
    },
    {
      name: "Scope",
      abbr: "S",
      mandatory: true,
      metrics: [
        { name: "Unchanged", abbr: "U" },
        { name: "Changed", abbr: "C" }
      ]
    },
    {
      name: "Confidentiality",
      abbr: "C",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0.22 },
        { name: "High", abbr: "H", numerical: 0.56 }
      ]
    },
    {
      name: "Integrity",
      abbr: "I",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0.22 },
        { name: "High", abbr: "H", numerical: 0.56 }
      ]
    },
    {
      name: "Availability",
      abbr: "A",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0.22 },
        { name: "High", abbr: "H", numerical: 0.56 }
      ]
    },
    {
      name: "Exploit Code Maturity",
      abbr: "E",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 1 },
        { name: "High", abbr: "H", numerical: 1 },
        { name: "Functional", abbr: "F", numerical: 0.97 },
        { name: "Proof of Concept", abbr: "P", numerical: 0.94 },
        { name: "Unproven", abbr: "U", numerical: 0.91 }
      ]
    },
    {
      name: "Remediation Level",
      abbr: "RL",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 1 },
        { name: "Unavailable", abbr: "U", numerical: 1 },
        { name: "Workaround", abbr: "W", numerical: 0.97 },
        { name: "Temporary Fix", abbr: "T", numerical: 0.96 },
        { name: "Official Fix", abbr: "O", numerical: 0.95 }
      ]
    },
    {
      name: "Report Confidence",
      abbr: "RC",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 1 },
        { name: "Confirmed", abbr: "C", numerical: 1 },
        { name: "Reasonable", abbr: "R", numerical: 0.96 },
        { name: "Unknown", abbr: "U", numerical: 0.92 }
      ]
    },
    {
      name: "Confidentiality Req.",
      abbr: "CR",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 1 },
        { name: "High", abbr: "H", numerical: 1.5 },
        { name: "Medium", abbr: "M", numerical: 1 },
        { name: "Low", abbr: "L", numerical: 0.5 }
      ]
    },
    {
      name: "Integrity Req.",
      abbr: "IR",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 1 },
        { name: "High", abbr: "H", numerical: 1.5 },
        { name: "Medium", abbr: "M", numerical: 1 },
        { name: "Low", abbr: "L", numerical: 0.5 }
      ]
    },
    {
      name: "Availability Req.",
      abbr: "AR",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 1 },
        { name: "High", abbr: "H", numerical: 1.5 },
        { name: "Medium", abbr: "M", numerical: 1 },
        { name: "Low", abbr: "L", numerical: 0.5 }
      ]
    },
    {
      name: "Modified Attack Vector",
      abbr: "MAV",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 1 },
        { name: "Network", abbr: "N", numerical: 0.85 },
        { name: "Adjacent", abbr: "A", numerical: 0.62 },
        { name: "Local", abbr: "L", numerical: 0.55 },
        { name: "Physical", abbr: "P", numerical: 0.2 }
      ]
    },
    {
      name: "Modified Attack Complexity",
      abbr: "MAC",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 1 },
        { name: "Low", abbr: "L", numerical: 0.77 },
        { name: "High", abbr: "H", numerical: 0.44 }
      ]
    },
    {
      name: "Modified Privileges Required",
      abbr: "MPR",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: { changed: 1, unchanged: 1 } },
        { name: "None", abbr: "N", numerical: { changed: 0.85, unchanged: 0.85 } },
        { name: "Low", abbr: "L", numerical: { changed: 0.68, unchanged: 0.62 } },
        { name: "High", abbr: "H", numerical: { changed: 0.5, unchanged: 0.27 } }
      ]
    },
    {
      name: "Modified User Interaction",
      abbr: "MUI",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 1 },
        { name: "None", abbr: "N", numerical: 0.85 },
        { name: "Required", abbr: "R", numerical: 0.62 }
      ]
    },
    {
      name: "Modified Scope",
      abbr: "MS",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X" },
        { name: "Unchanged", abbr: "U" },
        { name: "Changed", abbr: "C" }
      ]
    },
    {
      name: "Modified Confidentiality",
      abbr: "MC",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 1 },
        { name: "None", abbr: "N", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0.22 },
        { name: "High", abbr: "H", numerical: 0.56 }
      ]
    },
    {
      name: "Modified Integrity",
      abbr: "MI",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 1 },
        { name: "None", abbr: "N", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0.22 },
        { name: "High", abbr: "H", numerical: 0.56 }
      ]
    },
    {
      name: "Modified Availability",
      abbr: "MA",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 1 },
        { name: "None", abbr: "N", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0.22 },
        { name: "High", abbr: "H", numerical: 0.56 }
      ]
    }
  ]
};

// lib/cvss_4_0.ts
var definitions2 = {
  version: "4.0",
  definitions: [
    {
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
      name: "Attack Complexity",
      abbr: "AC",
      mandatory: true,
      metrics: [
        { name: "Low", abbr: "L", numerical: 0 },
        { name: "High", abbr: "H", numerical: 0.1 }
      ]
    },
    {
      name: "Attack Requirements",
      abbr: "AT",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0 },
        { name: "Present", abbr: "P", numerical: 0.1 }
      ]
    },
    {
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
      name: "Subsequent System Integrity Impact",
      abbr: "SI",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0.3 },
        { name: "Low", abbr: "L", numerical: 0.2 },
        { name: "High", abbr: "H", numerical: 0.1 },
        { name: "", abbr: "S", numerical: 0 }
      ]
    },
    {
      name: "Subsequent System Availability Impact",
      abbr: "SA",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0.3 },
        { name: "Low", abbr: "L", numerical: 0.2 },
        { name: "High", abbr: "H", numerical: 0.1 },
        { name: "", abbr: "S", numerical: 0 }
      ]
    },
    {
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
      name: "Automatable",
      abbr: "AU",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X" },
        { name: "No", abbr: "N" },
        { name: "Yes", abbr: "Y" }
      ]
    },
    {
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
var cvssLookup_global = {
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
var maxComposed = {
  eq1: {
    0: ["AV:N/PR:N/UI:N/"],
    1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
    2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"]
  },
  eq2: {
    0: ["AC:L/AT:N/"],
    1: ["AC:H/AT:N/", "AC:L/AT:P/"]
  },
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
  eq4: {
    0: ["SC:H/SI:S/SA:S/"],
    1: ["SC:H/SI:H/SA:H/"],
    2: ["SC:L/SI:L/SA:L/"]
  },
  eq5: {
    0: ["E:A/"],
    1: ["E:P/"],
    2: ["E:U/"]
  }
};
var maxSeverity = {
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

// lib/util.ts
function findMetric(abbr, cvssVersion) {
  const definitions3 = cvssVersion === "4.0" ? definitions2 : definitions;
  return definitions3.definitions.find((def) => def.abbr === abbr);
}
function findMetricValue(abbr, vectorObject) {
  const definition = findMetric(abbr, vectorObject.CVSS);
  let value = definition?.metrics.find((metric) => metric.abbr === vectorObject[definition.abbr]);
  return value;
}
function roundUpApprox(num, precision) {
  precision = Math.pow(10, precision);
  return Math.ceil(num * precision) / precision;
}
function roundUpExact(num) {
  const int_input = Math.round(num * 1e5);
  if (int_input % 1e4 === 0) {
    return int_input / 1e5;
  } else {
    return (Math.floor(int_input / 1e4) + 1) / 10;
  }
}
function getVectorObject(vector) {
  const vectorArray = vector.split("/");
  const definitions3 = vector.includes("4.0") ? definitions2 : definitions;
  const vectorObject = definitions3.definitions.map((definition) => definition.abbr).reduce((acc, curr) => {
    acc[curr] = "X";
    return acc;
  }, {});
  for (const entry of vectorArray) {
    const values = entry.split(":");
    vectorObject[values[0]] = values[1];
  }
  return vectorObject;
}
function getCleanVectorString(vector) {
  const vectorArray = vector.split("/");
  const cleanVectorArray = [];
  for (const entry of vectorArray) {
    const values = entry.split(":");
    if (values[1] !== "X")
      cleanVectorArray.push(entry);
  }
  return cleanVectorArray.join("/");
}
function getDetailedVectorObject(vector) {
  const vectorArray = vector.split("/");
  const vectorObject = vectorArray.reduce((vectorObjectAccumulator, vectorItem, index) => {
    const values = vectorItem.split(":");
    const metrics = { ...vectorObjectAccumulator.metrics };
    if (index) {
      const vectorDef = findMetric(values[0], vectorArray[0].split(":")[1]);
      const detailedVectorObject = {
        name: vectorDef?.name,
        abbr: vectorDef?.abbr,
        fullName: `${vectorDef?.name} (${vectorDef?.abbr})`,
        value: vectorDef?.metrics.find((def) => def.abbr === values[1])?.name,
        valueAbbr: values[1]
      };
      return Object.assign(vectorObjectAccumulator, {
        metrics: Object.assign(metrics, {
          [values[0].trim()]: detailedVectorObject
        })
      });
    } else {
      return Object.assign(vectorObjectAccumulator, {
        [values[0].trim()]: values[1]
      });
    }
  }, { metrics: {}, CVSS: "" });
  return vectorObject;
}
function getRating(score) {
  let rating = "None";
  if (score === 0) {
    rating = "None";
  } else if (score <= 3.9) {
    rating = "Low";
  } else if (score <= 6.9) {
    rating = "Medium";
  } else if (score <= 8.9) {
    rating = "High";
  } else {
    rating = "Critical";
  }
  return rating;
}
function isVectorValid(vector) {
  const definitions3 = vector.includes("4.0") ? definitions2 : definitions;
  const expression = definitions3.definitions.reduce((accumulator, currentValue, index) => {
    const serializedAbbr = `${currentValue.abbr}:[${currentValue.metrics.reduce((accumulator2, currentValue2) => {
      return accumulator2 + currentValue2.abbr;
    }, "")}]`;
    if (index !== 0) {
      return `(${accumulator}|${serializedAbbr})`;
    } else {
      return serializedAbbr;
    }
  }, "");
  const totalExpressionVector = new RegExp("^CVSS:(3.(0|1)|4.0)(/" + expression + ")+$");
  if (!totalExpressionVector.test(vector)) {
    return false;
  }
  const allExpressions = definitions3.definitions.map((currentValue) => {
    return new RegExp(`/${currentValue.abbr}:[${currentValue.metrics.reduce((accumulator2, currentValue2) => {
      return accumulator2 + currentValue2.abbr;
    }, "")}]`, "g");
  });
  for (const regex of allExpressions) {
    if ((vector.match(regex) || []).length > 1) {
      return false;
    }
  }
  const mandatoryExpressions = definitions3.definitions.filter((definition) => definition.mandatory).map((currentValue) => {
    return new RegExp(`/${currentValue.abbr}:[${currentValue.metrics.reduce((accumulator2, currentValue2) => {
      return accumulator2 + currentValue2.abbr;
    }, "")}]`, "g");
  });
  for (const regex of mandatoryExpressions) {
    if ((vector.match(regex) || []).length < 1) {
      return false;
    }
  }
  return true;
}
function parseVectorObjectToString(cvssInput) {
  if (typeof cvssInput === "string") {
    return cvssInput;
  }
  let vectorString = `CVSS:${cvssInput["CVSS"]}/`;
  const definitions3 = cvssInput.CVSS === "4.0" ? definitions2 : definitions;
  for (const entry of definitions3["definitions"]) {
    const metric = entry.abbr;
    if (Object.prototype.hasOwnProperty.call(cvssInput, metric)) {
      vectorString += `${metric}:${cvssInput[metric]}/`;
    }
  }
  vectorString = vectorString.slice(0, -1);
  return vectorString;
}
function updateVectorValue(vector, metric, value) {
  const vectorObject = getVectorObject(vector);
  vectorObject[metric] = value;
  const vectorString = parseVectorObjectToString(vectorObject);
  return getCleanVectorString(vectorString);
}
function getVersion(vector) {
  const version = vector.split("/");
  if (version[0] === "CVSS:3.0") {
    return "3.0";
  } else if (version[0] === "CVSS:3.1") {
    return "3.1";
  } else if (version[0] === "CVSS:4.0") {
    return "4.0";
  } else {
    return "Error";
  }
}
var util = {
  roundUpExact,
  roundUpApprox,
  getVectorObject,
  getDetailedVectorObject,
  findMetric,
  findMetricValue,
  getRating,
  updateVectorValue,
  isVectorValid,
  parseVectorObjectToString,
  getVersion,
  getCleanVectorString
};

// lib/score_3_0.ts
function getScore(vector) {
  const vectorObject = util.getVectorObject(vector);
  const scopeChanged = vectorObject.S === "C";
  const ISCBase = calculateISCBase(vectorObject);
  const ISC = calculateISC(ISCBase, scopeChanged, vector);
  if (ISC <= 0)
    return 0;
  const exploitability = calculateExploitability(vectorObject, scopeChanged);
  if (scopeChanged) {
    return roundUp(Math.min(1.08 * (ISC + exploitability), 10), 1, vector);
  }
  return roundUp(Math.min(ISC + exploitability, 10), 1, vector);
}
function getTemporalScore(vector) {
  const vectorObject = util.getVectorObject(vector);
  const baseScore = getScore(vector);
  const eMetric = util.findMetricValue("E", vectorObject);
  const exploitCodeMaturity = eMetric ? eMetric.numerical : 1;
  const rMetric = util.findMetricValue("RL", vectorObject);
  const remediationLevel = rMetric ? rMetric.numerical : 1;
  const rcMetric = util.findMetricValue("RC", vectorObject);
  const reportConfidence = rcMetric ? rcMetric.numerical : 1;
  return roundUp(baseScore * exploitCodeMaturity * remediationLevel * reportConfidence, 1, vector);
}
function calculateISCBase(vectorObject) {
  const cValue = util.findMetricValue("C", vectorObject).numerical;
  const iValue = util.findMetricValue("I", vectorObject).numerical;
  const aValue = util.findMetricValue("A", vectorObject).numerical;
  return 1 - (1 - cValue) * (1 - iValue) * (1 - aValue);
}
function getEnvironmentalScore(vector) {
  const vectorObject = util.getVectorObject(vector);
  const scopeChanged = vectorObject.MS === "X" ? vectorObject.S === "C" : vectorObject.MS === "C";
  const modifiedISCBase = calculateISCModifiedBase(vectorObject);
  const modifiedExploitability = calculateModifiedExploitability(vectorObject, scopeChanged);
  const modifiedISC = calculateModifiedISC(modifiedISCBase, scopeChanged, vector);
  if (modifiedISC <= 0)
    return 0;
  const e = util.findMetricValue("E", vectorObject);
  const rl = util.findMetricValue("RL", vectorObject);
  const rc = util.findMetricValue("RC", vectorObject);
  const eValue = e ? e.numerical : 1;
  const rlValue = rl ? rl.numerical : 1;
  const rcValue = rc ? rc.numerical : 1;
  if (!scopeChanged) {
    return roundUp(roundUp(Math.min(modifiedISC + modifiedExploitability, 10), 1, vector) * eValue * rlValue * rcValue, 1, vector);
  }
  return roundUp(roundUp(Math.min(1.08 * (modifiedISC + modifiedExploitability), 10), 1, vector) * eValue * rlValue * rcValue, 1, vector);
}
function calculateISC(iscBase, scopeChanged, vector) {
  if (!scopeChanged)
    return 6.42 * iscBase;
  if (util.getVersion(vector) === "3.0") {
    return 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
  }
  return 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
}
function calculateModifiedISC(iscBase, scopeChanged, vector) {
  if (!scopeChanged)
    return 6.42 * iscBase;
  if (util.getVersion(vector) === "3.0") {
    return 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
  }
  return 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase * 0.9731 - 0.02, 13);
}
function calculateExploitability(vectorObject, scopeChanged) {
  const avValue = util.findMetricValue("AV", vectorObject).numerical;
  const acValue = util.findMetricValue("AC", vectorObject).numerical;
  const prMetrics = util.findMetricValue("PR", vectorObject).numerical;
  const uiValue = util.findMetricValue("UI", vectorObject).numerical;
  const prValue = scopeChanged ? prMetrics.changed : prMetrics.unchanged;
  return 8.22 * avValue * acValue * prValue * uiValue;
}
function calculateISCModifiedBase(vectorObject) {
  let mcValue = util.findMetricValue("MC", vectorObject);
  let miValue = util.findMetricValue("MI", vectorObject);
  let maValue = util.findMetricValue("MA", vectorObject);
  const crValue = util.findMetricValue("CR", vectorObject).numerical;
  const irValue = util.findMetricValue("IR", vectorObject).numerical;
  const arValue = util.findMetricValue("AR", vectorObject).numerical;
  if (!mcValue || mcValue.abbr === "X")
    mcValue = util.findMetricValue("C", vectorObject);
  if (!miValue || miValue.abbr === "X")
    miValue = util.findMetricValue("I", vectorObject);
  if (!maValue || maValue.abbr === "X")
    maValue = util.findMetricValue("A", vectorObject);
  return Math.min(1 - (1 - mcValue.numerical * crValue) * (1 - miValue.numerical * irValue) * (1 - maValue.numerical * arValue), 0.915);
}
function calculateModifiedExploitability(vectorObject, scopeChanged) {
  let mavValue = util.findMetricValue("MAV", vectorObject);
  let macValue = util.findMetricValue("MAC", vectorObject);
  let mprMetrics = util.findMetricValue("MPR", vectorObject);
  let muiValue = util.findMetricValue("MUI", vectorObject);
  if (!mavValue || mavValue.abbr === "X")
    mavValue = util.findMetricValue("AV", vectorObject);
  if (!macValue || macValue.abbr === "X")
    macValue = util.findMetricValue("AC", vectorObject);
  if (!mprMetrics || mprMetrics.abbr === "X")
    mprMetrics = util.findMetricValue("PR", vectorObject);
  if (!muiValue || muiValue.abbr === "X")
    muiValue = util.findMetricValue("UI", vectorObject);
  const mprValue = scopeChanged ? mprMetrics.numerical.changed : mprMetrics.numerical.unchanged;
  return 8.22 * mavValue.numerical * macValue.numerical * mprValue * muiValue.numerical;
}
function roundUp(num, precision, vector) {
  if (util.getVersion(vector) === "3.0") {
    return util.roundUpApprox(num, precision);
  }
  return util.roundUpExact(num);
}
function getImpactSubScore(vector) {
  const vectorObject = util.getVectorObject(vector);
  const { S } = vectorObject;
  const ISCBase = calculateISCBase(vectorObject);
  return Number(calculateISC(ISCBase, S === "C", vector).toFixed(1));
}
function getExploitabilitySubScore(vector) {
  const vectorObject = util.getVectorObject(vector);
  const { S } = vectorObject;
  return Number(calculateExploitability(vectorObject, S === "C").toFixed(1));
}
var score = {
  getScore,
  getTemporalScore,
  getEnvironmentalScore,
  getImpactSubScore,
  getExploitabilitySubScore
};

// lib/score_4_0.ts
function parseMetric(abbr, vectorObject) {
  const definition = util.findMetric(abbr, vectorObject.CVSS);
  let value = util.findMetricValue(abbr, vectorObject);
  if (vectorObject.CVSS === "4.0") {
    if (abbr == "E" && vectorObject["E"] == "X") {
      return definition?.metrics.find((metric) => metric.abbr === "A");
    }
    if (abbr == "CR" && vectorObject["CR"] == "X") {
      return definition?.metrics.find((metric) => metric.abbr === "H");
    }
    if (abbr == "IR" && vectorObject["IR"] == "X") {
      return definition?.metrics.find((metric) => metric.abbr === "H");
    }
    if (abbr == "AR" && vectorObject["AR"] == "X") {
      return definition?.metrics.find((metric) => metric.abbr === "H");
    }
    if (vectorObject["M" + abbr] !== undefined && vectorObject["M" + abbr] !== "X") {
      const modifiedDefinition = util.findMetric("M" + abbr, vectorObject.CVSS);
      value = definition?.metrics.find((metric) => metric.abbr === vectorObject[modifiedDefinition.abbr]);
    }
  }
  return value;
}
function eq3eq6CalculateLowerMacroVector(eqLevels) {
  if (eqLevels.eq3 === "1" && eqLevels.eq6 === "1") {
    return cvssLookup_global[`${eqLevels.eq1}${eqLevels.eq2}${parseInt(eqLevels.eq3) + 1}${eqLevels.eq4}${eqLevels.eq5}${eqLevels.eq6}`];
  }
  if (eqLevels.eq3 === "1" && eqLevels.eq6 === "0") {
    return cvssLookup_global[`${eqLevels.eq1}${eqLevels.eq2}${eqLevels.eq3}${eqLevels.eq4}${eqLevels.eq5}${parseInt(eqLevels.eq6) + 1}`];
  }
  if (eqLevels.eq3 === "0" && eqLevels.eq6 === "1") {
    return cvssLookup_global[`${eqLevels.eq1}${eqLevels.eq2}${parseInt(eqLevels.eq3) + 1}${eqLevels.eq4}${eqLevels.eq5}${eqLevels.eq6}`];
  }
  if (eqLevels.eq3 === "0" && eqLevels.eq6 === "0") {
    const eq3eq6NextLowerLeftMarcoVector = cvssLookup_global[`${eqLevels.eq1}${eqLevels.eq2}${eqLevels.eq3}${eqLevels.eq4}${eqLevels.eq5}${parseInt(eqLevels.eq6) + 1}`];
    const eq3eq6NextLowerRightMarcoVector = cvssLookup_global[`${eqLevels.eq1}${eqLevels.eq2}${parseInt(eqLevels.eq3) + 1}${eqLevels.eq4}${eqLevels.eq5}${eqLevels.eq6}`];
    return eq3eq6NextLowerLeftMarcoVector > eq3eq6NextLowerRightMarcoVector ? eq3eq6NextLowerLeftMarcoVector : eq3eq6NextLowerRightMarcoVector;
  }
  return cvssLookup_global[`${eqLevels.eq1}${eqLevels.eq2}${parseInt(eqLevels.eq3) + 1}${eqLevels.eq4}${eqLevels.eq5}${parseInt(eqLevels.eq6) + 1}`];
}
function getScore2(vector) {
  const vectorObj = util.getVectorObject(vector);
  const metrics = {
    AV: {},
    PR: {},
    UI: {},
    AC: {},
    AT: {},
    VC: {},
    VI: {},
    VA: {},
    SC: {},
    SI: {},
    SA: {},
    MSI: {},
    MSA: {},
    E: {},
    CR: {},
    IR: {},
    AR: {}
  };
  for (let [key] of Object.entries(metrics)) {
    metrics[key] = parseMetric(key, vectorObj);
  }
  const eqLevels = {
    eq1: "0",
    eq2: "0",
    eq3: "0",
    eq4: "0",
    eq5: "0",
    eq6: "0"
  };
  if (metrics.AV.abbr === "N" && metrics.PR.abbr === "N" && metrics.UI.abbr === "N")
    eqLevels.eq1 = "0";
  if ((metrics.AV.abbr === "N" || metrics.PR.abbr === "N" || metrics.UI.abbr === "N") && !(metrics.AV.abbr === "N" && metrics.PR.abbr === "N" && metrics.UI.abbr === "N") && !(metrics.AV.abbr === "P"))
    eqLevels.eq1 = "1";
  if (metrics.AV.abbr === "P" || !(metrics.AV.abbr === "N" || metrics.PR.abbr === "N" || metrics.UI.abbr === "N"))
    eqLevels.eq1 = "2";
  if (metrics.AC.abbr === "L" && metrics.AT.abbr === "N")
    eqLevels.eq2 = "0";
  if (!(metrics.AC.abbr === "L" && metrics.AT.abbr === "N"))
    eqLevels.eq2 = "1";
  if (metrics.VC.abbr === "H" && metrics.VI.abbr === "H")
    eqLevels.eq3 = "0";
  if (!(metrics.VC.abbr === "H" && metrics.VI.abbr === "H") && (metrics.VC.abbr === "H" || metrics.VI.abbr === "H" || metrics.VA.abbr === "H"))
    eqLevels.eq3 = "1";
  if (!(metrics.VC.abbr === "H" || metrics.VI.abbr === "H" || metrics.VA.abbr === "H"))
    eqLevels.eq3 = "2";
  if (metrics.MSI.abbr === "S" || metrics.MSA.abbr === "S")
    eqLevels.eq4 = "0";
  if (!(metrics.MSI.abbr === "S" || metrics.MSA.abbr === "S") && (metrics.SC.abbr === "H" || metrics.SI.abbr === "H" || metrics.SA.abbr === "H"))
    eqLevels.eq4 = "1";
  if (!(metrics.MSI.abbr === "S" || metrics.MSA.abbr === "S") && !(metrics.SC.abbr === "H" || metrics.SI.abbr === "H" || metrics.SA.abbr === "H"))
    eqLevels.eq4 = "2";
  if (metrics.E.abbr === "A")
    eqLevels.eq5 = "0";
  if (metrics.E.abbr === "P")
    eqLevels.eq5 = "1";
  if (metrics.E.abbr === "U")
    eqLevels.eq5 = "2";
  if ((metrics.CR.abbr === "H" || metrics.CR.abbr === "X") && metrics.VC.abbr === "H" || (metrics.IR.abbr === "H" || metrics.IR.abbr === "X") && metrics.VI.abbr === "H" || (metrics.AR.abbr === "H" || metrics.AR.abbr === "X") && metrics.VA.abbr === "H")
    eqLevels.eq6 = "0";
  if (!((metrics.CR.abbr === "H" || metrics.CR.abbr === "X") && metrics.VC.abbr === "H") && !((metrics.IR.abbr === "H" || metrics.IR.abbr === "X") && metrics.VI.abbr === "H") && !((metrics.AR.abbr === "H" || metrics.AR.abbr === "X") && metrics.VA.abbr === "H"))
    eqLevels.eq6 = "1";
  const macroVector = eqLevels.eq1 + eqLevels.eq2 + eqLevels.eq3 + eqLevels.eq4 + eqLevels.eq5 + eqLevels.eq6;
  const eq1NextLowerMarcoVectorScore = cvssLookup_global[`${parseInt(eqLevels.eq1) + 1}${eqLevels.eq2}${eqLevels.eq3}${eqLevels.eq4}${eqLevels.eq5}${eqLevels.eq6}`];
  const eq2NextLowerMarcoVectorScore = cvssLookup_global[`${eqLevels.eq1}${parseInt(eqLevels.eq2) + 1}${eqLevels.eq3}${eqLevels.eq4}${eqLevels.eq5}${eqLevels.eq6}`];
  const eq4NextLowerMarcoVectorScore = cvssLookup_global[`${eqLevels.eq1}${eqLevels.eq2}${eqLevels.eq3}${parseInt(eqLevels.eq4) + 1}${eqLevels.eq5}${eqLevels.eq6}`];
  const eq5NextLowerMarcoVectorScore = cvssLookup_global[`${eqLevels.eq1}${eqLevels.eq2}${eqLevels.eq3}${eqLevels.eq4}${parseInt(eqLevels.eq5) + 1}${eqLevels.eq6}`];
  let eq3eq6NextLowerMarcoVector = eq3eq6CalculateLowerMacroVector(eqLevels);
  const maxima = {
    eq1: maxComposed["eq1"][parseInt(eqLevels.eq1)],
    eq2: maxComposed["eq2"][parseInt(eqLevels.eq2)],
    eq3eq6: maxComposed["eq3"][parseInt(eqLevels.eq3)][parseInt(eqLevels.eq6)],
    eq4: maxComposed["eq4"][parseInt(eqLevels.eq4)],
    eq5: maxComposed["eq5"][parseInt(eqLevels.eq5)]
  };
  const possibleMaximumVectorStrings = [];
  for (const eq1Max of maxima.eq1) {
    for (const eq2Max of maxima.eq2) {
      for (const eq3eq6Max of maxima.eq3eq6) {
        for (const eq4Max of maxima.eq4) {
          for (const eq5Max of maxima.eq5) {
            possibleMaximumVectorStrings.push("CVSS:4.0/" + eq1Max + eq2Max + eq3eq6Max + eq4Max + eq5Max);
          }
        }
      }
    }
  }
  const eqDistance = { eq1: 0, eq2: 0, eq3eq6: 0, eq4: 0, eq5: 0 };
  outerLoop:
    for (let i = 0;i < possibleMaximumVectorStrings.length; i++) {
      const max = possibleMaximumVectorStrings[i];
      const maxVectorObj = util.getVectorObject(max);
      const severityDistance = {
        AV: 0,
        PR: 0,
        UI: 0,
        AC: 0,
        AT: 0,
        VC: 0,
        VI: 0,
        VA: 0,
        SC: 0,
        SI: 0,
        SA: 0,
        CR: 0,
        IR: 0,
        AR: 0
      };
      innerLoop:
        for (let [key] of Object.entries(severityDistance)) {
          severityDistance[key] = metrics[key].numerical - parseMetric(key, maxVectorObj).numerical;
          if (severityDistance[key] < 0) {
            continue outerLoop;
          }
        }
      eqDistance.eq1 = severityDistance.AV + severityDistance.PR + severityDistance.UI;
      eqDistance.eq2 = severityDistance.AC + severityDistance.AT;
      eqDistance.eq3eq6 = severityDistance.VC + severityDistance.VI + severityDistance.VA + severityDistance.CR + severityDistance.IR + severityDistance.AR;
      eqDistance.eq4 = severityDistance.SC + severityDistance.SI + severityDistance.SA;
      eqDistance.eq5 = 0;
      break;
    }
  const currentMacroVectorValue = cvssLookup_global[macroVector];
  const msd = {
    eq1: currentMacroVectorValue - eq1NextLowerMarcoVectorScore,
    eq2: currentMacroVectorValue - eq2NextLowerMarcoVectorScore,
    eq3eq6: currentMacroVectorValue - eq3eq6NextLowerMarcoVector,
    eq4: currentMacroVectorValue - eq4NextLowerMarcoVectorScore,
    eq5: currentMacroVectorValue - eq5NextLowerMarcoVectorScore
  };
  const step = 0.1;
  const maxSeverityNormalized = {
    eq1: maxSeverity["eq1"][parseInt(eqLevels.eq1)] * step,
    eq2: maxSeverity["eq2"][parseInt(eqLevels.eq2)] * step,
    eq3eq6: maxSeverity["eq3eq6"][parseInt(eqLevels.eq3)][parseInt(eqLevels.eq6)] * step,
    eq4: maxSeverity["eq4"][parseInt(eqLevels.eq4)] * step,
    eq5: maxSeverity["eq5"][parseInt(eqLevels.eq5)] * step
  };
  let count = 0;
  if (!isNaN(msd.eq1)) {
    count++;
    msd.eq1 = msd.eq1 * (eqDistance.eq1 / maxSeverityNormalized.eq1);
  } else {
    msd.eq1 = 0;
  }
  if (!isNaN(msd.eq2)) {
    count++;
    msd.eq2 = msd.eq2 * (eqDistance.eq2 / maxSeverityNormalized.eq2);
  } else {
    msd.eq2 = 0;
  }
  if (!isNaN(msd.eq3eq6)) {
    count++;
    msd.eq3eq6 = msd.eq3eq6 * (eqDistance.eq3eq6 / maxSeverityNormalized.eq3eq6);
  } else {
    msd.eq3eq6 = 0;
  }
  if (!isNaN(msd.eq4)) {
    count++;
    msd.eq4 = msd.eq4 * (eqDistance.eq4 / maxSeverityNormalized.eq4);
  } else {
    msd.eq4 = 0;
  }
  if (!isNaN(msd.eq5)) {
    count++;
    msd.eq5 = 0;
  } else {
    msd.eq5 = 0;
  }
  let mean = 0;
  if (!isNaN(msd.eq1) || !isNaN(msd.eq2) || !isNaN(msd.eq3eq6) || !isNaN(msd.eq4) || !isNaN(msd.eq5)) {
    mean = (msd.eq1 + msd.eq2 + msd.eq3eq6 + msd.eq4 + msd.eq5) / count;
  }
  let vectorScore = currentMacroVectorValue - mean;
  if (vectorScore < 0) {
    vectorScore = 0;
  }
  if (vectorScore > 10) {
    vectorScore = 10;
  }
  return parseFloat(vectorScore.toFixed(1));
}
function getTemporalScore2(vector) {
  throw new Error("This function is not supported for this cvss version");
  return 0;
}
function getEnvironmentalScore2(vector) {
  throw new Error("This function is not supported for this cvss version");
  return 0;
}
function getImpactSubScore2(vector) {
  throw new Error("This function is not supported for this cvss version");
}
function getExploitabilitySubScore2(vector) {
  throw new Error("This function is not supported for this cvss version");
}
var score2 = {
  getScore: getScore2,
  getTemporalScore: getTemporalScore2,
  getEnvironmentalScore: getEnvironmentalScore2,
  getImpactSubScore: getImpactSubScore2,
  getExploitabilitySubScore: getExploitabilitySubScore2
};

// lib/cvss.ts
function CVSS(cvss) {
  const vector = util.parseVectorObjectToString(cvss);
  const score3 = util.getVersion(vector) === "4.0" ? score2 : score;
  function getVectorObject2() {
    return util.getVectorObject(vector);
  }
  function getDetailedVectorObject2() {
    return util.getDetailedVectorObject(vector);
  }
  function getRating2() {
    return util.getRating(getScore3());
  }
  function getTemporalRating() {
    return util.getRating(getTemporalScore3());
  }
  function getEnvironmentalRating() {
    return util.getRating(getEnvironmentalScore3());
  }
  function isVectorValid2() {
    return util.isVectorValid(vector);
  }
  function getVersion2() {
    return util.getVersion(vector);
  }
  function getScore3() {
    return score3.getScore(vector);
  }
  function getTemporalScore3() {
    return score3.getTemporalScore(vector);
  }
  function getEnvironmentalScore3() {
    return score3.getEnvironmentalScore(vector);
  }
  function getCleanVectorString2() {
    return util.getCleanVectorString(vector);
  }
  function updateVectorValue2(metric, value) {
    return util.updateVectorValue(vector, metric, value);
  }
  function getImpactSubScore3() {
    return score3.getImpactSubScore(vector);
  }
  function getExploitabilitySubScore3() {
    return score3.getExploitabilitySubScore(vector);
  }
  const isVersionValid = getVersion2();
  if (isVersionValid === "Error") {
    throw new Error("The vector version is not valid");
  }
  const isValid = isVectorValid2();
  if (!isValid) {
    throw new Error("The vector format is not valid!");
  }
  return {
    vector,
    getScore: getScore3,
    getTemporalScore: getTemporalScore3,
    getEnvironmentalScore: getEnvironmentalScore3,
    getRating: getRating2,
    getTemporalRating,
    getEnvironmentalRating,
    getVectorObject: getVectorObject2,
    getDetailedVectorObject: getDetailedVectorObject2,
    getVersion: getVersion2,
    getCleanVectorString: getCleanVectorString2,
    updateVectorValue: updateVectorValue2,
    getImpactSubScore: getImpactSubScore3,
    getExploitabilitySubScore: getExploitabilitySubScore3,
    isVersionValid,
    isValid
  };
}
export {
  CVSS
};
