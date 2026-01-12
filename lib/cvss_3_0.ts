import { CvssVersionDefinition } from "./types";

export const definitions: CvssVersionDefinition = {
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

// Pre-built lookup maps for O(1) access
export const metricMap: Record<string, typeof definitions.definitions[0]> = {};
export const metricValueMap: Record<string, Record<string, typeof definitions.definitions[0]["metrics"][0]>> = {};

for (const def of definitions.definitions) {
  metricMap[def.abbr] = def;
  metricValueMap[def.abbr] = {};
  for (const metric of def.metrics) {
    metricValueMap[def.abbr][metric.abbr] = metric;
  }
}
