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
        { name: "Adjacent", abbr: "A", numerical: 0 },
        { name: "Local", abbr: "L", numerical: 0 },
        { name: "Physical", abbr: "P", numerical: 0 }
      ]
    },
    {
      metricGroup: "Base",
      name: "Attack Complexity",
      abbr: "AC",
      mandatory: true,
      metrics: [
        { name: "Low", abbr: "L", numerical: 0 },
        { name: "High", abbr: "H", numerical: 0 }
      ]
    },
    {
      metricGroup: "Base",
      name: "Attack Requirements",
      abbr: "AT",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0 },
        { name: "Present", abbr: "P", numerical: 0 }
      ]
    },
    {
      metricGroup: "Base",
      name: "Privileges Required",
      abbr: "PR",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0 },
        { name: "High", abbr: "H", numerical: 0 }
      ]
    },
    {
      metricGroup: "Base",
      name: "User Interaction",
      abbr: "UI",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0 },
        { name: "Passive", abbr: "P", numerical: 0 },
        { name: "Active", abbr: "A", numerical: 0 }
      ]
    },
    {
      metricGroup: "Base",
      name: "Vulnerable System Confidentiality Impact",
      abbr: "VC",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0 },
        { name: "High", abbr: "H", numerical: 0 }
      ]
    },
    {
      metricGroup: "Base",
      name: "Vulnerable System Integrity Impact",
      abbr: "VI",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0 },
        { name: "High", abbr: "H", numerical: 0 }
      ]
    },
    {
      metricGroup: "Base",
      name: "Vulnerable System Availability Impact",
      abbr: "VA",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0 },
        { name: "High", abbr: "H", numerical: 0 }
      ]
    },
    {
      metricGroup: "Base",
      name: "Subsequent System Confidentiality Impact",
      abbr: "SC",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0 },
        { name: "High", abbr: "H", numerical: 0 }
      ]
    },
    {
      metricGroup: "Base",
      name: "Subsequent System Integrity Impact",
      abbr: "SI",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0 },
        { name: "High", abbr: "H", numerical: 0 }
      ]
    },
    {
      metricGroup: "Base",
      name: "Subsequent System Availability Impact",
      abbr: "SA",
      mandatory: true,
      metrics: [
        { name: "None", abbr: "N", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0 },
        { name: "High", abbr: "H", numerical: 0 }
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
        { name: "POC", abbr: "P", numerical: 0 },
        { name: "Unreported", abbr: "U", numerical: 0 }
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
        { name: "Medium", abbr: "M", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0 }
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
        { name: "Medium", abbr: "M", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0 }
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
        { name: "Medium", abbr: "M", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0 }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Modified Attack Vector",
      abbr: "MAV",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 0 },
        { name: "Network", abbr: "N", numerical: 0 },
        { name: "Adjacent", abbr: "A", numerical: 0 },
        { name: "Local", abbr: "L", numerical: 0 },
        { name: "Physical", abbr: "P", numerical: 0 }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Modified Attack Complexity",
      abbr: "MAC",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 0 },
        { name: "High", abbr: "H", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0 }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Modified Attack Requirements ",
      abbr: "MAT",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 0 },
        { name: "None", abbr: "N", numerical: 0 },
        { name: "Present", abbr: "P", numerical: 0 }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Modified Privileges Required",
      abbr: "MPR",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 0 },
        { name: "High", abbr: "H", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0 },
        { name: "None", abbr: "N", numerical: 0 }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Modified User Interaction",
      abbr: "MUI",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 0 },
        { name: "None", abbr: "N", numerical: 0 },
        { name: "Passive", abbr: "P", numerical: 0 },
        { name: "Active", abbr: "A", numerical: 0 }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Modified Vulnerable System Confidentiality",
      abbr: "MVC",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 0 },
        { name: "High", abbr: "H", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0 },
        { name: "None", abbr: "N", numerical: 0 }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Modified Vulnerable System Integrity",
      abbr: "MVI",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 0 },
        { name: "High", abbr: "H", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0 },
        { name: "None", abbr: "N", numerical: 0 }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Modified Vulnerable System Availability",
      abbr: "MVA",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 0 },
        { name: "High", abbr: "H", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0 },
        { name: "None", abbr: "N", numerical: 0 }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Modified Subsequent System Confidentiality",
      abbr: "MSC",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 0 },
        { name: "High", abbr: "H", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0 },
        { name: "Negligible", abbr: "N", numerical: 0 }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Modified Subsequent System Integrity",
      abbr: "MSI",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 0 },
        { name: "High", abbr: "H", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0 },
        { name: "Negligible", abbr: "N", numerical: 0 },
        { name: "Safety", abbr: "S", numerical: 0 }
      ]
    },
    {
      metricGroup: "Enviromental",
      name: "Modified Subsequent System Availability",
      abbr: "MSA",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 0 },
        { name: "High", abbr: "H", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0 },
        { name: "Negligible", abbr: "N", numerical: 0 },
        { name: "Safety", abbr: "S", numerical: 0 }
      ]
    },
    {
      metricGroup: "Supplemental",
      name: "Safety",
      abbr: "S",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 0 },
        { name: "Negligible", abbr: "N", numerical: 0 },
        { name: "Present", abbr: "P", numerical: 0 }
      ]
    },
    {
      metricGroup: "Supplemental",
      name: "Automatable",
      abbr: "Au",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 0 },
        { name: "No", abbr: "N", numerical: 0 },
        { name: "Yes", abbr: "Y", numerical: 0 }
      ]
    },
    {
      metricGroup: "Supplemental",
      name: "Recovery",
      abbr: "R",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 0 },
        { name: "Automatic", abbr: "A", numerical: 0 },
        { name: "User", abbr: "U", numerical: 0 },
        { name: "Irrecoverable", abbr: "I", numerical: 0 }
      ]
    },
    {
      metricGroup: "Supplemental",
      name: "Value Density",
      abbr: "V",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 0 },
        { name: "Diffuse", abbr: "D", numerical: 0 },
        { name: "Concentrated", abbr: "C", numerical: 0 }
      ]
    },
    {
      metricGroup: "Supplemental",
      name: "Vulnerability Response Effort",
      abbr: "RE",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 0 },
        { name: "Low", abbr: "L", numerical: 0 },
        { name: "Moderate", abbr: "M", numerical: 0 },
        { name: "High", abbr: "H", numerical: 0 }
      ]
    },
    {
      metricGroup: "Supplemental",
      name: "Provider Urgency",
      abbr: "U",
      mandatory: false,
      metrics: [
        { name: "Not Defined", abbr: "X", numerical: 0 },
        { name: "Clear", abbr: "Clear", numerical: 0 },
        { name: "Green", abbr: "Green", numerical: 0 },
        { name: "Amber", abbr: "Amber", numerical: 0 },
        { name: "Red", abbr: "Red", numerical: 0 }
      ]
    }
  ]
};
