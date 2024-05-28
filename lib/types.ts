export type CvssVectorObject = {
  AV: "N" | "A" | "L" | "P";
  AC: "L" | "H";
  PR: "N" | "L" | "H";
  UI: "N" | "R";
  S: "U" | "C";
  C: "N" | "L" | "H";
  I: "N" | "L" | "H";
  A: "N" | "L" | "H";
  E?: "X" | "H" | "F" | "P" | "U";
  RL?: "X" | "U" | "W" | "T" | "O";
  RC?: "X" | "C" | "R" | "U";
  CR?: "X" | "H" | "M" | "L";
  IR?: "X" | "H" | "M" | "L";
  AR?: "X" | "H" | "M" | "L";
  MAV?: "X" | "N" | "A" | "L" | "P";
  MAC?: "X" | "L" | "H";
  MPR?: "X" | "N" | "L" | "H";
  MUI?: "X" | "N" | "R";
  MS?: "X" | "U" | "C";
  MC?: "X" | "N" | "L" | "H";
  MI?: "X" | "N" | "L" | "H";
  MA?: "X" | "N" | "L" | "H";
  CVSS: string;
};

type DetailedMetric = {
  name: string;
  abbr: string;
  fullName: string;
  value: string;
  valueAbbr: string;
};

export type DetailedVectorObject = { metrics: DetailedMetric[]; CVSS: string };

export type Metric = {
  name: string;
  abbr: string;
  numerical: number;
};

export type MetricPrivilegesRequired = {
  name: string;
  abbr: string;
  numerical: { changed: number; unchanged: number };
};

export type MetricScope = {
  name: string;
  abbr: string;
};

export type MetricUnion = Metric | MetricScope | MetricPrivilegesRequired;

export type Definition = {
  name: string;
  abbr: string;
  mandatory: boolean;
  metrics: MetricUnion[];
};

export type CvssVersionDefinition = {
  version: string;
  definitions: Definition[];
};
export type CvssLookup = { [key: string]: number };

export type MaxComposed = {
  [key: string]: { [key: number]: { [key: string]: string[] } | string[] };
};

export type MaxSeverity = { [key: string]: { [key: number]: { [key: number]: number } | number } };
