<h1 align="center">cvss.js by <a href="https://turingpoint.eu" target="_blank">turingpoint.</a></h1>
<p>
  <img alt="Version" src="https://img.shields.io/badge/version-1.4.0-blue.svg?cacheSeconds=2592000" />
  <a href="#" target="_blank">
    <img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-yellow.svg" />
  </a>
</p>

> A tiny library to work with [CVSS vectors](https://www.first.org/cvss/v3.0/specification-document) (v3.0 and v3.1) in JavaScript. The Common Vulnerability Scoring System (CVSS) is a free and open standard. It is owned and managed by [FIRST.Org](https://first.org).

## Installation

Install the `@turingpointde/cvss.js` package:

```sh
# use yarn or npm
yarn add @turingpointde/cvss.js
```

Import the library to use it in your code:

```js
const CVSS = require("@turingpointde/cvss.js");
// or
import CVSS from "@turingpointde/cvss.js";
```

You can also use the library directly from the **CDN** (instead of yarn or npm):

```html
<script src="https://unpkg.com/@turingpointde/cvss.js@latest/dist/production.min.js"></script>
```

## Usage

After importing the library, the CVSS function must first be called with the vector as parameter.

```js
// Vector only with base score
const vector1 = CVSS("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:L");
// Vector with temporal score
const vector2 = CVSS("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R");
// Vector with environmental score
const vector3 = CVSS(
  "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N/CR:M/IR:H/AR:M/MAV:N/MAC:H/MPR:L/MUI:N/MS:C/MC:N/MI:L/MA:L"
);
```

It is possible to pass in an object as well

```js
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

console.log(CVSS(vectorObject).vector); // "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:N"
```

To get the scores, simply call the respective function.

```js
// Create a vector
const vector = CVSS(
  "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N/E:P/RL:O/CR:M/IR:H/AR:M/MAV:N/MAC:H/MPR:L/MUI:N/MS:C/MC:N/MI:L/MA:L"
);

console.log(vector.getScore()); // 3.6
console.log(vector.getTemporalScore()); // 3.3
console.log(vector.getEnvironmentalScore()); // 5.1
```

Sometimes it is useful to get a qualitative rating of a score

```js
const vector = CVSS("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:L");

console.log(vector.getRating()); // Medium
```

A few useful variables/functions to work with the vectors:

```js
const vector = CVSS("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:L");

console.log(vector.isValid); // true
console.log(vector.vector); // CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:L
console.log(vector.getVersion()); // "3.0"
```

The following functions are suitable for displaying the vector in a human-readable form or for performing your own calculations with the vector

```js
const vector = CVSS("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R");

console.log(vector.getVectorObject()); // { CVSS: "3.0", AV: "N", AC: "H", PR: "L", UI: "R", S: "C", C: "L", I: "L", A: "L", E: "U", RL: "T", RC: "R", CR: "X", IR: "X", AR: "X", MAV: "X", MAC: "X", MPR: "X", MUI: "X", MS: "X" , MC: "X", MI: "X", MA: "X" }
console.log(vector.getDetailedVectorObject()); // see spoiler below
```

<details>
  <summary>Output of vector.getDetailedVectorObject</summary>

```js
  {
    CVSS: '3.0',
    metrics: {
      AV: {
        name: 'Attack Vector',
        abbr: 'AV',
        fullName: 'Attack Vector (AV)',
        value: 'Network',
        valueAbbr: 'N'
      },
      AC: {
        name: 'Attack Complexity',
        abbr: 'AC',
        fullName: 'Attack Complexity (AC)',
        value: 'High',
        valueAbbr: 'H'
      },
      PR: {
        name: 'Privileges Required',
        abbr: 'PR',
        fullName: 'Privileges Required (PR)',
        value: 'Low',
        valueAbbr: 'L'
      },
      UI: {
        name: 'User Interaction',
        abbr: 'UI',
        fullName: 'User Interaction (UI)',
        value: 'Required',
        valueAbbr: 'R'
      },
      S: {
        name: 'Scope',
        abbr: 'S',
        fullName: 'Scope (S)',
        value: 'Changed',
        valueAbbr: 'C'
      },
      C: {
        name: 'Confidentiality',
        abbr: 'C',
        fullName: 'Confidentiality (C)',
        value: 'Low',
        valueAbbr: 'L'
      },
      I: {
        name: 'Integrity',
        abbr: 'I',
        fullName: 'Integrity (I)',
        value: 'Low',
        valueAbbr: 'L'
      },
      A: {
        name: 'Availability',
        abbr: 'A',
        fullName: 'Availability (A)',
        value: 'Low',
        valueAbbr: 'L'
      },
      E: {
        name: 'Exploit Code Maturity',
        abbr: 'E',
        fullName: 'Exploit Code Maturity (E)',
        value: 'Unproven',
        valueAbbr: 'U'
      },
      RL: {
        name: 'Remediation Level',
        abbr: 'RL',
        fullName: 'Remediation Level (RL)',
        value: 'Temporary Fix',
        valueAbbr: 'T'
      },
      RC: {
        name: 'Report Confidence',
        abbr: 'RC',
        fullName: 'Report Confidence (RC)',
        value: 'Reasonable',
        valueAbbr: 'R'
      }
    }
  }
```

</details>

## Contributing

Contributions, issues and feature requests are welcome.
Feel free to check out the [issues page](https://github.com/turingpointde/cvss.js/issues) if you want to contribute.

## License

Copyright © 2020 [turingpoint GmbH](https://turingpoint.eu).
This project is [MIT](LICENSE) licensed.
