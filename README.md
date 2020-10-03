<h1 align="center">cvss.js by <a href="https://turingpoint.eu" target="_blank">turingpoint.</a></h1>
<p>
  <img alt="Version" src="https://img.shields.io/badge/version-1.2.0-blue.svg?cacheSeconds=2592000" />
  <a href="#" target="_blank">
    <img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-yellow.svg" />
  </a>
</p>

> A tiny library to work with [CVSS vectors](https://www.first.org/cvss/v3.0/specification-document) in JavaScript

Note: We currently only support vectors from CVSS version 3.0.

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

## Usage

```js
const CVSS = require("@turingpointde/cvss.js");

const vector = CVSS("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R");

console.log(vector.getScore()); // 5.5
console.log(vector.getTemporalScore()); // 4.7
console.log(vector.getRating()); // Medium - Based on Qualitative Severity Rating Scale
console.log(vector.isVectorValid()); // { message: 'This vector is valid', isValid: true }
console.log(vector.vector); //  CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R
console.log(vector.getVectorObject()); // { CVSS: "3.0", AV: "N", AC: "H", PR: "L", UI: "R", S: "C", C: "L", I: "L", A: "L", E: "U", RL: "T", RC: "R" }
console.log(vector.getDetailedVectorObject());
/* { 
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
} */
```

## Contributing

Contributions, issues and feature requests are welcome.
Feel free to check out the [issues page](https://github.com/turingpointde/cvss.js/issues) if you want to contribute.

## License

Copyright © 2020 [turingpoint GmbH](https://turingpoint.eu).
This project is [MIT](LICENSE) licensed.
