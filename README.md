<h1 align="center">cvss.js by <a href="https://turingpoint.eu" target="_blank">turingpoint.</a></h1>
<p>
  <img alt="Version" src="https://img.shields.io/badge/version-1.1.1-blue.svg?cacheSeconds=2592000" />
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

const vector = CVSS(" CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R");

console.log(vector.getScore()); // 5.5
console.log(vector.getTemporalScore()); // 4.7
console.log(vector.getRating()); // Medium - Based on Qualitative Severity Rating Scale
console.log(vector.vector); //  CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R
console.log(vector.getVectorObject()); // { CVSS: "3.0", AV: "N", AC: "H", PR: "L", UI: "R", S: "C", C: "L", I: "L", A: "L", E: "U", RL: "T", RC: "R" }
```

## Contributing

Contributions, issues and feature requests are welcome.
Feel free to check out the [issues page](https://github.com/turingpointde/cvss.js/issues) if you want to contribute.

## License

Copyright © 2020 [turingpoint GmbH](https://turingpoint.eu).
This project is [MIT](LICENSE) licensed.
