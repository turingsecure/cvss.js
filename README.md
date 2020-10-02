<h1 align="center">cvss.js by <a href="https://turingpoint.eu" target="_blank">turingpoint GmbH</a></h1>
<p>
  <img alt="Version" src="https://img.shields.io/badge/version-1.0.0-blue.svg?cacheSeconds=2592000" />
  <a href="#" target="_blank">
    <img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-yellow.svg" />
  </a>
</p>

> A tiny library to work with cvss vectors

## Install

TODO: Implement after the package was published to npm.

## Usage

```js
const CVSS = require("@turingpointde/cvss.js");

const vector = CVSS("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:L");

console.log(vector.getScore()); // 4.4
console.log(vector.vector); // CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:L
```

## Contributing

Contributions, issues and feature requests are welcome.
Feel free to check out the [issues page](https://github.com/turingpointde/cvss.js/issues) if you want to contribute.

## License

Copyright © 2020 [turingpoint GmbH](https://turingpoint.eu).
This project is [MIT](LICENSE) licensed.
