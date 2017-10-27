/*!
 * sha256.js - sha256 for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/sha256');
} catch (e) {
  if (process.env.BCRYPTO_USE_JS)
    module.exports = require('./js/sha256');
  else
    module.exports = require('./node/sha256');
}
