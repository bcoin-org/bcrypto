/*!
 * secp256k1.js - secp256k1 for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/secp256k1');
} catch (e) {
  if (process.env.BCRYPTO_USE_JS)
    module.exports = require('./js/secp256k1');
  else
    module.exports = require('./node/secp256k1');
}
