/*!
 * blake2b.js - blake2b for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/blake2b');
} catch (e) {
  if (process.env.BCRYPTO_USE_JS)
    module.exports = require('./js/blake2b');
  else
    module.exports = require('./node/blake2b');
}
