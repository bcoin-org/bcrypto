/*!
 * hash256.js - hash256 for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/hash256');
} catch (e) {
  if (process.env.BCRYPTO_USE_JS)
    module.exports = require('./js/hash256');
  else
    module.exports = require('./node/hash256');
}
