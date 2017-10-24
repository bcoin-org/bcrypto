/*!
 * keccak.js - keccak for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/keccak');
} catch (e) {
  module.exports = require('./node/keccak');
}
