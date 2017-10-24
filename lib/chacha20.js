/*!
 * chacha20.js - chacha20 for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/chacha20');
} catch (e) {
  module.exports = require('./node/chacha20');
}
