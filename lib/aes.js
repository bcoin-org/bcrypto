/*!
 * aes.js - aes for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/aes');
} catch (e) {
  module.exports = require('./node/aes');
}
