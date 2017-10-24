/*!
 * sha512.js - sha512 for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/sha512');
} catch (e) {
  module.exports = require('./node/sha512');
}
