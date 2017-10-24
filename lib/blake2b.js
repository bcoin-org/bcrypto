/*!
 * blake2b.js - blake2b for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/blake2b');
} catch (e) {
  module.exports = require('./node/blake2b');
}
