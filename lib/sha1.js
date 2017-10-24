/*!
 * sha1.js - sha1 for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/sha1');
} catch (e) {
  module.exports = require('./node/sha1');
}
