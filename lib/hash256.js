/*!
 * hash256.js - hash256 for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/hash256');
} catch (e) {
  module.exports = require('./node/hash256');
}
