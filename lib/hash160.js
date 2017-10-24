/*!
 * hash160.js - hash160 for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/hash160');
} catch (e) {
  module.exports = require('./node/hash160');
}
