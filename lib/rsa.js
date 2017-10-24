/*!
 * rsa.js - rsa for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/rsa');
} catch (e) {
  module.exports = require('./node/rsa');
}
