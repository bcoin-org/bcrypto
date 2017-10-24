/*!
 * scrypt.js - scrypt for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/scrypt');
} catch (e) {
  module.exports = require('./node/scrypt');
}
