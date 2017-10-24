/*!
 * pbkdf2.js - pbkdf2 for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/pbkdf2');
} catch (e) {
  module.exports = require('./node/pbkdf2');
}
