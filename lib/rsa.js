/*!
 * rsa.js - RSA for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/rsa');
} catch (e) {
  module.exports = require('./js/rsa');
}
