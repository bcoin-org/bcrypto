/*!
 * scrypt.js - scrypt for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/scrypt');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/scrypt');
  else
    module.exports = require('./node/scrypt');
}
