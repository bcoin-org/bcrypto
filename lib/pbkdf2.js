/*!
 * pbkdf2.js - pbkdf2 for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/pbkdf2');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/pbkdf2');
  else
    module.exports = require('./node/pbkdf2');
}
