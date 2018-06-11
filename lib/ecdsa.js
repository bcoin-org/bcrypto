/*!
 * ecdsa.js - ECDSA for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/ecdsa');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/ecdsa');
  else
    module.exports = require('./node/ecdsa');
}
