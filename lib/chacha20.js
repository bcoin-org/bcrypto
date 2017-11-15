/*!
 * chacha20.js - chacha20 for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/chacha20');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/chacha20');
  else
    module.exports = require('./node/chacha20');
}
