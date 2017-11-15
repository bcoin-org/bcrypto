/*!
 * keccak.js - keccak for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/keccak');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/keccak');
  else
    module.exports = require('./node/keccak');
}
