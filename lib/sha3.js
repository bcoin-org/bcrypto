/*!
 * sha3.js - sha3 for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/sha3');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/sha3');
  else
    module.exports = require('./node/sha3');
}
