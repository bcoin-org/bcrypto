/*!
 * ripemd160.js - ripemd160 for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/ripemd160');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/ripemd160');
  else
    module.exports = require('./node/ripemd160');
}
