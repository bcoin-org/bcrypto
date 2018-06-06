/*!
 * sha384.js - SHA384 for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/sha384');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/sha384');
  else
    module.exports = require('./node/sha384');
}
