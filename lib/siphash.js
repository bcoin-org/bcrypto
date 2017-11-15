/*!
 * siphash.js - siphash for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/siphash');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/siphash');
  else
    module.exports = require('./node/siphash');
}
