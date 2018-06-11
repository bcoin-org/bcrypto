/*!
 * eddsa.js - EDDSA for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/eddsa');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/eddsa');
  else
    module.exports = require('./node/eddsa');
}
