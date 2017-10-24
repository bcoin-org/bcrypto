/*!
 * aes.js - aes for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/aes');
} catch (e) {
  if (process.env.BCOIN_USE_JS)
    module.exports = require('./js/aes');
  else
    module.exports = require('./node/aes');
}
