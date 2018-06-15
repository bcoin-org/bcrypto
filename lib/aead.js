/*!
 * aead.js - aead for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/aead');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/aead');
  else
    module.exports = require('./node/aead');
}
