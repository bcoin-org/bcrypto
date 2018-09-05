/*!
 * ed25519.js - ed25519 for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/ed25519');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/ed25519');
  else
    module.exports = require('./node/ed25519');
}
