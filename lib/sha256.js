/*!
 * sha256.js - sha256 for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  module.exports = require('./native/sha256');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/sha256');
  else if (process.env.NODE_BACKEND === 'node')
    module.exports = require('./node/sha256');
  else
    throw new Error(
      'Error locating bindings. '
      + 'export NODE_BACKEND=<js|node> or rebuild bcrypto with node-gyp.'
    )
}
