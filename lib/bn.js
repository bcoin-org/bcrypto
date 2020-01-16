/*!
 * bn.js - big numbers for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

if (process.env.BCRYPTO_FORCE_BIGINT || process.env.NODE_BACKEND !== 'js') {
  try {
    module.exports = require('./node/bn.js');
  } catch (e) {
    module.exports = require('./js/bn.js');
  }
} else {
  module.exports = require('./js/bn.js');
}
