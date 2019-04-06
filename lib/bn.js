/*!
 * bn.js - big numbers for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

try {
  try {
    module.exports = require('./native/bn.js');
  } catch (e) {
    module.exports = require('./node/bn.js');
  }
} catch (e) {
  module.exports = require('./js/bn.js');
}
