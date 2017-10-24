/*!
 * bcrypto
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

if (process.env.BCOIN_NO_NATIVE || process.env.BCOIN_USE_JS)
  throw new Error('Cannot use native bindings.');

module.exports = require('bindings')('bcrypto');
