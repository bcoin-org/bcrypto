/*!
 * bcrypto
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

if (process.env.BCRYPTO_BACKEND && process.env.BCRYPTO_BACKEND !== 'native')
  throw new Error('Non-native backend selected.');

module.exports = require('bindings')('bcrypto');
