/*!
 * keccak.js - keccak for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

let Keccak;

if (process.env.NODE_BACKEND === 'js')
  Keccak = require('./js/keccak');
else
  Keccak = require('./native/keccak');

module.exports = Keccak;
