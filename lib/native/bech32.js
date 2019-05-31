/*!
 * bech32.js - bech32 for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {bech32} = require('./binding');

bech32.native = 2;

module.exports = bech32;
