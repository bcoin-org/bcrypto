/*!
 * chacha20.js - chacha20 for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const {ChaCha20} = require('./binding');

ChaCha20.native = 2;

module.exports = ChaCha20;
