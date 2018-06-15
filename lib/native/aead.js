/*!
 * aead.js - aead for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const {AEAD} = require('./binding');

AEAD.native = 2;

module.exports = AEAD;
