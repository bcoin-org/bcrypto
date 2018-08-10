/*!
 * secp256k1.js - secp256k1 for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const ECDSA = require('./ecdsa');

module.exports = new ECDSA('secp256k1');
