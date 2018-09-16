/*!
 * secp256k1.js - secp256k1 for bcrypto
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const ECDSA = require('./ecdsa');

/*
 * Expose
 */

module.exports = new ECDSA('SECP256K1');
