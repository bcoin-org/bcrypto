/*!
 * secp256k1.js - secp256k1 for bcrypto
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const ECDSA = require('./ecdsa');

/**
 * Secp256k1
 */

class Secp256k1 extends ECDSA {
  constructor() {
    super('SECP256K1');
  }

  schnorrSign(msg, key) {
    return this.ec.schnorrSign(msg, key);
  }

  schnorrVerify(msg, sig, key) {
    return this.ec.schnorrVerify(msg, sig, key);
  }
}

/*
 * Expose
 */

module.exports = new Secp256k1();
