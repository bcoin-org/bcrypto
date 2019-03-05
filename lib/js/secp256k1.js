/*!
 * secp256k1.js - secp256k1 for bcrypto
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const ECDSA = require('./ecdsa');

class Secp256k1 extends ECDSA {
  constructor() {
    super('SECP256K1');
  }

  signRecoverable(msg, key) {
    const sig = this._sign(msg, key);

    return {
      signature: sig.encode(this.size),
      recovery: sig.param
    };
  }

  signRecoverableDER(msg, key) {
    const sig = this._sign(msg, key);

    return {
      signature: sig.toDER(this.size),
      recovery: sig.param
    };
  }
}

/*
 * Expose
 */

module.exports = new Secp256k1();
