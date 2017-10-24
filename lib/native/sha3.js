/*!
 * sha3.js - SHA3 implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const {Keccak} = require('./binding');

class SHA3 extends Keccak {
  constructor() {
    super();
  }
  final() {
    return super.final(true);
  }
  static hash() {
    return new SHA3();
  }
  static hmac() {
    throw new Error('Not implemented.');
  }
  static digest(data, bits = 256) {
    return super.digest(data, bits, true);
  }
  static root(left, right, bits = 256) {
    return super.root(left, right, bits, true);
  }
  static mac() {
    throw new Error('Not implemented.');
  }
}

module.exports = SHA3;
