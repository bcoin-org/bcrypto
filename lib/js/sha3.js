/*!
 * sha3.js - SHA3 implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const Keccak = require('./keccak');

/**
 * SHA3
 */

class SHA3 extends Keccak {
  /**
   * Create a SHA3 Context.
   * @constructor
   */

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

  static mac(data, key, bits = 256) {
    throw new Error('Not implemented.');
  }
}

/*
 * Expose
 */

module.exports = SHA3;
