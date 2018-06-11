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

  static multi(one, two, three, bits = 256) {
    return super.multi(one, two, three, bits, true);
  }

  static mac(data, key, bits = 256) {
    throw new Error('Not implemented.');
  }
}

SHA3.native = 0;
SHA3.id = 'sha3-256';
SHA3.size = 32;
SHA3.bits = 256;
SHA3.blockSize = 136;
SHA3.zero = Buffer.alloc(32, 0x00);
SHA3.ctx = new SHA3();

/*
 * Expose
 */

module.exports = SHA3;
