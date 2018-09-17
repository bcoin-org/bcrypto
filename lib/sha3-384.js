/*!
 * sha3-384.js - sha3-384 implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const SHA3 = require('./sha3');

/**
 * SHA3-384
 */

class SHA3_384 extends SHA3 {
  /**
   * Create a SHA3-384 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init() {
    return super.init(384);
  }

  static hash() {
    return new SHA3_384();
  }

  static hmac() {
    throw new Error('Not implemented.');
  }

  static digest(data) {
    return super.digest(data, 384);
  }

  static root(left, right) {
    return super.root(left, right, 384);
  }

  static multi(one, two, three) {
    return super.multi(one, two, three, 384);
  }

  static mac(data) {
    throw new Error('Not implemented.');
  }
}

SHA3_384.native = SHA3.native;
SHA3_384.id = 'SHA3_384';
SHA3_384.size = 48;
SHA3_384.bits = 384;
SHA3_384.blockSize = 104;
SHA3_384.zero = Buffer.alloc(48, 0x00);
SHA3_384.ctx = new SHA3_384();

/*
 * Expose
 */

module.exports = SHA3_384;
