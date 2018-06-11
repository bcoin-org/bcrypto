/*!
 * sha3-256.js - sha3-256 implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const SHA3 = require('./sha3');

/**
 * SHA3-256
 */

class SHA3_256 extends SHA3 {
  /**
   * Create a SHA3-256 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init() {
    return super.init(256);
  }

  static hash() {
    return new SHA3_256();
  }

  static hmac() {
    throw new Error('Not implemented.');
  }

  static digest(data) {
    return super.digest(data, 256);
  }

  static root(left, right) {
    return super.root(left, right, 256);
  }

  static multi(one, two, three) {
    return super.multi(one, two, three, 256);
  }

  static mac(data) {
    throw new Error('Not implemented.');
  }
}

SHA3_256.native = SHA3.native;
SHA3_256.id = 'sha3-256';
SHA3_256.size = 32;
SHA3_256.bits = 256;
SHA3_256.blockSize = 128;
SHA3_256.zero = Buffer.alloc(32, 0x00);
SHA3_256.ctx = new SHA3_256();

/*
 * Expose
 */

module.exports = SHA3_256;
