/*!
 * sha3-512.js - sha3-512 implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const SHA3 = require('./sha3');

/**
 * SHA3-512
 */

class SHA3_512 extends SHA3 {
  /**
   * Create a SHA3-512 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init() {
    return super.init(512);
  }

  static hash() {
    return new SHA3_512();
  }

  static hmac() {
    throw new Error('Not implemented.');
  }

  static digest(data) {
    return super.digest(data, 512);
  }

  static root(left, right) {
    return super.root(left, right, 512);
  }

  static multi(one, two, three) {
    return super.multi(one, two, three, 512);
  }

  static mac(data) {
    throw new Error('Not implemented.');
  }
}

SHA3_512.native = SHA3.native;
SHA3_512.id = 'sha3-512';
SHA3_512.size = 64;
SHA3_512.bits = 512;
SHA3_512.blockSize = 72;
SHA3_512.zero = Buffer.alloc(64, 0x00);
SHA3_512.ctx = new SHA3_512();

/*
 * Expose
 */

module.exports = SHA3_512;
