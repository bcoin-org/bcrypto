/*!
 * blake2b256.js - BLAKE2b implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const Blake2b = require('./blake2b');

/**
 * Blake2b256
 */

class Blake2b256 extends Blake2b {
  /**
   * Create a Blake2b256 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init(key = null) {
    return super.init(32, key);
  }

  static hash() {
    return new Blake2b256();
  }

  static hmac() {
    return new Blake2b256Hmac();
  }

  static digest(data, key = null) {
    return super.digest(data, 32, key);
  }

  static root(left, right) {
    return super.root(left, right, 32);
  }

  static multi(one, two, three) {
    return super.multi(one, two, three, 32);
  }

  static mac(data, key) {
    return super.mac(data, key, 32);
  }
}

Blake2b256.native = Blake2b.native;
Blake2b256.id = 'blake2b256';
Blake2b256.size = 32;
Blake2b256.bits = 256;
Blake2b256.blockSize = 128;
Blake2b256.zero = Buffer.alloc(32, 0x00);
Blake2b256.ctx = new Blake2b256();

/**
 * Blake2b256 HMAC
 * @private
 */

class Blake2b256Hmac extends Blake2b256 {
  constructor() {
    super();
  }

  init(key) {
    assert(Buffer.isBuffer(key));
    return super.init(key);
  }
}

/*
 * Expose
 */

module.exports = Blake2b256;
