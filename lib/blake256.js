/*!
 * blake256.js - BLAKE2b implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const Blake2b = require('./blake2b');

/**
 * Blake256
 */

class Blake256 extends Blake2b {
  /**
   * Create a Blake256 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init(key = null) {
    return super.init(32, key);
  }

  static hash() {
    return new Blake256();
  }

  static hmac() {
    return new Blake256Hmac();
  }

  static digest(data, key = null) {
    return Blake2b.digest(data, 32, key);
  }

  static root(left, right) {
    return Blake2b.root(left, right, 32);
  }

  static multi(one, two, three) {
    return Blake2b.multi(one, two, three, 32);
  }

  static mac(data, key) {
    return Blake2b.mac(data, key, 32);
  }
}

Blake256.id = 'blake2b256';
Blake256.size = 32;
Blake256.bits = 256;
Blake256.blockSize = 128;
Blake256.zero = Buffer.alloc(32, 0x00);
Blake256.ctx = new Blake256();

/**
 * Blake256 HMAC
 * @private
 */

class Blake256Hmac extends Blake256 {
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

module.exports = Blake256;
