/*!
 * blake2b512.js - BLAKE2b implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const Blake2b = require('./blake2b');

/**
 * Blake2b512
 */

class Blake2b512 extends Blake2b {
  /**
   * Create a Blake2b512 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init(key = null) {
    return super.init(64, key);
  }

  static hash() {
    return new Blake2b512();
  }

  static hmac() {
    return new Blake2b512Hmac();
  }

  static digest(data, key = null) {
    return super.digest(data, 64, key);
  }

  static root(left, right) {
    return super.root(left, right, 64);
  }

  static multi(one, two, three) {
    return super.multi(one, two, three, 64);
  }

  static mac(data, key) {
    return super.mac(data, key, 64);
  }
}

Blake2b512.native = Blake2b.native;
Blake2b512.id = 'blake2b512';
Blake2b512.size = 64;
Blake2b512.bits = 512;
Blake2b512.blockSize = 128;
Blake2b512.zero = Buffer.alloc(64, 0x00);
Blake2b512.ctx = new Blake2b512();

/**
 * Blake2b512 HMAC
 * @private
 */

class Blake2b512Hmac extends Blake2b512 {
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

module.exports = Blake2b512;
