/*!
 * blake2b160.js - BLAKE2b implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const Blake2b = require('./blake2b');

/**
 * Blake2b160
 */

class Blake2b160 extends Blake2b {
  /**
   * Create a Blake2b160 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init(key = null) {
    return super.init(20, key);
  }

  static hash() {
    return new Blake2b160();
  }

  static hmac() {
    return new Blake2b160Hmac();
  }

  static digest(data, key = null) {
    return super.digest(data, 20, key);
  }

  static root(left, right) {
    return super.root(left, right, 20);
  }

  static multi(one, two, three) {
    return super.multi(one, two, three, 20);
  }

  static mac(data, key) {
    return super.mac(data, key, 20);
  }
}

Blake2b160.native = Blake2b.native;
Blake2b160.id = 'blake2b160';
Blake2b160.size = 20;
Blake2b160.bits = 160;
Blake2b160.blockSize = 128;
Blake2b160.zero = Buffer.alloc(20, 0x00);
Blake2b160.ctx = new Blake2b160();

/**
 * Blake2b160 HMAC
 * @private
 */

class Blake2b160Hmac extends Blake2b160 {
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

module.exports = Blake2b160;
