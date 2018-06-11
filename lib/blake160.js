/*!
 * blake160.js - BLAKE2b implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const Blake2b = require('./blake2b');

/**
 * Blake160
 */

class Blake160 extends Blake2b {
  /**
   * Create a Blake160 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init(key = null) {
    return super.init(20, key);
  }

  static hash() {
    return new Blake160();
  }

  static hmac() {
    return new Blake160Hmac();
  }

  static digest(data, key = null) {
    return Blake2b.digest(data, 20, key);
  }

  static root(left, right) {
    return Blake2b.root(left, right, 20);
  }

  static multi(one, two, three) {
    return Blake2b.multi(one, two, three, 20);
  }

  static mac(data, key) {
    return Blake2b.mac(data, key, 20);
  }
}

Blake160.native = Blake2b.native;
Blake160.id = 'blake2b160';
Blake160.size = 20;
Blake160.bits = 160;
Blake160.blockSize = 128;
Blake160.zero = Buffer.alloc(20, 0x00);
Blake160.ctx = new Blake160();

/**
 * Blake160 HMAC
 * @private
 */

class Blake160Hmac extends Blake160 {
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

module.exports = Blake160;
