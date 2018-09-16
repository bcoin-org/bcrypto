/*!
 * blake2s160.js - BLAKE2s implementation for bcoin
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const Blake2s = require('./blake2s');

/**
 * Blake2s160
 */

class Blake2s160 extends Blake2s {
  /**
   * Create a Blake2s160 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init(key = null) {
    return super.init(20, key);
  }

  static hash() {
    return new Blake2s160();
  }

  static hmac() {
    return new Blake2s160Hmac();
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

Blake2s160.native = Blake2s.native;
Blake2s160.id = 'BLAKE2S160';
Blake2s160.size = 20;
Blake2s160.bits = 160;
Blake2s160.blockSize = 64;
Blake2s160.zero = Buffer.alloc(20, 0x00);
Blake2s160.ctx = new Blake2s160();

/**
 * Blake2s160 HMAC
 * @private
 */

class Blake2s160Hmac extends Blake2s160 {
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

module.exports = Blake2s160;
