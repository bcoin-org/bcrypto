/*!
 * blake2s128.js - BLAKE2s implementation for bcoin
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const Blake2s = require('./blake2s');

/**
 * Blake2s128
 */

class Blake2s128 extends Blake2s {
  /**
   * Create a Blake2s128 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init(key = null) {
    return super.init(16, key);
  }

  static hash() {
    return new Blake2s128();
  }

  static hmac() {
    return new Blake2s128Hmac();
  }

  static digest(data, key = null) {
    return super.digest(data, 16, key);
  }

  static root(left, right) {
    return super.root(left, right, 16);
  }

  static multi(one, two, three) {
    return super.multi(one, two, three, 16);
  }

  static mac(data, key) {
    return super.mac(data, key, 16);
  }
}

Blake2s128.native = Blake2s.native;
Blake2s128.id = 'BLAKE2S128';
Blake2s128.ossl = 'blake2s128';
Blake2s128.size = 16;
Blake2s128.bits = 128;
Blake2s128.blockSize = 64;
Blake2s128.zero = Buffer.alloc(16, 0x00);
Blake2s128.ctx = new Blake2s128();

/**
 * Blake2s128 HMAC
 * @private
 */

class Blake2s128Hmac extends Blake2s128 {
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

module.exports = Blake2s128;
