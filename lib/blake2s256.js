/*!
 * blake2s256.js - BLAKE2s implementation for bcoin
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const Blake2s = require('./blake2s');

/**
 * Blake2s256
 */

class Blake2s256 extends Blake2s {
  /**
   * Create a Blake2s256 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init(key = null) {
    return super.init(32, key);
  }

  static hash() {
    return new Blake2s256();
  }

  static hmac() {
    return new Blake2s256Hmac();
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

Blake2s256.native = Blake2s.native;
Blake2s256.id = 'BLAKE2S256';
Blake2s256.ossl = 'blake2s256';
Blake2s256.size = 32;
Blake2s256.bits = 256;
Blake2s256.blockSize = 64;
Blake2s256.zero = Buffer.alloc(32, 0x00);
Blake2s256.ctx = new Blake2s256();

/**
 * Blake2s256 HMAC
 * @private
 */

class Blake2s256Hmac extends Blake2s256 {
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

module.exports = Blake2s256;
