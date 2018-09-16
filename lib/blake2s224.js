/*!
 * blake2s224.js - BLAKE2s implementation for bcoin
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const Blake2s = require('./blake2s');

/**
 * Blake2s224
 */

class Blake2s224 extends Blake2s {
  /**
   * Create a Blake2s224 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init(key = null) {
    return super.init(28, key);
  }

  static hash() {
    return new Blake2s224();
  }

  static hmac() {
    return new Blake2s224Hmac();
  }

  static digest(data, key = null) {
    return super.digest(data, 28, key);
  }

  static root(left, right) {
    return super.root(left, right, 28);
  }

  static multi(one, two, three) {
    return super.multi(one, two, three, 28);
  }

  static mac(data, key) {
    return super.mac(data, key, 28);
  }
}

Blake2s224.native = Blake2s.native;
Blake2s224.id = 'BLAKE2S224';
Blake2s224.ossl = 'blake2s224';
Blake2s224.size = 28;
Blake2s224.bits = 224;
Blake2s224.blockSize = 64;
Blake2s224.zero = Buffer.alloc(28, 0x00);
Blake2s224.ctx = new Blake2s224();

/**
 * Blake2s224 HMAC
 * @private
 */

class Blake2s224Hmac extends Blake2s224 {
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

module.exports = Blake2s224;
