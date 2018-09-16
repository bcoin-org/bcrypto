/*!
 * blake2b384.js - BLAKE2b implementation for bcoin
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const Blake2b = require('./blake2b');

/**
 * Blake2b384
 */

class Blake2b384 extends Blake2b {
  /**
   * Create a Blake2b384 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init(key = null) {
    return super.init(48, key);
  }

  static hash() {
    return new Blake2b384();
  }

  static hmac() {
    return new Blake2b384Hmac();
  }

  static digest(data, key = null) {
    return super.digest(data, 48, key);
  }

  static root(left, right) {
    return super.root(left, right, 48);
  }

  static multi(one, two, three) {
    return super.multi(one, two, three, 48);
  }

  static mac(data, key) {
    return super.mac(data, key, 48);
  }
}

Blake2b384.native = Blake2b.native;
Blake2b384.id = 'BLAKE2B384';
Blake2b384.size = 48;
Blake2b384.bits = 384;
Blake2b384.blockSize = 128;
Blake2b384.zero = Buffer.alloc(48, 0x00);
Blake2b384.ctx = new Blake2b384();

/**
 * Blake2b384 HMAC
 * @private
 */

class Blake2b384Hmac extends Blake2b384 {
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

module.exports = Blake2b384;
