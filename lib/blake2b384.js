/*!
 * blake2b384.js - BLAKE2b implementation for bcoin
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const BLAKE2b = require('./blake2b');

/**
 * BLAKE2b384
 */

class BLAKE2b384 extends BLAKE2b {
  /**
   * Create a BLAKE2b384 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init(key = null) {
    return super.init(48, key);
  }

  static hash() {
    return new BLAKE2b384();
  }

  static hmac() {
    return new BLAKE2b384Hmac();
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

BLAKE2b384.native = BLAKE2b.native;
BLAKE2b384.id = 'BLAKE2B384';
BLAKE2b384.ossl = 'blake2b384';
BLAKE2b384.size = 48;
BLAKE2b384.bits = 384;
BLAKE2b384.blockSize = 128;
BLAKE2b384.zero = Buffer.alloc(48, 0x00);
BLAKE2b384.ctx = new BLAKE2b384();

/**
 * BLAKE2b384 HMAC
 * @private
 */

class BLAKE2b384Hmac extends BLAKE2b384 {
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

module.exports = BLAKE2b384;
