/*!
 * blake2s256.js - BLAKE2s implementation for bcoin
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const BLAKE2s = require('./blake2s');

/**
 * BLAKE2s256
 */

class BLAKE2s256 extends BLAKE2s {
  /**
   * Create a BLAKE2s256 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init(key = null) {
    return super.init(32, key);
  }

  static hash() {
    return new BLAKE2s256();
  }

  static hmac() {
    return new BLAKE2s256Hmac();
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

BLAKE2s256.native = BLAKE2s.native;
BLAKE2s256.id = 'BLAKE2S256';
BLAKE2s256.size = 32;
BLAKE2s256.bits = 256;
BLAKE2s256.blockSize = 64;
BLAKE2s256.zero = Buffer.alloc(32, 0x00);
BLAKE2s256.ctx = new BLAKE2s256();

/**
 * BLAKE2s256 HMAC
 * @private
 */

class BLAKE2s256Hmac extends BLAKE2s256 {
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

module.exports = BLAKE2s256;
