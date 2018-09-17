/*!
 * blake2s128.js - BLAKE2s implementation for bcoin
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const BLAKE2s = require('./blake2s');

/**
 * BLAKE2s128
 */

class BLAKE2s128 extends BLAKE2s {
  /**
   * Create a BLAKE2s128 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init(key = null) {
    return super.init(16, key);
  }

  static hash() {
    return new BLAKE2s128();
  }

  static hmac() {
    return new BLAKE2s128Hmac();
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

BLAKE2s128.native = BLAKE2s.native;
BLAKE2s128.id = 'BLAKE2S128';
BLAKE2s128.size = 16;
BLAKE2s128.bits = 128;
BLAKE2s128.blockSize = 64;
BLAKE2s128.zero = Buffer.alloc(16, 0x00);
BLAKE2s128.ctx = new BLAKE2s128();

/**
 * BLAKE2s128 HMAC
 * @private
 */

class BLAKE2s128Hmac extends BLAKE2s128 {
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

module.exports = BLAKE2s128;
