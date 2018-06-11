/*!
 * blake2b.js - BLAKE2b implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Parts of this software are based on blakejs:
 *   https://github.com/dcposch/blakejs/blob/master/blake2b.js
 */

'use strict';

const assert = require('assert');
const {Blake2b} = require('./binding');

Blake2b.hash = function hash() {
  return new Blake2b();
};

Blake2b.hmac = function hmac() {
  return new BlakeHmac();
};

Blake2b.mac = function mac(data, key, size = 32) {
  assert(Buffer.isBuffer(key));
  return Blake2b.digest(data, size, key);
};

Blake2b.native = 2;
Blake2b.id = 'blake2b256';
Blake2b.size = 32;
Blake2b.bits = 256;
Blake2b.blockSize = 128;
Blake2b.zero = Buffer.alloc(32, 0x00);
Blake2b.ctx = new Blake2b();

class BlakeHmac extends Blake2b {
  constructor() {
    super();
  }

  init(key, size = 32) {
    assert(Buffer.isBuffer(key));
    return super.init(size, key);
  }
}

module.exports = Blake2b;
