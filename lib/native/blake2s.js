/*!
 * blake2s.js - BLAKE2s implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const {Blake2s} = require('./binding');

Blake2s.hash = function hash() {
  return new Blake2s();
};

Blake2s.hmac = function hmac() {
  return new BlakeHmac();
};

Blake2s.mac = function mac(data, key, size = 32) {
  assert(Buffer.isBuffer(key));
  return Blake2s.digest(data, size, key);
};

Blake2s.native = 2;
Blake2s.id = 'BLAKE2S256';
Blake2s.ossl = 'blake2s256';
Blake2s.size = 32;
Blake2s.bits = 256;
Blake2s.blockSize = 64;
Blake2s.zero = Buffer.alloc(32, 0x00);
Blake2s.ctx = new Blake2s();

class BlakeHmac extends Blake2s {
  constructor() {
    super();
  }

  init(key, size = 32) {
    assert(Buffer.isBuffer(key));
    return super.init(size, key);
  }
}

module.exports = Blake2s;
