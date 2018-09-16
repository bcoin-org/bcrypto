/*!
 * blake2s.js - BLAKE2s implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const {BLAKE2s} = require('./binding');

BLAKE2s.hash = function hash() {
  return new BLAKE2s();
};

BLAKE2s.hmac = function hmac() {
  return new BlakeHmac();
};

BLAKE2s.mac = function mac(data, key, size = 32) {
  assert(Buffer.isBuffer(key));
  return BLAKE2s.digest(data, size, key);
};

BLAKE2s.native = 2;
BLAKE2s.id = 'BLAKE2S256';
BLAKE2s.ossl = 'blake2s256';
BLAKE2s.size = 32;
BLAKE2s.bits = 256;
BLAKE2s.blockSize = 64;
BLAKE2s.zero = Buffer.alloc(32, 0x00);
BLAKE2s.ctx = new BLAKE2s();

class BlakeHmac extends BLAKE2s {
  constructor() {
    super();
  }

  init(key, size = 32) {
    assert(Buffer.isBuffer(key));
    return super.init(size, key);
  }
}

module.exports = BLAKE2s;
