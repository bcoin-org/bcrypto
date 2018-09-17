/*!
 * blake2b.js - BLAKE2b implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const {BLAKE2b} = require('./binding');

BLAKE2b.hash = function hash() {
  return new BLAKE2b();
};

BLAKE2b.hmac = function hmac() {
  return new BlakeHmac();
};

BLAKE2b.mac = function mac(data, key, size = 32) {
  assert(Buffer.isBuffer(key));
  return BLAKE2b.digest(data, size, key);
};

BLAKE2b.native = 2;
BLAKE2b.id = 'BLAKE2B256';
BLAKE2b.size = 32;
BLAKE2b.bits = 256;
BLAKE2b.blockSize = 128;
BLAKE2b.zero = Buffer.alloc(32, 0x00);
BLAKE2b.ctx = new BLAKE2b();

class BlakeHmac extends BLAKE2b {
  constructor() {
    super();
  }

  init(key, size = 32) {
    assert(Buffer.isBuffer(key));
    return super.init(size, key);
  }
}

module.exports = BLAKE2b;
