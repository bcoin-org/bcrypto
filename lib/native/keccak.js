/*!
 * keccak.js - Keccak implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const {Keccak} = require('./binding');

Keccak.hash = function hash() {
  return new Keccak();
};

Keccak.hmac = function hmac() {
  throw new Error('Not implemented.');
};

Keccak.mac = function mac(data, bits = 256, std = false) {
  throw new Error('Not implemented.');
};

Keccak.native = 2;
Keccak.id = 'keccak256';
Keccak.size = 32;
Keccak.bits = 256;
Keccak.blockSize = 136;
Keccak.zero = Buffer.alloc(32, 0x00);
Keccak.ctx = new Keccak();

module.exports = Keccak;
