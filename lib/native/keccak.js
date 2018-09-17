/*!
 * keccak.js - Keccak implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {Keccak} = require('./binding');
const HMAC = require('../internal/hmac');

Keccak.hash = function hash() {
  return new Keccak();
};

Keccak.hmac = function hmac(bits = 256, std = false) {
  const bs = (1600 - bits * 2) / 8;
  return new HMAC(Keccak, bs, bits, std);
};

Keccak.mac = function mac(data, key, bits = 256, std = false) {
  return Keccak.hmac(bits, std).init(key).update(data).final();
};

Keccak.native = 2;
Keccak.id = 'KECCAK256';
Keccak.size = 32;
Keccak.bits = 256;
Keccak.blockSize = 136;
Keccak.zero = Buffer.alloc(32, 0x00);
Keccak.ctx = new Keccak();

module.exports = Keccak;
