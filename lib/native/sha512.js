/*!
 * sha512.js - SHA512 implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const {SHA512} = require('./binding');
const HMAC = require('../hmac');

SHA512.hash = function hash() {
  return new SHA512();
};

SHA512.hmac = function hmac() {
  return new HMAC(SHA512, 128);
};

SHA512.mac = function mac(data, key) {
  return SHA512.hmac().init(key).update(data).final();
};

SHA512.native = 2;
SHA512.id = 'sha512';
SHA512.size = 64;
SHA512.bits = 512;
SHA512.blockSize = 128;
SHA512.zero = Buffer.alloc(64, 0x00);
SHA512.ctx = new SHA512();

module.exports = SHA512;
