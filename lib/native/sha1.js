/*!
 * sha1.js - SHA1 implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const {SHA1} = require('./binding');
const HMAC = require('../hmac');

SHA1.hash = function hash() {
  return new SHA1();
};

SHA1.hmac = function hmac() {
  return new HMAC(SHA1, 64);
};

SHA1.mac = function mac(data, key) {
  return SHA1.hmac().init(key).update(data).final();
};

SHA1.native = 2;
SHA1.id = 'sha1';
SHA1.size = 20;
SHA1.bits = 160;
SHA1.blockSize = 64;
SHA1.zero = Buffer.alloc(20, 0x00);
SHA1.ctx = new SHA1();

module.exports = SHA1;
