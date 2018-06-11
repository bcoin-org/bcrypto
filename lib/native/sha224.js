/*!
 * sha224.js - SHA224 implementation for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const {SHA224} = require('./binding');
const HMAC = require('../hmac');

SHA224.hash = function hash() {
  return new SHA224();
};

SHA224.hmac = function hmac() {
  return new HMAC(SHA224, 64);
};

SHA224.mac = function mac(data, key) {
  return SHA224.hmac().init(key).update(data).final();
};

SHA224.native = 2;
SHA224.id = 'sha224';
SHA224.size = 28;
SHA224.bits = 224;
SHA224.blockSize = 64;
SHA224.zero = Buffer.alloc(28, 0x00);
SHA224.ctx = new SHA224();

module.exports = SHA224;
