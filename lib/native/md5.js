/*!
 * md5.js - MD5 implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const {MD5} = require('./binding');
const HMAC = require('../hmac');

MD5.hash = function hash() {
  return new MD5();
};

MD5.hmac = function hmac() {
  return new HMAC(MD5, 64);
};

MD5.mac = function mac(data, key) {
  return MD5.hmac().init(key).update(data).final();
};

MD5.native = 2;
MD5.id = 'md5';
MD5.size = 16;
MD5.bits = 128;
MD5.blockSize = 64;
MD5.zero = Buffer.alloc(16, 0x00);
MD5.ctx = new MD5();

module.exports = MD5;
