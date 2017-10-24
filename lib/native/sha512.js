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
  return this.hmac().init(key).update(data).final();
};

module.exports = SHA512;
