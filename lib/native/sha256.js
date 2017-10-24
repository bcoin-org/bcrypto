/*!
 * sha256.js - SHA256 implementation for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const {SHA256} = require('./binding');
const HMAC = require('../hmac');

SHA256.hash = function hash() {
  return new SHA256();
};

SHA256.hmac = function hmac() {
  return new HMAC(SHA256, 64);
};

SHA256.mac = function mac(data, key) {
  return this.hmac().init(key).update(data).final();
};

module.exports = SHA256;
