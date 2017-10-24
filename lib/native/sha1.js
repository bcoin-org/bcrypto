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
  return this.hmac().init(key).update(data).final();
};

module.exports = SHA1;
