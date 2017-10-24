/*!
 * ripemd160.js - RIPEMD160 implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const {RIPEMD160} = require('./binding');
const HMAC = require('../hmac');

RIPEMD160.hash = function hash() {
  return new RIPEMD160();
};

RIPEMD160.hmac = function hmac() {
  return new HMAC(RIPEMD160, 64);
};

RIPEMD160.mac = function mac(data, key) {
  return this.hmac().init(key).update(data).final();
};

module.exports = RIPEMD160;
