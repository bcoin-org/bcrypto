/*!
 * hash160.js - hash160 implementation for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const {Hash160} = require('./binding');
const HMAC = require('../hmac');

Hash160.hash = function hash() {
  return new Hash160();
};

Hash160.hmac = function hmac() {
  return new HMAC(Hash160, 64);
};

Hash160.mac = function mac(data, key) {
  return this.hmac().init(key).update(data).final();
};

module.exports = Hash160;
