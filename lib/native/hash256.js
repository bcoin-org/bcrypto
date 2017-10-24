/*!
 * hash256.js - hash256 implementation for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 * Parts of this software based on hash.js.
 */

'use strict';

const {Hash256} = require('./binding');
const HMAC = require('../hmac');

Hash256.hash = function hash() {
  return new Hash256();
};

Hash256.hmac = function hmac() {
  return new HMAC(Hash256, 64);
};

Hash256.mac = function mac(data, key) {
  return this.hmac().init(key).update(data).final();
};

module.exports = Hash256;
