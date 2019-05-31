/*!
 * cashaddr.js - cashaddr for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const {cashaddr} = require('./binding');

module.exports = {
  native: 2,
  encode(prefix, type, hash) {
    assert((type & 0x0f) === type, 'Invalid cashaddr type.');
    return cashaddr.encode(prefix, type, hash);
  },
  decode(str, defaultPrefix = 'bitcoincash') {
    return cashaddr.decode(str, defaultPrefix);
  },
  test(str, defaultPrefix = 'bitcoincash') {
    return cashaddr.test(str, defaultPrefix);
  }
};
