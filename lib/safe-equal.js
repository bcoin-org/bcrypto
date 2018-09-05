/*!
 * safe-equal.js - constant-time equals for bcrypto
 * Copyright (c) 2016-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');

/**
 * memcmp in constant time (can only return true or false).
 * This protects us against timing attacks when
 * comparing an input against a secret string.
 * @see https://cryptocoding.net/index.php/Coding_rules
 * @see `$ man 3 memcmp` (NetBSD's consttime_memequal)
 * @param {Buffer} a
 * @param {Buffer} b
 * @returns {Boolean}
 */

module.exports = function safeEqual(a, b) {
  assert(Buffer.isBuffer(a));
  assert(Buffer.isBuffer(b));

  if (b.length === 0)
    return a.length === 0;

  let res = a.length ^ b.length;

  for (let i = 0; i < a.length; i++)
    res |= a[i] ^ b[i % b.length];

  return res === 0;
};
