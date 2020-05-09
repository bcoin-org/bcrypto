/*!
 * base58.js - base58 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/*
 * Base58
 */

function encode(data) {
  assert(Buffer.isBuffer(data));
  return binding.base58_encode(data);
}

function decode(str) {
  assert(typeof str === 'string');

  const [out, len] = binding.base58_decode(str);

  if (out.length === len)
    return out;

  return out.slice(0, len);
}

function test(str) {
  assert(typeof str === 'string');
  return binding.base58_test(str);
}

/*
 * Expose
 */

exports.native = 2;
exports.encode = encode;
exports.decode = decode;
exports.test = test;
