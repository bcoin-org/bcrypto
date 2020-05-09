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

  if (data.length <= 1024)
    return binding.base58_encode_1024(data);

  return binding.base58_encode(data);
}

function decode(str) {
  assert(typeof str === 'string');

  if (str.length <= 1399)
    return binding.base58_decode_1024(str);

  const {buffer, length} = binding.base58_decode(str);

  return Buffer.from(buffer, 0, length);
}

function test(str) {
  assert(typeof str === 'string');

  if (str.length <= 1399)
    return binding.base58_test_1024(str);

  return binding.base58_test(str);
}

/*
 * Expose
 */

exports.native = 2;
exports.encode = encode;
exports.decode = decode;
exports.test = test;
