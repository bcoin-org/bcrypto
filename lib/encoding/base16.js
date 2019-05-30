/*!
 * base16.js - base16 for javascript
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc4648
 */

'use strict';

const assert = require('bsert');

/*
 * Base16
 */

function encode(data) {
  assert(Buffer.isBuffer(data));
  return data.toString('hex');
}

function encodeLE(data) {
  const str = encode(data);

  let out = '';

  for (let i = str.length - 2; i >= 0; i -= 2)
    out += str[i] + str[i + 1];

  return out;
}

function decode(str) {
  assert(typeof str === 'string');

  const data = Buffer.from(str, 'hex');

  if (str.length !== data.length * 2)
    throw new Error('Invalid hex string.');

  return data;
}

function decodeLE(str) {
  const data = decode(str);

  for (let i = data.length - 1, j = 0; i > j; i--, j++)
    [data[i], data[j]] = [data[j], data[i]];

  return data;
}

function test(str) {
  assert(typeof str === 'string');

  if (str.length & 1)
    return false;

  return /^[0-9a-f]*$/i.test(str);
}

/*
 * Expose
 */

exports.encode = encode;
exports.encodeLE = encodeLE;
exports.decode = decode;
exports.decodeLE = decodeLE;
exports.test = test;
