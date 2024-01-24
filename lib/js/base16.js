/*!
 * base16.js - base16 for javascript
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc4648
 */

'use strict';

const assert = require('../internal/assert');

/*
 * Constants
 */

const CHARSET = '0123456789abcdef';

const TABLE = [
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
   0,  1,  2,  3,  4,  5,  6,  7,
   8,  9, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1
];

/*
 * Base16
 */

function encode(data) {
  assert(Buffer.isBuffer(data));

  let str = '';

  for (let i = 0; i < data.length; i++) {
    str += CHARSET[data[i] >> 4];
    str += CHARSET[data[i] & 15];
  }

  return str;
}

function decode(str) {
  assert(typeof str === 'string');

  if (str.length & 1)
    throw new Error('Invalid hex string.');

  const len = str.length >>> 1;
  const data = Buffer.alloc(len);

  let z = 0;

  for (let i = 0; i < len; i++) {
    const c1 = str.charCodeAt(i * 2 + 0);
    const c2 = str.charCodeAt(i * 2 + 1);
    const hi = TABLE[c1 & 0x7f];
    const lo = TABLE[c2 & 0x7f];

    z |= c1 | c2 | hi | lo;

    data[i] = (hi << 4) | lo;
  }

  // Check for errors at the end.
  if (z & 0xffffff80)
    throw new Error('Invalid hex string.');

  return data;
}

function test(str) {
  assert(typeof str === 'string');

  if (str.length & 1)
    return false;

  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    if (ch & 0xff80)
      return false;

    if (TABLE[ch] === -1)
      return false;
  }

  return true;
}

/*
 * Base16 (Little Endian)
 */

function encodeLE(data) {
  assert(Buffer.isBuffer(data));

  let str = '';

  for (let i = data.length - 1; i >= 0; i--) {
    str += CHARSET[data[i] >> 4];
    str += CHARSET[data[i] & 15];
  }

  return str;
}

function decodeLE(str) {
  assert(typeof str === 'string');

  if (str.length & 1)
    throw new Error('Invalid hex string.');

  const len = str.length >>> 1;
  const data = Buffer.alloc(len);

  let z = 0;

  for (let i = 0; i < len; i++) {
    const c1 = str.charCodeAt(i * 2 + 0);
    const c2 = str.charCodeAt(i * 2 + 1);
    const hi = TABLE[c1 & 0x7f];
    const lo = TABLE[c2 & 0x7f];

    z |= c1 | c2 | hi | lo;

    data[len - 1 - i] = (hi << 4) | lo;
  }

  // Check for errors at the end.
  if (z & 0xffffff80)
    throw new Error('Invalid hex string.');

  return data;
}

function testLE(str) {
  return test(str);
}

/*
 * Expose
 */

exports.native = 0;
exports.encode = encode;
exports.decode = decode;
exports.test = test;
exports.encodeLE = encodeLE;
exports.decodeLE = decodeLE;
exports.testLE = testLE;
