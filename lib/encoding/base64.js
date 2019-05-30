/*!
 * base64.js - base64 for javascript
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc4648
 */

'use strict';

const assert = require('bsert');

/*
 * Base64
 */

function encode(data) {
  assert(Buffer.isBuffer(data));
  return data.toString('base64');
}

function decode(str) {
  assert(typeof str === 'string');

  if (/[\-_]/.test(str))
    throw new Error('Invalid base64 string.');

  const data = Buffer.from(str, 'base64');

  if (str.length !== size64(data.length))
    throw new Error('Invalid base64 string.');

  return data;
}

function test(str) {
  assert(typeof str === 'string');

  if (/[\-_]/.test(str))
    return false;

  const size = Buffer.byteLength(str, 'base64');

  return str.length === size64(size);
}

function encodeURL(data) {
  assert(Buffer.isBuffer(data));

  const raw = data.toString('base64');
  const str = raw
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  return str;
}

function decodeURL(str) {
  assert(typeof str === 'string');

  if (/[=\+\/]/.test(str))
    throw new Error('Invalid base64-url string.');

  const raw = pad64(str)
    .replace(/\-/g, '+')
    .replace(/_/g, '/');

  const data = Buffer.from(raw, 'base64');

  if (raw.length !== size64(data.length))
    throw new Error('Invalid base64-url string.');

  return data;
}

function testURL(str) {
  assert(typeof str === 'string');

  if (/[=\+\/]/.test(str))
    return false;

  const raw = pad64(str)
    .replace(/\-/g, '+')
    .replace(/_/g, '/');

  const size = Buffer.byteLength(raw, 'base64');

  return raw.length === size64(size);
}

/*
 * Helpers
 */

function pad64(str) {
  switch (str.length & 3) {
    case 2:
      str += '==';
      break;
    case 3:
      str += '=';
      break;
  }
  return str;
}

function size64(size) {
  const expect = ((4 * size / 3) + 3) & ~3;
  return expect >>> 0;
}

/*
 * Expose
 */

exports.encode = encode;
exports.decode = decode;
exports.test = test;
exports.encodeURL = encodeURL;
exports.decodeURL = decodeURL;
exports.testURL = testURL;
