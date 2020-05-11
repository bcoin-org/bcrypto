/*!
 * bech32.js - bech32 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on sipa/bech32:
 *   Copyright (c) 2017, Pieter Wuille (MIT License).
 *   https://github.com/sipa/bech32
 *
 * Resources:
 *   https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
 *   https://github.com/sipa/bech32/blob/master/ref/c/segwit_addr.c
 *   https://github.com/bitcoin/bitcoin/blob/master/src/bech32.cpp
 */

'use strict';

const assert = require('../internal/assert');

/**
 * Constants
 */

const POOL65 = Buffer.alloc(65);
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

const TABLE = [
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  15, -1, 10, 17, 21, 20, 26, 30,
   7,  5, -1, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8,
  23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,
   6,  4,  2, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8,
  23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,
   6,  4,  2, -1, -1, -1, -1, -1
];

/**
 * Update checksum.
 * @ignore
 * @param {Number} chk
 * @returns {Number}
 */

function polymod(pre) {
  const b = pre >>> 25;

  return ((pre & 0x1ffffff) << 5)
    ^ (0x3b6a57b2 & -((b >> 0) & 1))
    ^ (0x26508e6d & -((b >> 1) & 1))
    ^ (0x1ea119fa & -((b >> 2) & 1))
    ^ (0x3d4233dd & -((b >> 3) & 1))
    ^ (0x2a1462b3 & -((b >> 4) & 1));
}

/**
 * Encode hrp and data as a bech32 string.
 * @param {String} hrp
 * @param {Buffer} data
 * @returns {String}
 */

function serialize(hrp, data) {
  assert(typeof hrp === 'string');
  assert(Buffer.isBuffer(data));

  let str = '';
  let chk = 1;
  let i;

  for (i = 0; i < hrp.length; i++) {
    const ch = hrp.charCodeAt(i);

    if (ch < 33 || ch > 126)
      throw new Error('Invalid bech32 character.');

    if (ch >= 65 && ch <= 90)
      throw new Error('Invalid bech32 character.');

    chk = polymod(chk) ^ (ch >>> 5);
  }

  if (hrp.length + 1 + data.length + 6 > 90)
    throw new Error('Invalid bech32 data length.');

  chk = polymod(chk);

  for (let i = 0; i < hrp.length; i++) {
    const ch = hrp.charCodeAt(i);

    chk = polymod(chk) ^ (ch & 0x1f);
    str += hrp[i];
  }

  str += '1';

  for (let i = 0; i < data.length; i++) {
    const ch = data[i];

    if (ch >>> 5)
      throw new Error('Invalid bech32 value.');

    chk = polymod(chk) ^ ch;
    str += CHARSET[ch];
  }

  for (let i = 0; i < 6; i++)
    chk = polymod(chk);

  chk ^= 1;

  for (let i = 0; i < 6; i++)
    str += CHARSET[(chk >>> ((5 - i) * 5)) & 0x1f];

  return str;
}

/**
 * Decode a bech32 string.
 * @param {String} str
 * @returns {Array} [hrp, data]
 */

function deserialize(str) {
  assert(typeof str === 'string');

  if (str.length < 7 || str.length > 90)
    throw new Error('Invalid bech32 string length.');

  let hlen = str.length;

  while (hlen > 0 && str[hlen - 1] !== '1')
    hlen -= 1;

  if (hlen === 0)
    throw new Error('Invalid bech32 string.');

  hlen -= 1;

  const dlen = str.length - (hlen + 1);

  if (dlen < 6)
    throw new Error('Invalid bech32 data length.');

  const data = Buffer.alloc(dlen - 6);

  let chk = 1;
  let lower = false;
  let upper = false;
  let hrp = '';
  let j = 0;
  let i;

  for (i = 0; i < hlen; i++) {
    let ch = str.charCodeAt(i);

    if (ch < 33 || ch > 126)
      throw new Error('Invalid bech32 character.');

    if (ch >= 97 && ch <= 122) {
      lower = true;
    } else if (ch >= 65 && ch <= 90) {
      upper = true;
      ch += 32;
    }

    hrp += String.fromCharCode(ch);
    chk = polymod(chk) ^ (ch >>> 5);
  }

  chk = polymod(chk);

  for (i = 0; i < hlen; i++)
    chk = polymod(chk) ^ (str.charCodeAt(i) & 0x1f);

  i += 1;

  while (i < str.length) {
    const ch = str.charCodeAt(i);
    const val = (ch & 0xff80) ? -1 : TABLE[ch];

    if (val === -1)
      throw new Error('Invalid bech32 character.');

    if (ch >= 97 && ch <= 122)
      lower = true;
    else if (ch >= 65 && ch <= 90)
      upper = true;

    chk = polymod(chk) ^ val;

    if (i < str.length - 6)
      data[j++] = val;

    i += 1;
  }

  if (lower && upper)
    throw new Error('Invalid bech32 casing.');

  if (chk !== 1)
    throw new Error('Invalid bech32 checksum.');

  assert(j === data.length);

  return [hrp, data];
}

/**
 * Test whether a string is a bech32 string.
 * @param {String} str
 * @returns {Boolean}
 */

function is(str) {
  assert(typeof str === 'string');

  try {
    deserialize(str);
  } catch (e) {
    return false;
  }

  return true;
}

/**
 * Convert serialized data to another base.
 * @param {Buffer} input
 * @param {Number} i
 * @param {Buffer} output
 * @param {Number} j
 * @param {Number} frombits
 * @param {Number} tobits
 * @param {Boolean} pad
 * @returns {Buffer}
 */

function convert(input, i, output, j, frombits, tobits, pad) {
  assert(Buffer.isBuffer(input));
  assert((i >>> 0) === i);
  assert(Buffer.isBuffer(output));
  assert((j >>> 0) === j);
  assert((frombits >>> 0) === frombits);
  assert((tobits >>> 0) === tobits);
  assert(typeof pad === 'boolean');
  assert(frombits >= 1 && frombits <= 8);
  assert(tobits >= 1 && tobits <= 8);

  const mask = (1 << tobits) - 1;

  let acc = 0;
  let bits = 0;

  for (; i < input.length; i++) {
    acc = (acc << frombits) | input[i];
    bits += frombits;

    while (bits >= tobits) {
      bits -= tobits;
      output[j++] = (acc >>> bits) & mask;
    }
  }

  const left = tobits - bits;

  if (pad) {
    if (bits)
      output[j++] = (acc << left) & mask;
  } else {
    if (((acc << left) & mask) || bits >= frombits)
      throw new Error('Invalid bits.');
  }

  if (j === output.length)
    return output;

  assert(j < output.length);

  return output.slice(0, j);
}

/**
 * Calculate size required for bit conversion.
 * @param {Number} len
 * @param {Number} frombits
 * @param {Number} tobits
 * @param {Boolean} pad
 * @returns {Number}
 */

function convertSize(len, frombits, tobits, pad) {
  assert((len >>> 0) === len);
  assert((frombits >>> 0) === frombits);
  assert((tobits >>> 0) === tobits);
  assert(typeof pad === 'boolean');
  assert(frombits >= 1 && frombits <= 8);
  assert(tobits >= 1 && tobits <= 8);

  return ((len * frombits + (tobits - 1) * (pad | 0)) / tobits) >>> 0;
}

/**
 * Convert serialized data to another base.
 * @param {Buffer} data
 * @param {Number} frombits
 * @param {Number} tobits
 * @param {Boolean} pad
 * @returns {Buffer}
 */

function convertBits(data, frombits, tobits, pad) {
  assert(Buffer.isBuffer(data));

  const size = convertSize(data.length, frombits, tobits, pad);
  const out = Buffer.alloc(size);

  return convert(data, 0, out, 0, frombits, tobits, pad);
}

/**
 * Serialize data to bech32 address.
 * @param {String} hrp
 * @param {Number} version
 * @param {Buffer} hash
 * @returns {String}
 */

function encode(hrp, version, hash) {
  assert(typeof hrp === 'string');
  assert((version >>> 0) === version);
  assert(Buffer.isBuffer(hash));

  if (version > 31)
    throw new Error('Invalid bech32 version.');

  if (hash.length < 2 || hash.length > 40)
    throw new Error('Invalid bech32 data length.');

  const out = POOL65;

  out[0] = version;

  const data = convert(hash, 0, out, 1, 8, 5, true);

  return serialize(hrp, data);
}

/**
 * Deserialize data from bech32 address.
 * @param {String} str
 * @returns {Array}
 */

function decode(str) {
  const [hrp, data] = deserialize(str);

  if (data.length === 0 || data.length > 65)
    throw new Error('Invalid bech32 data length.');

  const version = data[0];

  if (version > 31)
    throw new Error('Invalid bech32 version.');

  const hash = convert(data, 1, data, 0, 5, 8, false);

  if (hash.length < 2 || hash.length > 40)
    throw new Error('Invalid bech32 data length.');

  return [hrp, version, hash];
}

/**
 * Test whether a string is a bech32 string.
 * @param {String} str
 * @returns {Boolean}
 */

function test(str) {
  assert(typeof str === 'string');

  let data;

  try {
    [, data] = deserialize(str);
  } catch (e) {
    return false;
  }

  if (data.length === 0 || data.length > 65)
    return false;

  const version = data[0];

  if (version > 31)
    return false;

  return true;
}

/*
 * Expose
 */

exports.native = 0;
exports.serialize = serialize;
exports.deserialize = deserialize;
exports.is = is;
exports.convertBits = convertBits;
exports.encode = encode;
exports.decode = decode;
exports.test = test;
