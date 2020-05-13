/*!
 * cash32.js - cashaddr for bcrypto
 * Copyright (c) 2018-2020, The Bcoin Developers (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on Bitcoin-ABC/bitcoin-abc:
 *   Copyright (c) 2009-2019, The Bitcoin Developers (MIT License).
 *   Copyright (c) 2009-2017, The Bitcoin Core Developers (MIT License).
 *   https://github.com/Bitcoin-ABC/bitcoin-abc
 *
 * Parts of this software are based on sipa/bech32:
 *   Copyright (c) 2017, Pieter Wuille (MIT License).
 *   https://github.com/sipa/bech32
 *
 * Resources:
 *   https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md
 *   https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/cashaddr.cpp
 *   https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/cashaddrenc.cpp
 *   https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/util/strencodings.h
 */

'use strict';

const assert = require('../internal/assert');

/**
 * Constants
 */

const POOL104 = Buffer.alloc(104);
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

const CHECKSUM_MASK = [0x00000007, 0xffffffff];

const GENERATOR = [
  0x00000098, 0xf2bc8e61,
  0x00000079, 0xb76d99e2,
  0x000000f3, 0x3e5fb3c4,
  0x000000ae, 0x2eabe2a8,
  0x0000001e, 0x4f43e470
];

/**
 * Update checksum
 * @ignore
 * @param {Number[]} chk
 * @param {Number} x
 * @returns {Number[]} -- new checksum
 */

function polymod(pre, x) {
  const c = pre;

  // b = c >> 35
  const b = c[0] >>> 3;

  // c = (c & CHECKSUM_MASK) << 5
  c[0] &= CHECKSUM_MASK[0];
  c[1] &= CHECKSUM_MASK[1];
  c[0] <<= 5;
  c[0] |= c[1] >>> 27;
  c[1] <<= 5;

  for (let i = 0; i < 5; i++) {
    if ((b >>> i) & 1) {
      // c ^= GENERATOR[i]
      c[0] ^= GENERATOR[i * 2 + 0];
      c[1] ^= GENERATOR[i * 2 + 1];
    }
  }

  // c ^= x
  c[1] ^= x;

  return c;
}

/**
 * Serialize data to cash32.
 * @param {String} prefix
 * @param {Buffer} data - 5bit serialized
 * @returns {String}
 */

function serialize(prefix, data) {
  assert(typeof prefix === 'string');
  assert(Buffer.isBuffer(data));

  if (prefix.length === 0 || prefix.length > 83)
    throw new Error('Invalid cash32 prefix.');

  if (data.length > 104)
    throw new Error('Invalid cash32 data.');

  const chk = [0, 1];

  let str = '';

  for (let i = 0; i < prefix.length; i++) {
    const ch = prefix.charCodeAt(i);

    if ((ch < 33 || ch > 126)
        || (ch >= 65 && ch <= 90)
        || (ch >= 48 && ch <= 57)
        || ch === 58) {
      throw new Error('Invalid cash32 prefix.');
    }

    polymod(chk, ch & 0x1f);

    str += String.fromCharCode(ch);
  }

  polymod(chk, 0);

  str += ':';

  for (let i = 0; i < data.length; i++) {
    const ch = data[i];

    if (ch >>> 5)
      throw new Error('Invalid cash32 value.');

    polymod(chk, ch);

    str += CHARSET[ch];
  }

  for (let i = 0; i < 8; i++)
    polymod(chk, 0);

  chk[1] ^= 1;

  // i = 0, shift = 35
  str += CHARSET[(chk[0] >>> 3) & 0x1f];

  for (let i = 1; i < 7; i++) {
    const shift = (7 - i) * 5;
    const val = (chk[1] >>> shift) | (chk[0] << (32 - shift));

    str += CHARSET[val & 0x1f];
  }

  // i = 7, shift = 0
  str += CHARSET[chk[1] & 0x1f];

  return str;
}

/**
 * Decode cash32 string.
 * @param {String} str
 * @param {String} prefix (lowercase and w/o numbers)
 * @returns {Array} [prefix, data]
 */

function deserialize(str, prefix) {
  assert(typeof str === 'string');
  assert(typeof prefix === 'string');

  if (prefix.length === 0 || prefix.length > 83)
    throw new Error('Invalid cash32 prefix.');

  if (str.length < 8 || str.length > 196) // 83 + 1 + 112
    throw new Error('Invalid cash32 string.');

  let dlen = str.length;

  if (str.length > prefix.length && str[prefix.length] === ':')
    dlen = str.length - (prefix.length + 1);

  if (dlen < 8 || dlen > 112)
    throw new Error('Invalid cash32 data.');

  let lower = false;
  let upper = false;

  if (dlen !== str.length) {
    for (let i = 0; i < prefix.length; i++) {
      let ch = str.charCodeAt(i);

      if (ch >= 97 && ch <= 122) {
        lower = true;
      } else if (ch >= 65 && ch <= 90) {
        upper = true;
        ch += 32;
      }

      if (ch !== prefix.charCodeAt(i))
        throw new Error('Invalid cash32 prefix.');
    }
  }

  const chk = [0, 1];

  for (let i = 0; i < prefix.length; i++) {
    const ch = prefix.charCodeAt(i);

    if ((ch < 33 || ch > 126)
        || (ch >= 65 && ch <= 90)
        || (ch >= 48 && ch <= 57)
        || ch === 58) {
      throw new Error('Invalid cash32 prefix.');
    }

    polymod(chk, ch & 0x1f);
  }

  polymod(chk, 0);

  const data = Buffer.alloc(dlen - 8);

  let j = 0;

  for (let i = str.length - dlen; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    if (ch & 0xff80)
      throw new Error('Invalid cash32 character.');

    const val = TABLE[ch];

    if (val === -1)
      throw new Error('Invalid cash32 character.');

    if (ch >= 97 && ch <= 122)
      lower = true;
    else if (ch >= 65 && ch <= 90)
      upper = true;

    polymod(chk, val);

    if (i < str.length - 8)
      data[j++] = val;
  }

  if (upper && lower)
    throw new Error('Invalid cash32 casing.');

  if (!(chk[0] === 0 && chk[1] === 1))
    throw new Error('Invalid cash32 checksum.');

  return data;
}

/**
 * Test whether a string is a cash32 string.
 * @param {String} str
 * @returns {Boolean}
 */

function is(str, prefix) {
  assert(typeof str === 'string');
  assert(typeof prefix === 'string');

  try {
    deserialize(str, prefix);
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Convert serialized data to another base.
 * @param {Buffer} dst
 * @param {Number} dstoff
 * @param {Number} dstbits
 * @param {Buffer} src
 * @param {Number} srcoff
 * @param {Number} srcbits
 * @param {Boolean} pad
 * @returns {Buffer}
 */

function convert(dst, dstoff, dstbits, src, srcoff, srcbits, pad) {
  assert(Buffer.isBuffer(dst));
  assert((dstoff >>> 0) === dstoff);
  assert((dstbits >>> 0) === dstbits);
  assert(Buffer.isBuffer(src));
  assert((srcoff >>> 0) === srcoff);
  assert((srcbits >>> 0) === srcbits);
  assert(typeof pad === 'boolean');
  assert(dstbits >= 1 && dstbits <= 8);
  assert(srcbits >= 1 && srcbits <= 8);

  const mask = (1 << dstbits) - 1;
  const maxacc = (1 << (srcbits + dstbits - 1)) - 1;

  let acc = 0;
  let bits = 0;
  let i = srcoff;
  let j = dstoff;

  for (; i < src.length; i++) {
    acc = ((acc << srcbits) | src[i]) & maxacc;
    bits += srcbits;

    while (bits >= dstbits) {
      bits -= dstbits;
      dst[j++] = (acc >>> bits) & mask;
    }
  }

  const left = dstbits - bits;

  if (pad) {
    if (bits)
      dst[j++] = (acc << left) & mask;
  } else {
    if (bits >= srcbits || ((acc << left) & mask))
      throw new Error('Invalid bits.');
  }

  assert(j <= dst.length);

  return dst.slice(0, j);
}

/**
 * Calculate size required for bit conversion.
 * @param {Number} len
 * @param {Number} srcbits
 * @param {Number} dstbits
 * @param {Boolean} pad
 * @returns {Number}
 */

function convertSize(len, srcbits, dstbits, pad) {
  assert((len >>> 0) === len);
  assert((srcbits >>> 0) === srcbits);
  assert((dstbits >>> 0) === dstbits);
  assert(typeof pad === 'boolean');
  assert(srcbits >= 1 && srcbits <= 8);
  assert(dstbits >= 1 && dstbits <= 8);

  return ((len * srcbits + (dstbits - 1) * (pad | 0)) / dstbits) >>> 0;
}

/**
 * Convert serialized data to another base.
 * @param {Buffer} data
 * @param {Number} srcbits
 * @param {Number} dstbits
 * @param {Boolean} pad
 * @returns {Buffer}
 */

function convertBits(data, srcbits, dstbits, pad) {
  assert(Buffer.isBuffer(data));

  const size = convertSize(data.length, srcbits, dstbits, pad);
  const out = Buffer.alloc(size);

  return convert(out, 0, dstbits, data, 0, srcbits, pad);
}

/**
 * Get cash32 encoded size.
 * @param {Number} size
 * @returns {Number}
 */

function encodedSize(size) {
  assert((size >>> 0) === size);

  switch (size) {
    case 20:
      return 0;
    case 24:
      return 1;
    case 28:
      return 2;
    case 32:
      return 3;
    case 40:
      return 4;
    case 48:
      return 5;
    case 56:
      return 6;
    case 64:
      return 7;
    default:
      throw new Error('Non standard length.');
  }
}

/**
 * Serialize data to cash32
 * @param {String} prefix
 * @param {Number} type - (0 = P2PKH, 1 = P2SH)
 * @param {Buffer} hash
 * @returns {String}
 */

function encode(prefix, type, hash) {
  assert(typeof prefix === 'string');
  assert((type >>> 0) === type);
  assert(Buffer.isBuffer(hash));

  if (type > 15)
    throw new Error('Invalid cash32 type.');

  const size = encodedSize(hash.length);
  const data = Buffer.alloc(hash.length + 1);

  data[0] = (type << 3) | size;

  hash.copy(data, 1);

  const output = POOL104;
  const conv = convert(output, 0, 5, data, 0, 8, true);

  return serialize(prefix, conv);
}

/**
 * Deserialize data from cash32 address.
 * @param {String} str
 * @param {String} prefix (lowercase and w/o numbers)
 * @returns {Array}
 */

function decode(str, prefix = 'bitcoincash') {
  const conv = deserialize(str, prefix);

  if (conv.length === 0 || conv.length > 104)
    throw new Error('Invalid cash32 data.');

  const output = conv; // Works because dstbits > srcbits.
  const data = convert(output, 0, 8, conv, 0, 5, false);

  if (data.length === 0 || data.length > 1 + 64)
    throw new Error('Invalid cash32 data.');

  const type = (data[0] >>> 3) & 31;
  const hash = data.slice(1);

  let size = 20 + 4 * (data[0] & 3);

  if (data[0] & 4)
    size *= 2;

  if (type > 15)
    throw new Error('Invalid cash32 type.');

  if (size !== hash.length)
    throw new Error('Invalid cash32 data length.');

  return [type, hash];
}

/**
 * Test whether a string is a cash32 string.
 * @param {String} str
 * @param {String} prefix (lowercase and w/o numbers)
 * @returns {Boolean}
 */

function test(str, prefix = 'bitcoincash') {
  assert(typeof str === 'string');
  assert(typeof prefix === 'string');

  try {
    decode(str, prefix);
    return true;
  } catch (e) {
    return false;
  }
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
