/*!
 * random.js - random number generator for bcrypto
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://wiki.openssl.org/index.php/Random_Numbers
 *   https://csrc.nist.gov/projects/random-bit-generation/
 *   http://www.pcg-random.org/posts/bounded-rands.html
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');

/**
 * Generate pseudo-random bytes.
 * @param {Number} size
 * @returns {Buffer}
 */

function randomBytes(size) {
  assert((size >>> 0) === size);

  const data = Buffer.alloc(size, 0x00);

  crypto.randomFillSync(data, 0, size);

  return data;
}

/**
 * Generate pseudo-random bytes.
 * @param {Buffer} data
 * @param {Number} [off=0]
 * @param {Number} [size=data.length-off]
 * @returns {Buffer}
 */

function randomFill(data, off, size) {
  assert(Buffer.isBuffer(data));

  if (off == null)
    off = 0;

  assert((off >>> 0) === off);

  if (size == null)
    size = data.length - off;

  assert((size >>> 0) === size);
  assert(off + size <= data.length);

  data.fill(0x00, off, off + size);

  crypto.randomFillSync(data, off, size);

  return data;
}

/**
 * Generate a random uint32.
 * @returns {Number}
 */

function randomInt() {
  return randomBytes(4).readUInt32LE(0);
}

/**
 * Generate a random uint32 within a range.
 * @param {Number} min - Inclusive.
 * @param {Number} max - Exclusive.
 * @returns {Number}
 */

function randomRange(min, max) {
  assert((min >>> 0) === min);
  assert((max >>> 0) === max);
  assert(max >= min);

  const space = max - min;

  if (space === 0)
    return min;

  const top = -space >>> 0;
  const data = Buffer.alloc(4);

  let x, r;

  do {
    randomFill(data, 0, 4);

    x = 0;
    x += data[0];
    x += data[1] * 0x100;
    x += data[2] * 0x10000;
    x += data[3] * 0x1000000;

    r = x % space;
  } while (x - r > top);

  return r + min;
}

/*
 * Expose
 */

exports.native = 1;
exports.randomBytes = randomBytes;
exports.randomFill = randomFill;
exports.randomInt = randomInt;
exports.randomRange = randomRange;
