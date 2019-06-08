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
 * Whether the backend is a binding.
 * @const {Number}
 */

exports.native = 1;

/**
 * Generate pseudo-random bytes.
 * @function
 * @param {Number} size
 * @returns {Buffer}
 */

exports.randomBytes = function randomBytes(size) {
  return crypto.randomBytes(size);
};

/**
 * Generate pseudo-random bytes.
 * @param {Buffer} data
 * @param {Number} [off=0]
 * @param {Number} [size=data.length-off]
 * @returns {Buffer}
 */

exports.randomFill = crypto.randomFillSync;

/**
 * Generate a random uint32.
 * @returns {Number}
 */

exports.randomInt = function randomInt() {
  return crypto.randomBytes(4).readUInt32LE(0);
};

/**
 * Generate a random uint32 within a range.
 * @param {Number} min - Inclusive.
 * @param {Number} max - Exclusive.
 * @returns {Number}
 */

exports.randomRange = function randomRange(min, max) {
  assert((min >>> 0) === min);
  assert((max >>> 0) === max);
  assert(max >= min);

  const space = max - min;

  if (space === 0)
    return min;

  const top = -space >>> 0;
  const data = Buffer.allocUnsafe(4);

  let x, r;

  do {
    crypto.randomFillSync(data, 0, 4);

    x = 0;
    x += data[0] * 0x1;
    x += data[1] * 0x100;
    x += data[2] * 0x10000;
    x += data[3] * 0x1000000;

    r = x % space;
  } while (x - r > top);

  return r + min;
};
