/*!
 * random.js - randomness for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const crypto = global.crypto || global.msCrypto || {};

/**
 * Generate pseudo-random bytes.
 * @param {Number} size
 * @returns {Buffer}
 */

exports.randomBytes = function randomBytes(size) {
  assert((size >>> 0) === size);
  const data = new Uint8Array(size);
  crypto.getRandomValues(data);
  return Buffer.from(data.buffer);
};

if (!crypto.getRandomValues) {
  // Out of luck here. Use bad randomness for now.
  exports.randomBytes = function randomBytes(size) {
    assert((size >>> 0) === size);

    const data = Buffer.allocUnsafe(size);

    for (let i = 0; i < data.length; i++)
      data[i] = Math.floor(Math.random() * 256);

    return data;
  };
}

/**
 * Generate a random uint32.
 * Probably more cryptographically sound than
 * `Math.random()`.
 * @returns {Number}
 */

exports.randomInt = function randomInt() {
  return exports.randomBytes(4).readUInt32LE(0, true);
};

/**
 * Generate a random number within a range.
 * Probably more cryptographically sound than
 * `Math.random()`.
 * @param {Number} min - Inclusive.
 * @param {Number} max - Exclusive.
 * @returns {Number}
 */

exports.randomRange = function randomRange(min, max) {
  assert(typeof min === 'number');
  assert(typeof max === 'number');
  const num = exports.randomInt();
  return Math.floor((num / 0x100000000) * (max - min) + min);
};
