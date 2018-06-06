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
  exports.randomBytes = function randomBytes(size) {
    throw new Error('Entropy source not available.');
  };
}

/**
 * Generate a random uint32.
 * Probably more cryptographically sound than
 * `Math.random()`.
 * @returns {Number}
 */

exports.randomInt = function randomInt() {
  return exports.randomBytes(4).readUInt32LE(0);
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
