/*!
 * random.js - random number generator for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const binding = require('./binding').random;

/**
 * Whether the backend is a binding.
 * @const {Number}
 */

exports.native = 2;

/**
 * Generate pseudo-random bytes.
 * @function
 * @param {Number} size
 * @returns {Buffer}
 */

exports.randomBytes = function randomBytes(size) {
  assert((size >>> 0) === size);
  return binding.randomBytes(size);
};

/**
 * Generate pseudo-random bytes.
 * @param {Buffer} buf
 * @param {Number} [off=0]
 * @param {Number} [size=buf.length-off]
 * @returns {Buffer}
 */

exports.randomFill = function randomFill(buf, off, size) {
  assert(Buffer.isBuffer(buf));

  if (off == null)
    off = 0;

  assert((off >>> 0) === off);

  if (size == null)
    size = buf.length - off;

  assert((size >>> 0) === size);

  return binding.randomFill(buf, off, size);
};

/**
 * Generate pseudo-random bytes.
 * @param {Number} size
 * @returns {Promise}
 */

exports.randomBytesAsync = async function randomBytesAsync(size) {
  return exports.randomBytes(size);
};

/**
 * Generate pseudo-random bytes.
 * @param {Buffer} buf
 * @param {Number} [off=0]
 * @param {Number} [size=buf.length-size]
 * @returns {Promise}
 */

exports.randomFillAsync = async function randomFillAsync(buf, off, size) {
  return exports.randomFill(buf, off, size);
};

/**
 * Generate a random uint32.
 * Probably more cryptographically sound than
 * `Math.random()`.
 * @returns {Number}
 */

exports.randomInt = function randomInt() {
  return binding.randomInt();
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
  assert((min >>> 0) === min);
  assert((max >>> 0) === max);
  return binding.randomRange(min, max);
};
