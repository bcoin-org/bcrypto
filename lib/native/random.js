/*!
 * random.js - pseduo-randomness for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const binding = require('./binding');

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
  const buf = Buffer.allocUnsafe(size);
  return binding.randomFill(buf, 0, size);
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

exports.randomBytesAsync = function randomBytesAsync(size) {
  return new Promise((resolve, reject) => {
    let r;
    try {
      r = exports.randomBytes(size);
    } catch (e) {
      reject(e);
      return;
    }
    resolve(r);
  });
};

/**
 * Generate pseudo-random bytes.
 * @param {Buffer} buf
 * @param {Number} [off=0]
 * @param {Number} [size=buf.length-size]
 * @returns {Promise}
 */

exports.randomFillAsync = function randomFillAsync(buf, off, size) {
  return new Promise((resolve, reject) => {
    let r;
    try {
      r = exports.randomFill(buf, off, size);
    } catch (e) {
      reject(e);
      return;
    }
    resolve(r);
  });
};

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
  assert((min >>> 0) === min);
  assert((max >>> 0) === max);
  assert(max >= min);
  const num = exports.randomInt();
  return Math.floor((num / 0x100000000) * (max - min) + min);
};
