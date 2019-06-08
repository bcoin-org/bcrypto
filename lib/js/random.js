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

/**
 * Whether the backend is a binding.
 * @const {Number}
 */

exports.native = 0;

/**
 * Generate pseudo-random bytes.
 * @param {Number} size
 * @returns {Buffer}
 */

exports.randomBytes = function randomBytes(size) {
  assert((size >>> 0) === size);

  const data = Buffer.alloc(size);

  exports.randomFill(data, 0, data.length);

  return data;
};

/**
 * Generate pseudo-random bytes.
 * @param {Buffer} data
 * @param {Number} [off=0]
 * @param {Number} [size=data.length-off]
 * @returns {Buffer}
 */

exports.randomFill = function randomFill(data, off, size) {
  assert(Buffer.isBuffer(data));
  assert(data.buffer instanceof ArrayBuffer);
  assert((data.byteOffset >>> 0) === data.byteOffset);

  if (off == null)
    off = 0;

  assert((off >>> 0) === off);

  if (size == null)
    size = data.length - off;

  assert((size >>> 0) === size);
  assert(off + size <= data.length);

  const array = new Uint8Array(
    data.buffer,
    data.byteOffset + off,
    size
  );

  getRandomValues(array);

  return data;
};

/**
 * Generate a random uint32.
 * @returns {Number}
 */

exports.randomInt = function randomInt() {
  const array = new Uint32Array(1);

  getRandomValues(array);

  return array[0];
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
  const array = new Uint32Array(1);

  let x, r;

  do {
    getRandomValues(array);

    x = array[0];
    r = x % space;
  } while (x - r > top);

  return r + min;
};

/*
 * Helpers
 */

function isTesting() {
  return typeof process === 'object'
      && process
      && process.env
      && process.env.NODE_TEST === '1'
      && !process.browser;
}

function getRandomValues(array) {
  assert(array && typeof array.constructor);

  const {BYTES_PER_ELEMENT} = array.constructor;

  assert(BYTES_PER_ELEMENT <= 4);

  if (array.byteLength > (2 ** 31 - 1))
    throw new RangeError('The value "size" is out of range.');

  const crypto = global.crypto || global.msCrypto;

  // Native WebCrypto support.
  // https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues
  if (crypto && typeof crypto.getRandomValues === 'function') {
    const max = 65536 / BYTES_PER_ELEMENT;

    if (array.length > max) {
      for (let i = 0; i < array.length; i += max) {
        let j = i + max;

        if (j > array.length)
          j = array.length;

        crypto.getRandomValues(array.subarray(i, j));
      }
    } else {
      if (array.length > 0)
        crypto.getRandomValues(array);
    }

    return;
  }

  // Fallback to Math.random (FOR TESTING ONLY).
  if (isTesting()) {
    const mask = 2 ** (BYTES_PER_ELEMENT * 8);

    for (let i = 0; i < array.length; i++)
      array[i] = Math.floor(Math.random() * mask);

    return;
  }

  // Error if no randomness is available.
  // We don't want people using bad randomness
  // when keys are at stake!
  throw new Error('Entropy source not available.');
}
