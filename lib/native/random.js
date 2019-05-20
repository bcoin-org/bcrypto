/*!
 * random.js - random number generator for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const backend = require('./binding');
const binding = backend.random;

/**
 * Generate pseudo-random bytes.
 * @param {Number} size
 * @returns {Buffer}
 */

function randomBytes(size) {
  assert((size >>> 0) === size);
  backend.reseed();
  return binding.randomBytes(size);
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

  backend.reseed();

  return binding.randomFill(data, off, size);
}

/**
 * Generate a random uint32.
 * @returns {Number}
 */

function randomInt() {
  backend.reseed();
  return binding.randomInt();
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
  backend.reseed();
  return binding.randomRange(min, max);
}

/*
 * Expose
 */

exports.native = 2;
exports.randomBytes = randomBytes;
exports.randomFill = randomFill;
exports.randomInt = randomInt;
exports.randomRange = randomRange;
