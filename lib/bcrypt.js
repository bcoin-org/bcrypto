/*!
 * bcrypt.js - bcrypt for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on joyent/node-bcrypt-pbkdf:
 *   Copyright (c) 2016, Joyent Inc
 *   https://github.com/joyent/node-bcrypt-pbkdf
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Bcrypt
 *   http://www.usenix.org/events/usenix99/provos/provos_html/node1.html
 *   https://github.com/joyent/node-bcrypt-pbkdf/blob/master/index.js
 */

'use strict';

const assert = require('bsert');
const SHA512 = require('./sha512');
const Blowfish = require('./js/ciphers/blowfish');

/*
 * Constants
 */

const CIPHERTEXT192 = Buffer.from('OrpheanBeholderScryDoubt', 'binary');
const BCRYPT_BLOCKS192 = 6;
const BCRYPT_SIZE192 = 24;

const CIPHERTEXT256 = Buffer.from('OxychromaticBlowfishSwatDynamite', 'binary');
const BCRYPT_BLOCKS256 = 8;
const BCRYPT_SIZE256 = 32;

/*
 * Bcrypt
 */

function _hash192(pass, salt, rounds, out) {
  const state = new Blowfish();
  const cdata = new Uint32Array(BCRYPT_BLOCKS192);

  state.init(pass, salt);

  const r = 2 ** rounds;

  for (let i = 0; i < r; i++) {
    state.expand0state(pass);
    state.expand0state(salt);
  }

  for (let i = 0; i < BCRYPT_BLOCKS192; i++)
    cdata[i] = state.stream2word(CIPHERTEXT192);

  for (let i = 0; i < 64; i++)
    state.enc(cdata);

  for (let i = 0; i < BCRYPT_BLOCKS192; i++) {
    out[4 * i + 3] = cdata[i] >>> 24;
    out[4 * i + 2] = cdata[i] >>> 16;
    out[4 * i + 1] = cdata[i] >>> 8;
    out[4 * i + 0] = cdata[i];
  }

  return out;
}

function _hash256(pass, salt, rounds, out) {
  const state = new Blowfish();
  const cdata = new Uint32Array(BCRYPT_BLOCKS256);

  state.init(pass, salt);

  const r = 2 ** rounds;

  for (let i = 0; i < r; i++) {
    state.expand0state(salt);
    state.expand0state(pass);
  }

  for (let i = 0; i < BCRYPT_BLOCKS256; i++)
    cdata[i] = state.stream2word(CIPHERTEXT256);

  for (let i = 0; i < 64; i++)
    state.enc(cdata);

  for (let i = 0; i < BCRYPT_BLOCKS256; i++) {
    out[4 * i + 3] = cdata[i] >>> 24;
    out[4 * i + 2] = cdata[i] >>> 16;
    out[4 * i + 1] = cdata[i] >>> 8;
    out[4 * i + 0] = cdata[i];
  }

  return out;
}

/*
 * API
 */

function hash192(pass, salt, rounds) {
  if (typeof pass === 'string')
    pass = Buffer.from(pass, 'utf8');

  if (typeof salt === 'string')
    salt = Buffer.from(salt, 'binary');

  assert(Buffer.isBuffer(pass));
  assert(Buffer.isBuffer(salt));
  assert((rounds >>> 0) === rounds);

  if (rounds < 4 || rounds > 31)
    throw new RangeError('Invalid rounds.');

  return _hash192(pass, salt, rounds, Buffer.alloc(BCRYPT_SIZE192));
}

function hash256(pass, salt, rounds) {
  if (typeof pass === 'string')
    pass = Buffer.from(pass, 'utf8');

  if (typeof salt === 'string')
    salt = Buffer.from(salt, 'binary');

  assert(Buffer.isBuffer(pass));
  assert(Buffer.isBuffer(salt));
  assert((rounds >>> 0) === rounds);

  if (rounds < 4 || rounds > 31)
    throw new RangeError('Invalid rounds.');

  return _hash256(pass, salt, rounds, Buffer.alloc(BCRYPT_SIZE256));
}

function pbkdf(pass, salt, rounds, size) {
  if (typeof pass === 'string')
    pass = Buffer.from(pass, 'utf8');

  if (typeof salt === 'string')
    salt = Buffer.from(salt, 'binary');

  assert(Buffer.isBuffer(pass));
  assert(Buffer.isBuffer(salt));
  assert((rounds >>> 0) === rounds);
  assert((size >>> 0) === size);

  const out = Buffer.alloc(BCRYPT_SIZE256);
  const tmpout = Buffer.alloc(BCRYPT_SIZE256);
  const countsalt = Buffer.alloc(salt.length + 4);
  const key = Buffer.alloc(size);

  if (rounds < 1
      || pass.length === 0
      || salt.length === 0
      || size === 0
      || size > out.length ** 2
      || salt.length > (1 << 20)) {
    throw new Error('Invalid bcrypt parameters.');
  }

  const stride = ((size + out.length - 1) / out.length) >>> 0;
  const amount = ((size + stride - 1) / stride) >>> 0;

  salt.copy(countsalt, 0);

  const sha2pass = SHA512.digest(pass);

  let sha2salt = Buffer.alloc(0);
  let keylen = size;
  let amt = amount;

  for (let count = 1; keylen > 0; count++) {
    countsalt[salt.length + 0] = count >>> 24;
    countsalt[salt.length + 1] = count >>> 16;
    countsalt[salt.length + 2] = count >>> 8;
    countsalt[salt.length + 3] = count;

    sha2salt = SHA512.digest(countsalt);

    _hash256(sha2pass, sha2salt, 6, tmpout);

    tmpout.copy(out, 0);

    for (let i = 1; i < rounds; i++) {
      sha2salt = SHA512.digest(tmpout);

      _hash256(sha2pass, sha2salt, 6, tmpout);

      for (let j = 0; j < out.length; j++)
        out[j] ^= tmpout[j];
    }

    amt = Math.min(amt, keylen);

    let i = 0;

    for (; i < amt; i++) {
      const dest = i * stride + (count - 1);

      if (dest >= size)
        break;

      key[dest] = out[i];
    }

    keylen -= i;
  }

  return key;
}

/*
 * Expose
 */

exports.native = 0;
exports.hash192 = hash192;
exports.hash256 = hash256;
exports.pbkdf = pbkdf;
