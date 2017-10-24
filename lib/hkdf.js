/*!
 * hkdf.js - hkdf for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');

/**
 * Perform hkdf extraction.
 * @param {Object} alg
 * @param {Buffer} ikm
 * @param {Buffer} key
 * @returns {Buffer}
 */

exports.extract = function extract(alg, ikm, key) {
  assert(alg && typeof alg.name === 'string');
  assert(Buffer.isBuffer(ikm));
  assert(Buffer.isBuffer(key));
  return alg.mac(ikm, key);
};

/**
 * Perform hkdf expansion.
 * @param {Function} alg
 * @param {Buffer} prk
 * @param {Buffer} info
 * @param {Number} len
 * @returns {Buffer}
 */

exports.expand = function expand(alg, prk, info, len) {
  assert(alg && typeof alg.name === 'string');
  assert(Buffer.isBuffer(prk));
  assert(Buffer.isBuffer(info));
  assert((len >>> 0) === len);

  const size = alg.digest(Buffer.alloc(0)).length;
  const blocks = Math.ceil(len / size);

  if (blocks > 255)
    throw new Error('Too many blocks.');

  const okm = Buffer.allocUnsafe(len);

  if (blocks === 0)
    return okm;

  const buf = Buffer.allocUnsafe(size + info.length + 1);

  // First round:
  info.copy(buf, size);
  buf[buf.length - 1] = 1;

  let out = alg.mac(buf.slice(size), prk);
  out.copy(okm, 0);

  for (let i = 1; i < blocks; i++) {
    out.copy(buf, 0);
    buf[buf.length - 1] += 1;
    out = alg.mac(buf, prk);
    out.copy(okm, i * size);
  }

  return okm;
};
