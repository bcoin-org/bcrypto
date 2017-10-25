/*!
 * pbkdf2.js - pbkdf2 for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const crypto = global.crypto || global.msCrypto || {};
const subtle = crypto.subtle || {};

/**
 * Perform key derivation using PBKDF2.
 * @param {Function} alg
 * @param {Buffer} key
 * @param {Buffer} salt
 * @param {Number} iter
 * @param {Number} len
 * @returns {Buffer}
 */

exports.derive = function derive(alg, key, salt, iter, len) {
  assert(alg && typeof alg.name === 'string');
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(salt));
  assert((iter >>> 0) === iter);
  assert((len >>> 0) === len);

  const size = alg.digest(Buffer.alloc(0)).length;
  const blocks = Math.ceil(len / size);
  const out = Buffer.allocUnsafe(len);
  const buf = Buffer.allocUnsafe(salt.length + 4);
  const block = Buffer.allocUnsafe(size);

  let pos = 0;

  salt.copy(buf, 0);

  for (let i = 0; i < blocks; i++) {
    buf.writeUInt32BE(i + 1, salt.length, true);

    let mac = alg.mac(buf, key);
    mac.copy(block, 0);

    for (let j = 1; j < iter; j++) {
      mac = alg.mac(mac, key);
      for (let k = 0; k < size; k++)
        block[k] ^= mac[k];
    }

    block.copy(out, pos);
    pos += size;
  }

  return out;
};

/**
 * Execute pbkdf2 asynchronously.
 * @param {Function} alg
 * @param {Buffer} key
 * @param {Buffer} salt
 * @param {Number} iter
 * @param {Number} len
 * @returns {Promise}
 */

exports.deriveAsync = async function deriveAsync(alg, key, salt, iter, len) {
  assert(alg && typeof alg.name === 'string');
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(salt));
  assert((iter >>> 0) === iter);
  assert((len >>> 0) === len);

  const algo = { name: 'PBKDF2' };
  const use = ['deriveBits'];
  const hash = getHash(alg);

  if (!subtle.importKey || !subtle.deriveBits || !hash)
    return exports.derive(alg, key, salt, iter, len);

  const options = {
    name: 'PBKDF2',
    salt: salt,
    iterations: iter,
    hash: hash
  };

  const imported = await subtle.importKey('raw', key, algo, false, use);
  const data = await subtle.deriveBits(options, imported, len * 8);

  return Buffer.from(data);
};

/*
 * Helpers
 */

function getHash(alg) {
  const name = alg.name.toLowerCase();
  switch (name) {
    case 'sha1':
      return 'SHA-1';
    case 'sha256':
      return 'SHA-256';
    case 'sha384':
      return 'SHA-384';
    case 'sha512':
      return 'SHA-512';
    default:
      return null;
  }
}
