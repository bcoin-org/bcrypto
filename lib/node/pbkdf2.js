/*!
 * pbkdf2.js - pbkdf2 for bcrypto
 * Copyright (c) 2014-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
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
 * Perform key derivation using PBKDF2.
 * @param {Object} alg
 * @param {Buffer} key
 * @param {Buffer} salt
 * @param {Number} iter
 * @param {Number} len
 * @returns {Buffer}
 */

exports.derive = function derive(alg, key, salt, iter, len) {
  assert(alg && typeof alg.id === 'string');
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(salt));
  assert((iter >>> 0) === iter);
  assert((len >>> 0) === len);

  const id = alg.id.toLowerCase();

  return crypto.pbkdf2Sync(key, salt, iter, len, id);
};

/**
 * Execute pbkdf2 asynchronously.
 * @param {Object} alg
 * @param {Buffer} key
 * @param {Buffer} salt
 * @param {Number} iter
 * @param {Number} len
 * @returns {Promise}
 */

exports.deriveAsync = async function deriveAsync(alg, key, salt, iter, len) {
  assert(alg && typeof alg.id === 'string');
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(salt));
  assert((iter >>> 0) === iter);
  assert((len >>> 0) === len);

  const id = alg.id.toLowerCase();

  return new Promise((resolve, reject) => {
    try {
      crypto.pbkdf2(key, salt, iter, len, id, (err, result) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(result);
      });
    } catch (e) {
      reject(e);
    }
  });
};
