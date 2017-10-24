/*!
 * pbkdf2.js - pbkdf2 for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const crypto = require('crypto');

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
  assert(alg && typeof alg.name === 'string');
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(salt));
  assert((iter >>> 0) === iter);
  assert((len >>> 0) === len);
  const name = alg.name.toLowerCase();
  return crypto.pbkdf2Sync(key, salt, iter, len, name);
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

exports.deriveAsync = function deriveAsync(alg, key, salt, iter, len) {
  return new Promise((resolve, reject) => {
    try {
      assert(alg && typeof alg.name === 'string');
      assert(Buffer.isBuffer(key));
      assert(Buffer.isBuffer(salt));
      assert((iter >>> 0) === iter);
      assert((len >>> 0) === len);

      const name = alg.name.toLowerCase();

      crypto.pbkdf2(key, salt, iter, len, name, (err, result) => {
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
