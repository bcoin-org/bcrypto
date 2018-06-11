/*!
 * pbkdf2.js - pbkdf2 for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const binding = require('./binding');

exports.native = 2;

exports.derive = function derive(alg, data, salt, iter, len) {
  assert(alg && typeof alg.id === 'string');
  return binding.pbkdf2(alg.id, data, salt, iter, len);
};

exports.deriveAsync = function deriveAsync(alg, data, salt, iter, len) {
  return new Promise((resolve, reject) => {
    try {
      assert(alg && typeof alg.id === 'string');

      binding.pbkdf2Async(alg.id, data, salt, iter, len, (err, key) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(key);
      });
    } catch (e) {
      reject(e);
    }
  });
};
