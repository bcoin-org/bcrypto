/*!
 * pbkdf2.js - pbkdf2 for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const binding = require('./binding').pbkdf2;

exports.native = 2;

exports.derive = function derive(alg, data, salt, iter, len) {
  assert(alg && typeof alg.id === 'string');
  const id = alg.id.toLowerCase();
  return binding.derive(id, data, salt, iter, len);
};

exports.deriveAsync = async function deriveAsync(alg, data, salt, iter, len) {
  assert(alg && typeof alg.id === 'string');

  const id = alg.id.toLowerCase();

  return new Promise((resolve, reject) => {
    try {
      binding.deriveAsync(id, data, salt, iter, len, (err, key) => {
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
