/*!
 * pbkdf2.js - pbkdf2 for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const binding = require('./binding').pbkdf2;

exports.native = 2;

exports.derive = function derive(hash, data, salt, iter, len) {
  assert(hash && typeof hash.id === 'string');
  return binding.derive(hash.id, data, salt, iter, len);
};

exports.deriveAsync = async function deriveAsync(hash, data, salt, iter, len) {
  assert(hash && typeof hash.id === 'string');

  return new Promise((resolve, reject) => {
    const cb = (err, result) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(result);
    };

    try {
      binding.deriveAsync(hash.id, data, salt, iter, len, cb);
    } catch (e) {
      reject(e);
    }
  });
};
