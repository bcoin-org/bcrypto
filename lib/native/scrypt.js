/*!
 * scrypt.js - scrypt for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const binding = require('./binding');

exports.derive = binding.scrypt;

exports.deriveAsync = function deriveAsync(passwd, salt, N, r, p, len) {
  return new Promise((resolve, reject) => {
    try {
      binding.scryptAsync(passwd, salt, N, r, p, len, (err, key) => {
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
