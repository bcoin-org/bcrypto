/*!
 * scrypt.js - scrypt for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const binding = require('./binding').scrypt;

exports.native = 2;

exports.derive = function derive(passwd, salt, N, r, p, len) {
  if (typeof passwd === 'string')
    passwd = Buffer.from(passwd, 'utf8');

  if (typeof salt === 'string')
    salt = Buffer.from(salt, 'utf8');

  if (salt == null)
    salt = Buffer.alloc(0);

  return binding.derive(passwd, salt, N, r, p, len);
};

exports.deriveAsync = async function deriveAsync(passwd, salt, N, r, p, len) {
  if (typeof passwd === 'string')
    passwd = Buffer.from(passwd, 'utf8');

  if (typeof salt === 'string')
    salt = Buffer.from(salt, 'utf8');

  if (salt == null)
    salt = Buffer.alloc(0);

  return new Promise((resolve, reject) => {
    const cb = (err, key) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(key);
    };

    try {
      binding.deriveAsync(passwd, salt, N, r, p, len, cb);
    } catch (e) {
      reject(e);
    }
  });
};
