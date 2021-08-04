/*!
 * bcrypt.js - bcrypt for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/*
 * Bcrypt
 */

function generate(pass, salt, rounds, minor = 'b') {
  if (typeof pass === 'string')
    pass = Buffer.from(pass, 'utf8');

  assert(Buffer.isBuffer(pass));
  assert(typeof salt === 'string' || Buffer.isBuffer(salt));
  assert((rounds >>> 0) === rounds);
  assert(typeof minor === 'string');
  assert(minor.length === 1);

  minor = minor.charCodeAt(0) & 0x7f;

  return binding.bcrypt_generate(pass, salt, rounds, minor);
}

function verify(pass, record) {
  if (typeof pass === 'string')
    pass = Buffer.from(pass, 'utf8');

  assert(Buffer.isBuffer(pass));
  assert(typeof record === 'string');

  return binding.bcrypt_verify(pass, record);
}

function pbkdf(pass, salt, rounds, size) {
  if (typeof pass === 'string')
    pass = Buffer.from(pass, 'utf8');

  if (typeof salt === 'string')
    salt = Buffer.from(salt, 'utf8');

  if (salt == null)
    salt = binding.NULL;

  assert(Buffer.isBuffer(pass));
  assert(Buffer.isBuffer(salt));
  assert((rounds >>> 0) === rounds);
  assert((size >>> 0) === size);

  return binding.bcrypt_pbkdf(pass, salt, rounds, size);
}

async function pbkdfAsync(pass, salt, rounds, size) {
  if (typeof pass === 'string')
    pass = Buffer.from(pass, 'utf8');

  if (typeof salt === 'string')
    salt = Buffer.from(salt, 'utf8');

  if (salt == null)
    salt = binding.NULL;

  assert(Buffer.isBuffer(pass));
  assert(Buffer.isBuffer(salt));
  assert((rounds >>> 0) === rounds);
  assert((size >>> 0) === size);

  return binding.bcrypt_pbkdf_async(pass, salt, rounds, size);
}

/*
 * Expose
 */

exports.native = 2;
exports.generate = generate;
exports.verify = verify;
exports.pbkdf = pbkdf;
exports.pbkdfAsync = pbkdfAsync;
