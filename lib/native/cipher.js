/*!
 * cipher.js - ciphers for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const ciphers = require('../internal/ciphers');
const {CipherBase} = require('./binding');

/**
 * Cipher
 * @param {String} name
 */

class Cipher extends CipherBase {
  constructor(name) {
    super(name, true);
  }
}

/**
 * Decipher
 * @param {String} name
 */

class Decipher extends CipherBase {
  constructor(name) {
    super(name, false);
  }
}

/*
 * API
 */

function encrypt(name, key, iv, data) {
  const ctx = new Cipher(name);
  ctx.init(key, iv);
  return Buffer.concat([
    ctx.update(data),
    ctx.final()
  ]);
}

function decrypt(name, key, iv, data) {
  const ctx = new Decipher(name);
  ctx.init(key, iv);
  return Buffer.concat([
    ctx.update(data),
    ctx.final()
  ]);
}

/*
 * Expose
 */

exports.native = 2;
exports.Cipher = Cipher;
exports.Decipher = Decipher;
exports.has = ciphers.has;
exports.get = ciphers.get;
exports.encrypt = encrypt;
exports.decrypt = decrypt;
