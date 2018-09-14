/*!
 * cipher.js - ciphers for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const ciphers = require('../internal/ciphers');

/**
 * CipherBase
 * @param {String} name
 * @param {Boolean} encrypt
 */

class CipherBase {
  constructor(name, encrypt) {
    assert(typeof name === 'string');
    assert(typeof encrypt === 'boolean');

    if (!ciphers.has(name))
      throw new Error('Unsupported cipher.');

    this.name = name;
    this.encrypt = encrypt;
    this.ctx = null;
  }

  init(key, iv) {
    assert(Buffer.isBuffer(key));
    assert(!iv || Buffer.isBuffer(iv));

    this.ctx = this.encrypt
      ? crypto.createCipheriv(this.name, key, iv)
      : crypto.createDecipheriv(this.name, key, iv);

    return this;
  }

  update(data) {
    assert(Buffer.isBuffer(data));
    assert(this.ctx);
    return this.ctx.update(data);
  }

  final() {
    assert(this.ctx);

    const out = this.ctx.final();

    this.ctx = null;

    return out;
  }
}

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

exports.native = 1;
exports.Cipher = Cipher;
exports.Decipher = Decipher;
exports.info = ciphers.info;
exports.get = ciphers.get;
exports.has = ciphers.has;
exports.encrypt = encrypt;
exports.decrypt = decrypt;
