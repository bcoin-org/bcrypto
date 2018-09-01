/*!
 * cipher.js - ciphers for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const {AESCipher, AESDecipher} = require('../aes');

/**
 * CipherBase
 * @param {String} name
 * @param {Boolean} encrypt
 */

class CipherBase {
  constructor(name, encrypt) {
    assert(typeof name === 'string');
    assert(typeof encrypt === 'boolean');

    this.bits = 256;
    this.chain = false;
    this.encrypt = encrypt;
    this.ctx = null;
    this._init(name);
  }

  _init(name) {
    assert(typeof name === 'string');

    switch (name.toUpperCase()) {
      case 'AES-128-ECB':
        this.bits = 128;
        break;
      case 'AES-192-ECB':
        this.bits = 192;
        break;
      case 'AES-256-ECB':
        this.bits = 256;
        break;
      case 'AES-128-CBC':
        this.bits = 128;
        this.chain = true;
        break;
      case 'AES-192-CBC':
        this.bits = 192;
        this.chain = true;
        break;
      case 'AES-256-CBC':
        this.bits = 256;
        this.chain = true;
        break;
      default:
        throw new Error('Unknown cipher.');
    }
  }

  init(key, iv) {
    this.ctx = this.encrypt
      ? new AESCipher(this.bits, this.chain)
      : new AESDecipher(this.bits, this.chain);

    this.ctx.init(key, iv);

    return this;
  }

  update(data) {
    assert(this.ctx);
    return this.ctx.update(data);
  }

  final(data) {
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
 * Expose
 */

exports.native = 0;
exports.Cipher = Cipher;
exports.Decipher = Decipher;
