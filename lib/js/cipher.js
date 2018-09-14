/*!
 * cipher.js - ciphers for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const modes = require('./ciphers/modes');
const AES = require('./ciphers/aes');
const Blowfish = require('./ciphers/blowfish');
const CAST5 = require('./ciphers/cast5');
const {DES, EDE} = require('./ciphers/des');

/**
 * CipherBase
 */

class CipherBase {
  constructor(name, encrypt) {
    assert(typeof name === 'string');
    assert(typeof encrypt === 'boolean');

    this.encrypt = encrypt;
    this.ctx = null;
    this._init(name);
  }

  _error(name) {
    const err = new Error(`Unknown cipher: ${name}.`);

    if (Error.captureStackTrace)
      Error.captureStackTrace(err, this._error);

    throw err;
  }

  _init(name) {
    assert(typeof name === 'string');
    assert(name.length <= 255);

    const parts = name.split('-', 5);

    if (parts.length < 2 || parts.length > 3)
      return this._error(name);

    const alg = parts[0];

    switch (alg) {
      case 'aes':
      case 'AES': {
        if (parts.length !== 3)
          return this._error(name);

        const bits = parts[1] >>> 0;
        const mode = parts[2];
        const Mode = modes.get(mode, this.encrypt);

        this.ctx = new Mode(new AES(bits));

        break;
      }

      case 'bf':
      case 'BF': {
        if (parts.length !== 2)
          return this._error(name);

        const mode = parts[1];
        const Mode = modes.get(mode, this.encrypt);

        this.ctx = new Mode(new Blowfish());

        break;
      }

      case 'cast5':
      case 'CAST5': {
        if (parts.length !== 2)
          return this._error(name);

        const mode = parts[1];
        const Mode = modes.get(mode, this.encrypt);

        this.ctx = new Mode(new CAST5());

        break;
      }

      case 'des':
      case 'DES': {
        switch (parts.length) {
          case 2: {
            const mode = parts[1];
            const Mode = modes.get(mode, this.encrypt);

            this.ctx = new Mode(new DES());

            break;
          }
          case 3: {
            if (parts[1] !== 'ede3' && parts[1] !== 'EDE3')
              return this._error(name);

            const mode = parts[2];
            const Mode = modes.get(mode, this.encrypt);

            this.ctx = new Mode(new EDE());

            break;
          }
          default: {
            this._error(name);
            break;
          }
        }

        break;
      }

      default: {
        this._error(name);
        break;
      }
    }

    return this;
  }

  init(key, iv) {
    this.ctx.init(key, iv);
    return this;
  }

  update(data) {
    assert(this.ctx);
    return this.ctx.update(data);
  }

  final() {
    const out = this.ctx.final();

    this.ctx = null;

    return out;
  }
}

/**
 * Cipher
 * @extends CipherBase
 */

class Cipher extends CipherBase {
  constructor(name) {
    super(name, true);
  }
}

/**
 * Decipher
 * @extends CipherBase
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
