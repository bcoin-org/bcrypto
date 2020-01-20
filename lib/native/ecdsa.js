/*!
 * ecdsa.js - ecdsa wrapper for openssl
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const binding = require('./binding');
const rng = require('./random');
const {padLeft} = require('../encoding/util');

/**
 * ECDSA
 */

class ECDSA extends binding.ECDSA {
  constructor(name) {
    super(name);

    this.id = name;
    this.type = 'ecdsa';
    this.size = this._size();
    this.bits = this._bits();
    this.native = 2;

    this._randomize(binding.entropy());
  }

  privateKeyGenerate() {
    return super.privateKeyGenerate(binding.entropy());
  }

  privateKeyExport(key, compress) {
    const pub = this.publicKeyCreate(key, false);

    return {
      d: Buffer.from(key),
      x: pub.slice(1, 1 + this.size),
      y: pub.slice(1 + this.size, 1 + this.size * 2)
    };
  }

  privateKeyImport(json) {
    assert(json && typeof json === 'object');

    const key = padLeft(json.d, this.size);

    if (!this.privateKeyVerify(key))
      throw new Error('Invalid private key.');

    return key;
  }

  publicKeyExport(key) {
    const pub = this.publicKeyConvert(key, false);

    return {
      x: pub.slice(1, 1 + this.size),
      y: pub.slice(1 + this.size, 1 + this.size * 2)
    };
  }

  publicKeyImport(json, compress) {
    assert(json && typeof json === 'object');

    let key;

    if (json.y != null) {
      key = Buffer.concat([
        Buffer.from([0x04]),
        padLeft(json.x, this.size),
        padLeft(json.y, this.size)
      ]);
    } else {
      key = Buffer.concat([
        Buffer.from([0x02 | json.sign]),
        padLeft(json.x, this.size)
      ]);
    }

    return this.publicKeyConvert(key, compress);
  }

  publicKeyToUniform(key, hint = rng.randomInt()) {
    return super.publicKeyToUniform(key, hint);
  }

  publicKeyToHash(key) {
    return super.publicKeyToHash(key, binding.entropy());
  }
}

/*
 * Expose
 */

module.exports = ECDSA;
