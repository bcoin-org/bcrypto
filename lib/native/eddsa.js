/*!
 * eddsa.js - EdDSA for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const binding = require('./binding');
const rng = require('../random');
const {padRight} = require('../encoding/util');

/*
 * EDDSA
 */

class EDDSA extends binding.EDDSA {
  constructor(name) {
    super(name);

    this.id = name;
    this.type = 'eddsa';
    this.size = this._size();
    this.bits = this._bits();
    this.native = 2;
  }

  privateKeyGenerate() {
    return super.privateKeyGenerate(binding.entropy());
  }

  scalarGenerate() {
    return super.scalarGenerate(binding.entropy());
  }

  privateKeyExport(secret) {
    const pub = this.publicKeyCreate(secret);
    const {y, sign} = this.publicKeyExport(pub);

    return {
      d: Buffer.from(secret),
      y,
      sign
    };
  }

  privateKeyImport(json) {
    assert(json && typeof json === 'object');
    assert(Buffer.isBuffer(json.d));

    if (json.d.length !== this.size)
      throw new Error('Invalid private key.');

    return Buffer.from(json.d);
  }

  publicKeyToUniform(key, hint = rng.randomInt()) {
    return super.publicKeyToUniform(key, hint);
  }

  publicKeyExport(key) {
    if (!this.publicKeyVerify(key))
      throw new Error('Invalid public key.');

    const y = Buffer.from(key);
    const sign = y[this.size - 1] >> 7;

    y[this.size - 1] &= 0x7f;

    return {
      y: y.slice(0, (this.bits + 7) >> 3),
      sign: sign === 1
    };
  }

  publicKeyImport(json) {
    assert(json && typeof json === 'object');

    const key = padRight(json.y, this.size);

    key[this.size - 1] |= json.sign << 7;

    if (!this.publicKeyVerify(key))
      throw new Error('Invalid public key.');

    return key;
  }

  publicKeyToHash(key) {
    return super.publicKeyToHash(key, binding.entropy());
  }
}

/*
 * Expose
 */

module.exports = EDDSA;
