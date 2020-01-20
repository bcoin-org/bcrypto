/*!
 * ecdh.js - ECDH for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://cr.yp.to/ecdh.html
 *   https://cr.yp.to/ecdh/curve25519-20060209.pdf
 *   https://tools.ietf.org/html/rfc7748
 */

'use strict';

const assert = require('bsert');
const binding = require('./binding');
const rng = require('../random');
const {padRight} = require('../encoding/util');

/**
 * ECDH
 */

class ECDH extends binding.ECDH {
  constructor(name) {
    super(name);

    this.id = name;
    this.type = 'ecdh';
    this.size = this._size();
    this.bits = this._bits();
    this.native = 2;
  }

  privateKeyGenerate() {
    return super.privateKeyGenerate(binding.entropy());
  }

  privateKeyExport(key) {
    const pub = this.publicKeyCreate(key);

    return {
      d: Buffer.from(key),
      x: pub
    };
  }

  privateKeyImport(json) {
    assert(json && typeof json === 'object');
    assert(Buffer.isBuffer(json.d));

    const key = padRight(json.d, this.size);

    if (!this.privateKeyVerify(key))
      throw new Error('Invalid private key.');

    return key;
  }

  publicKeyExport(key) {
    if (!this.publicKeyVerify(key))
      throw new Error('Invalid public key.');

    return {
      x: Buffer.from(key)
    };
  }

  publicKeyImport(json) {
    assert(json && typeof json === 'object');

    const key = padRight(json.x, this.size);

    if (!this.publicKeyVerify(key))
      throw new Error('Invalid public key.');

    return key;
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

module.exports = ECDH;
