/*!
 * eddsa.js - wrapper for elliptic
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const elliptic = require('../../vendor/elliptic');
const random = require('../random');

/**
 * EDDSA
 */

class EDDSA {
  constructor(name) {
    assert(typeof name === 'string');

    this.id = name;
    this._ec = null;
    this._bits = -1;
    this._zero = null;
    this._order = null;
    this.native = 0;
  }

  get ec() {
    if (!this._ec)
      this._ec = elliptic.eddsa(this.id);
    return this._ec;
  }

  get curve() {
    return this.ec.curve;
  }

  get size() {
    return this.ec.encodingLength;
  }

  get bits() {
    if (this._bits === -1)
      this._bits = this.curve.n.bitLength();
    return this._bits;
  }

  get zero() {
    if (!this._zero)
      this._zero = Buffer.alloc(this.size, 0x00);
    return this._zero;
  }

  get order() {
    if (!this._order)
      this._order = toBuffer(this.curve.n, this.size);
    return this._order;
  }

  secretGenerate() {
    return random.randomBytes(this.size);
  }

  secretVerify(secret) {
    assert(Buffer.isBuffer(secret));
    return secret.length === this.size;
  }

  privateKeyCreate(secret) {
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.size);

    const k = this.ec.keyFromSecret(secret);

    return Buffer.from(k.privBytes());
  }

  publicKeyCreate(secret) {
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.size);

    const k = this.ec.keyFromSecret(secret);

    return Buffer.from(k.pubBytes());
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    const k = toArray(key);

    try {
      const pub = this.ec.keyFromPublic(k);
      return pub.pub().validate();
    } catch (e) {
      return false;
    }
  }

  sign(msg, secret) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.size);

    const sig = this.ec.sign(msg, secret);

    return Buffer.from(sig.toBytes());
  }

  verify(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    if (sig.length === 0)
      return false;

    if (key.length === 0)
      return false;

    const k = toArray(key);
    const s = toArray(sig);

    try {
      return this.ec.verify(msg, s, k);
    } catch (e) {
      return false;
    }
  }
}

/*
 * Helpers
 */

function toArray(buf) {
  if (Array.from)
    return Array.from(buf);
  return Array.prototype.slice.call(buf);
}

function toBuffer(n, size) {
  return n.toArrayLike(Buffer, 'be', size);
}

/*
 * Expose
 */

module.exports = EDDSA;
