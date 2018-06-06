/*!
 * eddsa.js - wrapper for elliptic
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const elliptic = require('elliptic');
const random = require('../random');

/*
 * EDDSA
 */

class EDDSA {
  constructor(name) {
    assert(typeof name === 'string');

    this.name = name;
    this._ec = null;
  }

  get ec() {
    if (!this._ec)
      this._ec = elliptic.eddsa(this.name);
    return this._ec;
  }

  get curve() {
    return this.ec.curve;
  }

  get size() {
    return this.ec.encodingLength;
  }

  get hashSize() {
    return this.ec.hash.outSize >>> 3;
  }

  privateKeyGenerate() {
    return random.randomBytes(this.size);
  }

  generatePrivateKey() {
    return this.privateKeyGenerate();
  }

  publicKeyCreate(secret) {
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.size);

    const k = this.ec.keyFromSecret(secret);

    return Buffer.from(k.pubBytes());
  }

  publicKeyConvert(key) {
    throw new Error('Not implemented.');
  }

  privateKeyTweakAdd(key, tweak) {
    throw new Error('Not implemented.');
  }

  publicKeyTweakAdd(key, tweak) {
    throw new Error('Not implemented.');
  }

  ecdh(pub, priv) {
    throw new Error('Not implemented.');
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    const k = toArray(key);

    try {
      const pub = this.ec.keyFromPublic(k);
      pub.pub();
      return true;
    } catch (e) {
      return false;
    }
  }

  privateKeyVerify(secret) {
    assert(Buffer.isBuffer(secret));

    if (secret.length !== this.size)
      return false;

    return true;
  }

  sign(msg, secret) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.size);

    const sig = this.ec.sign(msg, secret);

    return Buffer.from(sig.toBytes());
  }

  signDER(msg, key) {
    throw new Error('Not implemented.');
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

  verifyDER(msg, sig, key) {
    throw new Error('Not implemented.');
  }

  recover(msg, sig, param, compress) {
    throw new Error('Not implemented.');
  }

  fromDER(raw) {
    throw new Error('Not implemented.');
  }

  toDER(raw) {
    throw new Error('Not implemented.');
  }

  isLowS(raw) {
    throw new Error('Not implemented.');
  }

  isLowDER(raw) {
    throw new Error('Not implemented.');
  }
}

/*
 * Helpers
 */

function toArray(buf) {
  return Array.prototype.slice.call(buf);
}

/*
 * Expose
 */

module.exports = EDDSA;
