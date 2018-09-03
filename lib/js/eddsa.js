/*!
 * eddsa.js - wrapper for elliptic
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const elliptic = require('../../vendor/elliptic');
const random = require('../random');
const edkey = require('../internal/edkey');
const ecsig = require('../internal/ecsig');

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
    this._half = null;
    this._key = null;
    this._sig = null;
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

  get half() {
    if (!this._half) {
      const nh = this.curve.n.ushrn(1);
      this._half = toBuffer(nh, this.size);
    }
    return this._half;
  }

  get _keys() {
    if (!this._key)
      this._key = edkey(this);
    return this._key;
  }

  get Key() {
    return this._keys.EDDSAKey;
  }

  get PublicKey() {
    return this._keys.EDDSAPublicKey;
  }

  get PrivateKey() {
    return this._keys.EDDSAPrivateKey;
  }

  get Signature() {
    if (!this._sig)
      this._sig = ecsig(this);
    return this._sig;
  }

  secretGenerate() {
    return random.randomBytes(this.size);
  }

  privateKeyGenerate() {
    return this.secretGenerate();
  }

  generatePrivateKey() {
    return this.privateKeyGenerate();
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

  secretVerify(secret) {
    assert(Buffer.isBuffer(secret));

    if (secret.length !== this.size)
      return false;

    return true;
  }

  privateKeyVerify(priv) {
    return this.secretVerify(priv);
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

  recover(msg, sig, param, compress) {
    throw new Error('Not implemented.');
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
