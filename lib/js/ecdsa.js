/*!
 * ecdsa.js - wrapper for elliptic
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const elliptic = require('elliptic');
const ecsig = require('../internal/ecsig');
const Signature = ecsig.ECSignature;

/**
 * ECDSA
 */

class ECDSA {
  constructor(name) {
    assert(typeof name === 'string');

    this.id = name;
    this._ec = null;
    this._size = -1;
    this._bits = -1;
    this._zero = null;
    this._order = null;
    this._half = null;
    this.native = 0;
  }

  get ec() {
    if (!this._ec)
      this._ec = elliptic.ec(this.id);
    return this._ec;
  }

  bn(num, option) {
    const BN = this.ec.n.constructor;
    return new BN(num, option);
  }

  get curve() {
    return this.ec.curve;
  }

  get size() {
    if (this._size === -1)
      this._size = this.curve.n.byteLength();
    return this._size;
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
    if (!this._half)
      this._half = toBuffer(this.ec.nh, this.size);
    return this._half;
  }

  privateKeyGenerate() {
    const key = this.ec.genKeyPair();
    return toBuffer(key.getPrivate(), this.size);
  }

  generatePrivateKey() {
    return this.privateKeyGenerate();
  }

  publicKeyCreate(key, compress) {
    if (compress == null)
      compress = true;

    assert(Buffer.isBuffer(key));
    assert(typeof compress === 'boolean');

    const pub = this.ec.keyFromPrivate(key);
    const point = pub.getPublic();

    return encodePoint(point, compress);
  }

  publicKeyConvert(key, compress) {
    if (compress == null)
      compress = true;

    assert(Buffer.isBuffer(key));
    assert(typeof compress === 'boolean');

    const point = this.curve.decodePoint(key);

    return encodePoint(point, compress);
  }

  privateKeyTweakAdd(key, tweak) {
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));
    assert(key.length === this.size);

    const k = this.bn(key, 'be');
    const t = this.bn(tweak, 'be');

    k.iadd(t);

    const m = k.mod(this.curve.n);
    const priv = toBuffer(m, this.size);

    // Only a 1 in 2^127 chance of happening.
    if (!this.privateKeyVerify(priv))
      throw new Error('Private key is invalid.');

    return priv;
  }

  publicKeyTweakAdd(key, tweak, compress) {
    if (compress == null)
      compress = true;

    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));
    assert(typeof compress === 'boolean');

    const k = this.curve.decodePoint(key);
    const t = this.bn(tweak, 'be');
    const point = this.curve.g.mul(t).add(k);
    const pub = encodePoint(point, compress);

    // Only a 1 in 2^127 chance of happening.
    if (!this.publicKeyVerify(pub))
      throw new Error('Public key is invalid.');

    return pub;
  }

  ecdh(pub, priv, compress) {
    if (compress == null)
      compress = true;

    assert(Buffer.isBuffer(pub));
    assert(Buffer.isBuffer(priv));
    assert(typeof compress === 'boolean');

    const pk = this.ec.keyFromPublic(pub);
    const sk = this.ec.keyFromPrivate(priv);
    const secret = sk.derive(pk.getPublic());
    const point = this.curve.g.mul(secret);

    return encodePoint(point, compress);
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    let k;
    try {
      k = this.ec.keyFromPublic(key);
    } catch (e) {
      return false;
    }

    return k.validate().result;
  }

  privateKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    if (key.length !== this.size)
      return false;

    if (key.equals(this.zero))
      return false;

    return key.compare(this.order) < 0;
  }

  _sign(msg, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(key));
    assert(key.length === this.size);

    // Sign message and ensure low S value.
    const es = this.ec.sign(msg, key, { canonical: true });

    const r = toBuffer(es.r, this.size);
    const s = toBuffer(es.s, this.size);

    const sig = new Signature();
    sig.r = r;
    sig.s = s;

    return sig;
  }

  sign(msg, key) {
    const sig = this._sign(msg, key);
    return sig.encode(this.size);
  }

  signDER(msg, key) {
    const sig = this._sign(msg, key);
    return sig.toDER(this.size);
  }

  verify(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    if (sig.length !== this.size * 2)
      return false;

    if (key.length === 0)
      return false;

    const s = this.toDER(sig);

    try {
      return this.ec.verify(msg, s, key);
    } catch (e) {
      return false;
    }
  }

  verifyDER(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    if (sig.length === 0)
      return false;

    if (key.length === 0)
      return false;

    // Attempt to normalize the signature
    // length before passing to elliptic.
    // https://github.com/indutny/elliptic/issues/78
    let s;
    try {
      s = ecsig.reencode(sig, this.size);
    } catch (e) {
      return false;
    }

    try {
      return this.ec.verify(msg, s, key);
    } catch (e) {
      return false;
    }
  }

  recover(msg, sig, param, compress) {
    assert(Buffer.isBuffer(sig));

    if (sig.length !== this.size * 2)
      return null;

    const s = this.toDER(sig);

    return this.recoverDER(msg, s, param, compress);
  }

  recoverDER(msg, sig, param, compress) {
    if (param == null)
      param = 0;

    if (compress == null)
      compress = true;

    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert((param >>> 0) === param);
    assert(typeof compress === 'boolean');

    let point;
    try {
      point = this.ec.recoverPubKey(msg, sig, param);
    } catch (e) {
      return null;
    }

    return encodePoint(point, compress);
  }

  fromDER(sig) {
    return ecsig.fromDER(sig, this.size);
  }

  fromLax(sig) {
    return ecsig.fromLax(sig, this.size);
  }

  toDER(sig) {
    return ecsig.toDER(sig, this.size);
  }

  isLowS(sig) {
    return ecsig.isLowS(sig, this.size, this.half);
  }

  isLowDER(sig) {
    return ecsig.isLowDER(sig, this.size, this.half);
  }
}

/*
 * Helpers
 */

function toBuffer(n, size) {
  return n.toArrayLike(Buffer, 'be', size);
}

function encodePoint(point, compress) {
  const arr = point.encode('array', compress);
  return Buffer.from(arr);
}

/*
 * Expose
 */

module.exports = ECDSA;
