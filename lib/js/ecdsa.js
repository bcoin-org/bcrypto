/*!
 * ecdsa.js - wrapper for elliptic
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const elliptic = require('../../vendor/elliptic');
const BN = require('../../vendor/bn.js');
const Signature = require('../internal/signature');
const sec1 = require('../encoding/sec1');

/**
 * ECDSA
 */

class ECDSA {
  constructor(name) {
    assert(typeof name === 'string');

    this.id = name;
    this.edwards = false;
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
      this._ec = elliptic.ec(this.id.toLowerCase());
    return this._ec;
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

  privateKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    if (key.length !== this.size)
      return false;

    if (key.equals(this.zero))
      return false;

    return key.compare(this.order) < 0;
  }

  privateKeyExport(key, compress) {
    const pub = this.publicKeyCreate(key, compress);
    return new sec1.ECPrivateKey(1, key, this.id, pub).encode();
  }

  privateKeyImport(raw) {
    const key = sec1.ECPrivateKey.decode(raw);

    assert(key.version.toNumber() === 1);
    assert(key.namedCurveOID.getCurveName() === this.id);
    assert(key.privateKey.value.length === this.size);

    return key.privateKey.value;
  }

  privateKeyTweakAdd(key, tweak) {
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));
    assert(key.length === this.size);
    assert(tweak.length === this.size);

    const k = new BN(key);
    const t = new BN(tweak);

    k.iadd(t);

    const m = k.mod(this.curve.n);
    const priv = toBuffer(m, this.size);

    // Only a 1 in 2^127 chance of happening.
    if (!this.privateKeyVerify(priv))
      throw new Error('Private key is invalid.');

    return priv;
  }

  publicKeyCreate(key, compress) {
    if (compress == null)
      compress = true;

    assert(Buffer.isBuffer(key));
    assert(typeof compress === 'boolean');
    assert(key.length === this.size);

    const pub = this.ec.keyFromPrivate(key);
    const point = pub.getPublic();

    return encodePoint(point, compress);
  }

  publicKeyConvert(key, compress) {
    if (compress == null)
      compress = true;

    assert(Buffer.isBuffer(key));
    assert(typeof compress === 'boolean');
    assert(isValidPoint(key, this.size));

    const point = this.curve.decodePoint(key);

    return encodePoint(point, compress);
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    if (!isValidPoint(key, this.size))
      return false;

    let k;
    try {
      k = this.ec.keyFromPublic(key);
    } catch (e) {
      return false;
    }

    return k.validate().result;
  }

  publicKeyExport(key) {
    return this.publicKeyConvert(key, false).slice(1);
  }

  publicKeyImport(raw, compress) {
    assert(Buffer.isBuffer(raw));
    assert(raw.length === this.size * 2);

    const key = Buffer.allocUnsafe(1 + raw.length);
    key[0] = 0x04;
    raw.copy(key, 1);

    return this.publicKeyConvert(key, compress);
  }

  publicKeyTweakAdd(key, tweak, compress) {
    if (compress == null)
      compress = true;

    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));
    assert(typeof compress === 'boolean');
    assert(isValidPoint(key, this.size));
    assert(tweak.length === this.size);

    const k = this.curve.decodePoint(key);
    const t = new BN(tweak);
    const point = this.curve.g.mul(t).add(k);
    const pub = encodePoint(point, compress);

    // Only a 1 in 2^127 chance of happening.
    if (!this.publicKeyVerify(pub))
      throw new Error('Public key is invalid.');

    return pub;
  }

  signatureExport(sig) {
    return Signature.toDER(sig, this.size);
  }

  signatureImport(sig) {
    return Signature.toRS(sig, this.size);
  }

  _sign(msg, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(key));
    assert(msg.length >= 20 && msg.length <= 128);
    assert(key.length === this.size);

    // Sign message and ensure low S value.
    const es = this.ec.sign(msg, key, { canonical: true });

    const r = toBuffer(es.r, this.size);
    const s = toBuffer(es.s, this.size);

    const sig = new Signature();
    sig.r = r;
    sig.s = s;
    sig.param = es.recoveryParam | 0;

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

    if (msg.length < 20 || msg.length > 128)
      return false;

    if (sig.length !== this.size * 2)
      return false;

    if (!isValidPoint(key, this.size))
      return false;

    const s = Signature.toDER(sig, this.size);

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

    if (msg.length < 20 || msg.length > 128)
      return false;

    if (!isValidPoint(key, this.size))
      return false;

    // Attempt to normalize the signature
    // length before passing to elliptic.
    // https://github.com/indutny/elliptic/issues/78
    let s;
    try {
      s = Signature.normalize(sig, this.size);
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

    const s = Signature.toDER(sig, this.size);

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

    if (msg.length < 20 || msg.length > 128)
      return null;

    let point;
    try {
      point = this.ec.recoverPubKey(msg, sig, param);
    } catch (e) {
      return null;
    }

    return encodePoint(point, compress);
  }

  derive(pub, priv, compress) {
    if (compress == null)
      compress = true;

    assert(Buffer.isBuffer(pub));
    assert(Buffer.isBuffer(priv));
    assert(typeof compress === 'boolean');
    assert(isValidPoint(pub, this.size));
    assert(priv.length === this.size);

    const pk = this.ec.keyFromPublic(pub);
    const sk = this.ec.keyFromPrivate(priv);
    const point = pk.getPublic().mul(sk.priv);

    return encodePoint(point, compress);
  }

  isLowS(sig) {
    return Signature.isLowS(sig, this.size, this.half);
  }

  isLowDER(sig) {
    return Signature.isLowDER(sig, this.size, this.half);
  }

  /*
   * Compat
   */

  generatePrivateKey() {
    return this.privateKeyGenerate();
  }

  fromDER(sig) {
    return this.signatureImport(sig);
  }

  toDER(sig) {
    return this.signatureExport(sig);
  }

  ecdh(pub, priv, compress) {
    return this.derive(pub, priv, compress);
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

function isValidPoint(point, size) {
  assert(Buffer.isBuffer(point));
  assert((size >>> 0) === size);

  if (point.length < 1 + size)
    return false;

  switch (point[0]) {
    case 0x02:
    case 0x03:
      return point.length === 1 + size;
    case 0x04:
      return point.length === 1 + size * 2;
    case 0x06:
    case 0x07:
      return point.length === 1 + size * 2
          && (point[0] & 1) === (point[point.length - 1] & 1);
    default:
      return false;
  }
}

/*
 * Expose
 */

module.exports = ECDSA;
