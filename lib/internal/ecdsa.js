/*!
 * ecdsa.js - wrapper for elliptic
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const elliptic = require('elliptic');

/*
 * ECDSA
 */

class ECDSA {
  constructor(name) {
    assert(typeof name === 'string');

    this.name = name;
    this._ec = null;
    this._size = -1;
    this._signature = null;
    this._bn = null;
  }

  get ec() {
    if (!this._ec)
      this._ec = elliptic.ec(this.name);
    return this._ec;
  }

  get curve() {
    return this.ec.curve;
  }

  get size() {
    if (this._size === -1)
      this._size = this.ec.curve.p.byteLength();
    return this._size;
  }

  get hashSize() {
    return this.ec.hash.outSize >>> 3;
  }

  _cache() {
    if (this._signature)
      return;

    const msg = Buffer.alloc(this.hashSize, 0x00);
    const key = Buffer.alloc(this.size, 0x00);
    key[key.length - 1] = 0x01;

    const k = this.ec.keyFromPrivate(key);
    const s = k.sign(msg);

    assert(s && typeof s === 'object');
    assert(typeof s.constructor === 'function');
    assert(s.r && typeof s.r === 'object');
    assert(typeof s.r.constructor === 'function');

    this._signature = s.constructor;
    this._bn = s.r.constructor;
  }

  signature(options) {
    this._cache();
    const Signature = this._signature;
    return new Signature(options);
  }

  bn(num, option) {
    this._cache();
    const BN = this._bn;
    return new BN(num, option);
  }

  privateKeyGenerate() {
    const key = this.ec.genKeyPair();
    return key.getPrivate().toArrayLike(Buffer, 'be', this.size);
  }

  generatePrivateKey() {
    return this.privateKeyGenerate();
  }

  publicKeyCreate(key, compress) {
    if (compress == null)
      compress = true;

    assert(Buffer.isBuffer(key));
    assert(typeof compress === 'boolean');

    const k = this.ec.keyFromPrivate(key);

    return Buffer.from(k.getPublic(compress, 'array'));
  }

  publicKeyConvert(key, compress) {
    if (compress == null)
      compress = true;

    assert(Buffer.isBuffer(key));
    assert(typeof compress === 'boolean');

    const point = this.curve.decodePoint(key);

    return Buffer.from(point.encode('array', compress));
  }

  privateKeyTweakAdd(key, tweak) {
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));

    let k = this.bn(tweak);

    k = k.iadd(this.bn(key));
    k = k.mod(this.curve.n);
    k = k.toArrayLike(Buffer, 'be', this.size);

    // Only a 1 in 2^127 chance of happening.
    if (!this.privateKeyVerify(k))
      throw new Error('Private key is invalid.');

    return k;
  }

  publicKeyTweakAdd(key, tweak, compress) {
    if (compress == null)
      compress = true;

    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));
    assert(typeof compress === 'boolean');

    const k = this.curve.decodePoint(key);
    const point = this.curve.g.mul(this.bn(tweak)).add(k);
    const pub = Buffer.from(point.encode('array', compress));

    if (!this.publicKeyVerify(pub))
      throw new Error('Public key is invalid.');

    return pub;
  }

  ecdh(pub, priv) {
    assert(Buffer.isBuffer(pub));
    assert(Buffer.isBuffer(priv));

    const pk = this.ec.keyFromPublic(pub);
    const sk = this.ec.keyFromPrivate(priv);
    const k = sk.derive(pk.getPublic());

    return k.toArrayLike(Buffer, 'be', this.size);
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    try {
      const k = this.ec.keyFromPublic(key);
      return k.validate();
    } catch (e) {
      return false;
    }
  }

  privateKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    if (key.length !== this.size)
      return false;

    const k = this.bn(key);

    return !k.isZero() && k.lt(this.curve.n);
  }

  sign(msg, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(key));

    // Sign message and ensure low S value.
    const sig = this.ec.sign(msg, key, { canonical: true });
    const out = Buffer.allocUnsafe(this.size * 2);

    sig.r.toArrayLike(Buffer, 'be', this.size).copy(out, 0);
    sig.s.toArrayLike(Buffer, 'be', this.size).copy(out, this.size);

    return out;
  }

  signDER(msg, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(key));

    // Sign message and ensure low S value.
    const sig = this.ec.sign(msg, key, { canonical: true });

    // Convert to DER.
    return Buffer.from(sig.toDER());
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
    const s = normalizeLength(sig);

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

    return Buffer.from(point.encode('array', compress));
  }

  fromDER(raw) {
    assert(Buffer.isBuffer(raw));

    const sig = this.signature(raw);
    const out = Buffer.allocUnsafe(this.size * 2);

    sig.r.toArrayLike(Buffer, 'be', this.size).copy(out, 0);
    sig.s.toArrayLike(Buffer, 'be', this.size).copy(out, this.size);

    return out;
  }

  toDER(raw) {
    assert(Buffer.isBuffer(raw));
    assert(raw.length === this.size * 2);

    const r = raw.slice(0, this.size);
    const s = raw.slice(this.size, this.size * 2);

    const sig = this.signature({
      r: this.bn(r, 'be'),
      s: this.bn(s, 'be')
    });

    return Buffer.from(sig.toDER());
  }

  isLowS(raw) {
    assert(Buffer.isBuffer(raw));

    if (raw.length !== this.size * 2)
      return false;

    const sig = this.toDER(raw);

    return this.isLowDER(sig);
  }

  isLowDER(raw) {
    assert(Buffer.isBuffer(raw));

    let sig;

    try {
      sig = this.signature(raw);
    } catch (e) {
      return false;
    }

    if (sig.s.isZero())
      return false;

    if (sig.s.gt(this.ec.nh))
      return false;

    return true;
  }
}

/*
 * Helpers
 */

function normalizeLength(sig) {
  let data = sig;
  let pos = 0;
  let len;

  if (data[pos++] !== 0x30)
    return sig;

  [len, pos] = getLength(data, pos);

  if (data.length > len + pos)
    data = data.slice(0, len + pos);

  if (data[pos++] !== 0x02)
    return sig;

  // R length.
  [len, pos] = getLength(data, pos);

  pos += len;

  if (data[pos++] !== 0x02)
    return sig;

  // S length.
  [len, pos] = getLength(data, pos);

  if (data.length > len + pos)
    data = data.slice(0, len + pos);

  return data;
}

function getLength(buf, pos) {
  const initial = buf[pos++];

  if (!(initial & 0x80))
    return [initial, pos];

  const len = initial & 0xf;
  let val = 0;

  for (let i = 0; i < len; i++) {
    val <<= 8;
    val |= buf[pos++];
  }

  return [val, pos];
}

/*
 * Expose
 */

module.exports = ECDSA;
