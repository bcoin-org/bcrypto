/*!
 * ed25519.js - ed25519 for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc7748
 *   https://tools.ietf.org/html/rfc7748#section-5
 *   https://tools.ietf.org/html/rfc8032
 *   https://tools.ietf.org/html/rfc8032#appendix-A
 *   https://tools.ietf.org/html/rfc8032#appendix-B
 */

'use strict';

const assert = require('bsert');
const elliptic = require('../../vendor/elliptic');
const random = require('../random');
const SHA512 = require('../sha512');
const asn1 = require('../encoding/asn1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');

/*
 * Constants
 */

const SLAB = Buffer.alloc(1);

const params = {
  id: 'ED25519',
  xid: 'X25519',
  edwards: true,
  c: 3,
  n: '1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed',
  bit: 254,
  bits: 253,
  size: 32,
  hash: SHA512,
  prefix: 'SigEd25519 no Ed25519 collisions'
};

/*
 * API
 */

class API {
  constructor() {
    this.id = params.id;
    this.xid = params.xid;
    this.edwards = params.edwards;
    this.size = params.size;
    this.bits = params.bits;
    this.zero = Buffer.alloc(this.size, 0x00);
    this.order = Buffer.from(params.n, 'hex');
    this.native = 0;
    this._ec = null;
  }

  get ec() {
    if (!this._ec)
      this._ec = new Ed25519(params);
    return this._ec;
  }

  privateKeyGenerate() {
    return this.ec.privateKeyGenerate();
  }

  privateKeyConvert(secret) {
    return this.ec.privateKeyConvert(secret);
  }

  privateKeyVerify(secret) {
    return this.ec.privateKeyVerify(secret);
  }

  privateKeyExport(secret) {
    return this.ec.privateKeyExport(secret);
  }

  privateKeyImport(raw) {
    return this.ec.privateKeyImport(raw);
  }

  privateKeyExportPKCS8(secret) {
    return this.ec.privateKeyExportPKCS8(secret);
  }

  privateKeyImportPKCS8(raw) {
    return this.ec.privateKeyImportPKCS8(raw);
  }

  publicKeyCreate(secret) {
    return this.ec.publicKeyCreate(secret);
  }

  publicKeyConvert(key) {
    return this.ec.publicKeyConvert(key);
  }

  publicKeyDeconvert(key, sign) {
    return this.ec.publicKeyDeconvert(key, sign);
  }

  publicKeyVerify(key) {
    return this.ec.publicKeyVerify(key);
  }

  publicKeyExport(key) {
    return this.ec.publicKeyExport(key);
  }

  publicKeyImport(raw) {
    return this.ec.publicKeyImport(raw);
  }

  publicKeyExportSPKI(key) {
    return this.ec.publicKeyExportSPKI(key);
  }

  publicKeyImportSPKI(raw) {
    return this.ec.publicKeyImportSPKI(raw);
  }

  publicKeyTweakAdd(key, tweak) {
    return this.ec.publicKeyTweakAdd(key, tweak);
  }

  publicKeyTweakMul(key, tweak) {
    return this.ec.publicKeyTweakMul(key, tweak);
  }

  sign(msg, secret) {
    return this.ec.sign(msg, secret);
  }

  signTweakAdd(msg, secret, tweak) {
    return this.ec.signTweakAdd(msg, secret, tweak);
  }

  signTweakMul(msg, secret, tweak) {
    return this.ec.signTweakMul(msg, secret, tweak);
  }

  verify(msg, sig, key, ph, ctx) {
    return this.ec.verify(msg, sig, key, ph, ctx);
  }

  derive(edpub, secret) {
    return this.ec.derive(edpub, secret);
  }

  exchange(xpub, secret) {
    return this.ec.exchange(xpub, secret);
  }

  /*
   * Compat
   */

  ecdh(edpub, secret) {
    return this.ec.ecdh(edpub, secret);
  }
}

/**
 * Ed25519
 */

class Ed25519 {
  constructor(params) {
    this.ec = elliptic.eddsa('ed25519');
    this.ka = elliptic.ec('curve25519');
    this.curve = this.ec.curve;
    this.id = params.id;
    this.c = params.c;
    this.n = this.curve.n;
    this.g = this.ec.g;
    this.bit = params.bit;
    this.bits = params.bits;
    this.size = params.size;
    this.hash = params.hash;
    this.prefix = Buffer.from(params.prefix, 'binary');
  }

  clamp(data) {
    assert(Buffer.isBuffer(data));
    assert(data.length >= this.size);

    const raw = data.slice(0, this.size);

    raw[0] &= 248;
    raw[this.size - 1] &= 127;
    raw[this.size - 1] |= 64;

    return raw;
  }

  encodeInt(num) {
    return Buffer.from(this.ec.encodeInt(num));
  }

  decodeInt(raw) {
    return this.ec.decodeInt(raw);
  }

  hashKey(secret) {
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.size);

    // SHA512.
    return this.hash.digest(secret);
  }

  hashInt(ph, ctx, ...items) {
    assert(ph == null || typeof ph === 'boolean');
    assert(ctx == null || Buffer.isBuffer(ctx));
    assert(!ctx || ctx.length <= 255);

    // eslint-disable-next-line
    const h = new this.hash();

    // SHA512.
    h.init();

    if (ph != null) {
      // Prefix.
      h.update(this.prefix);

      // Pre-hash Flag.
      SLAB[0] = Number(ph);
      h.update(SLAB);

      // Context.
      if (ctx) {
        SLAB[0] = ctx.length;
        h.update(SLAB);
        h.update(ctx);
      } else {
        SLAB[0] = 0x00;
        h.update(SLAB);
      }
    } else {
      assert(ctx == null, 'Must pass pre-hash flag with context.');
    }

    // Integers.
    for (const item of items)
      h.update(item);

    const hash = h.final();
    const num = this.decodeInt(hash);

    return num.umod(this.n);
  }

  encodePoint(point) {
    return Buffer.from(this.ec.encodePoint(point));
  }

  decodePoint(raw) {
    return this.ec.decodePoint(toArray(raw));
  }

  privateKeyGenerate() {
    return random.randomBytes(this.size);
  }

  privateKeyConvert(secret) {
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.size);

    return this.clamp(this.hashKey(secret));
  }

  privateKeyVerify(secret) {
    assert(Buffer.isBuffer(secret));
    return secret.length === this.size;
  }

  privateKeyExport(secret) {
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.size);
    return new asn1.OctString(secret).encode();
  }

  privateKeyImport(raw) {
    const key = asn1.OctString.decode(raw);

    assert(key.value.length === this.size);

    return key.value;
  }

  privateKeyExportPKCS8(secret) {
    // https://tools.ietf.org/html/draft-ietf-curdle-pkix-eddsa-00
    // https://tools.ietf.org/html/rfc8410
    // https://tools.ietf.org/html/rfc5958
    // https://tools.ietf.org/html/rfc7468
    return new pkcs8.PrivateKeyInfo(
      0,
      asn1.objects.curves[this.id],
      new asn1.Null(),
      this.privateKeyExport(secret)
    ).encode();
  }

  privateKeyImportPKCS8(raw) {
    const pki = pkcs8.PrivateKeyInfo.decode(raw);
    const version = pki.version.toNumber();
    const {algorithm, parameters} = pki.algorithm;

    assert(version === 0 || version === 1);
    assert(algorithm.toString() === asn1.objects.curves[this.id]);
    assert(parameters.node.type === asn1.types.NULL);

    return this.privateKeyImport(pki.privateKey.value);
  }

  scalarTweakAdd(key, tweak) {
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));
    assert(key.length === this.size);
    assert(tweak.length === this.size);

    const t = this.decodeInt(tweak).umod(this.n);
    const k = this.decodeInt(key).iadd(t).umod(this.n);

    if (k.isZero())
      throw new Error('Invalid private key.');

    return this.encodeInt(k);
  }

  scalarTweakMul(key, tweak) {
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));
    assert(key.length === this.size);
    assert(tweak.length === this.size);

    const t = this.decodeInt(tweak).umod(this.n);
    const k = this.decodeInt(key).imul(t).umod(this.n);

    if (k.isZero())
      throw new Error('Invalid private key.');

    return this.encodeInt(k);
  }

  publicKeyCreate(secret) {
    const key = this.privateKeyConvert(secret);
    const a = this.decodeInt(key);
    const A = this.g.mul(a);

    return this.encodePoint(A);
  }

  publicKeyConvert(key) {
    assert(Buffer.isBuffer(key));
    assert(key.length === this.size);

    // Edwards point.
    const {y, z} = this.decodePoint(key);

    // x = ((y + z) * inverse(z - y)) % p
    const yplusz = y.redAdd(z);
    const zminusy = z.redSub(y);
    const zinv = zminusy.redInvm();
    const zmul = yplusz.redMul(zinv);
    const x = zmul.fromRed();

    // Montgomery point.
    return toBuffer(x, this.size, 'le');
  }

  publicKeyDeconvert(key, sign = false) {
    assert(Buffer.isBuffer(key));
    assert(key.length === this.size);
    assert(typeof sign === 'boolean');

    // Montgomery point.
    const mont = reverse(Buffer.from(key));
    const {x, z} = this.ka.curve.decodePoint(mont);

    // y = (x - z) / (x + z)
    const xminusz = x.redSub(z);
    const xplusz = x.redAdd(z);
    const xinv = xplusz.redInvm();
    const xmul = xminusz.redMul(xinv);
    const y = xmul.fromRed();

    // Edwards point.
    const ed = toBuffer(y, this.size, 'le');

    if (sign)
      ed[this.size - 1] |= 0x80;

    return ed;
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    if (key.length !== this.size)
      return false;

    let point;

    try {
      point = this.decodePoint(key);
    } catch (e) {
      return false;
    }

    return point.validate();
  }

  publicKeyExport(key) {
    assert(Buffer.isBuffer(key));
    assert(key.length === this.size);
    return key;
  }

  publicKeyImport(raw) {
    assert(Buffer.isBuffer(raw));
    assert(raw.length === this.size);

    if (!this.publicKeyVerify(raw))
      throw new Error('Invalid public key.');

    return raw;
  }

  publicKeyExportSPKI(key) {
    // https://tools.ietf.org/html/rfc8410
    return new x509.SubjectPublicKeyInfo(
      asn1.objects.curves[this.id],
      new asn1.Null(),
      this.publicKeyExport(key)
    ).encode();
  }

  publicKeyImportSPKI(raw) {
    const spki = x509.SubjectPublicKeyInfo.decode(raw);
    const {algorithm, parameters} = spki.algorithm;

    assert(algorithm.toString() === asn1.objects.curves[this.id]);
    assert(parameters.node.type === asn1.types.NULL);

    return this.publicKeyImport(spki.publicKey.rightAlign());
  }

  publicKeyTweakAdd(key, tweak) {
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));
    assert(key.length === this.size);
    assert(tweak.length === this.size);

    const t = this.decodeInt(tweak).umod(this.n);
    const k = this.decodePoint(key);
    const point = this.g.mul(t).add(k);

    if (point.isInfinity())
      throw new Error('Invalid public key.');

    return this.encodePoint(point);
  }

  publicKeyTweakMul(key, tweak) {
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));
    assert(key.length === this.size);
    assert(tweak.length === this.size);

    const t = this.decodeInt(tweak).umod(this.n);
    const k = this.decodePoint(key);
    const point = k.mul(t);

    if (point.isInfinity())
      throw new Error('Invalid private key.');

    return this.encodePoint(point);
  }

  sign(msg, secret, ph, ctx) {
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.size);

    const hash = this.hashKey(secret);
    const key = this.clamp(hash);
    const prefix = hash.slice(this.size);

    return this._sign(msg, key, prefix, ph, ctx);
  }

  signTweakAdd(msg, secret, tweak, ph, ctx) {
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.size);

    const hash = this.hashKey(secret);
    const key_ = this.clamp(hash);
    const prefix_ = hash.slice(this.size);
    const key = this.scalarTweakAdd(key_, tweak);
    const prefix = this.hash.multi(prefix_, tweak).slice(0, this.size);

    return this._sign(msg, key, prefix, ph, ctx);
  }

  signTweakMul(msg, secret, tweak, ph, ctx) {
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.size);

    const hash = this.hashKey(secret);
    const key_ = this.clamp(hash);
    const prefix_ = hash.slice(this.size);
    const key = this.scalarTweakMul(key_, tweak);
    const prefix = this.hash.multi(prefix_, tweak).slice(0, this.size);

    return this._sign(msg, key, prefix, ph, ctx);
  }

  _sign(msg, key, prefix, ph, ctx) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(prefix));
    assert(key.length === this.size);
    assert(prefix.length === this.size);

    const a = this.decodeInt(key);
    const A = this.encodePoint(this.g.mul(a));
    const r = this.hashInt(ph, ctx, prefix, msg);
    const R = this.encodePoint(this.g.mul(r));
    const h = this.hashInt(ph, ctx, R, A, msg);
    const S = r.add(h.mul(a)).umod(this.n);

    return Buffer.concat([R, this.encodeInt(S)]);
  }

  verify(msg, sig, key, ph, ctx) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    if (sig.length !== this.size * 2)
      return false;

    if (key.length !== this.size)
      return false;

    try {
      return this._verify(msg, sig, key, ph, ctx);
    } catch (e) {
      return false;
    }
  }

  _verify(msg, sig, key, ph, ctx) {
    const Rraw = sig.slice(0, this.size);
    const Sraw = sig.slice(this.size);
    const R = this.decodePoint(Rraw);
    const S = this.decodeInt(Sraw);
    const A = this.decodePoint(key);

    if (S.cmp(this.n) >= 0)
      return false;

    const h = this.hashInt(ph, ctx, Rraw, key, msg);
    const lhs = R.add(A.mul(h));
    const rhs = this.g.mul(S);

    return lhs.eq(rhs);
  }

  derive(pub, secret) {
    assert(Buffer.isBuffer(pub));
    assert(Buffer.isBuffer(secret));
    assert(pub.length === this.size);
    assert(secret.length === this.size);

    const priv = this.privateKeyConvert(secret);
    const a = this.decodeInt(priv).umod(this.n);
    const A = this.decodePoint(pub);
    const point = A.mul(a);

    if (point.isInfinity())
      throw new Error('Invalid public key.');

    return this.encodePoint(point);
  }

  exchange(xpub, secret) {
    assert(Buffer.isBuffer(xpub) && xpub.length === this.size);

    const pub = Buffer.from(xpub);
    const priv = this.privateKeyConvert(secret);
    const pk = this.ka.keyFromPublic(reverse(pub));
    const sk = this.ka.keyFromPrivate(reverse(priv));
    const point = pk.getPublic().mul(sk.priv);

    if (point.isInfinity())
      throw new Error('Invalid public key.');

    return reverse(encodePoint(point));
  }

  /*
   * Compat
   */

  ecdh(edpub, secret) {
    return this.derive(edpub, secret);
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

function toBuffer(n, size, endian = 'be') {
  return n.toArrayLike(Buffer, endian, size);
}

function encodePoint(point) {
  const arr = point.encode('array', false);
  return Buffer.from(arr);
}

function reverse(key) {
  let i = key.length - 1;
  let j = 0;

  while (i > j) {
    const t = key[i];
    key[i] = key[j];
    key[j] = t;
    i -= 1;
    j += 1;
  }

  return key;
}

/*
 * Expose
 */

module.exports = new API();
