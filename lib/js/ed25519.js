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
const eckey = require('../internal/eckey');
const asn1 = require('../encoding/asn1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');
const BN = require('../bn.js');
const random = require('../random');
const SHA512 = require('../sha512');

/*
 * Constants
 */

const SLAB = Buffer.alloc(1);

const params = {
  id: 'ED25519',
  edwards: true,
  mont: false,
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
    this.edwards = params.edwards;
    this.mont = params.mont;
    this.bits = params.bits;
    this.size = params.size;
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

  scalarGenerate() {
    return this.ec.scalarGenerate();
  }

  privateKeyConvert(secret) {
    return this.ec.privateKeyConvert(secret);
  }

  privateKeyVerify(secret) {
    return this.ec.privateKeyVerify(secret);
  }

  scalarVerify(scalar) {
    return this.ec.scalarVerify(scalar);
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

  privateKeyExportJWK(key) {
    return this.ec.privateKeyExportJWK(this, key);
  }

  privateKeyImportJWK(json) {
    return this.ec.privateKeyImportJWK(this, json);
  }

  scalarTweakAdd(scalar, tweak) {
    return this.ec.scalarTweakAdd(scalar, tweak);
  }

  scalarTweakMul(scalar, tweak) {
    return this.ec.scalarTweakMul(scalar, tweak);
  }

  publicKeyCreate(secret) {
    return this.ec.publicKeyCreate(secret);
  }

  publicKeyFromScalar(scalar) {
    return this.ec.publicKeyFromScalar(scalar);
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

  publicKeyExportJWK(key) {
    return this.ec.publicKeyExportJWK(this, key);
  }

  publicKeyImportJWK(json) {
    return this.ec.publicKeyImportJWK(this, json);
  }

  publicKeyTweakAdd(key, tweak) {
    return this.ec.publicKeyTweakAdd(key, tweak);
  }

  publicKeyTweakMul(key, tweak) {
    return this.ec.publicKeyTweakMul(key, tweak);
  }

  sign(msg, secret, ph, ctx) {
    return this.ec.sign(msg, secret, ph, ctx);
  }

  signWithScalar(msg, scalar, prefix, ph, ctx) {
    return this.ec.signWithScalar(msg, scalar, prefix, ph, ctx);
  }

  signTweakAdd(msg, secret, tweak, ph, ctx) {
    return this.ec.signTweakAdd(msg, secret, tweak, ph, ctx);
  }

  signTweakMul(msg, secret, tweak, ph, ctx) {
    return this.ec.signTweakMul(msg, secret, tweak, ph, ctx);
  }

  verify(msg, sig, key, ph, ctx) {
    return this.ec.verify(msg, sig, key, ph, ctx);
  }

  derive(pub, secret) {
    return this.ec.derive(pub, secret);
  }

  deriveWithScalar(pub, scalar) {
    return this.ec.deriveWithScalar(pub, scalar);
  }

  exchange(xpub, secret) {
    return this.ec.exchange(xpub, secret);
  }

  exchangeWithScalar(xpub, scalar) {
    return this.ec.exchangeWithScalar(xpub, scalar);
  }
}

/**
 * Ed25519
 */

class Ed25519 {
  constructor(params) {
    this.ec = elliptic.eddsa('ed25519');
    this.curve = this.ec.curve;
    this.id = params.id;
    this.n = this.curve.n;
    this.g = this.ec.g;
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
    assert(num instanceof BN);
    return num.toArrayLike(Buffer, 'le', this.size);
  }

  decodeInt(raw) {
    assert(Buffer.isBuffer(raw));
    assert(raw.length === this.size);
    return new BN(raw, 'le');
  }

  encodeField(num) {
    assert(num instanceof BN);
    assert(num.red);
    return this.encodeInt(num.fromRed());
  }

  decodeField(raw) {
    const num = this.decodeInt(raw);
    return num.maskn(255).toRed(this.curve.red);
  }

  encodePoint(point) {
    assert(point && typeof point === 'object');

    const raw = this.encodeInt(point.getY());

    if (point.getX().isOdd())
      raw[this.size - 1] |= 0x80;

    return raw;
  }

  decodePoint(raw) {
    assert(Buffer.isBuffer(raw));
    assert(raw.length === this.size);

    const xIsOdd = (raw[this.size - 1] & 0x80) !== 0;

    // Normalize.
    if (xIsOdd) {
      raw = Buffer.from(raw);
      raw[this.size - 1] &= ~0x80;
    }

    const y = this.decodeInt(raw);

    return this.curve.pointFromY(y, xIsOdd);
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
      SLAB[0] = ph & 0xff;
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
    const num = new BN(hash, 'le');

    return num.umod(this.n);
  }

  privateKeyGenerate() {
    return random.randomBytes(this.size);
  }

  scalarGenerate() {
    const scalar = random.randomBytes(this.size);
    return this.clamp(scalar);
  }

  privateKeyConvert(secret) {
    return this.clamp(this.hashKey(secret));
  }

  privateKeyVerify(secret) {
    assert(Buffer.isBuffer(secret));
    return secret.length === this.size;
  }

  scalarVerify(scalar) {
    assert(Buffer.isBuffer(scalar));

    if (scalar.length !== this.size)
      return false;

    if (scalar[0] & ~248)
      return false;

    if (scalar[this.size - 1] & ~127)
      return false;

    if (!(scalar[this.size - 1] & 64))
      return false;

    return true;
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

  privateKeyExportJWK(curve, key) {
    return eckey.privateKeyExportJWK(curve, key);
  }

  privateKeyImportJWK(curve, json) {
    return eckey.privateKeyImportJWK(curve, json);
  }

  scalarTweakAdd(scalar, tweak) {
    const t = this.decodeInt(tweak).umod(this.n);
    const k = this.decodeInt(scalar).iadd(t).umod(this.n);

    if (k.isZero())
      throw new Error('Invalid scalar.');

    return this.encodeInt(k);
  }

  scalarTweakMul(scalar, tweak) {
    const t = this.decodeInt(tweak).umod(this.n);
    const k = this.decodeInt(scalar).imul(t).umod(this.n);

    if (k.isZero())
      throw new Error('Invalid scalar.');

    return this.encodeInt(k);
  }

  publicKeyCreate(secret) {
    const key = this.privateKeyConvert(secret);
    return this.publicKeyFromScalar(key);
  }

  publicKeyFromScalar(scalar) {
    const a = this.decodeInt(scalar).umod(this.n);
    const A = this.g.mul(a);

    return this.encodePoint(A);
  }

  publicKeyConvert(key) {
    // Edwards point.
    const {y, z} = this.decodePoint(key);

    // x = ((y + z) * inverse(z - y)) % p
    const yplusz = y.redAdd(z);
    const zminusy = z.redSub(y);
    const zinv = zminusy.redInvm();
    const zmul = yplusz.redMul(zinv);
    const x = zmul;

    // Montgomery point.
    return this.encodeField(x);
  }

  publicKeyDeconvert(key, sign = false) {
    assert(typeof sign === 'boolean');

    // Montgomery point.
    const x = this.decodeField(key);
    const z = this.curve.one;

    // y = (x - z) / (x + z)
    const xminusz = x.redSub(z);
    const xplusz = x.redAdd(z);
    const xinv = xplusz.redInvm();
    const xmul = xminusz.redMul(xinv);
    const y = xmul;

    // Edwards point.
    const ed = this.encodeField(y);

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

  publicKeyExportJWK(curve, key) {
    return eckey.publicKeyExportJWK(curve, key);
  }

  publicKeyImportJWK(curve, json) {
    return eckey.publicKeyImportJWK(curve, json, false);
  }

  publicKeyTweakAdd(key, tweak) {
    const t = this.decodeInt(tweak).umod(this.n);
    const k = this.decodePoint(key);
    const point = this.g.mul(t).add(k);

    if (point.isInfinity())
      throw new Error('Invalid public key.');

    return this.encodePoint(point);
  }

  publicKeyTweakMul(key, tweak) {
    const t = this.decodeInt(tweak).umod(this.n);
    const k = this.decodePoint(key);
    const point = k.mul(t);

    if (point.isInfinity())
      throw new Error('Invalid private key.');

    return this.encodePoint(point);
  }

  sign(msg, secret, ph, ctx) {
    const hash = this.hashKey(secret);
    const key = this.clamp(hash);
    const prefix = hash.slice(this.size);

    return this.signWithScalar(msg, key, prefix, ph, ctx);
  }

  signWithScalar(msg, scalar, prefix, ph, ctx) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(prefix));
    assert(prefix.length === this.size);

    const a = this.decodeInt(scalar);
    const A = this.encodePoint(this.g.mul(a));
    const r = this.hashInt(ph, ctx, prefix, msg);
    const R = this.encodePoint(this.g.mul(r));
    const h = this.hashInt(ph, ctx, R, A, msg);
    const S = r.add(h.mul(a)).umod(this.n);

    return Buffer.concat([R, this.encodeInt(S)]);
  }

  signTweakAdd(msg, secret, tweak, ph, ctx) {
    const hash = this.hashKey(secret);
    const key_ = this.clamp(hash);
    const prefix_ = hash.slice(this.size);
    const key = this.scalarTweakAdd(key_, tweak);
    const expanded = this.hash.multi(prefix_, tweak);
    const prefix = expanded.slice(0, this.size);

    return this.signWithScalar(msg, key, prefix, ph, ctx);
  }

  signTweakMul(msg, secret, tweak, ph, ctx) {
    const hash = this.hashKey(secret);
    const key_ = this.clamp(hash);
    const prefix_ = hash.slice(this.size);
    const key = this.scalarTweakMul(key_, tweak);
    const expanded = this.hash.multi(prefix_, tweak);
    const prefix = expanded.slice(0, this.size);

    return this.signWithScalar(msg, key, prefix, ph, ctx);
  }

  verify(msg, sig, key, ph, ctx) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));
    assert(!ctx || ctx.length <= 255);

    if (ph == null)
      assert(ctx == null, 'Must pass pre-hash flag with context.');

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
    const priv = this.privateKeyConvert(secret);
    return this.deriveWithScalar(pub, priv);
  }

  deriveWithScalar(pub, scalar) {
    const a = this.decodeInt(scalar).umod(this.n);
    const A = this.decodePoint(pub);
    const point = A.mul(a);

    if (point.isInfinity())
      throw new Error('Invalid public key.');

    return this.encodePoint(point);
  }

  exchange(xpub, secret) {
    const priv = this.privateKeyConvert(secret);
    return this.exchangeWithScalar(xpub, priv);
  }

  exchangeWithScalar(xpub, scalar) {
    assert(Buffer.isBuffer(scalar));
    assert(scalar.length === this.size);

    const bits = this.curve.p.bitLength();
    const nd = new BN(121666).toRed(this.curve.red);

    let x1 = this.decodeField(xpub);
    let x2 = this.curve.one.clone();
    let z2 = this.curve.zero.clone();
    let x3 = x1.clone();
    let z3 = this.curve.one.clone();
    let t1, t2;

    let swap = 0;

    const k = this.clamp(Buffer.from(scalar));

    for (let t = bits - 1; t >= 0; t--) {
      const b = (k[t >>> 3] >>> (t & 7)) & 1;

      swap ^= b;

      [x2, x3] = cswap(swap, x2, x3);
      [z2, z3] = cswap(swap, z2, z3);

      swap = b;

      t1 = x3.redSub(z3);
      t2 = x2.redSub(z2);
      x2 = x2.redIAdd(z2);
      z2 = x3.redIAdd(z3);
      z3 = t1.redIMul(x2);
      z2 = z2.redIMul(t2);
      t1 = t2.redISqr();
      t2 = x2.redISqr();
      x3 = z3.redAdd(z2);
      z2 = z3.redISub(z2);
      x2 = t2.redMul(t1);
      t2 = t2.redISub(t1);
      z2 = z2.redISqr();
      z3 = t2.redMul(nd);
      x3 = x3.redISqr();
      t1 = t1.redIAdd(z3);
      z3 = x1.redMul(z2);
      z2 = t2.redIMul(t1);
    }

    // Finish.
    [x2, x3] = cswap(swap, x2, x3);
    [z2, z3] = cswap(swap, z2, z3);

    z2 = z2.redInvm();
    x1 = x2.redMul(z2);

    if (x1.isZero())
      throw new Error('Invalid public key.');

    return this.encodeField(x1);
  }
}

/*
 * Helpers
 */

function cswap(swap, x, y) {
  const items = [x, y];
  items[0 ^ swap] = x;
  items[1 ^ swap] = y;
  return items;
}

/*
 * Expose
 */

module.exports = new API();
