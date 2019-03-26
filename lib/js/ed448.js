/*!
 * ed448.js - ed448 for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/elliptic:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/elliptic
 *
 * Resources:
 *   https://eprint.iacr.org/2015/625.pdf
 *   https://tools.ietf.org/html/rfc7748
 *   https://tools.ietf.org/html/rfc7748#section-5
 *   https://tools.ietf.org/html/rfc8032
 *   https://tools.ietf.org/html/rfc8032#appendix-A
 *   https://tools.ietf.org/html/rfc8032#appendix-B
 *   http://ed448goldilocks.sourceforge.net/
 *   git://git.code.sf.net/p/ed448goldilocks/code
 *   https://git.zx2c4.com/goldilocks/tree/src
 */

'use strict';

const assert = require('bsert');
const BN = require('../bn.js');
const curves = require('./curves');
const eckey = require('../internal/eckey');
const asn1 = require('../encoding/asn1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');
const random = require('../random');
const SHAKE256 = require('../shake256');

/*
 * Constants
 */

const EMPTY = Buffer.alloc(0);
const SLAB = Buffer.alloc(1);

/*
 * API
 */

class API {
  constructor() {
    this.id = 'ED448';
    this.edwards = true;
    this.mont = false;
    this.bits = 446;
    this.size = 57;
    this.native = 0;
    this._ec = null;
  }

  get ec() {
    if (!this._ec)
      this._ec = new Ed448();
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

/*
 * Ed448
 */

class Ed448 extends curves.Ed448 {
  constructor() {
    super();
    this.x = new curves.X448();
    this.hash = SHAKE256;
  }

  clamp(data) {
    assert(Buffer.isBuffer(data));
    assert(data.length >= this.size);

    const raw = data.slice(0, this.size);

    raw[0] &= ~3;
    raw[this.size - 1] = 0;
    raw[this.size - 2] |= 0x80;

    return raw;
  }

  hashKey(secret) {
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.size);

    // SHAKE256 (permuted to 114 bytes).
    return this.hash.digest(secret, this.size * 2);
  }

  hashInt(ph, ctx, ...items) {
    assert(typeof ph === 'boolean');
    assert(Buffer.isBuffer(ctx));
    assert(ctx.length <= 255);

    // eslint-disable-next-line
    const h = new this.hash();

    // SHAKE256 (permuted to 114 bytes).
    h.init();

    // Prefix (SigEd448).
    h.update(this.prefix);

    // Pre-hash Flag.
    SLAB[0] = ph & 0xff;
    h.update(SLAB);

    // Context.
    SLAB[0] = ctx.length;
    h.update(SLAB);
    h.update(ctx);

    // Integers.
    for (const item of items)
      h.update(item);

    const hash = h.final(this.size * 2);
    const num = new BN(hash, 'le');

    return num.umod(this.n);
  }

  privateKeyGenerate() {
    return random.randomBytes(this.size);
  }

  scalarGenerate() {
    const scalar = random.randomBytes(this.size - 1);

    scalar[0] &= ~3;
    scalar[this.size - 2] |= 128;

    return scalar;
  }

  privateKeyVerify(secret) {
    assert(Buffer.isBuffer(secret));
    return secret.length === this.size;
  }

  scalarVerify(scalar) {
    assert(Buffer.isBuffer(scalar));

    if (scalar.length !== this.size - 1)
      return false;

    if (scalar[0] & 3)
      return false;

    if (!(scalar[this.size - 2] & 128))
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

  privateKeyConvert(secret) {
    const hash = this.hashKey(secret);
    return this.clamp(hash).slice(0, -1);
  }

  scalarTweakAdd(scalar, tweak) {
    const t = this.decodeScalar(tweak).umod(this.n);
    const k = this.decodeScalar(scalar).iadd(t).umod(this.n);

    if (k.isZero())
      throw new Error('Invalid scalar.');

    return this.encodeScalar(k);
  }

  scalarTweakMul(scalar, tweak) {
    const t = this.decodeScalar(tweak).umod(this.n);
    const k = this.decodeScalar(scalar).imul(t).umod(this.n);

    if (k.isZero())
      throw new Error('Invalid scalar.');

    return this.encodeScalar(k);
  }

  publicKeyCreate(secret) {
    const k = this.privateKeyConvert(secret);
    return this.publicKeyFromScalar(k);
  }

  publicKeyFromScalar(scalar) {
    const a = this.decodeScalar(scalar).umod(this.n);
    const A = this.g.mul(a);

    if (A.isInfinity())
      throw new Error('Invalid private key.');

    return this.encodePoint(A);
  }

  publicKeyConvert(key) {
    // Edwards point.
    const {x, y} = this.decodePoint(key);

    // Convert to montgomery.
    const xi = x.redInvm(); // 1/x
    const yd = xi.redIMul(y); // y/x
    const u = yd.redISqr(); // (y/x)^2

    // Montgomery point.
    return this.encodeScalar(u.fromRed());
  }

  publicKeyDeconvert(key, sign = false) {
    assert(Buffer.isBuffer(key));
    assert(key.length === this.size - 1);

    throw new Error('Unimplemented.');
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    let A;

    try {
      A = this.decodePoint(key);
    } catch (e) {
      return false;
    }

    return A.validate();
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

  publicKeyExportJWK(curve, key) {
    return eckey.publicKeyExportJWK(curve, key);
  }

  publicKeyImportJWK(curve, json) {
    return eckey.publicKeyImportJWK(curve, json, false);
  }

  publicKeyTweakAdd(key, tweak) {
    const k = this.decodePoint(key);
    const t = this.decodeScalar(tweak).umod(this.n);

    const point = this.g.mul(t).add(k);

    if (point.isInfinity())
      throw new Error('Invalid public key.');

    return this.encodePoint(point);
  }

  publicKeyTweakMul(key, tweak) {
    const k = this.decodePoint(key);
    const t = this.decodeScalar(tweak).umod(this.n);

    const point = k.mul(t);

    if (point.isInfinity())
      throw new Error('Invalid public key.');

    return this.encodePoint(point);
  }

  sign(msg, secret, ph, ctx) {
    const hash = this.hashKey(secret);
    const key = this.clamp(hash).slice(0, -1);
    const prefix = hash.slice(this.size);

    return this.signWithScalar(msg, key, prefix, ph, ctx);
  }

  signWithScalar(msg, scalar, prefix, ph, ctx) {
    if (ph == null)
      ph = false;

    if (ctx == null)
      ctx = EMPTY;

    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(prefix));
    assert(typeof ph === 'boolean');
    assert(Buffer.isBuffer(ctx));
    assert(prefix.length === this.size);
    assert(ctx.length <= 255);

    const a = this.decodeScalar(scalar);
    const A = this.encodePoint(this.g.mul(a));
    const r = this.hashInt(ph, ctx, prefix, msg);
    const R = this.encodePoint(this.g.mul(r));
    const h = this.hashInt(ph, ctx, R, A, msg);
    const S = r.add(h.mul(a)).umod(this.n);

    return Buffer.concat([R, this.encodeInt(S)]);
  }

  signTweakAdd(msg, secret, tweak, ph, ctx) {
    const hash = this.hashKey(secret);
    const key_ = this.clamp(hash).slice(0, -1);
    const prefix_ = hash.slice(this.size);
    const key = this.scalarTweakAdd(key_, tweak);
    const prefix = this.hash.multi(prefix_, tweak, null, this.size);

    return this.signWithScalar(msg, key, prefix, ph, ctx);
  }

  signTweakMul(msg, secret, tweak, ph, ctx) {
    const hash = this.hashKey(secret);
    const key_ = this.clamp(hash).slice(0, -1);
    const prefix_ = hash.slice(this.size);
    const key = this.scalarTweakMul(key_, tweak);
    const prefix = this.hash.multi(prefix_, tweak, null, this.size);

    return this.signWithScalar(msg, key, prefix, ph, ctx);
  }

  verify(msg, sig, key, ph, ctx) {
    if (ph == null)
      ph = false;

    if (ctx == null)
      ctx = EMPTY;

    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));
    assert(typeof ph === 'boolean');
    assert(Buffer.isBuffer(ctx));

    try {
      return this._verify(msg, sig, key, ph, ctx);
    } catch (e) {
      return false;
    }
  }

  _verify(msg, sig, key, ph, ctx) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));
    assert(typeof ph === 'boolean');
    assert(Buffer.isBuffer(ctx));

    if (sig.length !== this.size * 2)
      return false;

    if (key.length !== this.size)
      return false;

    if (ctx.length > 255)
      return false;

    const Rraw = sig.slice(0, this.size);
    const Sraw = sig.slice(this.size);
    const R = this.decodePoint(Rraw);
    const S = this.decodeInt(Sraw);
    const A = this.decodePoint(key);

    if (S.cmp(this.n) >= 0)
      return false;

    const h = this.hashInt(ph, ctx, Rraw, key, msg);

    let rhs = R.add(A.mul(h));
    let lhs = this.g.mul(S);

    for (let i = 0; i < 2; i++) {
      lhs = lhs.dbl();
      rhs = rhs.dbl();
    }

    return lhs.eq(rhs);
  }

  derive(pub, secret) {
    const priv = this.privateKeyConvert(secret);
    return this.deriveWithScalar(pub, priv);
  }

  deriveWithScalar(pub, scalar) {
    const A = this.decodePoint(pub);
    const a = this.decodeScalar(scalar).umod(this.n);
    const T = A.mul(a);

    if (T.isInfinity())
      throw new Error('Invalid public key.');

    return this.encodePoint(T);
  }

  exchange(xpub, secret) {
    const scalar = this.privateKeyConvert(secret);
    return this.exchangeWithScalar(xpub, scalar);
  }

  exchangeWithScalar(xpub, scalar) {
    scalar = Buffer.from(scalar);
    scalar[0] &= ~3;
    scalar[this.size - 2] |= 0x80;

    const u = this.x.decodePoint(xpub);
    const k = this.x.decodeScalar(scalar);
    const A = u.mul(k);

    if (A.isInfinity())
      throw new Error('Invalid public key.');

    return A.encode();
  }
}

/*
 * Expose
 */

module.exports = new API();
