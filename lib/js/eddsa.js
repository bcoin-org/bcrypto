/*!
 * eddsa.js - ed25519 for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/elliptic:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/elliptic
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/EdDSA
 *   https://tools.ietf.org/html/rfc7748
 *   https://tools.ietf.org/html/rfc7748#section-5
 *   https://tools.ietf.org/html/rfc8032
 *   https://tools.ietf.org/html/rfc8032#appendix-A
 *   https://tools.ietf.org/html/rfc8032#appendix-B
 *   https://eprint.iacr.org/2015/625.pdf
 *   http://ed448goldilocks.sourceforge.net/
 *   git://git.code.sf.net/p/ed448goldilocks/code
 *   https://git.zx2c4.com/goldilocks/tree/src
 */

'use strict';

const assert = require('bsert');
const elliptic = require('./elliptic');
const eckey = require('../internal/eckey');
const asn1 = require('../encoding/asn1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');
const BN = require('../bn.js');
const ChaCha20 = require('../chacha20');
const rng = require('../random');

// Notes about our EdDSA implementation:
//
// - In contrast to the ECDSA backend, we allow points at
//   infinity (in all functions).
//
// - Note that Mike Hamburg's Ed448-Goldilocks rejects both
//   infinity as well as the torsion point (0, -1). We
//   do not replicate this behavior.
//
// - For Ed25519, we do "cofactor-less" verification by default.
//   This means torsion components will affect the result of the
//   verification.
//
// - For Ed448, we do cofactor verification by default to mimic
//   OpenSSL and Mike Hamburg's Ed448-Goldilocks implementation.
//
// - `verifySingle`/`verifyBatch` do cofactor verification. Do
//   not use `verifyBatch` expecting the same results as the
//   regular `verify` call[1]. This will not be the case for
//   Ed25519.
//
// - All functions are completely unaware of points of small
//   order and torsion components (in other words, points will
//   not be explicitly checked for this, anywhere).
//
// - `deriveWithScalar` and `exchangeWithScalar` automatically
//   clamp scalars before multiplying (meaning torsion components
//   are removed from the result and points of small order will
//   be normalized to infinity).
//
// - The HD function, `publicKeyTweakMul`, _does not_ clamp
//   automatically. It is possible to end up with a torsion
//   component in the resulting point (assuming the input
//   point had one).
//
// - Ed448-Goldilocks is 4-isogenous to Curve448. This means
//   that when converting to Curve448, small order points will
//   be normalized to (0, 0). When converting back to Ed448,
//   any small order points will be normalized to infinity,
//   and any torsion components will be removed completely.
//   Also note that when converting back, the implementation
//   needs to divide the point by the cofactor. This is a major
//   perf hit, so treat `x448.publicKeyConvert` as if it were a
//   point multiplication.
//
// - Elligators should not be used with Edwards curves. As
//   Tibouchi notes[2], regular public keys will map to
//   _distinguishable_ field elements as they are always in
//   the primary subgroup. Either the Ristretto Elligator[3],
//   or a prime order curve with an Elligator Squared[2]
//   construction are suitable alternatives here.
//
// - These notes also spell out why you should avoid using
//   Edwards curves on a blockchain[4].
//
// [1] https://moderncrypto.org/mail-archive/curves/2016/000836.html
// [2] https://eprint.iacr.org/2014/043.pdf
// [3] https://ristretto.group/formulas/elligator.html
// [4] https://src.getmonero.org/2017/05/17/disclosure-of-a-major-bug-in-cryptonote-based-currencies.html

/*
 * EDDSA
 */

class EDDSA {
  constructor(id, mid, hash, pre) {
    assert(typeof id === 'string');
    assert(!mid || typeof mid === 'string');
    assert(hash);

    this.id = id;
    this.type = 'edwards';
    this.mid = mid || null;
    this.hash = hash;
    this._pre = pre || null;
    this._curve = null;
    this._mont = null;
    this.native = 0;
  }

  get curve() {
    if (!this._curve) {
      this._curve = elliptic.curve(this.id, this._pre);
      this._curve.precompute(rng);
      this._pre = null;
    }
    return this._curve;
  }

  get mont() {
    if (this.mid && !this._mont)
      this._mont = elliptic.curve(this.mid);
    return this._mont;
  }

  get size() {
    return this.curve.fieldSize;
  }

  get bits() {
    return this.curve.fieldBits;
  }

  hashInt(ph, ctx, ...items) {
    assert(ph == null || typeof ph === 'boolean');
    assert(ctx == null || Buffer.isBuffer(ctx));
    assert(!ctx || ctx.length <= 255);

    // eslint-disable-next-line
    const h = new this.hash();

    h.init();

    if (this.curve.context || ph != null) {
      // Prefix.
      h.update(this.curve.prefix);

      // Pre-hash Flag.
      h.update(byte(ph));

      // Context.
      if (ctx) {
        h.update(byte(ctx.length));
        h.update(ctx);
      } else {
        h.update(byte(0x00));
      }
    } else {
      assert(ctx == null, 'Must pass pre-hash flag with context.');
    }

    // Integers.
    for (const item of items)
      h.update(item);

    const hash = h.final(this.curve.fieldSize * 2);
    const num = BN.decode(hash, this.curve.endian);

    return num.imod(this.curve.n);
  }

  privateKeyGenerate() {
    return rng.randomBytes(this.curve.fieldSize);
  }

  scalarGenerate() {
    const scalar = rng.randomBytes(this.curve.scalarSize);
    return this.curve.clamp(scalar);
  }

  privateKeyExpand(secret) {
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.curve.fieldSize);

    const hash = this.hash.digest(secret, this.curve.fieldSize * 2);

    return this.curve.splitHash(hash);
  }

  privateKeyConvert(secret) {
    const [key] = this.privateKeyExpand(secret);
    return key;
  }

  privateKeyVerify(secret) {
    assert(Buffer.isBuffer(secret));
    return secret.length === this.curve.fieldSize;
  }

  scalarVerify(scalar) {
    assert(Buffer.isBuffer(scalar));
    return scalar.length === this.curve.scalarSize;
  }

  scalarIsZero(scalar) {
    assert(Buffer.isBuffer(scalar));

    let k;
    try {
      k = this.curve.decodeScalar(scalar).imod(this.curve.n);
    } catch (e) {
      return false;
    }

    return k.isZero();
  }

  scalarClamp(scalar) {
    assert(Buffer.isBuffer(scalar));
    assert(scalar.length === this.curve.scalarSize);

    return this.curve.clamp(Buffer.from(scalar));
  }

  privateKeyExport(secret) {
    if (!this.privateKeyVerify(secret))
      throw new Error('Invalid private key.');

    return new asn1.OctString(secret).encode();
  }

  privateKeyImport(raw) {
    const secret = asn1.OctString.decode(raw);

    if (!this.privateKeyVerify(secret.value))
      throw new Error('Invalid private key.');

    return secret.value;
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

  privateKeyExportJWK(secret) {
    return eckey.privateKeyExportJWK(this, secret);
  }

  privateKeyImportJWK(json) {
    return eckey.privateKeyImportJWK(this, json);
  }

  scalarTweakAdd(scalar, tweak) {
    const a = this.curve.decodeScalar(scalar);
    const t = this.curve.decodeScalar(tweak);
    const s = a.iadd(t).imod(this.curve.n);

    return this.curve.encodeScalar(s);
  }

  scalarTweakMul(scalar, tweak) {
    const a = this.curve.decodeScalar(scalar);
    const t = this.curve.decodeScalar(tweak);
    const s = a.imul(t).imod(this.curve.n);

    return this.curve.encodeScalar(s);
  }

  scalarReduce(scalar) {
    assert(Buffer.isBuffer(scalar));

    if (scalar.length > this.curve.scalarSize)
      scalar = scalar.slice(0, this.curve.scalarSize);

    const s = BN.decode(scalar, this.curve.endian).imod(this.curve.n);

    return this.curve.encodeScalar(s);
  }

  scalarNegate(scalar) {
    const a = this.curve.decodeScalar(scalar).imod(this.curve.n);
    const s = a.ineg().imod(this.curve.n);

    return this.curve.encodeScalar(s);
  }

  scalarInvert(scalar) {
    const a = this.curve.decodeScalar(scalar).imod(this.curve.n);

    if (a.isZero())
      throw new Error('Invalid scalar.');

    const s = a.invert(this.curve.n);

    return this.curve.encodeScalar(s);
  }

  publicKeyCreate(secret) {
    const key = this.privateKeyConvert(secret);
    return this.publicKeyFromScalar(key);
  }

  publicKeyFromScalar(scalar) {
    const a = this.curve.decodeScalar(scalar).imod(this.curve.n);
    const A = this.curve.g.mulBlind(a);

    return A.encode();
  }

  publicKeyConvert(key) {
    if (!this.mont)
      throw new Error('No equivalent montgomery curve.');

    const point = this.curve.decodePoint(key);
    const x = this.mont.pointFromEdwards(point);

    return x.encode();
  }

  publicKeyFromUniform(bytes) {
    const u = this.curve.decodeUniform(bytes);
    const p = this.curve.pointFromUniform(u, this.mont);

    return p.encode();
  }

  publicKeyToUniform(pub, hint = rng.randomInt()) {
    const p = this.curve.decodePoint(pub);
    const u = this.curve.pointToUniform(p, hint, this.mont);

    return this.curve.encodeUniform(u, rng);
  }

  publicKeyFromHash(bytes, pake = false) {
    const p = this.curve.pointFromHash(bytes, pake, this.mont);

    return p.encode();
  }

  publicKeyToHash(pub) {
    const p = this.curve.decodePoint(pub);
    return this.curve.pointToHash(p, rng, this.mont);
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    try {
      this.curve.decodePoint(key);
    } catch (e) {
      return false;
    }

    return true;
  }

  publicKeyIsInfinity(key) {
    assert(Buffer.isBuffer(key));

    let p;
    try {
      p = this.curve.decodePoint(key);
    } catch (e) {
      return false;
    }

    return p.isInfinity();
  }

  publicKeyIsSmall(key) {
    assert(Buffer.isBuffer(key));

    let p;
    try {
      p = this.curve.decodePoint(key);
    } catch (e) {
      return false;
    }

    return p.isSmall();
  }

  publicKeyHasTorsion(key) {
    assert(Buffer.isBuffer(key));

    let p;
    try {
      p = this.curve.decodePoint(key);
    } catch (e) {
      return false;
    }

    return p.hasTorsion();
  }

  publicKeyExport(key) {
    if (!this.publicKeyVerify(key))
      throw new Error('Invalid public key.');

    return Buffer.from(key);
  }

  publicKeyImport(raw) {
    if (!this.publicKeyVerify(raw))
      throw new Error('Invalid public key.');

    return Buffer.from(raw);
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

  publicKeyExportJWK(key) {
    return eckey.publicKeyExportJWK(this, key);
  }

  publicKeyImportJWK(json) {
    return eckey.publicKeyImportJWK(this, json, false);
  }

  publicKeyTweakAdd(key, tweak) {
    const t = this.curve.decodeScalar(tweak).imod(this.curve.n);
    const A = this.curve.decodePoint(key);
    const T = this.curve.g.mul(t);
    const point = T.add(A);

    return point.encode();
  }

  publicKeyTweakMul(key, tweak) {
    const t = this.curve.decodeScalar(tweak);
    const A = this.curve.decodePoint(key);
    const point = A.mul(t);

    return point.encode();
  }

  publicKeyAdd(key1, key2) {
    const A1 = this.curve.decodePoint(key1);
    const A2 = this.curve.decodePoint(key2);
    const point = A1.add(A2);

    return point.encode();
  }

  publicKeyCombine(keys) {
    assert(Array.isArray(keys));

    let acc = this.curve.point();

    for (const key of keys) {
      const point = this.curve.decodePoint(key);

      acc = acc.add(point);
    }

    return acc.encode();
  }

  publicKeyNegate(key) {
    const A = this.curve.decodePoint(key);
    const point = A.neg();

    return point.encode();
  }

  sign(msg, secret, ph, ctx) {
    const [key, prefix] = this.privateKeyExpand(secret);
    return this.signWithScalar(msg, key, prefix, ph, ctx);
  }

  signWithScalar(msg, scalar, prefix, ph, ctx) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(prefix));
    assert(prefix.length === this.curve.fieldSize);

    const N = this.curve.n;
    const G = this.curve.g;
    const k = this.hashInt(ph, ctx, prefix, msg);
    const Rraw = G.mulBlind(k).encode();
    const a = this.curve.decodeScalar(scalar);
    const Araw = G.mulBlind(a).encode();
    const e = this.hashInt(ph, ctx, Rraw, Araw, msg);

    // Scalar blinding factor.
    const [blind, unblind] = this.curve.getBlinding();

    // Blind.
    a.imul(blind).imod(N);
    k.imul(blind).imod(N);

    // S := (k + e * a) mod n
    const S = k.iadd(e.imul(a)).imod(N);

    // Unblind.
    S.imul(unblind).imod(N);

    // Note: S is technically a scalar, but decode
    // as a field element due to the useless byte.
    return Buffer.concat([Rraw, this.curve.encodeField(S)]);
  }

  signTweakAdd(msg, secret, tweak, ph, ctx) {
    const [key_, prefix_] = this.privateKeyExpand(secret);
    const key = this.scalarTweakAdd(key_, tweak);
    const expanded = this.hash.multi(prefix_, tweak, null,
                                     this.curve.fieldSize * 2);
    const prefix = expanded.slice(0, this.curve.fieldSize);

    return this.signWithScalar(msg, key, prefix, ph, ctx);
  }

  signTweakMul(msg, secret, tweak, ph, ctx) {
    const [key_, prefix_] = this.privateKeyExpand(secret);
    const key = this.scalarTweakMul(key_, tweak);
    const expanded = this.hash.multi(prefix_, tweak, null,
                                     this.curve.fieldSize * 2);
    const prefix = expanded.slice(0, this.curve.fieldSize);

    return this.signWithScalar(msg, key, prefix, ph, ctx);
  }

  verify(msg, sig, key, ph, ctx) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));
    assert(ph == null || typeof ph === 'boolean');
    assert(ctx == null || Buffer.isBuffer(ctx));
    assert(!ctx || ctx.length <= 255);

    if (!this.curve.context && ctx != null)
      assert(ph != null, 'Must pass pre-hash flag with context.');

    if (sig.length !== this.curve.fieldSize * 2)
      return false;

    if (key.length !== this.curve.fieldSize)
      return false;

    try {
      // Ed448-Goldilocks always uses cofactor verification.
      if (this.curve.iso4)
        return this._verifySingle(msg, sig, key, ph, ctx);

      // Otherwise, legacy "cofactor-less" verification.
      return this._verify(msg, sig, key, ph, ctx);
    } catch (e) {
      return false;
    }
  }

  _verify(msg, sig, key, ph, ctx) {
    const N = this.curve.n;
    const G = this.curve.g;
    const Rraw = sig.slice(0, this.curve.fieldSize);
    const Sraw = sig.slice(this.curve.fieldSize);
    const R = this.curve.decodePoint(Rraw);
    const S = this.curve.decodeField(Sraw);
    const A = this.curve.decodePoint(key);

    // Note: S is technically a scalar, but decode
    // as a field element due to the useless byte.
    if (S.cmp(N) >= 0)
      return false;

    // e = H(R, A, m).
    const e = this.hashInt(ph, ctx, Rraw, key, msg);

    // In concept, we should check:
    //   G * S == R + A * e
    // But we can use Shamir's trick to check:
    //   R == G * S - A * e
    return G.mulAdd(S, A.neg(), e).eq(R);
  }

  verifySingle(msg, sig, key, ph, ctx) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));
    assert(ph == null || typeof ph === 'boolean');
    assert(ctx == null || Buffer.isBuffer(ctx));
    assert(!ctx || ctx.length <= 255);

    if (!this.curve.context && ctx != null)
      assert(ph != null, 'Must pass pre-hash flag with context.');

    if (sig.length !== this.curve.fieldSize * 2)
      return false;

    if (key.length !== this.curve.fieldSize)
      return false;

    try {
      return this._verifySingle(msg, sig, key, ph, ctx);
    } catch (e) {
      return false;
    }
  }

  _verifySingle(msg, sig, key, ph, ctx) {
    const N = this.curve.n;
    const G = this.curve.g;
    const Rraw = sig.slice(0, this.curve.fieldSize);
    const Sraw = sig.slice(this.curve.fieldSize);
    const R = this.curve.decodePoint(Rraw);
    const S = this.curve.decodeField(Sraw);
    const A = this.curve.decodePoint(key);

    // Note: S is technically a scalar, but decode
    // as a field element due to the useless byte.
    if (S.cmp(N) >= 0)
      return false;

    // e = H(R, A, m).
    const e = this.hashInt(ph, ctx, Rraw, key, msg);

    // Ensure terms are multiples of `h`.
    const Sh = this.curve.imulH(S);
    const Ah = A.mulH();
    const Rh = R.mulH();

    // The spec says to check:
    //   (G * S) * h == (R + A * e) * h
    // But we can use Shamir's trick to check:
    //   R * h == G * (S * h) - (A * h) * e
    return G.mulAdd(Sh, Ah.neg(), e).eq(Rh);
  }

  verifyBatch(batch, ph, ctx) {
    assert(Array.isArray(batch));
    assert(ph == null || typeof ph === 'boolean');
    assert(ctx == null || Buffer.isBuffer(ctx));
    assert(!ctx || ctx.length <= 255);

    if (!this.curve.context && ctx != null)
      assert(ph != null, 'Must pass pre-hash flag with context.');

    for (const item of batch) {
      assert(Array.isArray(item) && item.length === 3);

      const [msg, sig, key] = item;

      assert(Buffer.isBuffer(msg));
      assert(Buffer.isBuffer(sig));
      assert(Buffer.isBuffer(key));

      if (sig.length !== this.curve.fieldSize * 2)
        return false;

      if (key.length !== this.curve.fieldSize)
        return false;
    }

    try {
      return this._verifyBatch(batch, ph, ctx);
    } catch (e) {
      return false;
    }
  }

  _verifyBatch(batch, ph, ctx) {
    const N = this.curve.n;
    const G = this.curve.g;
    const rng = new RNG(this);
    const points = new Array(1 + batch.length * 2);
    const coeffs = new Array(1 + batch.length * 2);
    const sum = new BN(0);

    // Seed the RNG with our batch.
    rng.init(batch);

    // Setup multiplication for G * lhs.
    points[0] = G;
    coeffs[0] = sum;

    // Verify all signatures.
    for (let i = 0; i < batch.length; i++) {
      const [msg, sig, key] = batch[i];
      const Rraw = sig.slice(0, this.curve.fieldSize);
      const Sraw = sig.slice(this.curve.fieldSize);
      const R = this.curve.decodePoint(Rraw);
      const S = this.curve.decodeField(Sraw);
      const A = this.curve.decodePoint(key);

      // Note: S is technically a scalar, but decode
      // as a field element due to the useless byte.
      if (S.cmp(N) >= 0)
        return false;

      // e = H(R, A, m).
      const e = this.hashInt(ph, ctx, Rraw, key, msg);
      const a = i === 0 ? new BN(1) : rng.generate();
      const ea = e.imul(a).imod(N);

      // lhs = (((S * a) + ...) * h) mod n
      sum.iadd(S.imul(a)).imod(N);

      // rhs = -(R * h) * a + -(A * h) * ((e * a) mod n) + ...
      points[1 + i * 2 + 0] = R.mulH().neg();
      coeffs[1 + i * 2 + 0] = a;
      points[1 + i * 2 + 1] = A.mulH().neg();
      coeffs[1 + i * 2 + 1] = ea;
    }

    // Ensure sum is a multiple of `h`.
    this.curve.imulH(sum);

    // In concept, we can validate the batch with:
    //   G * lhs == rhs
    // But we can use Shamir's trick to check:
    //   G * lhs - rhs == O
    // Hence the point negations above.
    return this.curve.mulAll(points, coeffs).isInfinity();
  }

  derive(pub, secret) {
    const priv = this.privateKeyConvert(secret);
    return this.deriveWithScalar(pub, priv);
  }

  deriveWithScalar(pub, scalar) {
    const s = this.curve.decodeScalar(scalar);
    const A = this.curve.decodePoint(pub);
    const k = this.curve.reduce(s);
    const point = A.mulConst(k, rng);

    if (point.isInfinity())
      throw new Error('Invalid point.');

    return point.encode();
  }
}

/**
 * RNG
 */

class RNG {
  constructor(eddsa) {
    this.curve = eddsa.curve;
    this.hash = eddsa.hash;
    this.chacha = new ChaCha20();
    // Nothing up my sleeve.
    this.iv = Buffer.from('EDDSARNG');
  }

  init(batch) {
    assert(Array.isArray(batch));

    // eslint-disable-next-line
    const hash = new this.hash();

    hash.init();

    for (const [msg, sig, key] of batch) {
      hash.update(this.hash.digest(msg));
      hash.update(sig);
      hash.update(key);
    }

    let key = hash.final(32);

    if (key.length > 32)
      key = key.slice(0, 32);

    this.chacha.init(key, this.iv, 0);

    return this;
  }

  randomBytes(size) {
    return this.chacha.encrypt(Buffer.alloc(size, 0x00));
  }

  generate() {
    return BN.random(this, 1, this.curve.n);
  }
}

/*
 * Helpers
 */

function byte(ch) {
  const buf = Buffer.alloc(1);
  buf[0] = ch & 0xff;
  return buf;
}

/*
 * Expose
 */

module.exports = EDDSA;
