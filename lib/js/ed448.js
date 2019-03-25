/*!
 * ed448.js - ed448 for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
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
const BN = require('../../vendor/bn.js');
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

const params = {
  id: 'ED448',
  edwards: true,
  mont: false,

  // 2 ** 448 - 2 ** 224 - 1
  p: ''
    + 'ffffffffffffffffffffffffffff'
    + 'fffffffffffffffffffffffffffe'
    + 'ffffffffffffffffffffffffffff'
    + 'ffffffffffffffffffffffffffff',

  // -39081 mod p
  d: ''
    + 'ffffffffffffffffffffffffffff'
    + 'fffffffffffffffffffffffffffe'
    + 'ffffffffffffffffffffffffffff'
    + 'ffffffffffffffffffffffff6756',

  n: ''
    + '3fffffffffffffffffffffffffff'
    + 'ffffffffffffffffffffffffffff'
    + '7cca23e9c44edb49aed63690216c'
    + 'c2728dc58f552378c292ab5844f3',

  x: ''
    + '4f1970c66bed0ded221d15a622bf'
    + '36da9e146570470f1767ea6de324'
    + 'a3d3a46412ae1af72ab66511433b'
    + '80e18b00938e2626a82bc70cc05e',

  y: ''
    + '693f46716eb6bc248876203756c9'
    + 'c7624bea73736ca3984087789c1e'
    + '05a0c2d73ad3ff1ce67c39c4fdbd'
    + '132c4ed7c8ad9808795bf230fa14',

  bits: 456,
  size: 57,

  hash: SHAKE256,
  prefix: 'SigEd448'
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
      this._ec = new Ed448(params);
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

class Ed448 {
  constructor(params) {
    this.curve = new Curve(params);
    this.id = this.curve.id;
    this.n = this.curve.n;
    this.g = this.curve.base();
    this.g.precompute(this.n.bitLength() + 1);
    this.bits = this.curve.bits;
    this.size = this.curve.size;
    this.hash = this.curve.hash;
    this.prefix = this.curve.prefix;
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

  encodeInt(num) {
    assert(num instanceof BN);
    return num.toArrayLike(Buffer, 'le', this.size);
  }

  decodeInt(raw) {
    assert(Buffer.isBuffer(raw));
    assert(raw.length === this.size);
    return new BN(raw, 'le');
  }

  encodeScalar(num) {
    assert(num instanceof BN);
    return num.toArrayLike(Buffer, 'le', this.size - 1);
  }

  decodeScalar(raw) {
    assert(Buffer.isBuffer(raw));
    assert(raw.length === this.size - 1);
    return new BN(raw, 'le');
  }

  encodeField(num, bits) {
    return this.curve.encodeField(num, bits);
  }

  decodeField(raw) {
    return this.curve.decodeField(raw);
  }

  encodePoint(point) {
    return this.curve.encodePoint(point);
  }

  decodePoint(raw) {
    return this.curve.decodePoint(raw);
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

    if (!A.validate())
      throw new Error('Invalid private key.');

    return this.encodePoint(A);
  }

  publicKeyConvert(key) {
    // Edwards point.
    const bits = this.bits - 8;
    const {x, y} = this.decodePoint(key);

    // Convert to montgomery.
    const xi = x.redInvm(); // 1/x
    const yd = xi.redIMul(y); // y/x
    const u = yd.redISqr(); // (y/x)^2

    // Montgomery point.
    return this.encodeField(u, bits);
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

    if (!point.validate())
      throw new Error('Invalid public key.');

    return this.encodePoint(point);
  }

  publicKeyTweakMul(key, tweak) {
    const k = this.decodePoint(key);
    const t = this.decodeScalar(tweak).umod(this.n);

    const point = k.mul(t);

    if (!point.validate())
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
      lhs = lhs.double();
      rhs = rhs.double();
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

    if (!T.validate())
      throw new Error('Invalid public key.');

    return this.encodePoint(T);
  }

  exchange(xpub, secret) {
    const scalar = this.privateKeyConvert(secret);
    return this.exchangeWithScalar(xpub, scalar);
  }

  exchangeWithScalar(xpub, scalar) {
    assert(Buffer.isBuffer(xpub));
    assert(Buffer.isBuffer(scalar));
    assert(xpub.length === this.size - 1);
    assert(scalar.length === this.size - 1);

    const bits = this.bits - 8;
    const nd = this.curve.d.redNeg();

    let x1 = this.decodeField(xpub);
    let x2 = this.curve.one.clone();
    let z2 = this.curve.zero.clone();
    let x3 = x1.clone();
    let z3 = this.curve.one.clone();
    let t1, t2;

    let swap = 0;

    for (let t = bits - 1; t >= 0; t--) {
      let sb = scalar[t >>> 3];
      let k = 0;

      if ((t >>> 3) === 0)
        sb &= -4 & 0xff;
      else if (t === bits - 1)
        sb = -1 & 0xff;

      k = (sb >>> (t & 7)) & 1;
      k = -k & 0xff;

      swap ^= k;

      [x2, x3] = cswap(swap, x2, x3);
      [z2, z3] = cswap(swap, z2, z3);

      swap = k;

      t1 = x2.redAdd(z2); // A = x2 + z2 (2+e)
      t2 = x2.redISub(z2); // B = x2 - z2 (3+e)
      z2 = x3.redSub(z3); // D = x3 - z3 (3+e)
      x2 = t1.redMul(z2); // DA
      z2 = z3.redIAdd(x3); // C = x3 + z3 (2+e)
      x3 = t2.redMul(z2); // CB
      z3 = x2.redSub(x3); // DA-CB (3+e)
      z2 = z3.redISqr(); // (DA-CB)^2
      z3 = x1.redMul(z2); // z3 = x1(DA-CB)^2
      z2 = x2.redIAdd(x3); // (DA+CB) (2+e)
      x3 = z2.redISqr(); // x3 = (DA+CB)^2

      z2 = t1.redISqr(); // AA = A^2
      t1 = t2.redISqr(); // BB = B^2
      x2 = z2.redMul(t1); // x2 = AA*BB
      t2 = z2.redSub(t1); // E = AA-BB (3+e)

      t1 = t2.redMul(nd); // E*-d = a24*E
      t1 = t1.redIAdd(z2); // AA + a24*E (2+e)
      z2 = t2.redIMul(t1); // z2 = E(AA+a24*E)
    }

    // Finish.
    [x2, x3] = cswap(swap, x2, x3);
    [z2, z3] = cswap(swap, z2, z3);

    z2 = z2.redInvm();
    x1 = x2.redIMul(z2);

    if (x1.isZero())
      throw new Error('Invalid public key.');

    return this.encodeField(x1, bits);
  }
}

/*
 * Curve
 */

class Curve {
  constructor(params) {
    assert(params && typeof params === 'object');

    this.id = params.id;
    this.p = new BN(params.p, 16);
    this.red = BN.red('p448');
    this.d = this.field(new BN(params.d, 16));
    this.n = new BN(params.n, 16);
    this.x = this.field(new BN(params.x, 16));
    this.y = this.field(new BN(params.y, 16));
    this.bits = params.bits;
    this.size = params.size;
    this.hash = params.hash;
    this.prefix = Buffer.from(params.prefix, 'binary');
    this.zero = this.field(new BN(0));
    this.one = this.field(new BN(1));

    this.validate();
  }

  validate() {
    const g = this.base();
    const z = this.point();
    const n = this.n.addn(1);

    let p = g;
    let q = z;

    assert(p.validate());
    assert(q.validate());

    for (let i = 0; i < this.bits; i++) {
      if (n.testn(i)) {
        q = q.add(p);

        assert(q.validate());
      }

      p = p.double();

      assert(p.validate());
    }

    assert(q.eq(g));
    assert(!q.eq(p));
    assert(!q.eq(z));
  }

  point() {
    return new Point(this);
  }

  base() {
    return Point.from(this, this.x, this.y);
  }

  field(num) {
    assert(num instanceof BN);
    assert(!num.red);
    return num.toRed(this.red);
  }

  encodeField(num, bits) {
    assert(num instanceof BN);
    assert((bits >>> 0) === bits);
    assert(num.red);

    return num.fromRed().toArrayLike(Buffer, 'le', bits >>> 3);
  }

  decodeField(raw) {
    assert(Buffer.isBuffer(raw));

    const num = new BN(raw, 'le').imaskn(this.bits - 1);

    if (num.cmp(this.p) >= 0)
      throw new Error('Invalid field.');

    return this.field(num);
  }

  encodePoint(point) {
    assert(point instanceof Point);

    const bits = this.bits;
    const {x, y, z} = point;

    const zinv = z.redInvm();
    const xp = x.redMul(zinv);
    const yp = y.redMul(zinv);
    const raw = this.encodeField(yp, bits);

    if (xp.isOdd())
      raw[(bits - 1) >>> 3] |= 1 << ((bits - 1) & 7);

    return raw;
  }

  decodePoint(raw) {
    assert(Buffer.isBuffer(raw));

    if (raw.length !== this.size)
      throw new Error('Invalid point size.');

    const bits = this.bits;
    const oct = (bits - 1) >>> 3;
    const bit = (bits - 1) & 7;
    const sign = ((raw[oct] >>> bit) & 1) === 1;
    const y = this.decodeField(raw);

    let x = this.solveX2(y).redSqrt();

    if (x.isZero() && sign !== x.isOdd())
      throw new Error('Invalid X coordinate.');

    if (x.isOdd() !== sign)
      x = x.redNeg();

    return Point.from(this, x, y);
  }

  solveX2(y) {
    assert(y instanceof BN);
    assert(y.red);

    const ys = y.redSqr();
    const a = ys.redSub(this.one);
    const b = this.d.redMul(ys).redSub(this.one);

    return a.redMul(b.redInvm());
  }
}

/*
 * Point
 */

class Point {
  constructor(curve) {
    assert(curve instanceof Curve);

    this.curve = curve;
    this.x = curve.zero;
    this.y = curve.one;
    this.z = curve.one.clone();
    this.precomputed = null;
  }

  mulSlow(num) {
    assert(num instanceof BN);
    assert(!num.red);

    const bits = num.bitLength();

    let r = this.curve.point();
    let s = this;

    for (let i = 0; i < bits; i++) {
      if (num.testn(i))
        r = r.add(s);
      s = s.double();
    }

    return r;
  }

  mul(num) {
    assert(num instanceof BN);
    assert(!num.red);

    if (this.hasDoubles(num))
      return this.fixedNafMul(num);

    return this.wnafMul(num);
  }

  eq(y) {
    assert(y instanceof Point);

    const x = this;
    const xn1 = x.x.redMul(y.z);
    const xn2 = y.x.redMul(x.z);
    const yn1 = x.y.redMul(y.z);
    const yn2 = y.y.redMul(x.z);

    return xn1.eq(xn2) && yn1.eq(yn2);
  }

  add(y) {
    assert(y instanceof Point);

    const {d} = this.curve;
    const x = this;
    const xcp = x.x.redMul(y.x);
    const ycp = x.y.redMul(y.y);
    const zcp = x.z.redMul(y.z);
    const B = zcp.redSqr();
    const E = d.redMul(xcp).redIMul(ycp);
    const F = B.redSub(E);
    const G = B.redIAdd(E);

    const a = x.x.redAdd(x.y);
    const b = y.x.redAdd(y.y);
    const c = a.redIMul(b).redISub(xcp).redISub(ycp);
    const p = this.curve.point();

    p.x = zcp.redMul(F).redIMul(c);
    p.y = zcp.redIMul(G).redIMul(ycp.redISub(xcp));
    p.z = F.redIMul(G);

    return p;
  }

  double() {
    const x1s = this.x.redSqr();
    const y1s = this.y.redSqr();
    const z1s = this.z.redSqr();
    const xys = this.x.redAdd(this.y);
    const F = x1s.redAdd(y1s);
    const J = F.redSub(z1s.redAdd(z1s));

    const a = xys.redISqr().redISub(x1s).redISub(y1s);
    const p = this.curve.point();

    p.x = a.redIMul(J);
    p.y = F.redMul(x1s.redISub(y1s));
    p.z = F.redIMul(J);

    return p;
  }

  dblp(k) {
    let r = this;

    for (let i = 0; i < k; i++)
      r = r.double();

    return r;
  }

  neg() {
    const p = this.curve.point();
    p.x = this.x.redNeg();
    p.y = this.y;
    p.z = this.z;
    return p;
  }

  validate() {
    const {d} = this.curve;
    const {x, y, z} = this;

    const x2 = x.redSqr();
    const y2 = y.redSqr();
    const z2 = z.redSqr();

    const lhs = x2.redAdd(y2).redIMul(z2);
    const dxy = d.redMul(x2).redIMul(y2);
    const rhs = z2.redISqr().redIAdd(dxy);

    return lhs.eq(rhs);
  }

  precompute(power) {
    if (!this.precomputed) {
      this.precomputed = {
        naf: this.getNAFPoints(8),
        doubles: this.getDoubles(4, power)
      };
    }

    return this;
  }

  hasDoubles(k) {
    if (!this.precomputed)
      return false;

    const {doubles} = this.precomputed;
    const {points, step} = doubles;

    return points.length >= Math.ceil((k.bitLength() + 1) / step);
  }

  getDoubles(step, power) {
    if (this.precomputed)
      return this.precomputed.doubles;

    const points = [this];

    let acc = this;

    for (let i = 0; i < power; i += step) {
      for (let j = 0; j < step; j++)
        acc = acc.double();

      points.push(acc);
    }

    return {
      step,
      points
    };
  }

  getNAFPoints(wnd) {
    if (this.precomputed)
      return this.precomputed.naf;

    const max = (1 << wnd) - 1;
    const dbl = max === 1 ? null : this.double();
    const points = [this];

    for (let i = 1; i < max; i++)
      points[i] = points[i - 1].add(dbl);

    return {
      wnd,
      points
    };
  }

  fixedNafMul(k) {
    assert(this.precomputed);

    const {points, step} = this.getDoubles();
    const I = ((1 << (step + 1)) - (step % 2 === 0 ? 2 : 1)) / 3;
    const naf = getNAF(k, 1);

    // Translate into more windowed form
    const repr = [];

    for (let j = 0; j < naf.length; j += step) {
      let nafW = 0;

      for (let k = j + step - 1; k >= j; k--)
        nafW = (nafW << 1) + naf[k];

      repr.push(nafW);
    }

    let a = this.curve.point();
    let b = this.curve.point();

    for (let i = I; i > 0; i--) {
      for (let j = 0; j < repr.length; j++) {
        const nafW = repr[j];

        if (nafW === i)
          b = b.add(points[j]);
        else if (nafW === -i)
          b = b.add(points[j].neg());
      }

      a = a.add(b);
    }

    return a;
  }

  wnafMul(k) {
    // Precompute window
    const nafPoints = this.getNAFPoints(4);
    const w = nafPoints.wnd;
    const wnd = nafPoints.points;

    // Get NAF form
    const naf = getNAF(k, w);

    // Add `this`*(N+1) for every w-NAF index
    let acc = this.curve.point();

    for (let i = naf.length - 1; i >= 0; i--) {
      // Count zeroes
      let k = 0;

      for (; i >= 0 && naf[i] === 0; i--)
        k++;

      if (i >= 0)
        k++;

      acc = acc.dblp(k);

      if (i < 0)
        break;

      const z = naf[i];

      assert(z !== 0);

      // J +- J
      if (z > 0)
        acc = acc.add(wnd[(z - 1) >> 1]);
      else
        acc = acc.add(wnd[(-z - 1) >> 1].neg());
    }

    return acc;
  }

  static from(curve, x, y) {
    assert(curve instanceof Curve);
    assert(x instanceof BN);
    assert(y instanceof BN);
    assert(x.red && y.red);

    const xs = x.redSqr();
    const ys = y.redSqr();
    const a = ys.redAdd(xs);
    const b = curve.d.redMul(xs.redIMul(ys));

    if (!a.eq(b.redIAdd(curve.one)))
      throw new Error('Invalid point.');

    const p = new Point(curve);

    p.x = x;
    p.y = y;

    return p;
  }
}

/*
 * Helpers
 */

function cswap(swap, x, y) {
  const items = [x, y];
  const b = swap & 1;
  items[0 ^ b] = x;
  items[1 ^ b] = y;
  return items;
}

function getNAF(num, w) {
  const naf = [];
  const ws = 1 << (w + 1);
  const k = num.clone();

  while (k.cmpn(1) >= 0) {
    let z;

    if (k.isOdd()) {
      const mod = k.andln(ws - 1);

      if (mod > (ws >> 1) - 1)
        z = (ws >> 1) - mod;
      else
        z = mod;

      k.isubn(z);
    } else {
      z = 0;
    }

    naf.push(z);

    // Optimization, shift by word if possible
    const shift = (k.cmpn(0) !== 0 && k.andln(ws - 1) === 0) ? (w + 1) : 1;

    for (let i = 1; i < shift; i++)
      naf.push(0);

    k.iushrn(shift);
  }

  return naf;
}

/*
 * Expose
 */

module.exports = new API();
