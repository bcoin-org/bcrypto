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

  a: 1,
  c: 2,

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

  bit: 447,
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
    this.c = this.curve.c;
    this.n = this.curve.n;
    this.g = this.curve.base();
    this.bit = this.curve.bit;
    this.bits = this.curve.bits;
    this.size = this.curve.size;
    this.hash = this.curve.hash;
    this.prefix = this.curve.prefix;
  }

  clamp(data) {
    assert(Buffer.isBuffer(data));
    assert(data.length >= this.size);

    const raw = data.slice(0, this.size);

    for (let i = 0; i < this.c; i++)
      raw[i >>> 3] &= ~(1 << (i & 7));

    raw[this.bit >>> 3] |= 1 << (this.bit & 7);

    for (let i = this.bit + 1; i < this.bits; i++)
      raw[i >>> 3] &= ~(1 << (i & 7));

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
    return this.g.mul(a).encode();
  }

  publicKeyConvert(key) {
    // Edwards point.
    const bits = this.bits - 8;
    const point = this.curve.decodePoint(key);

    if (point == null)
      throw new Error('Invalid public key.');

    let {x, y, z} = point;

    // Convert to montgomery.
    x = x.redInvm(); // 1/x
    z = x.redMul(y); // y/x
    y = z.redSqr(); // (y/x)^2

    // Montgomery point.
    return this.curve.encodeField(y, bits);
  }

  publicKeyDeconvert(key, sign = false) {
    assert(Buffer.isBuffer(key));
    assert(key.length === this.size - 1);
    assert(typeof sign === 'boolean');

    throw new Error('Unimplemented.');
  }

  publicKeyVerify(key) {
    const A = this.curve.decodePoint(key);

    if (A == null)
      return false;

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
    const t = this.decodeScalar(tweak).umod(this.n);
    const k = this.curve.decodePoint(key);

    if (k == null || !k.validate())
      throw new Error('Invalid public key.');

    const point = this.g.mul(t).add(k);

    if (!point.validate())
      throw new Error('Invalid public key.');

    return point.encode();
  }

  publicKeyTweakMul(key, tweak) {
    const t = this.decodeScalar(tweak).umod(this.n);
    const k = this.curve.decodePoint(key);

    if (k == null || !k.validate())
      throw new Error('Invalid public key.');

    const point = k.mul(t);

    if (!point.validate())
      throw new Error('Invalid public key.');

    return point.encode();
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
    const A = this.g.mul(a).encode();
    const r = this.hashInt(ph, ctx, prefix, msg);
    const R = this.g.mul(r).encode();
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
    const R = this.curve.decodePoint(Rraw);
    const S = this.decodeInt(Sraw);
    const A = this.curve.decodePoint(key);

    if (R == null || A == null || S.cmp(this.n) >= 0)
      return false;

    const h = this.hashInt(ph, ctx, Rraw, key, msg);

    let rhs = R.add(A.mul(h));
    let lhs = this.g.mul(S);

    for (let i = 0; i < this.c; i++) {
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
    const a = this.decodeScalar(scalar).umod(this.n);
    const A = this.curve.decodePoint(pub);

    if (A == null || !A.validate())
      throw new Error('Invalid public key.');

    return A.mul(a).encode();
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

    let x1 = this.curve.decodeField(xpub);
    let x2 = this.curve.f1;
    let z2 = this.curve.f0;
    let x3 = x1;
    let z3 = this.curve.f1;
    let t1, t2;

    if (x1 == null)
      throw new Error('Invalid public key.');

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
      t2 = x2.redSub(z2); // B = x2 - z2 (3+e)
      z2 = x3.redSub(z3); // D = x3 - z3 (3+e)
      x2 = t1.redMul(z2); // DA
      z2 = z3.redAdd(x3); // C = x3 + z3 (2+e)
      x3 = t2.redMul(z2); // CB
      z3 = x2.redSub(x3); // DA-CB (3+e)
      z2 = z3.redSqr(); // (DA-CB)^2
      z3 = x1.redMul(z2); // z3 = x1(DA-CB)^2
      z2 = x2.redAdd(x3); // (DA+CB) (2+e)
      x3 = z2.redSqr(); // x3 = (DA+CB)^2

      z2 = t1.redSqr(); // AA = A^2
      t1 = t2.redSqr(); // BB = B^2
      x2 = z2.redMul(t1); // x2 = AA*BB
      t2 = z2.redSub(t1); // E = AA-BB (3+e)

      t1 = t2.redMul(nd); // E*-d = a24*E
      t1 = t1.redAdd(z2); // AA + a24*E (2+e)
      z2 = t2.redMul(t1); // z2 = E(AA+a24*E)
    }

    // Finish.
    [x2, x3] = cswap(swap, x2, x3);
    [z2, z3] = cswap(swap, z2, z3);

    z2 = z2.redInvm();
    x1 = x2.redMul(z2);

    if (x1.isZero())
      throw new Error('Invalid public key.');

    return this.curve.encodeField(x1, bits);
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
    this.red = BN.red(this.p);
    this.a = params.a;
    this.c = params.c;
    this.d = this.field(new BN(params.d, 16));
    this.n = new BN(params.n, 16);
    this.x = this.field(new BN(params.x, 16));
    this.y = this.field(new BN(params.y, 16));
    this.bit = params.bit;
    this.bits = params.bits;
    this.size = params.size;
    this.hash = params.hash;
    this.prefix = Buffer.from(params.prefix, 'binary');
    this.f0 = this.field(new BN(0));
    this.f1 = this.field(new BN(1));
    this.mask = new BN(1).ushln(this.bits - 1);

    this.validate();
  }

  validate() {
    const g = this.base();
    const z = this.zero();
    const n = this.n.addn(1);

    let p = g;
    let q = z;

    assert(p.validate());
    assert(q.validate());

    for (let i = 0; i < this.bits; i++) {
      if (n.andln(1)) {
        q = q.add(p);

        assert(q.validate());
      }

      p = p.double();
      n.iushrn(1);

      assert(p.validate());
    }

    assert(q.encode().equals(g.encode()));
    assert(!q.encode().equals(p.encode()));
    assert(!q.encode().equals(z.encode()));
  }

  zero() {
    return new Point(this, this.f0, this.f1);
  }

  base() {
    return new Point(this, this.x, this.y);
  }

  field(x) {
    return x.toRed(this.red);
  }

  encodeField(x, bits) {
    assert(x instanceof BN);
    assert((bits >>> 0) === bits);
    return x.fromRed().toArrayLike(Buffer, 'le', bits >>> 3);
  }

  decodeField(x) {
    assert(Buffer.isBuffer(x));

    const rv = new BN(x, 'le').umod(this.mask);

    if (rv.gte(this.p))
      return null;

    return this.field(rv);
  }

  decodePoint(s) {
    assert(Buffer.isBuffer(s));

    const bits = this.bits;

    if (s.length !== (bits >>> 3))
      return null;

    const xs = ((s[(bits - 1) >>> 3] >>> ((bits - 1) & 7)) & 1) === 1;
    const y = this.decodeField(s);

    if (y == null)
      return null;

    let x = this.solveX2(y).redSqrt();

    if (x == null || (x.isZero() && xs !== x.isOdd()))
      return null;

    if (x.isOdd() !== xs)
      x = x.redNeg();

    try {
      return new Point(this, x, y);
    } catch (e) {
      return null;
    }
  }

  solveX2(y) {
    assert(y instanceof BN);
    const a = y.redSqr().redSub(this.f1);
    const b = this.d.redMul(y.redSqr()).redSub(this.f1);
    return a.redMul(b.redInvm());
  }
}

/*
 * Point
 */

class Point {
  constructor(curve, x, y) {
    assert(curve instanceof Curve);
    assert(x instanceof BN);
    assert(y instanceof BN);

    const a = y.redSqr().redAdd(x.redSqr());
    const b = curve.d.redMul(x.redSqr().redMul(y.redSqr()));

    if (!a.eq(curve.f1.redAdd(b)))
      throw new Error('Invalid point.');

    this.curve = curve;
    this.x = x;
    this.y = y;
    this.z = curve.field(new BN(1));
  }

  encode() {
    const bits = this.curve.bits;
    const zinv = this.z.redInvm();
    const xp = this.x.redMul(zinv);
    const yp = this.y.redMul(zinv);
    const s = this.curve.encodeField(yp, bits);

    if (xp.isOdd())
      s[(bits - 1) >>> 3] |= 1 << ((bits - 1) & 7);

    return s;
  }

  mul(x) {
    assert(x instanceof BN);

    let r = this.curve.zero();
    let s = this;

    x = x.clone();

    while (!x.isZero()) {
      if (x.andln(1))
        r = r.add(s);
      s = s.double();
      x.iushrn(1);
    }

    return r;
  }

  eq(y) {
    assert(y instanceof Point);

    const xn1 = this.x.redMul(y.z);
    const xn2 = y.x.redMul(this.z);
    const yn1 = this.y.redMul(y.z);
    const yn2 = y.y.redMul(this.z);

    return xn1.eq(xn2) && yn1.eq(yn2);
  }

  add(y) {
    assert(y instanceof Point);

    const tmp = this.curve.zero();
    const xcp = this.x.redMul(y.x);
    const ycp = this.y.redMul(y.y);
    const zcp = this.z.redMul(y.z);
    const B = zcp.redSqr();
    const E = this.curve.d.redMul(xcp).redMul(ycp);
    const F = B.redSub(E);
    const G = B.redAdd(E);

    const a = this.x.redAdd(this.y);
    const b = y.x.redAdd(y.y);
    const c = a.redMul(b).redSub(xcp).redSub(ycp);

    tmp.x = zcp.redMul(F).redMul(c);
    tmp.y = zcp.redMul(G).redMul(ycp.redSub(xcp));
    tmp.z = F.redMul(G);

    return tmp;
  }

  double() {
    const tmp = this.curve.zero();
    const x1s = this.x.redSqr();
    const y1s = this.y.redSqr();
    const z1s = this.z.redSqr();
    const xys = this.x.redAdd(this.y);
    const F = x1s.redAdd(y1s);
    const J = F.redSub(z1s.redAdd(z1s));

    const a = xys.redSqr().redSub(x1s).redSub(y1s);

    tmp.x = a.redMul(J);
    tmp.y = F.redMul(x1s.redSub(y1s));
    tmp.z = F.redMul(J);

    return tmp;
  }

  validate() {
    const {x, y, z} = this;
    const x2 = x.redSqr();
    const y2 = y.redSqr();
    const z2 = z.redSqr();
    const lhs = x2.redAdd(y2).redMul(z2);
    const rhs = z2.redSqr().redAdd(this.curve.d.redMul(x2).redMul(y2));
    return lhs.eq(rhs);
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

/*
 * Expose
 */

module.exports = new API();
