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
const SHAKE256 = require('../shake256');
const random = require('../random');
const asn1 = require('../encoding/asn1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');

/*
 * Constants
 */

const EMPTY = Buffer.alloc(0);
const ZERO = Buffer.from([0]);
const ONE = Buffer.from([1]);
const SLAB = Buffer.alloc(1);

const params = {
  id: 'ED448',
  xid: 'CURVE448',
  edwards: true,

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
      this._ec = new Ed448(params);
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

  sign(msg, secret, ph, ctx) {
    return this.ec.sign(msg, secret, ph, ctx);
  }

  signTweak(msg, secret, tweak, ph, ctx) {
    return this.ec.signTweak(msg, secret, tweak, ph, ctx);
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

    const Hash = this.hash;
    const h = new Hash();

    // SHAKE256 (permuted to 114 bytes).
    h.init();

    // Prefix (SigEd448).
    h.update(this.prefix);

    // Pre-hash Flag.
    if (ph)
      h.update(ONE);
    else
      h.update(ZERO);

    // Context.
    SLAB[0] = ctx.length;
    h.update(SLAB);
    h.update(ctx);

    // Integers.
    for (const item of items)
      h.update(item);

    const hash = h.final(this.size * 2);
    const num = this.decodeInt(hash);

    return num.umod(this.n);
  }

  privateKeyGenerate() {
    return random.randomBytes(this.size);
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

  privateKeyConvert(secret) {
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.size);

    const hash = this.hashKey(secret);

    return this.clamp(hash).slice(0, -1);
  }

  publicKeyCreate(secret) {
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.size);

    const k = this.privateKeyConvert(secret);
    const a = this.decodeInt(k);

    return this.g.mul(a).encode();
  }

  publicKeyConvert(key) {
    assert(Buffer.isBuffer(key));
    assert(key.length === this.size);

    // Edwards point.
    const bits = this.bits - 8;
    const point = this.curve.decodePoint(key);

    if (point == null)
      throw new Error('Invalid public key.');

    let {x, y, z} = point;
    let a, b, c, d, t;

    // 4-isogeny 2xy/(y^2-ax^2), (y^2+ax^2)/(2-y^2-ax^2)
    c = x.sqr();
    a = y.sqr();
    d = c.add(a);
    t = y.add(x);
    b = t.sqr();
    b = b.sub(d);
    t = a.sub(c);
    x = z.sqr();
    z = x.add(x);
    a = z.sub(d);
    x = a.mul(b);
    z = t.mul(a);
    y = t.mul(d);
    t = b.mul(d);

    // Make eslint happy.
    [c, d] = [d, c];

    // Convert to montgomery.
    t = x.invm(); // 1/x
    z = t.mul(y); // y/x
    y = z.sqr(); // (y/x)^2

    // Montgomery point.
    return y.encode(bits);
  }

  publicKeyDeconvert(key, sign = false) {
    assert(Buffer.isBuffer(key));
    assert(key.length === this.size - 1);
    assert(typeof sign === 'boolean');

    throw new Error('Unimplemented.');
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    if (key.length !== this.size)
      return false;

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

  publicKeyTweakAdd(key, tweak) {
    throw new Error('Unimplemented.');
  }

  sign(msg, secret, ph, ctx) {
    if (ph == null)
      ph = false;

    if (ctx == null)
      ctx = EMPTY;

    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(secret));
    assert(typeof ph === 'boolean');
    assert(Buffer.isBuffer(ctx));
    assert(secret.length === this.size);
    assert(ctx.length <= 255);

    const hash = this.hashKey(secret);
    const k = this.clamp(hash);
    const a = this.decodeInt(k);
    const key = this.g.mul(a).encode();
    const seed = hash.slice(this.size);
    const r = this.hashInt(ph, ctx, seed, msg);
    const R = this.g.mul(r).encode();
    const h = this.hashInt(ph, ctx, R, key, msg);
    const S = r.add(h.mul(a)).umod(this.n);

    return Buffer.concat([R, this.encodeInt(S)]);
  }

  signTweak(msg, secret, tweak, ph, ctx) {
    throw new Error('Unimplemented.');
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

  derive(edpub, secret) {
    assert(Buffer.isBuffer(edpub));
    assert(edpub.length === this.size);
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.size);

    const priv = this.privateKeyConvert(secret);
    const a = this.decodeInt(priv);
    const A = this.curve.decodePoint(edpub);

    if (A == null || !A.validate())
      throw new Error('Invalid public key.');

    const point = A.mul(a).encode();

    return this.publicKeyConvert(point);
  }

  exchange(xpub, secret) {
    assert(Buffer.isBuffer(xpub));
    assert(xpub.length === this.size - 1);

    const bits = this.bits - 8;
    const scalar = this.privateKeyConvert(secret);
    const nd = this.curve.d.neg();

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

      if (swap) {
        [x2, x3] = [x3, x2];
        [z2, z3] = [z3, z2];
      }

      swap = k;

      t1 = x2.add(z2); // A = x2 + z2 (2+e)
      t2 = x2.sub(z2); // B = x2 - z2 (3+e)
      z2 = x3.sub(z3); // D = x3 - z3 (3+e)
      x2 = t1.mul(z2); // DA
      z2 = z3.add(x3); // C = x3 + z3 (2+e)
      x3 = t2.mul(z2); // CB
      z3 = x2.sub(x3); // DA-CB (3+e)
      z2 = z3.sqr(); // (DA-CB)^2
      z3 = x1.mul(z2); // z3 = x1(DA-CB)^2
      z2 = x2.add(x3); // (DA+CB) (2+e)
      x3 = z2.sqr(); // x3 = (DA+CB)^2

      z2 = t1.sqr(); // AA = A^2
      t1 = t2.sqr(); // BB = B^2
      x2 = z2.mul(t1); // x2 = AA*BB
      t2 = z2.sub(t1); // E = AA-BB (3+e)

      t1 = t2.mul(nd); // E*-d = a24*E
      t1 = t1.add(z2); // AA + a24*E (2+e)
      z2 = t2.mul(t1); // z2 = E(AA+a24*E)
    }

    // Finish.
    if (swap) {
      [x2, x3] = [x3, x2];
      [z2, z3] = [z3, z2];
    }

    z2 = z2.invm();
    x1 = x2.mul(z2);

    if (x1.isZero())
      throw new Error('Invalid public key.');

    return x1.encode(bits);
  }

  /*
   * Compat
   */

  ecdh(edpub, secret) {
    return this.derive(edpub, secret);
  }
}

/*
 * Curve
 */

class Curve {
  constructor(params) {
    assert(params && typeof params === 'object');

    this.id = params.id;
    this.p = new Field(new BN(1), new BN(params.p, 16));
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
    return new Field(x, this.p.p);
  }

  decodeField(x) {
    assert(Buffer.isBuffer(x));

    const rv = new BN(x, 'le').umod(this.mask);

    if (rv.gte(this.p.p))
      return null;

    return new Field(rv, this.p.p);
  }

  decodePoint(s) {
    assert(Buffer.isBuffer(s));

    const bits = this.bits;

    if (s.length !== (bits >>> 3))
      return null;

    const xs = (s[(bits - 1) >>> 3] >>> ((bits - 1) & 7)) & 1;
    const y = this.decodeField(s);

    if (y == null)
      return null;

    let x = this.solveX2(y).sqrt();

    if (x == null || (x.isZero() && xs !== x.sign()))
      return null;

    if (x.sign() !== xs)
      x = x.neg();

    try {
      return new Point(this, x, y);
    } catch (e) {
      return null;
    }
  }

  solveX2(y) {
    assert(y instanceof Field);
    const a = y.sqr().sub(this.f1);
    const b = this.d.mul(y.sqr()).sub(this.f1);
    return a.div(b);
  }
}

/*
 * Point
 */

class Point {
  constructor(curve, x, y) {
    assert(curve instanceof Curve);
    assert(x instanceof Field);
    assert(y instanceof Field);

    const a = y.sqr().add(x.sqr());
    const b = curve.d.mul(x.sqr().mul(y.sqr()));

    if (!a.eq(curve.f1.add(b)))
      throw new Error('Invalid point.');

    this.curve = curve;
    this.x = x;
    this.y = y;
    this.z = curve.field(new BN(1));
  }

  encode() {
    const bits = this.curve.bits;
    const xp = this.x.div(this.z);
    const yp = this.y.div(this.z);
    const s = yp.encode(bits);

    if (xp.sign() !== 0)
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

    const xn1 = this.x.mul(y.z);
    const xn2 = y.x.mul(this.z);
    const yn1 = this.y.mul(y.z);
    const yn2 = y.y.mul(this.z);

    return xn1.eq(xn2) && yn1.eq(yn2);
  }

  add(y) {
    assert(y instanceof Point);

    const tmp = this.curve.zero();
    const xcp = this.x.mul(y.x);
    const ycp = this.y.mul(y.y);
    const zcp = this.z.mul(y.z);
    const B = zcp.sqr();
    const E = this.curve.d.mul(xcp).mul(ycp);
    const F = B.sub(E);
    const G = B.add(E);

    const a = this.x.add(this.y);
    const b = y.x.add(y.y);
    const c = a.mul(b).sub(xcp).sub(ycp);

    tmp.x = zcp.mul(F).mul(c);
    tmp.y = zcp.mul(G).mul(ycp.sub(xcp));
    tmp.z = F.mul(G);

    return tmp;
  }

  double() {
    const tmp = this.curve.zero();
    const x1s = this.x.sqr();
    const y1s = this.y.sqr();
    const z1s = this.z.sqr();
    const xys = this.x.add(this.y);
    const F = x1s.add(y1s);
    const J = F.sub(z1s.add(z1s));

    const a = xys.sqr().sub(x1s).sub(y1s);

    tmp.x = a.mul(J);
    tmp.y = F.mul(x1s.sub(y1s));
    tmp.z = F.mul(J);

    return tmp;
  }

  validate() {
    const {x, y, z} = this;
    const x2 = x.sqr();
    const y2 = y.sqr();
    const z2 = z.sqr();
    const lhs = x2.add(y2).mul(z2);
    const rhs = z2.sqr().add(this.curve.d.mul(x2).mul(y2));
    return lhs.eq(rhs);
  }
}

/*
 * Field
 */

class Field {
  constructor(x, p) {
    assert(x instanceof BN);
    assert(p instanceof BN);

    this.x = x.umod(p);
    this.p = p;
  }

  check(y) {
    assert(y instanceof Field);

    if (!this.p.eq(y.p))
      throw new Error('Fields do not match.');
  }

  add(y) {
    this.check(y);
    return new Field(this.x.add(y.x), this.p);
  }

  sub(y) {
    this.check(y);
    return new Field(this.p.add(this.x).sub(y.x), this.p);
  }

  neg() {
    return new Field(this.p.sub(this.x), this.p);
  }

  mul(y) {
    this.check(y);
    return new Field(this.x.mul(y.x), this.p);
  }

  sqr() {
    return this.mul(this);
  }

  div(y) {
    this.check(y);
    return this.mul(y.invm());
  }

  invm() {
    return new Field(modPow(this.x, this.p.subn(2), this.p), this.p);
  }

  sqrt() {
    let y;

    if (this.p.modn(4) === 3)
      y = sqrt4k3(this.x, this.p);
    else if (this.p.modn(8) === 5)
      y = sqrt8k5(this.x, this.p);
    else
      throw new Error('Invalid prime.');

    const f = new Field(y, this.p);

    if (f.sqr().eq(this))
      return f;

    return null;
  }

  isZero() {
    return this.x.isZero();
  }

  eq(y) {
    assert(y instanceof Field);
    return this.x.eq(y.x) && this.p.eq(y.p);
  }

  encode(bits) {
    assert((bits >>> 0) === bits);
    return this.x.toArrayLike(Buffer, 'le', bits >>> 3);
  }

  sign() {
    return this.x.andln(1);
  }
}

/*
 * Helpers
 */

function modPow(x, y, m) {
  assert(x instanceof BN);
  assert(y instanceof BN);
  assert(m instanceof BN);
  return x.toRed(BN.red(m)).redPow(y).fromRed();
}

function sqrt4k3(x, p) {
  assert(x instanceof BN);
  assert(p instanceof BN);
  return modPow(x, p.addn(1).divn(4), p);
}

function sqrt8k5(x, p) {
  assert(x instanceof BN);
  assert(p instanceof BN);

  const y = modPow(x, p.addn(3).divn(8), p);

  if (y.sqr().umod(p).eq(x.umod(p)))
    return y;

  const z = modPow(new BN(2), p.subn(1).divn(4), p);

  return y.mul(z).umod(p);
}

/*
 * Expose
 */

module.exports = new API();
