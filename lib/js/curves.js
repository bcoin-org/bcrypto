/*!
 * curves.js - elliptic curves for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/elliptic:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/elliptic
 *
 * Resources:
 *   https://safecurves.cr.yp.to/
 *   https://hyperelliptic.org/EFD/
 */

'use strict';

const {custom} = require('../internal/custom');
const BN = require('../bn.js');

/*
 * Constants
 */

const types = {
  AFFINE: 0,
  JACOBIAN: 1,
  PROJECTIVE: 2
};

const jsfIndex = [
  -3, // -1 -1
  -1, // -1 0
  -5, // -1 1
  -7, // 0 -1
  0, // 0 0
  7, // 0 1
  5, // 1 -1
  1, // 1 0
  3  // 1 1
];

/**
 * Curve
 */

class Curve {
  constructor(type, conf) {
    this.id = null;
    this.ossl = null;
    this.type = 'base';
    this.endian = 'be';
    this.hash = null;
    this.prefix = null;
    this.context = false;
    this.p = null;
    this.red = null;
    this.fieldSize = 0;
    this.fieldBits = 0;
    this.signBit = 0;
    this.zero = null;
    this.one = null;
    this.two = null;
    this.three = null;
    this.twisted = false;
    this.extended = false;
    this.n = null;
    this.h = null;
    this.g = null;
    this.nh = null;
    this.scalarSize = 0;
    this.scalarBits = 0;
    this.mask = null;
    this.maxwellTrick = false;
    this.redN = null;
    this.blinding = null;
    this.init(type, conf);
  }

  init(type, conf) {
    assert(typeof type === 'string');
    assert(conf && typeof conf === 'object');
    assert(conf.p != null, 'Must pass a prime.');

    // Meta.
    this.id = conf.id || null;
    this.ossl = conf.ossl || null;
    this.type = type;
    this.endian = conf.endian || (type === 'short' ? 'be' : 'le');
    this.hash = conf.hash || null;
    this.prefix = conf.prefix ? Buffer.from(conf.prefix, 'binary') : null;
    this.context = conf.context || false;

    // Prime.
    this.p = new BN(conf.p, 16);

    // Use Montgomery, when there is no fast reduction for the prime.
    this.red = conf.prime ? BN.red(conf.prime) : BN.mont(this.p);

    // Precalculate encoding length.
    this.fieldSize = this.p.byteLength();
    this.fieldBits = this.p.bitLength();
    this.signBit = this.fieldSize * 8 - 1;

    // Figure out where the sign bit goes on edwards/mont.
    if (this.p.testn(this.signBit)) {
      // If the hi bit is set on our prime, we need an
      // extra byte to encode the sign bit (a la Ed448).
      if (this.type === 'edwards')
        this.fieldSize += 1;

      // Move the sign bit over.
      if (this.type === 'mont' || this.type === 'edwards')
        this.signBit += 8;
    }

    // Useful for many curves.
    this.zero = new BN(0).toRed(this.red);
    this.one = new BN(1).toRed(this.red);
    this.two = new BN(2).toRed(this.red);
    this.three = new BN(3).toRed(this.red);

    // Necessary for edwards curves.
    if (this.type === 'edwards' && conf.a != null) {
      const a = new BN(conf.a, 16).toRed(this.red);

      this.twisted = a.cmp(this.one) !== 0;
      this.extended = a.cmp(this.one.redNeg()) === 0;
    }

    // Curve configuration, optional.
    this.n = conf.n ? new BN(conf.n, 16) : new BN(0);
    this.h = conf.h ? new BN(conf.h, 16) : new BN(0);
    this.g = conf.g ? this.pointFromJSON(conf.g) : this.point();
    this.nh = this.n.ushrn(1);
    this.scalarSize = this.n.byteLength();
    this.scalarBits = this.n.bitLength();
    this.mask = new Mask(this);

    // Generalized Greg Maxwell's trick.
    this.maxwellTrick = !this.n.isZero() && this.p.div(this.n).cmpn(100) <= 0;
    this.redN = this.n.toRed(this.red);

    // Scalar blinding.
    this.blinding = null;

    return this;
  }

  point() {
    throw new Error('Not implemented.');
  }

  validate() {
    throw new Error('Not implemented.');
  }

  precompute(rng) {
    assert(!this.g.isInfinity(), 'Must have base point.');
    assert(!this.n.isZero(), 'Must have order.');

    this.g.precompute(this.n.bitLength() + 1, rng);
    this.blinding = this._scalarBlinding(rng);

    return this;
  }

  encodeField(num) {
    assert(num instanceof BN);
    assert(!num.red);
    return num.encode(this.endian, this.fieldSize);
  }

  decodeField(bytes) {
    assert(Buffer.isBuffer(bytes));

    if (bytes.length !== this.fieldSize)
      throw new Error('Invalid field element size.');

    return BN.decode(bytes, this.endian);
  }

  encodeScalar(num) {
    assert(num instanceof BN);
    assert(!num.red);
    return num.encode(this.endian, this.scalarSize);
  }

  decodeScalar(bytes) {
    assert(Buffer.isBuffer(bytes));

    if (bytes.length !== this.scalarSize)
      throw new Error('Invalid scalar size.');

    return BN.decode(bytes, this.endian);
  }

  encodePoint(point, compact) {
    assert(point instanceof Point);
    return point.encode(compact);
  }

  decodePoint(bytes) {
    throw new Error('Not implemented.');
  }

  splitHash(bytes) {
    return this.mask.splitHash(bytes);
  }

  clamp(bytes) {
    return this.mask.clamp(bytes);
  }

  isClamped(bytes) {
    return this.mask.isClamped(bytes);
  }

  getBlinding() {
    if (!this.blinding)
      return [new BN(1), new BN(1)];

    return this.blinding;
  }

  _scalarBlinding(rng) {
    if (!rng)
      return null;

    if (this.n.isZero())
      return null;

    // We blind scalar multiplications too.
    // Our bigint implementation is only
    // constant time for 235-285 bit ints.
    // This is only effective if an attacker
    // is not able to observe the start up.
    for (;;) {
      const blind = BN.random(rng, 1, this.n);

      try {
        return [blind, blind.invert(this.n)];
      } catch (e) {
        continue;
      }
    }
  }

  _simpleMul(p, k, initial, jacobian) {
    assert(p instanceof Point);
    assert(k instanceof BN);
    assert(!k.red);
    assert(initial == null || (initial instanceof Point));
    assert(typeof jacobian === 'boolean');

    const bits = k.bitLength();

    let acc = this.jpoint();

    if (k.sign() < 0)
      p = p.neg();

    for (let i = bits - 1; i >= 0; i--) {
      acc = acc.dbl();

      if (k.utestn(i)) {
        if (p.type === types.AFFINE)
          acc = acc.mixedAdd(p);
        else
          acc = acc.add(p);
      }
    }

    if (initial)
      acc = acc.add(initial);

    if (jacobian)
      return acc;

    return p.type === types.AFFINE ? acc.toP() : acc;
  }

  _simpleMulAdd(points, coeffs, initial, jacobian) {
    assert(Array.isArray(points));
    assert(Array.isArray(coeffs));
    assert(initial == null || (initial instanceof Point));
    assert(typeof jacobian === 'boolean');
    assert(points.length === coeffs.length);
    assert(points.length === 0 || (points[0] instanceof Point));

    // Type checking.
    const type = points.length > 0
      ? points[0].type
      : types.AFFINE;

    // Pad to even.
    if (points.length & 1) {
      if (type === types.AFFINE)
        points.push(this.point());
      else
        points.push(this.jpoint());

      coeffs.push(new BN(0));
    }

    // Check types.
    for (let i = 0; i < points.length; i++) {
      const point = points[i];
      const coeff = coeffs[i];

      assert(point instanceof Point);
      assert(coeff instanceof BN);
      assert(!coeff.red);

      if (point.type !== type)
        throw new Error('Cannot mix points.');
    }

    let acc = initial || this.jpoint();

    assert(acc.type !== types.AFFINE);

    // Multiply, add, and accumulate.
    for (let i = 0; i < points.length; i += 2) {
      const k1 = coeffs[i + 0];
      const k2 = coeffs[i + 1];
      const bits = Math.max(k1.bitLength(), k2.bitLength());

      let p1 = points[i + 0];
      let p2 = points[i + 1];
      let p = this.jpoint();

      if (k1.sign() < 0)
        p1 = p1.neg();

      if (k2.sign() < 0)
        p2 = p2.neg();

      for (let i = bits - 1; i >= 0; i--) {
        p = p.dbl();

        if (type === types.AFFINE) {
          if (k1.utestn(i))
            p = p.mixedAdd(p1);

          if (k2.utestn(i))
            p = p.mixedAdd(p2);
        } else {
          if (k1.utestn(i))
            p = p.add(p1);

          if (k2.utestn(i))
            p = p.add(p2);
        }
      }

      acc = acc.add(p);
    }

    if (jacobian)
      return acc;

    return type === types.AFFINE ? acc.toP() : acc;
  }

  _fixedNafMul(p, k, initial, jacobian) {
    assert(p instanceof Point);
    assert(k instanceof BN);
    assert(initial == null || (initial instanceof Point));
    assert(typeof jacobian === 'boolean');
    assert(p.precomputed);

    const {step, points} = p._getDoubles(0, 0);
    const naf = getNAF(k, 1, k.bitLength() + 1);
    const I = ((1 << (step + 1)) - (step % 2 === 0 ? 2 : 1)) / 3;

    // Translate into more windowed form.
    const repr = [];

    for (let j = 0; j < naf.length; j += step) {
      let nafW = 0;

      for (let k = j + step - 1; k >= j; k--)
        nafW = (nafW << 1) + naf[k];

      repr.push(nafW);
    }

    let a = initial || this.jpoint();
    let b = this.jpoint();

    assert(a.type !== types.AFFINE);

    for (let i = I; i > 0; i--) {
      for (let j = 0; j < repr.length; j++) {
        const nafW = repr[j];

        if (p.type === types.AFFINE) {
          if (nafW === i)
            b = b.mixedAdd(points[j]);
          else if (nafW === -i)
            b = b.mixedAdd(points[j].neg());
        } else {
          if (nafW === i)
            b = b.add(points[j]);
          else if (nafW === -i)
            b = b.add(points[j].neg());
        }
      }

      a = a.add(b);
    }

    if (jacobian)
      return a;

    return p.type === types.AFFINE ? a.toP() : a;
  }

  _wnafMul(p, k, initial, jacobian) {
    assert(p instanceof Point);
    assert(k instanceof BN);
    assert(initial == null || (initial instanceof Point));
    assert(typeof jacobian === 'boolean');

    // Precompute window.
    const nafPoints = p._getNAFPoints(4);
    const w = nafPoints.wnd;
    const wnd = nafPoints.points;

    // Get NAF form.
    const naf = getNAF(k, w, k.bitLength() + 1);

    // Add `this`*(N+1) for every w-NAF index.
    let acc = this.jpoint();

    for (let i = naf.length - 1; i >= 0; i--) {
      // Count zeroes.
      let k = 0;

      for (; i >= 0 && naf[i] === 0; i--)
        k += 1;

      if (i >= 0)
        k += 1;

      acc = acc.dblp(k);

      if (i < 0)
        break;

      const z = naf[i];

      assert(z !== 0);

      if (p.type === types.AFFINE) {
        // J +- P
        if (z > 0)
          acc = acc.mixedAdd(wnd[(z - 1) >> 1]);
        else
          acc = acc.mixedAdd(wnd[(-z - 1) >> 1].neg());
      } else {
        // J +- J
        if (z > 0)
          acc = acc.add(wnd[(z - 1) >> 1]);
        else
          acc = acc.add(wnd[(-z - 1) >> 1].neg());
      }
    }

    if (initial)
      acc = acc.add(initial);

    if (jacobian)
      return acc;

    return p.type === types.AFFINE ? acc.toP() : acc;
  }

  _wnafMulAdd(defW, points, coeffs, initial, jacobian) {
    assert((defW >>> 0) === defW);
    assert(Array.isArray(points));
    assert(Array.isArray(coeffs));
    assert(initial == null || (initial instanceof Point));
    assert(typeof jacobian === 'boolean');
    assert(points.length === coeffs.length);
    assert(points.length === 0 || (points[0] instanceof Point));

    // Type checking.
    const type = points.length > 0
      ? points[0].type
      : types.AFFINE;

    // Pad to even.
    if (points.length & 1) {
      if (type === types.AFFINE)
        points.push(this.point());
      else
        points.push(this.jpoint());

      coeffs.push(new BN(0));
    }

    const len = points.length;
    const width = new Array(len);
    const wnd = new Array(len);
    const naf = new Array(len);

    let size = 0;

    // Fill all arrays.
    for (let i = 0; i < len; i++) {
      const point = points[i];
      const coeff = coeffs[i];

      assert(point instanceof Point);
      assert(coeff instanceof BN);

      if (point.type !== type)
        throw new Error('Cannot mix points.');

      const nafPoints = point._getNAFPoints(defW);

      width[i] = nafPoints.wnd;
      wnd[i] = nafPoints.points;
      naf[i] = null;

      size = Math.max(size, coeff.bitLength() + 1);
    }

    // Comb small window NAFs.
    for (let i = len - 1; i >= 1; i -= 2) {
      const a = i - 1;
      const b = i;

      if (width[a] !== 1 || width[b] !== 1) {
        naf[a] = getNAF(coeffs[a], width[a], size);
        naf[b] = getNAF(coeffs[b], width[b], size);
        continue;
      }

      const comb = [
        points[a], // 1
        null, // 3
        null, // 5
        points[b] // 7
      ];

      if (type === types.AFFINE) {
        // Try to avoid Projective points, if possible.
        if ((points[a].inf | points[b].inf) === 0) {
          if (points[a].y.cmp(points[b].y) === 0) {
            comb[1] = points[a].add(points[b]);
            comb[2] = points[a].toJ().mixedAdd(points[b].neg());
          } else if (points[a].y.cmp(points[b].y.redNeg()) === 0) {
            comb[1] = points[a].toJ().mixedAdd(points[b]);
            comb[2] = points[a].add(points[b].neg());
          }
        }

        if (comb[1] === null) {
          comb[1] = points[a].toJ().mixedAdd(points[b]);
          comb[2] = points[a].toJ().mixedAdd(points[b].neg());
        }
      } else {
        comb[1] = points[a].add(points[b]);
        comb[2] = points[a].add(points[b].neg());
      }

      wnd[a] = comb;

      [naf[a], naf[b]] = getJSF(coeffs[a], coeffs[b], size);
    }

    const tmp = new Array(len);

    let acc = this.jpoint();

    for (let i = size - 1; i >= 0; i--) {
      let k = 0;

      while (i >= 0) {
        let zero = true;

        for (let j = 0; j < len; j++) {
          tmp[j] = naf[j][i];
          if (tmp[j] !== 0)
            zero = false;
        }

        if (!zero)
          break;

        k += 1;
        i -= 1;
      }

      if (i >= 0)
        k += 1;

      acc = acc.dblp(k);

      if (i < 0)
        break;

      for (let j = 0; j < len; j++) {
        const z = tmp[j];

        if (z === 0)
          continue;

        let p = null;

        if (z > 0)
          p = wnd[j][(z - 1) >> 1];
        else
          p = wnd[j][(-z - 1) >> 1].neg();

        if (p.type === types.AFFINE)
          acc = acc.mixedAdd(p);
        else
          acc = acc.add(p);
      }
    }

    if (initial)
      acc = acc.add(initial);

    if (jacobian)
      return acc;

    return type === types.AFFINE ? acc.toP() : acc;
  }

  mulAll(points, coeffs) {
    return this._mulAll(points, coeffs, null, false);
  }

  jmulAll(points, coeffs) {
    return this._mulAll(points, coeffs, null, true);
  }

  mulAllSlow(points, coeffs) {
    return this._simpleMulAdd(points, coeffs, null, false);
  }

  jmulAllSlow(points, coeffs) {
    return this._simpleMulAdd(points, coeffs, null, true);
  }
}

/**
 * Mask
 */

class Mask {
  constructor(curve) {
    assert(curve instanceof Curve);

    const bytes = curve.p.byteLength();
    const bits = Math.max(8, (bytes - 1) * 8);

    // Our curve.
    this.curve = curve;

    // Cofactor mask (p25519=-8, p448=-4).
    this.h = -curve.h.toNumber() & 0xff;

    // Group order top byte (p25519=0x7f, p448=0xff).
    // In theory we should get this from the
    // _real_ order, not the prime.
    this.n = curve.p.ushrn(bits).toNumber();

    // High bit (p25519=0x40, p448=0x80).
    this.b = (this.n + 1) >>> 1;

    // AND mask (p25519=0x7fff...f8, p448=0xffff...fc).
    this.and = BN.shift(this.n + 1, bits - 8).isubn(1);
    this.and.iushln(8).iuorn(this.h);

    // OR mask (p25519=0x4000..., p448=0x8000...).
    this.or = BN.shift(this.b, bits);

    // Verify clamping constants.
    if (curve.id === 'ed25519' || curve.id === 'x25519') {
      assert(this.h === (-8 & 0xff));
      assert(this.n === 0x7f);
      assert(this.b === 0x40);
    } else if (curve.id === 'ed448' || curve.id === 'x448') {
      assert(this.h === (-4 & 0xff));
      assert(this.n === 0xff);
      assert(this.b === 0x80);
    }
  }

  reduce(num) {
    assert(num instanceof BN);
    assert(!num.red);

    num.iuand(this.and);
    num.iuor(this.or);

    return num;
  }

  splitHash(bytes) {
    assert(Buffer.isBuffer(bytes));
    assert(bytes.length === this.curve.fieldSize * 2);

    const scalar = bytes.slice(0, this.curve.scalarSize);
    const prefix = bytes.slice(this.curve.fieldSize);

    this.clamp(scalar);

    return [scalar, prefix];
  }

  clamp(bytes) {
    assert(Buffer.isBuffer(bytes));
    assert(bytes.length === this.curve.scalarSize);

    let i = 0;
    let j = this.curve.scalarSize - 1;

    if (this.curve.endian === 'be')
      [i, j] = [j, i];

    // Ensure a multiple of the cofactor.
    bytes[i] &= this.h;

    // Clamp to the group order.
    bytes[j] &= this.n;

    // Set the high bit.
    bytes[j] |= this.b;

    return bytes;
  }

  isClamped(bytes) {
    assert(Buffer.isBuffer(bytes));

    if (bytes.length !== this.curve.scalarSize)
      return false;

    let i = 0;
    let j = this.curve.scalarSize - 1;

    if (this.curve.endian === 'be')
      [i, j] = [j, i];

    // Must be a multiple of the cofactor.
    if (bytes[i] & ~this.h)
      return false;

    // Must be clamped to the group order.
    if (bytes[j] & ~this.n)
      return false;

    // Must have high bit set.
    if (!(bytes[j] & this.b))
      return false;

    return true;
  }
}

/**
 * Point
 */

class Point {
  constructor(curve, type) {
    assert(curve instanceof Curve);
    assert((type >>> 0) === type);

    this.curve = curve;
    this.type = type;
    this.precomputed = null;
  }

  init() {
    throw new Error('Not implemented.');
  }

  eq(point) {
    throw new Error('Not implemented.');
  }

  validate() {
    return this.curve.validate(this);
  }

  encode(compact) {
    throw new Error('Not implemented.');
  }

  precompute(power, rng) {
    assert((power >>> 0) === power);

    if (!this.precomputed) {
      this.precomputed = {
        naf: null,
        doubles: null,
        beta: null,
        blinding: null
      };
    }

    if (!this.precomputed.naf)
      this.precomputed.naf = this._getNAFPoints(8);

    if (!this.precomputed.doubles)
      this.precomputed.doubles = this._getDoubles(4, power);

    if (!this.precomputed.beta)
      this.precomputed.beta = this._getBeta();

    if (!this.precomputed.blinding)
      this.precomputed.blinding = this._getBlinding(rng);

    return this;
  }

  _getNAFPoints(wnd) {
    assert((wnd >>> 0) === wnd);

    if (this.precomputed && this.precomputed.naf)
      return this.precomputed.naf;

    const points = [this];
    const max = (1 << wnd) - 1;
    const dbl = max === 1 ? null : this.dbl();

    for (let i = 1; i < max; i++)
      points.push(points[i - 1].add(dbl));

    return { wnd, points };
  }

  _getDoubles(step, power) {
    assert((step >>> 0) === step);
    assert((power >>> 0) === power);

    if (this.precomputed && this.precomputed.doubles)
      return this.precomputed.doubles;

    const points = [this];

    let acc = this;

    for (let i = 0; i < power; i += step) {
      for (let j = 0; j < step; j++)
        acc = acc.dbl();

      points.push(acc);
    }

    return { step, points };
  }

  _getBeta() {
    return null;
  }

  _getBlinding(rng) {
    if (this.precomputed && this.precomputed.blinding)
      return this.precomputed.blinding;

    if (!rng)
      return null;

    if (this.curve.n.isZero())
      return null;

    for (;;) {
      const blind = BN.random(rng, 1, this.curve.n);
      const unblind = this.jmul(blind);

      if (unblind.isInfinity())
        continue;

      return { blind, unblind };
    }
  }

  _hasDoubles(k) {
    assert(k instanceof BN);

    if (!this.precomputed)
      return false;

    const {doubles} = this.precomputed;

    if (!doubles)
      return false;

    const {points, step} = doubles;

    return points.length >= Math.ceil((k.bitLength() + 1) / step);
  }

  _mulBlind(k, rng = null, jacobian) {
    assert(k instanceof BN);
    assert(!k.red);

    const blinding = this._getBlinding(rng);

    if (!blinding)
      return this._mul(k, null, jacobian);

    const {blind, unblind} = blinding;
    const t = k.sub(blind);

    return this._mul(t, unblind, jacobian);
  }

  mul(k) {
    return this._mul(k, null, false);
  }

  jmul(k) {
    return this._mul(k, null, true);
  }

  mulAdd(k1, p2, k2) {
    return this._mulAdd(k1, p2, k2, null, false);
  }

  jmulAdd(k1, p2, k2) {
    return this._mulAdd(k1, p2, k2, null, true);
  }

  mulBlind(k, rng = null) {
    return this._mulBlind(k, rng, false);
  }

  jmulBlind(k, rng = null) {
    return this._mulBlind(k, rng, true);
  }

  mulSlow(k) {
    return this.curve._simpleMul(this, k, null, false);
  }

  jmulSlow(k) {
    return this.curve._simpleMul(this, k, null, true);
  }

  mulAddSlow(k1, p2, k2) {
    return this.curve._simpleMulAdd([this, p2], [k1, k2], null, false);
  }

  jmulAddSlow(k1, p2, k2) {
    return this.curve._simpleMulAdd([this, p2], [k1, k2], null, true);
  }

  dblp(pow) {
    assert((pow >>> 0) === pow);

    if (pow === 0)
      return this;

    if (this.isInfinity())
      return this;

    let r = this;

    for (let i = 0; i < pow; i++)
      r = r.dbl();

    return r;
  }
}

/**
 * ShortCurve
 */

class ShortCurve extends Curve {
  constructor(conf) {
    super('short', conf);

    this.a = new BN(conf.a, 16).toRed(this.red);
    this.b = new BN(conf.b, 16).toRed(this.red);
    this.tinv = this.two.redInvert();

    this.zeroA = this.a.sign() === 0;
    this.threeA = this.a.cmp(this.three.redNeg()) === 0;

    // If the curve is endomorphic, precalculate beta and lambda.
    this.endo = this._getEndomorphism(conf);
  }

  _getEndomorphism(conf) {
    assert(conf && typeof conf === 'object');

    // No curve params.
    if (this.n.isZero() || this.g.isInfinity())
      return null;

    // No efficient endomorphism.
    if (!this.zeroA || this.p.modrn(3) !== 1)
      return null;

    // Compute beta and lambda, that lambda * P = (beta * Px; Py).
    let beta, lambda;

    if (conf.beta) {
      beta = new BN(conf.beta, 16).toRed(this.red);
    } else {
      const betas = this._getEndoRoots(this.p);

      // Choose the smallest beta.
      beta = betas[0].cmp(betas[1]) < 0 ? betas[0] : betas[1];
      beta = beta.toRed(this.red);
    }

    if (conf.lambda) {
      lambda = new BN(conf.lambda, 16);
    } else {
      // Choose the lambda that is matching selected beta.
      const lambdas = this._getEndoRoots(this.n);

      if (this.g.mul(lambdas[0]).x.cmp(this.g.x.redMul(beta)) === 0) {
        lambda = lambdas[0];
      } else {
        lambda = lambdas[1];
        assert(this.g.mul(lambda).x.cmp(this.g.x.redMul(beta)) === 0);
      }
    }

    // Get basis vectors, used for balanced length-two representation.
    let basis;

    if (conf.basis) {
      basis = conf.basis.map(({a, b}) => {
        return {
          a: new BN(a, 16),
          b: new BN(b, 16)
        };
      });
    } else {
      basis = this._getEndoBasis(lambda);
    }

    return { beta, lambda, basis };
  }

  _getEndoRoots(num) {
    assert(num instanceof BN);
    assert(!num.red);

    // Find roots of for x^2 + x + 1 in F.
    // Root = (-1 +- Sqrt(-3)) / 2
    const red = num === this.p ? this.red : BN.mont(num);
    const tinv = new BN(2).toRed(red).redInvert();
    const ntinv = tinv.redNeg();

    const s = new BN(3).toRed(red).redINeg().redSqrt().redMul(tinv);

    const l1 = ntinv.redAdd(s).fromRed();
    const l2 = ntinv.redISub(s).fromRed();

    return [l1, l2];
  }

  _getEndoBasis(lambda) {
    assert(lambda instanceof BN);
    assert(!lambda.red);
    assert(!this.n.isZero());

    // aprxSqrt >= sqrt(this.n)
    const aprxSqrt = this.n.ushrn(this.n.bitLength() >>> 1);

    // Run EGCD, until r(L + 1) < aprxSqrt.
    let u = lambda;
    let v = this.n.clone();
    let x1 = new BN(1);
    let y1 = new BN(0);
    let x2 = new BN(0);
    let y2 = new BN(1);
    let i = 0;

    // All vectors are roots of: a + b * lambda = 0 (mod n).
    let a0, b0;

    // First vector.
    let a1, b1;

    // Second vector.
    let a2, b2;

    // Inner.
    let prevR, r, x;

    while (u.sign() !== 0) {
      assert(v.sign() >= 0);

      const q = v.div(u);

      r = v.sub(q.mul(u));
      x = x2.sub(q.mul(x1));

      const y = y2.sub(q.mul(y1));

      if (!a1 && r.cmp(aprxSqrt) < 0) {
        a0 = prevR.neg();
        b0 = x1;
        a1 = r.neg();
        b1 = x;
      } else if (a1 && ++i === 2) {
        break;
      }

      prevR = r;

      v = u;
      u = r;
      x2 = x1;
      x1 = x;
      y2 = y1;
      y1 = y;
    }

    a2 = r.neg();
    b2 = x;

    const len1 = a1.sqr().iadd(b1.sqr());
    const len2 = a2.sqr().iadd(b2.sqr());

    if (len2.cmp(len1) >= 0) {
      a2 = a0;
      b2 = b0;
    }

    // Normalize signs.
    if (a1.sign() < 0) {
      a1 = a1.neg();
      b1 = b1.neg();
    }

    if (a2.sign() < 0) {
      a2 = a2.neg();
      b2 = b2.neg();
    }

    return [
      { a: a1, b: b1 },
      { a: a2, b: b2 }
    ];
  }

  _endoSplit(k) {
    assert(k instanceof BN);
    assert(!k.red);
    assert(!this.n.isZero());

    const [v1, v2] = this.endo.basis;

    const c1 = v2.b.mul(k).divRound(this.n);
    const c2 = v1.b.neg().imul(k).divRound(this.n);

    const p1 = c1.mul(v1.a);
    const p2 = c2.mul(v2.a);
    const q1 = c1.mul(v1.b);
    const q2 = c2.mul(v2.b);

    // Calculate answer.
    const k1 = k.sub(p1).isub(p2);
    const k2 = q1.add(q2).ineg();

    return [k1, k2];
  }

  _endoBeta(point) {
    assert(point instanceof ShortPoint);
    return [point, point._getBeta()];
  }

  pointFromX(x, odd) {
    assert(x instanceof BN);

    if (!x.red)
      x = x.toRed(this.red);

    // y^2 = x^3 + a * x + b
    const y2 = x.redPown(3).redIAdd(this.b);

    if (!this.zeroA)
      y2.redIAdd(this.a.redMul(x));

    const y = y2.redSqrt();

    if (y.redIsOdd() !== Boolean(odd))
      y.redINeg();

    return this.point(x, y);
  }

  pointFromR(x) {
    assert(x instanceof BN);

    if (!x.red)
      x = x.toRed(this.red);

    // y^2 = x^3 + a * x + b
    const y2 = x.redPown(3).redIAdd(this.b);

    if (!this.zeroA)
      y2.redIAdd(this.a.redMul(x));

    const y = y2.redSqrt();

    return this.point(x, y);
  }

  validate(point) {
    assert(point instanceof ShortPoint);

    if (point.inf)
      return true;

    const {x, y} = point;

    // y^2 = x^3 + a * x + b
    const y2 = x.redPown(3).redIAdd(this.b);

    if (!this.zeroA)
      y2.redIAdd(this.a.redMul(x));

    return y.redSqr().cmp(y2) === 0;
  }

  decodePoint(bytes) {
    assert(Buffer.isBuffer(bytes));

    const len = this.fieldSize;

    if (bytes.length < 1 + len)
      throw new Error('Not a point.');

    const form = bytes[0];

    switch (form) {
      case 0x02:
      case 0x03: {
        if (bytes.length !== 1 + len)
          throw new Error('Invalid point size for compressed.');

        const x = this.decodeField(bytes.slice(1, 1 + len));

        if (x.cmp(this.p) >= 0)
          throw new Error('Invalid point.');

        const p = this.pointFromX(x, form === 0x03);

        assert(!p.isInfinity());

        return p;
      }

      case 0x04:
      case 0x06:
      case 0x07: {
        if (bytes.length !== 1 + len * 2)
          throw new Error('Invalid point size for uncompressed.');

        const x = this.decodeField(bytes.slice(1, 1 + len));
        const y = this.decodeField(bytes.slice(1 + len, 1 + 2 * len));

        if (x.cmp(this.p) >= 0 || y.cmp(this.p) >= 0)
          throw new Error('Invalid point.');

        if (form !== 0x04 && form !== (0x06 | y.isOdd()))
          throw new Error('Invalid hybrid encoding.');

        const p = this.point(x, y);

        if (!p.validate())
          throw new Error('Invalid point.');

        assert(!p.isInfinity());

        return p;
      }

      default: {
        throw new Error('Unknown point format.');
      }
    }
  }

  _endoWnafMulAdd(points, coeffs, initial, jacobian) {
    assert(Array.isArray(points));
    assert(Array.isArray(coeffs));
    assert(points.length === coeffs.length);
    assert(this.endo != null);

    const len = points.length;
    const npoints = new Array(len * 2);
    const ncoeffs = new Array(len * 2);

    for (let i = 0; i < len; i++) {
      const [p1, p2] = this._endoBeta(points[i]);
      const [k1, k2] = this._endoSplit(coeffs[i]);

      npoints[i * 2 + 0] = p1;
      ncoeffs[i * 2 + 0] = k1;
      npoints[i * 2 + 1] = p2;
      ncoeffs[i * 2 + 1] = k2;
    }

    return this._wnafMulAdd(1, npoints, ncoeffs, initial, jacobian);
  }

  _mulAll(points, coeffs, initial, jacobian) {
    assert(Array.isArray(points));
    assert(points.length === 0 || (points[0] instanceof Point));

    if (this.endo && points.length > 0 && points[0].type === types.AFFINE)
      return this._endoWnafMulAdd(points, coeffs, initial, jacobian);

    return this._wnafMulAdd(1, points, coeffs, initial, jacobian);
  }

  point(x, y) {
    return new ShortPoint(this, x, y);
  }

  pointFromJSON(json) {
    return ShortPoint.fromJSON(this, json);
  }

  jpoint(x, y, z) {
    return new JPoint(this, x, y, z);
  }
}

/**
 * ShortPoint
 */

class ShortPoint extends Point {
  constructor(curve, x, y) {
    assert(curve instanceof ShortCurve);

    super(curve, types.AFFINE);

    this.x = null;
    this.y = null;
    this.inf = true;

    if (x != null)
      this.init(x, y);
  }

  init(x, y) {
    assert(x != null);
    assert(y != null);

    this.x = BN.cast(x, 16);
    this.y = BN.cast(y, 16);

    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);

    if (!this.y.red)
      this.y = this.y.toRed(this.curve.red);

    this.inf = false;
  }

  _getBeta() {
    if (!this.curve.endo)
      return null;

    const pre = this.precomputed;

    if (pre && pre.beta)
      return pre.beta;

    const beta = this.curve.point(this.x.redMul(this.curve.endo.beta), this.y);

    if (pre) {
      const curve = this.curve;
      const endoMul = p =>
        curve.point(p.x.redMul(curve.endo.beta), p.y);

      pre.beta = beta;

      beta.precomputed = {
        naf: pre.naf && {
          wnd: pre.naf.wnd,
          points: pre.naf.points.map(endoMul)
        },
        doubles: pre.doubles && {
          step: pre.doubles.step,
          points: pre.doubles.points.map(endoMul)
        },
        beta: null,
        blinding: null
      };
    }

    return beta;
  }

  encode(compact) {
    if (compact == null)
      compact = true;

    assert(typeof compact === 'boolean');

    const {fieldSize} = this.curve;

    if (compact) {
      const p = Buffer.allocUnsafe(1 + fieldSize);
      const x = this.curve.encodeField(this.getX());

      p[0] = 0x02 | this.y.redIsOdd();
      x.copy(p, 1);

      return p;
    }

    const p = Buffer.allocUnsafe(1 + fieldSize * 2);
    const x = this.curve.encodeField(this.getX());
    const y = this.curve.encodeField(this.getY());

    p[0] = 0x04;
    x.copy(p, 1);
    y.copy(p, 1 + fieldSize);

    return p;
  }

  toJSON() {
    const x = this.x.fromRed();
    const y = this.y.fromRed();

    if (!this.precomputed)
      return [x, y];

    return [x, y, {
      naf: this.precomputed.naf && {
        wnd: this.precomputed.naf.wnd,
        points: this.precomputed.naf.points.slice(1)
      },
      doubles: this.precomputed.doubles && {
        step: this.precomputed.doubles.step,
        points: this.precomputed.doubles.points.slice(1)
      }
    }];
  }

  isInfinity() {
    return this.inf;
  }

  add(p) {
    assert(p instanceof ShortPoint);

    // O + P = P
    if (this.inf)
      return p;

    // P + O = P
    if (p.inf)
      return this;

    // P + P = 2P
    if (this.eq(p))
      return this.dbl();

    // P + (-P) = O
    if (this.neg().eq(p))
      return this.curve.point();

    // P + Q = O
    if (this.x.cmp(p.x) === 0)
      return this.curve.point();

    // https://hyperelliptic.org/EFD/g1p/auto-shortw.html
    // 1I + 2M + 1S + 6A

    // C = (Y1 - Y2) / (X1 - X2)
    let c = this.y.redSub(p.y);

    if (c.sign() !== 0)
      c = c.redMul(this.x.redSub(p.x).redInvert());

    // X3 = C^2 - X1 - X2
    const nx = c.redSqr().redISub(this.x).redISub(p.x);

    // Y3 = C * (X1 - X3) - Y1
    const ny = c.redMul(this.x.redSub(nx)).redISub(this.y);

    return this.curve.point(nx, ny);
  }

  mixedAdd(p) {
    assert(p instanceof JPoint);
    return p.mixedAdd(this).toP();
  }

  dbl() {
    // P = O
    if (this.inf)
      return this;

    // https://hyperelliptic.org/EFD/g1p/auto-shortw.html
    // 1I + 2M + 2S + 5A + 1*2 + 1*3

    // S = 2*Y
    const s = this.y.redMuln(2);

    // 2P = O
    if (s.sign() === 0)
      return this.curve.point();

    // XX = X^2
    const xx = this.x.redSqr();

    // C = (XX * 3 + A) / S
    const c = xx.redIMuln(3).redIAdd(this.curve.a).redMul(s.redInvert());

    // X3 = C^2 - 2*X
    const nx = c.redSqr().redISub(this.x).redISub(this.x);

    // Y3 = C * (X1 - X3) - Y1
    const ny = c.redMul(this.x.redSub(nx)).redISub(this.y);

    return this.curve.point(nx, ny);
  }

  getX() {
    if (this.inf)
      throw new Error('Invalid point.');

    return this.x.fromRed();
  }

  getY() {
    if (this.inf)
      throw new Error('Invalid point.');

    return this.y.fromRed();
  }

  _mul(k, initial, jacobian) {
    assert(initial == null || (initial instanceof JPoint));

    if (this._hasDoubles(k))
      return this.curve._fixedNafMul(this, k, initial, jacobian);

    if (this.curve.endo)
      return this.curve._endoWnafMulAdd([this], [k], initial, jacobian);

    return this.curve._wnafMul(this, k, initial, jacobian);
  }

  _mulAdd(k1, p2, k2, initial, jacobian) {
    assert(p2 instanceof ShortPoint);
    assert(initial == null || (initial instanceof JPoint));

    const points = [this, p2];
    const coeffs = [k1, k2];

    if (this.curve.endo)
      return this.curve._endoWnafMulAdd(points, coeffs, initial, jacobian);

    return this.curve._wnafMulAdd(1, points, coeffs, initial, jacobian);
  }

  eq(p) {
    assert(p instanceof ShortPoint);

    if (this === p)
      return true;

    if (this.inf !== p.inf)
      return false;

    if (this.inf)
      return true;

    return this.x.cmp(p.x) === 0
        && this.y.cmp(p.y) === 0;
  }

  hasQuadY() {
    if (this.inf)
      return false;

    return this.y.redJacobi() === 1;
  }

  eqX(x) {
    assert(x instanceof BN);
    assert(!x.red);

    if (this.inf)
      return false;

    return this.getX().cmp(x) === 0;
  }

  eqXToP(x) {
    assert(x instanceof BN);
    assert(!x.red);
    assert(!this.curve.n.isZero());

    if (this.inf)
      return false;

    return this.getX().mod(this.curve.n).cmp(x) === 0;
  }

  neg() {
    if (this.inf)
      return this;

    return this.curve.point(this.x, this.y.redNeg());
  }

  toP() {
    return this;
  }

  toJ() {
    if (this.inf)
      return this.curve.jpoint();

    return this.curve.jpoint(this.x, this.y, this.curve.one);
  }

  normalize() {
    return this;
  }

  [custom]() {
    if (this.isInfinity())
      return '<ShortPoint: Infinity>';

    return '<ShortPoint:'
         + ' x=' + this.x.fromRed().toString(16, 2)
         + ' y=' + this.y.fromRed().toString(16, 2)
         + '>';
  }

  static fromJSON(curve, json) {
    assert(curve instanceof ShortCurve);
    assert(Array.isArray(json));

    const [x, y, pre] = json;
    const point = curve.point(x, y);

    if (!pre)
      return point;

    const {naf, doubles} = pre;
    const convert = ([x, y]) => curve.point(x, y);

    point.precomputed = {
      naf: naf && {
        wnd: naf.wnd,
        points: [point, ...naf.points.map(convert)]
      },
      doubles: doubles && {
        step: doubles.step,
        points: [point, ...doubles.points.map(convert)]
      },
      beta: null,
      blinding: null
    };

    return point;
  }
}

/**
 * JPoint
 */

class JPoint extends Point {
  constructor(curve, x, y, z) {
    assert(curve instanceof ShortCurve);

    super(curve, types.JACOBIAN);

    this.x = this.curve.one;
    this.y = this.curve.one;
    this.z = this.curve.zero;
    this.zOne = false;

    if (x != null)
      this.init(x, y, z);
  }

  init(x, y, z) {
    assert(x != null);
    assert(y != null);

    this.x = BN.cast(x, 16);
    this.y = BN.cast(y, 16);
    this.z = z != null ? BN.cast(z, 16) : this.curve.one;

    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);

    if (!this.y.red)
      this.y = this.y.toRed(this.curve.red);

    if (!this.z.red)
      this.z = this.z.toRed(this.curve.red);

    this.zOne = this.z.eq(this.curve.one);
  }

  validate() {
    return this.curve.validate(this.toP());
  }

  toP() {
    if (this.isInfinity())
      return this.curve.point();

    this.normalize();

    return this.curve.point(this.x, this.y);
  }

  toJ() {
    return this;
  }

  normalize() {
    // Z = 1
    if (this.zOne)
      return this;

    // P = O
    if (this.isInfinity())
      return this;

    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#scaling-z
    // 1I + 3M + 1S

    // A = 1/Z1
    const a = this.z.redInvert();

    // AA = A^2
    const aa = a.redSqr();

    // X3 = X1*AA
    this.x = this.x.redMul(aa);

    // Y3 = Y1*AA*A
    this.y = this.y.redMul(aa).redMul(a);

    // Z3 = 1
    this.z = this.curve.one;
    this.zOne = true;

    return this;
  }

  getX() {
    if (this.isInfinity())
      throw new Error('Invalid point.');

    this.normalize();

    return this.x.fromRed();
  }

  getY() {
    if (this.isInfinity())
      throw new Error('Invalid point.');

    this.normalize();

    return this.y.fromRed();
  }

  neg() {
    return this.curve.jpoint(this.x, this.y.redNeg(), this.z);
  }

  add(p) {
    assert(p instanceof JPoint);

    // O + P = P
    if (this.isInfinity())
      return p;

    // P + O = P
    if (p.isInfinity())
      return this;

    // Z1 = 1, Z2 = 1
    if (this.zOne && p.zOne)
      return this._affineAdd(p);

    // Z1 = 1
    if (this.zOne)
      return p._mixedAdd(this);

    // Z2 = 2
    if (p.zOne)
      return this._mixedAdd(p);

    return this._add(p);
  }

  mixedAdd(p) {
    assert(p instanceof ShortPoint);

    // O + P = P
    if (this.isInfinity())
      return p.toJ();

    // P + O = P
    if (p.isInfinity())
      return this;

    // Z1 = 1, Z2 = 1
    if (this.zOne)
      return this._affineAdd(p);

    return this._mixedAdd(p);
  }

  _add(p) {
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-add-1998-cmo-2
    // 12M + 4S + 6A + 1*2 (implemented as: 12M + 4S + 7A)

    // Z1Z1 = Z1^2
    const z1z1 = this.z.redSqr();

    // Z2Z2 = Z2^2
    const z2z2 = p.z.redSqr();

    // U1 = X1*Z2Z2
    const u1 = this.x.redMul(z2z2);

    // U2 = X2*Z1Z1
    const u2 = p.x.redMul(z1z1);

    // S1 = Y1*Z2*Z2Z2
    const s1 = this.y.redMul(p.z).redMul(z2z2);

    // S2 = Y2*Z1*Z1Z1
    const s2 = p.y.redMul(this.z).redMul(z1z1);

    // H = U2-U1
    const h = u2.redISub(u1);

    // r = S2-S1
    const r = s2.redISub(s1);

    if (h.sign() === 0) {
      if (r.sign() !== 0)
        return this.curve.jpoint();

      return this.dbl();
    }

    // HH = H^2
    const hh = h.redSqr();

    // HHH = H*HH
    const hhh = h.redMul(hh);

    // V = U1*HH
    const v = u1.redMul(hh);

    // X3 = r^2-HHH-2*V
    const nx = r.redSqr().redISub(hhh).redISub(v).redISub(v);

    // Y3 = r*(V-X3)-S1*HHH
    const ny = r.redMul(v.redISub(nx)).redISub(s1.redMul(hhh));

    // Z3 = Z1*Z2*H
    const nz = this.z.redMul(p.z).redMul(h);

    return this.curve.jpoint(nx, ny, nz);
  }

  _affineAdd(p) {
    // Assumes Z1=1 and Z2=1.
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-mmadd-2007-bl
    // 4M + 2S + 6A + 4*2 + 1*4 (implemented as: 4M + 2S + 7A + 3*2 + 1*4)

    // H = X2-X1
    const h = p.x.redSub(this.x);

    // r = 2*(Y2-Y1)
    const r = p.y.redSub(this.y).redIMuln(2);

    if (h.sign() === 0) {
      if (r.sign() !== 0)
        return this.curve.jpoint();

      return this.dbl();
    }

    // HH = H^2
    const hh = h.redSqr();

    // I = 4*HH
    const i = hh.redIMuln(4);

    // J = H*I
    const j = h.redMul(i);

    // V = X1*I
    const v = this.x.redMul(i);

    // X3 = r^2-J-2*V
    const nx = r.redSqr().redISub(j).redISub(v).redISub(v);

    // Y3 = r*(V-X3)-2*Y1*J
    const ny = r.redMul(v.redISub(nx)).redISub(this.y.redMul(j).redIMuln(2));

    // Z3 = 2*H
    const nz = h.redIMuln(2);

    return this.curve.jpoint(nx, ny, nz);
  }

  _mixedAdd(p) {
    // Assumes Z2=1.
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-madd
    // 8M + 3S + 6A + 5*2 (implemented as: 8M + 3S + 7A + 4*2)

    // Z1Z1 = Z1^2
    const z1z1 = this.z.redSqr();

    // U2 = X2*Z1Z1
    const u2 = p.x.redMul(z1z1);

    // S2 = Y2*Z1*Z1Z1
    const s2 = p.y.redMul(this.z).redMul(z1z1);

    // H = U2-X1
    const h = u2.redISub(this.x);

    // r = 2*(S2-Y1)
    const r = s2.redISub(this.y).redIMuln(2);

    if (h.sign() === 0) {
      if (r.sign() !== 0)
        return this.curve.jpoint();

      return this.dbl();
    }

    // I = (2*H)^2
    const i = h.redMuln(2).redSqr();

    // J = H*I
    const j = h.redMul(i);

    // V = X1*I
    const v = this.x.redMul(i);

    // X3 = r^2-J-2*V
    const nx = r.redSqr().redISub(j).redISub(v).redISub(v);

    // Y3 = r*(V-X3)-2*Y1*J
    const ny = r.redMul(v.redISub(nx)).redISub(this.y.redMul(j).redIMuln(2));

    // Z3 = 2*Z1*H
    const nz = this.z.redMul(h).redIMuln(2);

    return this.curve.jpoint(nx, ny, nz);
  }

  dbl() {
    if (this.isInfinity())
      return this;

    if (this.zOne)
      return this._affineDbl();

    if (this.curve.zeroA)
      return this._zeroDbl();

    if (this.curve.threeA)
      return this._threeDbl();

    return this._dbl();
  }

  _affineDbl() {
    // Assumes Z=1.
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-mdbl-2007-bl
    // 1M + 5S + 7A + 3*2 + 1*3 + 1*8
    // (implemented as: 1M + 5S + 8A + 2*2 + 1*3 + 1*8)

    // XX = X1^2
    const xx = this.x.redSqr();

    // YY = Y1^2
    const yy = this.y.redSqr();

    // YYYY = YY^2
    const yyyy = yy.redSqr();

    // S = 2*((X1+YY)^2-XX-YYYY)
    const s = yy.redIAdd(this.x).redSqr()
                .redISub(xx).redISub(yyyy)
                .redIMuln(2);

    // M = 3*XX+a
    const m = xx.redIMuln(3).redIAdd(this.curve.a);

    // T = M^2-2*S
    const t = m.redSqr().redISub(s).redISub(s);

    // X3 = T
    const nx = t;

    // Y3 = M*(S-T)-8*YYYY
    const ny = m.redMul(s.redISub(t)).redISub(yyyy.redIMuln(8));

    // Z3 = 2*Y1
    const nz = this.y.redMuln(2);

    return this.curve.jpoint(nx, ny, nz);
  }

  _zeroDbl() {
    // Assumes a=0.
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
    // 2M + 5S + 6A + 3*2 + 1*3 + 1*8
    // (implemented as: 2M + 5S + 7A + 2*2 + 1*3 + 1*8)

    // A = X1^2
    const a = this.x.redSqr();

    // B = Y1^2
    const b = this.y.redSqr();

    // C = B^2
    const c = b.redSqr();

    // D = 2 * ((X1 + B)^2 - A - C)
    const d = b.redIAdd(this.x).redSqr()
               .redISub(a).redISub(c)
               .redIMuln(2);

    // E = 3 * A
    const e = a.redIMuln(3);

    // F = E^2
    const f = e.redSqr();

    // X3 = F - 2 * D
    const nx = f.redISub(d).redISub(d);

    // Y3 = E * (D - X3) - 8 * C
    const ny = e.redMul(d.redISub(nx)).redISub(c.redIMuln(8));

    // Z3 = 2 * Y1 * Z1
    const nz = this.y.redMul(this.z).redIMuln(2);

    return this.curve.jpoint(nx, ny, nz);
  }

  _threeDbl() {
    // Assumes a=-3.
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
    // 3M + 5S + 8A + 1*3 + 1*4 + 2*8
    // (implemented as: 3M + 5S + 8A + 1*2 + 1*3 + 1*4 + 1*8)

    // delta = Z1^2
    const delta = this.z.redSqr();

    // gamma = Y1^2
    const gamma = this.y.redSqr();

    // beta = X1 * gamma
    const beta = this.x.redMul(gamma);

    // alpha = 3 * (X1 - delta) * (X1 + delta)
    const alpha = this.x.redSub(delta)
                        .redMul(this.x.redAdd(delta))
                        .redIMuln(3);

    // X3 = alpha^2 - 8 * beta
    const beta4 = beta.redIMuln(4);
    const beta8 = beta4.redMuln(2);

    const nx = alpha.redSqr().redISub(beta8);

    // Z3 = (Y1 + Z1)^2 - gamma - delta
    const nz = this.y.redAdd(this.z).redSqr().redISub(gamma).redISub(delta);

    // Y3 = alpha * (4 * beta - X3) - 8 * gamma^2
    const ny = alpha.redMul(beta4.redISub(nx))
                    .redISub(gamma.redSqr().redIMuln(8));

    return this.curve.jpoint(nx, ny, nz);
  }

  _dbl() {
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-1998-cmo-2
    // 3M + 6S + 4A + 1*a + 2*2 + 1*3 + 1*4 + 1*8
    // (implemented as: 3M + 6S + 5A + 1*a + 1*2 + 1*3 + 1*4 + 1*8)

    // XX = X1^2
    const xx = this.x.redSqr();

    // YY = Y1^2
    const yy = this.y.redSqr();

    // ZZ = Z1^2
    const zz = this.z.redSqr();

    // S = 4*X1*YY
    const s = this.x.redMul(yy).redIMuln(4);

    // M = 3*XX+a*ZZ^2
    const m = xx.redIMuln(3).redIAdd(this.curve.a.redMul(zz.redSqr()));

    // T = M^2-2*S
    const t = m.redSqr().redISub(s).redISub(s);

    // X3 = T
    const nx = t;

    // Y3 = M*(S-T)-8*YY^2
    const ny = m.redMul(s.redISub(t)).redISub(yy.redSqr().redIMuln(8));

    // Z3 = 2*Y1*Z1
    const nz = this.y.redMul(this.z).redIMuln(2);

    return this.curve.jpoint(nx, ny, nz);
  }

  dblp(pow) {
    assert((pow >>> 0) === pow);

    if (pow === 0)
      return this;

    if (this.isInfinity())
      return this;

    if (this.curve.zeroA || this.curve.threeA) {
      let r = this;

      for (let i = 0; i < pow; i++)
        r = r.dbl();

      return r;
    }

    return this._dblp(pow);
  }

  _dblp(pow) {
    // Modified version of:
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-1998-cmo-2
    // 1M + 2S + 1*2 + N * (5M + 4S + 4A + 1*3 + 2*2)
    // N = 1 => 6M + 6S + 4A + 1*3 + 3*2
    const {a, tinv} = this.curve;

    // Reuse results (y is always y*2).
    let x = this.x;
    let z = this.z;
    let y = this.y.redMuln(2);
    let zzzz = z.redPown(4);

    for (let i = 0; i < pow; i++) {
      // XX = X1^2
      const xx = x.redSqr();

      // YY = Y1^2
      const yy = y.redSqr();

      // M = 3*XX+a*ZZ^2
      const m = xx.redIMuln(3).redIAdd(a.redMul(zzzz));

      // S = 4*X1*YY
      const s = x.redMul(yy);

      // T = M^2-2*S
      const t = m.redSqr().redISub(s.redMuln(2));

      // X3 = T
      const nx = t;

      // Y3 = M*(S-T)-8*YY^2
      const yyyy = yy.redSqr();
      const ny = m.redMul(s.redISub(t)).redIMuln(2).redISub(yyyy);

      // Z3 = 2*Y1*Z1
      const nz = y.redMul(z);

      // Continue.
      if (i + 1 < pow)
        zzzz = zzzz.redMul(yyyy);

      x = nx;
      y = ny;
      z = nz;
    }

    return this.curve.jpoint(x, y.redMul(tinv), z);
  }

  trpl() {
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#tripling-tpl-2007-bl
    // 5M + 10S + 1*a + 15A + 1*3 + 2*4 + 1*6 + 1*8 + 1*16

    // XX = X1^2
    const xx = this.x.redSqr();

    // YY = Y1^2
    const yy = this.y.redSqr();

    // ZZ = Z1^2
    const zz = this.z.redSqr();

    // YYYY = YY^2
    const yyyy = yy.redSqr();

    // M = 3 * XX + a * ZZ^2
    const m = xx.redMuln(3);

    if (!this.zeroA)
      m.redIAdd(this.curve.a.redMul(zz.redSqr()));

    // MM = M^2
    const mm = m.redSqr();

    // E = 6 * ((X1 + YY)^2 - XX - YYYY) - MM
    const e = this.x.redAdd(yy).redSqr()
                    .redISub(xx).redISub(yyyy)
                    .redIMuln(6).redISub(mm);

    // EE = E^2
    const ee = e.redSqr();

    // T = 16*YYYY
    const t = yyyy.redIMuln(16);

    // U = (M + E)^2 - MM - EE - T
    const u = m.redIAdd(e).redSqr().redISub(mm).redISub(ee).redISub(t);

    // X3 = 4 * (X1 * EE - 4 * YY * U)
    const yyu4 = yy.redMul(u).redIMuln(4);
    const nx = this.x.redMul(ee).redISub(yyu4).redIMuln(4);

    // Y3 = 8 * Y1 * (U * (T - U) - E * EE)
    const utu = u.redMul(t.redISub(u));
    const eee = e.redMul(ee);
    const ny = this.y.redMul(utu.redISub(eee)).redIMuln(8);

    // Z3 = (Z1 + E)^2 - ZZ - EE
    const nz = e.redIAdd(this.z).redSqr().redISub(zz).redISub(ee);

    return this.curve.jpoint(nx, ny, nz);
  }

  _mul(k, initial, jacobian) {
    assert(initial == null || (initial instanceof JPoint));

    return this.curve._wnafMul(this, k, initial, jacobian);
  }

  _mulAdd(k1, p2, k2, initial, jacobian) {
    assert(p2 instanceof JPoint);
    assert(initial == null || (initial instanceof JPoint));

    return this.curve._wnafMulAdd(1, [this, p2], [k1, k2], initial, jacobian);
  }

  eq(p) {
    assert(p instanceof JPoint);

    if (this === p)
      return true;

    // x1 * z2^2 == x2 * z1^2
    const z2 = this.z.redSqr();
    const pz2 = p.z.redSqr();

    if (this.x.redMul(pz2).redISub(p.x.redMul(z2)).sign() !== 0)
      return false;

    // y1 * z2^3 == y2 * z1^3
    const z3 = z2.redMul(this.z);
    const pz3 = pz2.redMul(p.z);

    return this.y.redMul(pz3).redISub(p.y.redMul(z3)).sign() === 0;
  }

  hasQuadY() {
    return this.y.redMul(this.z).redJacobi() === 1;
  }

  eqX(x) {
    assert(x instanceof BN);

    const zs = this.z.redSqr();
    const rx = x.toRed(this.curve.red).redMul(zs);

    return this.x.cmp(rx) === 0;
  }

  eqXToP(x) {
    assert(x instanceof BN);
    assert(this.curve.maxwellTrick);

    const zs = this.z.redSqr();
    const rx = x.toRed(this.curve.red).redMul(zs);

    if (this.x.cmp(rx) === 0)
      return true;

    const xc = x.clone();
    const t = this.curve.redN.redMul(zs);

    for (;;) {
      xc.iadd(this.curve.n);

      if (xc.cmp(this.curve.p) >= 0)
        return false;

      rx.redIAdd(t);

      if (this.x.cmp(rx) === 0)
        break;
    }

    return true;
  }

  isInfinity() {
    // This code assumes that zero is always zero in red.
    return this.z.sign() === 0;
  }

  encode(compact) {
    return this.toP().encode(compact);
  }

  toJSON() {
    return this.toP().toJSON();
  }

  [custom]() {
    if (this.isInfinity())
      return '<JPoint: Infinity>';

    return '<JPoint:'
         + ' x=' + this.x.fromRed().toString(16, 2)
         + ' y=' + this.y.fromRed().toString(16, 2)
         + ' z=' + this.z.fromRed().toString(16, 2)
         + '>';
  }

  static fromJSON(curve, json) {
    return ShortPoint.fromJSON(curve, json).toJ();
  }
}

/**
 * MontCurve
 */

class MontCurve extends Curve {
  constructor(conf) {
    super('mont', conf);

    this.a = new BN(conf.a, 16).toRed(this.red);
    this.b = new BN(conf.b, 16).toRed(this.red);
    this.binv = this.b.redInvert();
    this.i4 = new BN(4).toRed(this.red).redInvert();
    this.a2 = this.a.redAdd(this.two);
    this.a24 = this.a2.redMul(this.i4);
    this.ladder = this.a2.cmp(this.a24.redMuln(4)) === 0;
  }

  decodePoint(bytes) {
    const x = this.decodeField(bytes);

    // We're supposed to ignore the hi bit
    // on montgomery points... I think. If
    // we don't, the X25519 test vectors
    // break, which is pretty convincing
    // evidence. This is a no-op for X448.
    x.setn(this.signBit, 0);

    // Note: montgomery points are meant to be
    // reduced by the prime and do not have to
    // be explicitly validated in order to do
    // the montgomery ladder (see rfc7748,
    // section 5).
    const p = this.point(x, this.one);

    assert(!p.isInfinity());

    return p;
  }

  pointFromX(x, odd) {
    assert(x instanceof BN);
    assert(odd == null);

    if (!x.red)
      x = x.toRed(this.red);

    return this.point(x, this.one);
  }

  pointFromEdwards(point) {
    assert(point instanceof EdwardsPoint);

    if (point.isInfinity())
      return this.point();

    point.normalize();

    // Edwards point.
    const {x, y, z} = point;

    // Montgomery `u`.
    let nx = null;

    if (point.curve.twisted) {
      // Birational maps:
      //   u = (1+y)/(1-y)
      //   v = sqrt(-486664)*u/x
      const lhs = z.redAdd(y);
      const rhs = z.redSub(y);

      nx = lhs.redMul(rhs.redInvert());
    } else {
      // Birational maps:
      //   u = (y-1)/(y+1)
      //   v = sqrt(156324)*u/x
      //
      // 4-isogeny maps:
      //   u = y^2/x^2
      //   v = (2 - x^2 - y^2)*y/x^3
      const lhs = y.redSqr();
      const rhs = x.redSqr();

      nx = lhs.redMul(rhs.redInvert());
    }

    // Montgomery point.
    return this.point(nx.fromRed(), this.one);
  }

  validate(point) {
    assert(point instanceof MontPoint);

    if (point.isInfinity())
      return true;

    // b*y^2 = x^3 + a*x^2 + x
    const x = point.normalize().x;
    const x2 = x.redSqr();
    const by2 = x2.redMul(x).redIAdd(this.a.redMul(x2)).redIAdd(x);
    const y2 = by2.redMul(this.binv);

    return y2.redJacobi() !== -1;
  }

  _mulAll(points, coeffs, initial, jacobian) {
    throw new Error('Not supported on Montgomery curve.');
  }

  _simpleMul(p, k, initial, jacobian) {
    throw new Error('Not supported on Montgomery curve.');
  }

  point(x, z) {
    return new MontPoint(this, x, z);
  }

  jpoint(x, y, z) {
    assert(x == null && y == null && z == null);
    return this.point();
  }

  pointFromJSON(json) {
    return MontPoint.fromJSON(this, json);
  }
}

/**
 * MontPoint
 */

class MontPoint extends Point {
  constructor(curve, x, z) {
    assert(curve instanceof MontCurve);

    super(curve, types.PROJECTIVE);

    this.x = this.curve.one;
    this.z = this.curve.zero;

    if (x != null)
      this.init(x, z);
  }

  init(x, z) {
    assert(x != null);

    this.x = BN.cast(x, 16);
    this.z = z != null ? BN.cast(z, 16) : this.curve.one;

    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);

    if (!this.z.red)
      this.z = this.z.toRed(this.curve.red);
  }

  precompute(power, rng) {
    // No-op.
    return this;
  }

  encode() {
    return this.curve.encodeField(this.getX());
  }

  isInfinity() {
    // This code assumes that zero is always zero in red.
    return this.z.sign() === 0;
  }

  dbl() {
    // https://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#doubling-dbl-1987-m-3
    // 2M + 2S + 4A + 1*a24

    // A = X1 + Z1
    const a = this.x.redAdd(this.z);

    // AA = A^2
    const aa = a.redSqr();

    // B = X1 - Z1
    const b = this.x.redSub(this.z);

    // BB = B^2
    const bb = b.redSqr();

    // C = AA - BB
    const c = aa.redSub(bb);

    // X3 = AA * BB
    const nx = aa.redMul(bb);

    // Z3 = C * (BB + A24 * C)
    const nz = c.redMul(bb.redIAdd(this.curve.a24.redMul(c)));

    return this.curve.point(nx, nz);
  }

  add() {
    throw new Error('Not supported on Montgomery curve.');
  }

  diffAdd(p, diff) {
    assert(p instanceof MontPoint);
    assert(diff instanceof MontPoint);

    // https://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#diffadd-dadd-1987-m-3
    // 4M + 2S + 6A

    // A = X2 + Z2
    const a = this.x.redAdd(this.z);

    // B = X2 - Z2
    const b = this.x.redSub(this.z);

    // C = X3 + Z3
    const c = p.x.redAdd(p.z);

    // D = X3 - Z3
    const d = p.x.redSub(p.z);

    // DA = D * A
    const da = d.redMul(a);

    // CB = C * B
    const cb = c.redMul(b);

    // X5 = Z1 * (DA + CB)^2
    const nx = diff.z.redMul(da.redAdd(cb).redSqr());

    // Z5 = X1 * (DA - CB)^2
    const nz = diff.x.redMul(da.redISub(cb).redSqr());

    return this.curve.point(nx, nz);
  }

  diffAddDbl(p, diff) {
    assert(p instanceof MontPoint);
    assert(diff instanceof MontPoint);

    if (!this.curve.ladder) {
      return [
        this.diffAdd(p, diff),
        p.dbl()
      ];
    }

    // Assumes 4*a24=a+2.
    // https://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#ladder-ladd-1987-m-3
    // 6M + 4S + 8A + 1*a24
    // Backwards to match the function name.

    // A = X2+Z2
    const a = p.x.redAdd(p.z);

    // AA = A^2
    const aa = a.redSqr();

    // B = X2-Z2
    const b = p.x.redSub(p.z);

    // BB = B^2
    const bb = b.redSqr();

    // E = AA-BB
    const e = aa.redSub(bb);

    // C = X3+Z3
    const c = this.x.redAdd(this.z);

    // D = X3-Z3
    const d = this.x.redSub(this.z);

    // DA = D*A
    const da = d.redMul(a);

    // CB = C*B
    const cb = c.redMul(b);

    // X5 = Z1*(DA+CB)^2
    const nx = diff.z.redMul(da.redAdd(cb).redSqr());

    // Z5 = X1*(DA-CB)^2
    const nz = diff.x.redMul(da.redISub(cb).redSqr());

    // X4 = AA*BB
    const dx = aa.redMul(bb);

    // Z4 = E*(BB+a24*E)
    const dz = e.redMul(bb.redIAdd(this.curve.a24.redMul(e)));

    return [
      this.curve.point(nx, nz),
      this.curve.point(dx, dz)
    ];
  }

  _mul(k, initial, jacobian) {
    assert(k instanceof BN);
    assert(!k.red);
    assert(initial == null || (initial instanceof MontPoint));
    assert(typeof jacobian === 'boolean');

    const s = this.curve.mask.reduce(k.clone());
    const bits = this.curve.p.bitLength();

    let a = this;
    let b = initial || this.curve.point();

    // Montgomery ladder (not constant time!).
    // https://tools.ietf.org/html/rfc7748#section-5
    for (let i = bits - 1; i >= 0; i--) {
      if (s.utestn(i))
        [b, a] = b.diffAddDbl(a, this);
      else
        [a, b] = a.diffAddDbl(b, this);
    }

    return b;
  }

  _mulBlind(k, rng = null, jacobian) {
    // Can't do this due to the clamping.
    throw new Error('Not supported on Montgomery curve.');
  }

  _mulAdd(k1, p2, k2, initial, jacobian) {
    throw new Error('Not supported on Montgomery curve.');
  }

  eq(other) {
    assert(other instanceof MontPoint);

    if (this === other)
      return true;

    if (this.isInfinity())
      return other.isInfinity();

    if (other.isInfinity())
      return false;

    return this.getX().cmp(other.getX()) === 0;
  }

  normalize() {
    if (this.isInfinity())
      return this;

    // https://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#scaling-scale
    // 1I + 1M

    // X3 = X1/Z1
    this.x = this.x.redMul(this.z.redInvert());

    // Z3 = 1
    this.z = this.curve.one;

    return this;
  }

  getX() {
    if (this.isInfinity())
      throw new Error('Invalid point.');

    this.normalize();

    return this.x.fromRed();
  }

  getY() {
    if (this.isInfinity())
      throw new Error('Invalid point.');

    // b*y^2 = x^3 + a*x^2 + x
    const x = this.normalize().x;
    const x2 = x.redSqr();
    const by2 = x2.redMul(x).redIAdd(this.curve.a.redMul(x2)).redIAdd(x);
    const y2 = by2.redMul(this.curve.binv);
    const y = y2.redSqrt();

    // Note: the `v` values in RFC 7748 are negated.
    // This tends not to matter if we are squaring.
    return y.fromRed();
  }

  mixedAdd(p) {
    throw new Error('Not supported on Montgomery curve.');
  }

  toP() {
    return this.normalize();
  }

  toJ() {
    return this.curve.point(this.x, this.z);
  }

  toJSON() {
    return [this.getX()];
  }

  [custom]() {
    if (this.isInfinity())
      return '<MontPoint: Infinity>';

    return '<MontPoint:'
        + ' x=' + this.x.fromRed().toString(16, 2)
        + ' z=' + this.z.fromRed().toString(16, 2)
        + '>';
  }

  static fromJSON(curve, json) {
    assert(curve instanceof MontCurve);
    assert(Array.isArray(json));

    const [x, z] = json;

    return curve.point(x, z || curve.one);
  }
}

/**
 * EdwardsCurve
 */

class EdwardsCurve extends Curve {
  constructor(conf) {
    super('edwards', conf);

    this.a = new BN(conf.a, 16).toRed(this.red);
    this.c = new BN(conf.c, 16).toRed(this.red);
    this.d = new BN(conf.d, 16).toRed(this.red);

    this.c2 = this.c.redSqr();
    this.cc2 = this.c2.redMuln(2);
    this.dd = this.d.redMuln(2);

    this.mOneA = this.a.cmp(this.one.redNeg()) === 0;
    this.oneC = this.c.cmp(this.one) === 0;

    assert(!this.twisted || this.c.cmp(this.one) === 0);
    assert(!this.twisted || this.a.cmp(this.one) !== 0);
    assert(!this.extended || this.a.cmp(this.one.redNeg()) === 0);
  }

  _mulA(num) {
    assert(num instanceof BN);

    if (this.mOneA)
      return num.redNeg();

    return this.a.redMul(num);
  }

  _mulC(num) {
    assert(num instanceof BN);

    if (this.oneC)
      return num;

    return this.c.redMul(num);
  }

  jpoint(x, y, z) {
    assert(x == null && y == null && z == null);
    return this.point();
  }

  pointFromX(x, odd) {
    assert(x instanceof BN);

    if (!x.red)
      x = x.toRed(this.red);

    // y^2 = (c^2 - a * x^2) / (1 - (c^2 * d * x^2))
    const x2 = x.redSqr();
    const lhs = this.c2.redSub(this.a.redMul(x2));
    const rhs = this.one.redSub(this.c2.redMul(this.d).redMul(x2));
    const y2 = lhs.redMul(rhs.redInvert());
    const y = y2.redSqrt();

    if (y.redIsOdd() !== Boolean(odd))
      y.redINeg();

    return this.point(x, y);
  }

  pointFromY(y, odd) {
    assert(y instanceof BN);

    if (!y.red)
      y = y.toRed(this.red);

    // x^2 = (y^2 - c^2) / (c^2 * d * y^2 - a)
    const y2 = y.redSqr();
    const lhs = y2.redSub(this.c2);
    const rhs = y2.redMul(this.d).redMul(this.c2).redISub(this.a);
    const x2 = lhs.redMul(rhs.redInvert());

    if (x2.sign() === 0) {
      if (odd)
        throw new Error('Invalid point.');
      return this.point(this.zero, y);
    }

    const x = x2.redSqrt();

    if (x.redIsOdd() !== Boolean(odd))
      x.redINeg();

    return this.point(x, y);
  }

  pointFromMont(point, odd) {
    assert(point instanceof MontPoint);

    if (point.isInfinity()) {
      if (odd)
        throw new Error('Invalid point.');
      return this.point();
    }

    point.normalize();

    // Montgomery point.
    const {x, z} = point;

    // Edwards `y`.
    let ny = null;

    if (this.twisted) {
      // Birational maps:
      //   x = sqrt(-486664)*u/v
      //   y = (u-1)/(u+1)
      const lhs = x.redSub(z);
      const rhs = x.redAdd(z);

      ny = lhs.redMul(rhs.redInvert());
    } else {
      // Birational maps:
      //   x = sqrt(156324)*u/v
      //   y = (1+u)/(1-u)
      //
      // 4-isogeny maps:
      //   x = 4*v*(u^2 - 1)/(u^4 - 2*u^2 + 4*v^2 + 1)
      //   y = -(u^5 - 2*u^3 - 4*u*v^2 + u)/
      //        (u^5 - 2*u^2*v^2 - 2*u^3 - 2*v^2 + u)
      throw new Error('Not implemented.');
    }

    // Edwards point.
    return this.pointFromY(ny.fromRed(), odd);
  }

  validate(point) {
    assert(point instanceof EdwardsPoint);

    if (point.isInfinity())
      return true;

    // a * x^2 + y^2 = c^2 * (1 + d * x^2 * y^2)
    point.normalize();

    const x2 = point.x.redSqr();
    const y2 = point.y.redSqr();
    const lhs = x2.redMul(this.a).redIAdd(y2);
    const rhs = this.c2.redMul(this.one.redAdd(this.d.redMul(x2).redMul(y2)));

    return lhs.cmp(rhs) === 0;
  }

  decodePoint(bytes) {
    const y = this.decodeField(bytes);
    const xIsOdd = y.testn(this.signBit);

    y.setn(this.signBit, 0);

    if (y.cmp(this.p) >= 0)
      throw new Error('Invalid point.');

    const p = this.pointFromY(y, xIsOdd);

    // Note that it _is_ possible to serialize
    // points at infinity for edwards curves.
    if (p.isInfinity())
      throw new Error('Invalid point.');

    return p;
  }

  _mulAll(points, coeffs, initial, jacobian) {
    return this._wnafMulAdd(1, points, coeffs, initial, jacobian);
  }

  pointFromJSON(json) {
    return EdwardsPoint.fromJSON(this, json);
  }

  point(x, y, z, t) {
    return new EdwardsPoint(this, x, y, z, t);
  }
}

/**
 * EdwardsPoint
 */

class EdwardsPoint extends Point {
  constructor(curve, x, y, z, t) {
    assert(curve instanceof EdwardsCurve);

    super(curve, types.PROJECTIVE);

    this.x = this.curve.zero;
    this.y = this.curve.one;
    this.z = this.curve.one;
    this.t = this.curve.zero;
    this.zOne = true;

    if (x != null)
      this.init(x, y, z, t);
  }

  init(x, y, z, t) {
    assert(x != null);
    assert(y != null);

    this.x = BN.cast(x, 16);
    this.y = BN.cast(y, 16);
    this.z = z != null ? BN.cast(z, 16) : this.curve.one;
    this.t = t != null ? BN.cast(t, 16) : null;

    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);

    if (!this.y.red)
      this.y = this.y.toRed(this.curve.red);

    if (!this.z.red)
      this.z = this.z.toRed(this.curve.red);

    if (this.t && !this.t.red)
      this.t = this.t.toRed(this.curve.red);

    this.zOne = this.z.eq(this.curve.one);

    // Use extended coordinates.
    if (this.curve.extended && !this.t) {
      this.t = this.x.redMul(this.y);
      if (!this.zOne)
        this.t = this.t.redMul(this.z.redInvert());
    }
  }

  encode() {
    if (this.isInfinity())
      throw new Error('Invalid point.');

    const y = this.getY();

    y.setn(this.curve.signBit, this.x.redIsOdd());

    return this.curve.encodeField(y);
  }

  isInfinity() {
    // This code assumes that zero is always zero in red.
    if (this.x.sign() !== 0)
      return false;

    if (this.y.cmp(this.z) === 0)
      return true;

    if (this.zOne && this.y.cmp(this.curve.c) === 0)
      return true;

    return false;
  }

  _extDbl() {
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#doubling-dbl-2008-hwcd
    // 4M + 4S + 6A + 1*a + 1*2

    // A = X1^2
    const a = this.x.redSqr();

    // B = Y1^2
    const b = this.y.redSqr();

    // C = 2 * Z1^2
    const c = this.zOne ? this.curve.two : this.z.redSqr().redIMuln(2);

    // D = a * A
    const d = this.curve._mulA(a);

    // E = (X1 + Y1)^2 - A - B
    const e = this.x.redAdd(this.y).redSqr().redISub(a).redISub(b);

    // G = D + B
    const g = d.redAdd(b);

    // F = G - C
    const f = g.redSub(c);

    // H = D - B
    const h = d.redISub(b);

    // X3 = E * F
    const nx = e.redMul(f);

    // Y3 = G * H
    const ny = g.redMul(h);

    // T3 = E * H
    const nt = e.redMul(h);

    // Z3 = F * G
    const nz = f.redMul(g);

    return this.curve.point(nx, ny, nz, nt);
  }

  _projDbl() {
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#doubling-dbl-2008-bbjlp
    // 2M + 4S + 7A + 1*a + 1*2
    // 3M + 4S + 6A + 1*a + 1*2
    //
    // https://hyperelliptic.org/EFD/g1p/auto-edwards-projective.html#doubling-dbl-2007-bl
    // 3M + 4S + 5A + 3*c + 1*2
    //
    // https://hyperelliptic.org/EFD/g1p/auto-edwards-projective.html#doubling-mdbl-2007-bl
    // 3M + 3S + 5A + 2*c

    // B = (X1 + Y1)^2
    const b = this.x.redAdd(this.y).redSqr();

    // C = X1^2
    const c = this.x.redSqr();

    // D = Y1^2
    const d = this.y.redSqr();

    let nx, ny, nz;

    if (this.curve.twisted) {
      // E = a * C
      const e = this.curve._mulA(c);

      // F = E + D
      const f = e.redAdd(d);

      if (this.zOne) {
        // X3 = (B - C - D) * (F - 2)
        nx = b.redSub(c).redISub(d).redMul(f.redSub(this.curve.two));

        // Y3 = F * (E - D)
        ny = f.redMul(e.redISub(d));

        // Z3 = F^2 - 2 * F
        nz = f.redSqr().redISub(f).redISub(f);
      } else {
        // H = Z1^2
        const h = this.z.redSqr();

        // J = F - 2 * H
        const j = f.redSub(h).redISub(h);

        // X3 = (B-C-D)*J
        nx = b.redISub(c).redISub(d).redMul(j);

        // Y3 = F * (E - D)
        ny = f.redMul(e.redISub(d));

        // Z3 = F * J
        nz = f.redMul(j);
      }
    } else {
      // E = C + D
      const e = c.redAdd(d);

      let j;

      if (this.zOne) {
        // J = E - 2 * c * c
        j = e.redSub(this.curve.cc2);
      } else {
        // H = (c * Z1)^2
        const h = this.curve._mulC(this.z).redSqr();

        // J = E - 2 * H
        j = e.redSub(h).redISub(h);
      }

      // X3 = c * (B - E) * J
      nx = this.curve._mulC(b.redISub(e)).redMul(j);

      // Y3 = c * E * (C - D)
      ny = this.curve._mulC(e).redMul(c.redISub(d));

      // Z3 = E * J
      nz = e.redMul(j);
    }

    return this.curve.point(nx, ny, nz);
  }

  dbl() {
    if (this.isInfinity())
      return this;

    // Double in extended coordinates
    if (this.curve.extended)
      return this._extDbl();

    return this._projDbl();
  }

  _extAdd(p) {
    assert(p instanceof EdwardsPoint);

    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-3
    // 8M + 8A + 1*k + 1*2
    //
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-madd-2008-hwcd-3
    // 7M + 8A + 1*k + 1*2

    // A = (Y1 - X1) * (Y2 - X2)
    const a = this.y.redSub(this.x).redMul(p.y.redSub(p.x));

    // B = (Y1 + X1) * (Y2 + X2)
    const b = this.y.redAdd(this.x).redMul(p.y.redAdd(p.x));

    // C = T1 * k * T2
    const c = this.t.redMul(this.curve.dd).redMul(p.t);

    // D = Z1 * 2 * Z2
    const d = this.zOne ? p.z.redMuln(2) : this.z.redMul(p.z).redIMuln(2);

    // E = B - A
    const e = b.redSub(a);

    // F = D - C
    const f = d.redSub(c);

    // G = D + C
    const g = d.redIAdd(c);

    // H = B + A
    const h = b.redIAdd(a);

    // X3 = E * F
    const nx = e.redMul(f);

    // Y3 = G * H
    const ny = g.redMul(h);

    // T3 = E * H
    const nt = e.redMul(h);

    // Z3 = F * G
    const nz = f.redMul(g);

    return this.curve.point(nx, ny, nz, nt);
  }

  _projAdd(p) {
    assert(p instanceof EdwardsPoint);

    // https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#addition-add-2008-bbjlp
    // 10M + 1S + 7A + 1*a + 1*d
    //
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#addition-madd-2008-bbjlp
    // 9M + 1S + 7A + 1*a + 1*d
    //
    // https://hyperelliptic.org/EFD/g1p/auto-edwards-projective.html#addition-add-2007-bl
    // 10M + 1S + 7A + 1*c + 1*d

    // A = Z1 * Z2
    const a = this.zOne ? p.z : this.z.redMul(p.z);

    // B = A^2
    const b = a.redSqr();

    // C = X1 * X2
    const c = this.x.redMul(p.x);

    // D = Y1 * Y2
    const d = this.y.redMul(p.y);

    // E = d * C * D
    const e = this.curve.d.redMul(c).redMul(d);

    // F = B - E
    const f = b.redSub(e);

    // G = B + E
    const g = b.redIAdd(e);

    // X3 = A * F * ((X1 + Y1) * (X2 + Y2) - C - D)
    const nx = this.x.redAdd(this.y)
                     .redMul(p.x.redAdd(p.y))
                     .redISub(c)
                     .redISub(d)
                     .redMul(a)
                     .redMul(f);

    let ny, nz;

    if (this.curve.twisted) {
      // Y3 = A * G * (D - a * C)
      ny = a.redMul(g).redMul(d.redISub(this.curve._mulA(c)));

      // Z3 = F * G
      nz = f.redMul(g);
    } else {
      // Y3 = A * G * (D - C)
      ny = a.redMul(g).redMul(d.redISub(c));

      // Z3 = c * F * G
      nz = this.curve._mulC(f).redMul(g);
    }

    return this.curve.point(nx, ny, nz);
  }

  add(p) {
    assert(p instanceof EdwardsPoint);

    if (this.isInfinity())
      return p;

    if (p.isInfinity())
      return this;

    if (this.curve.extended)
      return this._extAdd(p);

    return this._projAdd(p);
  }

  _mul(k, initial, jacobian) {
    assert(initial == null || (initial instanceof EdwardsPoint));

    if (this._hasDoubles(k))
      return this.curve._fixedNafMul(this, k, initial, jacobian);

    return this.curve._wnafMul(this, k, initial, jacobian);
  }

  _mulAdd(k1, p2, k2, initial, jacobian) {
    assert(p2 instanceof EdwardsPoint);
    assert(initial == null || (initial instanceof EdwardsPoint));

    return this.curve._wnafMulAdd(1, [this, p2], [k1, k2], initial, jacobian);
  }

  normalize() {
    if (this.zOne)
      return this;

    // https://hyperelliptic.org/EFD/g1p/auto-edwards-projective.html#scaling-z
    // 1I + 2M (+ 1M if extended)

    // A = 1/Z1
    const a = this.z.redInvert();

    // X3 = X1*A
    this.x = this.x.redMul(a);

    // Y3 = Y1*A
    this.y = this.y.redMul(a);

    // T3 = T1*A
    if (this.t)
      this.t = this.t.redMul(a);

    // Z3 = 1
    this.z = this.curve.one;
    this.zOne = true;

    return this;
  }

  neg() {
    return this.curve.point(this.x.redNeg(),
                            this.y,
                            this.z,
                            this.t && this.t.redNeg());
  }

  getX() {
    this.normalize();
    return this.x.fromRed();
  }

  getY() {
    this.normalize();
    return this.y.fromRed();
  }

  eq(other) {
    assert(other instanceof EdwardsPoint);

    if (this === other)
      return true;

    return this.getX().cmp(other.getX()) === 0
        && this.getY().cmp(other.getY()) === 0;
  }

  hasQuadY() {
    return this.y.redMul(this.z).redJacobi() === 1;
  }

  eqX(x) {
    assert(x instanceof BN);

    const rx = x.toRed(this.curve.red).redMul(this.z);

    return this.x.cmp(rx) === 0;
  }

  eqXToP(x) {
    assert(x instanceof BN);
    assert(this.curve.maxwellTrick);

    const rx = x.toRed(this.curve.red).redMul(this.z);

    if (this.x.cmp(rx) === 0)
      return true;

    const xc = x.clone();
    const t = this.curve.redN.redMul(this.z);

    for (;;) {
      xc.iadd(this.curve.n);

      if (xc.cmp(this.curve.p) >= 0)
        return false;

      rx.redIAdd(t);

      if (this.x.cmp(rx) === 0)
        break;
    }

    return true;
  }

  mixedAdd(p) {
    return this.add(p);
  }

  toP() {
    return this.normalize();
  }

  toJ() {
    return this.curve.point(this.x, this.y, this.z, this.t);
  }

  toJSON() {
    const x = this.getX();
    const y = this.getY();

    if (!this.precomputed)
      return [x, y];

    return [x, y, {
      naf: this.precomputed.naf && {
        wnd: this.precomputed.naf.wnd,
        points: this.precomputed.naf.points.slice(1)
      },
      doubles: this.precomputed.doubles && {
        step: this.precomputed.doubles.step,
        points: this.precomputed.doubles.points.slice(1)
      }
    }];
  }

  [custom]() {
    if (this.isInfinity())
      return '<EdwardsPoint: Infinity>';

    return '<EdwardsPoint:'
        + ' x=' + this.x.fromRed().toString(16, 2)
        + ' y=' + this.y.fromRed().toString(16, 2)
        + ' z=' + this.z.fromRed().toString(16, 2)
        + '>';
  }

  static fromJSON(curve, json) {
    assert(curve instanceof EdwardsCurve);
    assert(Array.isArray(json));

    const [x, y, pre] = json;
    const point = curve.point(x, y);

    if (!pre)
      return point;

    const {naf, doubles} = pre;
    const convert = ([x, y]) => curve.point(x, y);

    point.precomputed = {
      naf: naf && {
        wnd: naf.wnd,
        points: [point, ...naf.points.map(convert)]
      },
      doubles: doubles && {
        step: doubles.step,
        points: [point, ...doubles.points.map(convert)]
      },
      beta: null,
      blinding: null
    };

    return point;
  }
}

/**
 * P192
 */

class P192 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'P192',
      ossl: 'prime192v1',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prefix: null,
      context: false,
      seed: '3045ae6f c8422f64 ed579528 d38120ea'
          + 'e12196d5',
      prime: 'p192',
      p: 'ffffffff ffffffff ffffffff fffffffe'
       + 'ffffffff ffffffff',
      a: 'ffffffff ffffffff ffffffff fffffffe'
       + 'ffffffff fffffffc',
      b: '64210519 e59c80e7 0fa7e9ab 72243049'
       + 'feb8deec c146b9b1',
      n: 'ffffffff ffffffff ffffffff 99def836'
       + '146bc9b1 b4d22831',
      h: '1',
      g: [
        ['188da80e b03090f6 7cbf20eb 43a18800',
         'f4ff0afd 82ff1012'].join(''),
        ['07192b95 ffc8da78 631011ed 6b24cdd5',
         '73f977a1 1e794811'].join(''),
        pre
      ]
    });
  }
}

/**
 * P224
 */

class P224 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'P224',
      ossl: 'secp224r1',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prefix: null,
      context: false,
      seed: 'bd713447 99d5c7fc dc45b59f a3b9ab8f'
          + '6a948bc5',
      prime: 'p224',
      p: 'ffffffff ffffffff ffffffff ffffffff'
       + '00000000 00000000 00000001',
      a: 'ffffffff ffffffff ffffffff fffffffe'
       + 'ffffffff ffffffff fffffffe',
      b: 'b4050a85 0c04b3ab f5413256 5044b0b7'
       + 'd7bfd8ba 270b3943 2355ffb4',
      n: 'ffffffff ffffffff ffffffff ffff16a2'
       + 'e0b8f03e 13dd2945 5c5c2a3d',
      h: '1',
      g: [
        ['b70e0cbd 6bb4bf7f 321390b9 4a03c1d3',
         '56c21122 343280d6 115c1d21'].join(''),
        ['bd376388 b5f723fb 4c22dfe6 cd4375a0',
         '5a074764 44d58199 85007e34'].join(''),
        pre
      ]
    });
  }
}

/**
 * P256
 */

class P256 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'P256',
      ossl: 'prime256v1',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prefix: null,
      context: false,
      seed: 'c49d3608 86e70493 6a6678e1 139d26b7'
          + '819f7e90',
      prime: null,
      p: 'ffffffff 00000001 00000000 00000000'
       + '00000000 ffffffff ffffffff ffffffff',
      a: 'ffffffff 00000001 00000000 00000000'
       + '00000000 ffffffff ffffffff fffffffc',
      b: '5ac635d8 aa3a93e7 b3ebbd55 769886bc'
       + '651d06b0 cc53b0f6 3bce3c3e 27d2604b',
      n: 'ffffffff 00000000 ffffffff ffffffff'
       + 'bce6faad a7179e84 f3b9cac2 fc632551',
      h: '1',
      g: [
        ['6b17d1f2 e12c4247 f8bce6e5 63a440f2',
         '77037d81 2deb33a0 f4a13945 d898c296'].join(''),
        ['4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16',
         '2bce3357 6b315ece cbb64068 37bf51f5'].join(''),
        pre
      ]
    });
  }
}

/**
 * P384
 */

class P384 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'P384',
      ossl: 'secp384r1',
      type: 'short',
      endian: 'be',
      hash: 'SHA384',
      prefix: null,
      context: false,
      seed: 'a335926a a319a27a 1d00896a 6773a482'
          + '7acdac73',
      prime: null,
      p: 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff fffffffe'
       + 'ffffffff 00000000 00000000 ffffffff',
      a: 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff fffffffe'
       + 'ffffffff 00000000 00000000 fffffffc',
      b: 'b3312fa7 e23ee7e4 988e056b e3f82d19'
       + '181d9c6e fe814112 0314088f 5013875a'
       + 'c656398d 8a2ed19d 2a85c8ed d3ec2aef',
      n: 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff c7634d81 f4372ddf'
       + '581a0db2 48b0a77a ecec196a ccc52973',
      h: '1',
      g: [
        ['aa87ca22 be8b0537 8eb1c71e f320ad74',
         '6e1d3b62 8ba79b98 59f741e0 82542a38',
         '5502f25d bf55296c 3a545e38 72760ab7'].join(''),
        ['3617de4a 96262c6f 5d9e98bf 9292dc29',
         'f8f41dbd 289a147c e9da3113 b5f0b8c0',
         '0a60b1ce 1d7e819d 7a431d7c 90ea0e5f'].join(''),
        pre
      ]
    });
  }
}

/**
 * P521
 */

class P521 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'P521',
      ossl: 'secp521r1',
      type: 'short',
      endian: 'be',
      hash: 'SHA512',
      prefix: null,
      context: false,
      seed: 'd09e8800 291cb853 96cc6717 393284aa'
          + 'a0da64ba',
      prime: 'p521',
      p: '000001ff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff',
      a: '000001ff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'fffffffc',
      b: '00000051 953eb961 8e1c9a1f 929a21a0'
       + 'b68540ee a2da725b 99b315f3 b8b48991'
       + '8ef109e1 56193951 ec7e937b 1652c0bd'
       + '3bb1bf07 3573df88 3d2c34f1 ef451fd4'
       + '6b503f00',
      n: '000001ff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'fffffffa 51868783 bf2f966b 7fcc0148'
       + 'f709a5d0 3bb5c9b8 899c47ae bb6fb71e'
       + '91386409',
      h: '1',
      g: [
        ['000000c6 858e06b7 0404e9cd 9e3ecb66',
         '2395b442 9c648139 053fb521 f828af60',
         '6b4d3dba a14b5e77 efe75928 fe1dc127',
         'a2ffa8de 3348b3c1 856a429b f97e7e31',
         'c2e5bd66'].join(''),
        ['00000118 39296a78 9a3bc004 5c8a5fb4',
         '2c7d1bd9 98f54449 579b4468 17afbd17',
         '273e662c 97ee7299 5ef42640 c550b901',
         '3fad0761 353c7086 a272c240 88be9476',
         '9fd16650'].join(''),
        pre
      ]
    });
  }
}

/**
 * SECP256K1
 */

class SECP256K1 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'SECP256K1',
      ossl: 'secp256k1',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prefix: null,
      context: false,
      prime: 'k256',
      p: 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff fffffffe fffffc2f',
      a: '0',
      b: '7',
      n: 'ffffffff ffffffff ffffffff fffffffe'
       + 'baaedce6 af48a03b bfd25e8c d0364141',
      h: '1',
      g: [
        ['79be667e f9dcbbac 55a06295 ce870b07',
         '029bfcdb 2dce28d9 59f2815b 16f81798'].join(''),
        ['483ada77 26a3c465 5da4fbfc 0e1108a8',
         'fd17b448 a6855419 9c47d08f fb10d4b8'].join(''),
        pre
      ],
      // Precomputed endomorphism.
      beta: '7ae96a2b 657c0710 6e64479e ac3434e9'
          + '9cf04975 12f58995 c1396c28 719501ee',
      lambda: '5363ad4c c05c30e0 a5261c02 8812645a'
            + '122e22ea 20816678 df02967c 1b23bd72',
      basis: [
        {
          a: '3086d221a7d46bcde86c90e49284eb15',
          b: '-e4437ed6010e88286f547fa90abfe4c3'
        },
        {
          a: '114ca50f7a8e2f3f657c1108d9d44cfd8',
          b: '3086d221a7d46bcde86c90e49284eb15'
        }
      ]
    });
  }
}

/**
 * X25519
 */

class X25519 extends MontCurve {
  constructor() {
    super({
      id: 'X25519',
      ossl: 'X25519',
      type: 'mont',
      endian: 'le',
      hash: 'SHA512',
      prefix: null,
      context: false,
      prime: 'p25519',
      // 2^255 - 19
      p: '7fffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffed',
      a: '76d06',
      b: '1',
      n: '10000000 00000000 00000000 00000000'
       + '14def9de a2f79cd6 5812631a 5cf5d3ed',
      h: '8',
      g: [
        '9'
      ]
    });
  }
}

/**
 * ED25519
 */

class ED25519 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'ED25519',
      ossl: 'ED25519',
      type: 'edwards',
      endian: 'le',
      hash: 'SHA512',
      prefix: 'SigEd25519 no Ed25519 collisions',
      context: false,
      prime: 'p25519',
      // 2^255 - 19
      p: '7fffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffed',
      a: '-1',
      c: '1',
      // (-121665 * 121666^-1) mod p
      d: '52036cee 2b6ffe73 8cc74079 7779e898'
       + '00700a4d 4141d8ab 75eb4dca 135978a3',
      n: '10000000 00000000 00000000 00000000'
       + '14def9de a2f79cd6 5812631a 5cf5d3ed',
      h: '8', // c=3
      g: [
        ['216936d3 cd6e53fe c0a4e231 fdd6dc5c',
         '692cc760 9525a7b2 c9562d60 8f25d51a'].join(''),
        // 4/5
        ['66666666 66666666 66666666 66666666',
         '66666666 66666666 66666666 66666658'].join(''),
        pre
      ]
    });
  }
}

/**
 * X448
 */

class X448 extends MontCurve {
  constructor() {
    super({
      id: 'X448',
      ossl: 'X448',
      type: 'mont',
      endian: 'le',
      hash: 'SHAKE256',
      prefix: null,
      context: false,
      prime: 'p448',
      // 2^448 - 2^224 - 1
      p: 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff fffffffe ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff',
      a: '262a6',
      b: '1',
      n: '3fffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff 7cca23e9'
       + 'c44edb49 aed63690 216cc272 8dc58f55'
       + '2378c292 ab5844f3',
      h: '4',
      g: [
        '5'
      ]
    });
  }
}

/**
 * ED448
 */

class ED448 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'ED448',
      ossl: 'ED448',
      type: 'edwards',
      endian: 'le',
      hash: 'SHAKE256',
      prefix: 'SigEd448',
      context: true,
      prime: 'p448',
      // 2^448 - 2^224 - 1
      p: 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff fffffffe ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff',
      a: '1',
      c: '1',
      // -39081 mod p
      d: 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff fffffffe ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffff6756',
      n: '3fffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff 7cca23e9'
       + 'c44edb49 aed63690 216cc272 8dc58f55'
       + '2378c292 ab5844f3',
      h: '4', // c=2
      g: [
        ['4f1970c6 6bed0ded 221d15a6 22bf36da',
         '9e146570 470f1767 ea6de324 a3d3a464',
         '12ae1af7 2ab66511 433b80e1 8b00938e',
         '2626a82b c70cc05e'].join(''),
        ['693f4671 6eb6bc24 88762037 56c9c762',
         '4bea7373 6ca39840 87789c1e 05a0c2d7',
         '3ad3ff1c e67c39c4 fdbd132c 4ed7c8ad',
         '9808795b f230fa14'].join(''),
        pre
      ]
    });
  }
}

/**
 * BRAINPOOLP256
 */

class BRAINPOOLP256 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'BRAINPOOLP256',
      ossl: 'brainpoolP256r1',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prefix: null,
      context: false,
      prime: null,
      p: 'a9fb57db a1eea9bc 3e660a90 9d838d72'
       + '6e3bf623 d5262028 2013481d 1f6e5377',
      a: '7d5a0975 fc2c3057 eef67530 417affe7'
       + 'fb8055c1 26dc5c6c e94a4b44 f330b5d9',
      b: '26dc5c6c e94a4b44 f330b5d9 bbd77cbf'
       + '95841629 5cf7e1ce 6bccdc18 ff8c07b6',
      n: 'a9fb57db a1eea9bc 3e660a90 9d838d71'
       + '8c397aa3 b561a6f7 901e0e82 974856a7',
      h: '1',
      g: [
        ['8bd2aeb9 cb7e57cb 2c4b482f fc81b7af',
         'b9de27e1 e3bd23c2 3a4453bd 9ace3262'].join(''),
        ['547ef835 c3dac4fd 97f8461a 14611dc9',
         'c2774513 2ded8e54 5c1d54c7 2f046997'].join(''),
        pre
      ]
    });
  }
}

/**
 * BRAINPOOLP384
 */

class BRAINPOOLP384 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'BRAINPOOLP384',
      ossl: 'brainpoolP384r1',
      type: 'short',
      endian: 'be',
      hash: 'SHA384',
      prefix: null,
      context: false,
      prime: null,
      p: '8cb91e82 a3386d28 0f5d6f7e 50e641df'
       + '152f7109 ed5456b4 12b1da19 7fb71123'
       + 'acd3a729 901d1a71 87470013 3107ec53',
      a: '7bc382c6 3d8c150c 3c72080a ce05afa0'
       + 'c2bea28e 4fb22787 139165ef ba91f90f'
       + '8aa5814a 503ad4eb 04a8c7dd 22ce2826',
      b: '04a8c7dd 22ce2826 8b39b554 16f0447c'
       + '2fb77de1 07dcd2a6 2e880ea5 3eeb62d5'
       + '7cb43902 95dbc994 3ab78696 fa504c11',
      n: '8cb91e82 a3386d28 0f5d6f7e 50e641df'
       + '152f7109 ed5456b3 1f166e6c ac0425a7'
       + 'cf3ab6af 6b7fc310 3b883202 e9046565',
      h: '1',
      g: [
        ['1d1c64f0 68cf45ff a2a63a81 b7c13f6b',
         '8847a3e7 7ef14fe3 db7fcafe 0cbd10e8',
         'e826e034 36d646aa ef87b2e2 47d4af1e'].join(''),
        ['8abe1d75 20f9c2a4 5cb1eb8e 95cfd552',
         '62b70b29 feec5864 e19c054f f9912928',
         '0e464621 77918111 42820341 263c5315'].join(''),
        pre
      ]
    });
  }
}

/**
 * BRAINPOOLP512
 */

class BRAINPOOLP512 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'BRAINPOOLP512',
      ossl: 'brainpoolP512r1',
      type: 'short',
      endian: 'be',
      hash: 'SHA512',
      prefix: null,
      context: false,
      prime: null,
      p: 'aadd9db8 dbe9c48b 3fd4e6ae 33c9fc07'
       + 'cb308db3 b3c9d20e d6639cca 70330871'
       + '7d4d9b00 9bc66842 aecda12a e6a380e6'
       + '2881ff2f 2d82c685 28aa6056 583a48f3',
      a: '7830a331 8b603b89 e2327145 ac234cc5'
       + '94cbdd8d 3df91610 a83441ca ea9863bc'
       + '2ded5d5a a8253aa1 0a2ef1c9 8b9ac8b5'
       + '7f1117a7 2bf2c7b9 e7c1ac4d 77fc94ca',
      b: '3df91610 a83441ca ea9863bc 2ded5d5a'
       + 'a8253aa1 0a2ef1c9 8b9ac8b5 7f1117a7'
       + '2bf2c7b9 e7c1ac4d 77fc94ca dc083e67'
       + '984050b7 5ebae5dd 2809bd63 8016f723',
      n: 'aadd9db8 dbe9c48b 3fd4e6ae 33c9fc07'
       + 'cb308db3 b3c9d20e d6639cca 70330870'
       + '553e5c41 4ca92619 41866119 7fac1047'
       + '1db1d381 085ddadd b5879682 9ca90069',
      h: '1',
      g: [
        ['81aee4bd d82ed964 5a21322e 9c4c6a93',
         '85ed9f70 b5d916c1 b43b62ee f4d0098e',
         'ff3b1f78 e2d0d48d 50d1687b 93b97d5f',
         '7c6d5047 406a5e68 8b352209 bcb9f822'].join(''),
        ['7dde385d 566332ec c0eabfa9 cf7822fd',
         'f209f700 24a57b1a a000c55b 881f8111',
         'b2dcde49 4a5f485e 5bca4bd8 8a2763ae',
         'd1ca2b2f a8f05406 78cd1e0f 3ad80892'].join(''),
        pre
      ]
    });
  }
}

/*
 * Helpers
 */

function assert(val, msg) {
  if (!val)
    throw new Error(msg || 'Assertion failed');
}

function getNAF(c, w, size) {
  assert(c instanceof BN);
  assert(!c.red);
  assert((w >>> 0) === w);
  assert((size >>> 0) === size);

  const naf = new Array(size);
  const ws = 1 << (w + 1);
  const k = c.abs();
  const s = c.sign() | 1;

  let i = 0;

  while (k.cmpn(1) >= 0) {
    let z = 0;

    if (k.isOdd()) {
      const mod = k.andln(ws - 1);

      if (mod > (ws >> 1) - 1)
        z = (ws >> 1) - mod;
      else
        z = mod;

      k.isubn(z);
    }

    naf[i++] = z * s;

    // Optimization, shift by word if possible.
    const shift = (k.sign() !== 0 && k.andln(ws - 1) === 0) ? (w + 1) : 1;

    for (let j = 1; j < shift; j++)
      naf[i++] = 0;

    k.iushrn(shift);
  }

  assert(i <= size);

  for (; i < size; i++)
    naf[i] = 0;

  return naf;
}

function getJSF(c1, c2, size) {
  assert(c1 instanceof BN);
  assert(c2 instanceof BN);
  assert(!c1.red);
  assert(!c2.red);
  assert((size >>> 0) === size);

  const jsf = [new Array(size), new Array(size)];
  const k1 = c1.abs();
  const k2 = c2.abs();
  const s1 = c1.sign() | 1;
  const s2 = c2.sign() | 1;

  let i = 0;
  let d1 = 0;
  let d2 = 0;

  while (k1.cmpn(-d1) > 0 || k2.cmpn(-d2) > 0) {
    // First phase.
    let m14 = (k1.andln(3) + d1) & 3;
    let m24 = (k2.andln(3) + d2) & 3;

    if (m14 === 3)
      m14 = -1;

    if (m24 === 3)
      m24 = -1;

    let u1 = 0;

    if (m14 & 1) {
      const m8 = (k1.andln(7) + d1) & 7;

      if ((m8 === 3 || m8 === 5) && m24 === 2)
        u1 = -m14;
      else
        u1 = m14;
    }

    let u2 = 0;

    if (m24 & 1) {
      const m8 = (k2.andln(7) + d2) & 7;

      if ((m8 === 3 || m8 === 5) && m14 === 2)
        u2 = -m24;
      else
        u2 = m24;
    }

    const ja = u1 * s1;
    const jb = u2 * s2;

    // Convert to NAF.
    jsf[0][i] = jsfIndex[(ja + 1) * 3 + (jb + 1)];
    jsf[1][i] = 0;

    // Second phase.
    if (2 * d1 === u1 + 1)
      d1 = 1 - d1;

    if (2 * d2 === u2 + 1)
      d2 = 1 - d2;

    k1.iushrn(1);
    k2.iushrn(1);

    i += 1;
  }

  assert(i <= size);

  for (; i < size; i++) {
    jsf[0][i] = 0;
    jsf[1][i] = 0;
  }

  return jsf;
}

/*
 * Expose
 */

exports.Curve = Curve;
exports.Point = Point;
exports.ShortCurve = ShortCurve;
exports.ShortPoint = ShortPoint;
exports.JPoint = JPoint;
exports.MontCurve = MontCurve;
exports.MontPoint = MontPoint;
exports.EdwardsCurve = EdwardsCurve;
exports.EdwardsPoint = EdwardsPoint;
exports.P192 = P192;
exports.P224 = P224;
exports.P256 = P256;
exports.P384 = P384;
exports.P521 = P521;
exports.SECP256K1 = SECP256K1;
exports.X25519 = X25519;
exports.ED25519 = ED25519;
exports.X448 = X448;
exports.ED448 = ED448;
exports.BRAINPOOLP256 = BRAINPOOLP256;
exports.BRAINPOOLP384 = BRAINPOOLP384;
exports.BRAINPOOLP512 = BRAINPOOLP512;
