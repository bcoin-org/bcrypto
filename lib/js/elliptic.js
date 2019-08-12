/*!
 * elliptic.js - elliptic curves for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/elliptic:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/elliptic
 *
 * Formulas from DJB and Tanja Lange:
 *   https://hyperelliptic.org/EFD/
 *
 * Several algorithms from:
 *
 *   Guide to Elliptic Curve Cryptography
 *     D. Hankerson, A. Menezes, and S. Vanstone
 *     https://tinyurl.com/guide-to-ecc
 *
 *   Faster Point Multiplication on Elliptic Curves
 *     R. Gallant, R. Lambert, and S. Vanstone
 *     https://link.springer.com/content/pdf/10.1007/3-540-44647-8_11.pdf
 *
 *   The Arithmetic of Elliptic Curves, 2nd Edition
 *     Joseph H. Silverman
 *     http://www.pdmi.ras.ru/~lowdimma/BSD/Silverman-Arithmetic_of_EC.pdf
 *
 * Other resources:
 *   http://www.secg.org/sec1-v2.pdf
 *   https://tools.ietf.org/html/rfc7748
 *   https://tools.ietf.org/html/rfc8032
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
    this.iso4 = false;
    this.prime = null;
    this.p = null;
    this.red = null;
    this.fieldSize = 0;
    this.fieldBits = 0;
    this.signBit = 0;
    this.zero = null;
    this.one = null;
    this.two = null;
    this.three = null;
    this.n = null;
    this.h = null;
    this.q = null;
    this.g = null;
    this.nh = null;
    this.scalarSize = 0;
    this.scalarBits = 0;
    this.mask = null;
    this.maxwellTrick = false;
    this.redN = null;
    this.blinding = null;
    this.endo = null;
    this._init(type, conf);
  }

  _init(type, conf) {
    assert(typeof type === 'string');
    assert(conf && typeof conf === 'object');
    assert(conf.p != null, 'Must pass a prime.');
    assert(conf.id == null || typeof conf.id === 'string');
    assert(conf.ossl == null || typeof conf.ossl === 'string');
    assert(conf.endian == null || typeof conf.endian === 'string');
    assert(conf.hash == null || typeof conf.hash === 'string');
    assert(conf.prefix == null || typeof conf.prefix === 'string');
    assert(conf.context == null || typeof conf.context === 'boolean');
    assert(conf.iso4 == null || typeof conf.iso4 === 'boolean');
    assert(conf.prime == null || typeof conf.prime === 'string');

    // Meta.
    this.id = conf.id || null;
    this.ossl = conf.ossl || null;
    this.type = type;
    this.endian = conf.endian || (type === 'short' ? 'be' : 'le');
    this.hash = conf.hash || null;
    this.prefix = conf.prefix ? Buffer.from(conf.prefix, 'binary') : null;
    this.context = conf.context || false;
    this.iso4 = conf.iso4 || false;
    this.prime = conf.prime || null;

    // Prime.
    this.p = BN.fromJSON(conf.p);

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

    // Curve configuration, optional.
    this.n = conf.n ? BN.fromJSON(conf.n) : new BN(0);
    this.h = conf.h ? BN.fromJSON(conf.h) : new BN(1);
    this.q = this.n.mul(this.h);
    this.g = null;
    this.nh = this.n.ushrn(1);
    this.scalarSize = Math.max(this.n.byteLength(), this.p.byteLength());
    this.scalarBits = this.n.bitLength();
    this.mask = null;

    // Generalized Greg Maxwell's trick.
    this.maxwellTrick = !this.n.isZero() && this.p.div(this.n).cmpn(100) <= 0;
    this.redN = this.n.toRed(this.red);

    // Scalar blinding.
    this.blinding = null;

    // Endomorphism.
    this.endo = null;

    return this;
  }

  _finalize(conf) {
    assert(conf && typeof conf === 'object');

    // Create mask.
    this.mask = new Mask(this);

    // Create base point.
    this.g = conf.g ? this.pointFromJSON(conf.g) : this.point();

    return this;
  }

  _scalarBlinding(rng) {
    if (!rng)
      return null;

    if (this.n.isZero())
      return null;

    // We blind scalar multiplications too.
    // This is only effective if an attacker
    // is not able to observe the start up.
    //
    // Note that our bigint implementation
    // is only constant time for 235-285
    // bit ints (though, in reality it may
    // not be constant time at all due to
    // the deoptimizer kicking in after a
    // SMI overflow, or something).
    //
    // Perhaps to add more noise to the
    // signing process, we could generate
    // this value before each call instead
    // of pregenerating it. This would
    // involve using Fermat's little
    // theorem instead of the EGCD used
    // below.
    for (;;) {
      const blind = this.randomScalar(rng);

      try {
        return [blind, blind.invert(this.n)];
      } catch (e) {
        continue;
      }
    }
  }

  _simpleMul(p, k) {
    assert(p instanceof Point);
    assert(k instanceof BN);
    assert(!k.red);

    // Left-to-right point multiplication.
    //
    // See: Guide to Elliptic Curve Cryptography.
    // Algorithm 3.27, Page 97, Section 3.3.
    //
    // For the right-to-left method, see:
    // Algorithm 3.26, Page 96, Section 3.3.
    //
    // We prefer left-to-right since it
    // allows us to repeatedly add an
    // affine point to the accumulator.
    const bits = k.bitLength();

    // Flip sign if necessary.
    if (k.isNeg())
      p = p.neg();

    // Multiply.
    let acc = this.jpoint();

    for (let i = bits - 1; i >= 0; i--) {
      const bit = k.utestn(i);

      acc = acc.dbl();

      if (bit === 1)
        acc = acc.add(p);
    }

    return acc;
  }

  _simpleMulAdd(points, coeffs) {
    assert(Array.isArray(points));
    assert(Array.isArray(coeffs));
    assert(points.length === coeffs.length);

    // Multiple point multiplication, also known
    // as "Shamir's trick".
    //
    // See: Guide to Elliptic Curve Cryptography.
    // Algorithm 3.48, Page 109, Section 3.3.3.
    const len = points.length;
    const npoints = new Array(len);
    const ncoeffs = coeffs;

    // Check arrays and calculate size.
    let max = 0;

    for (let i = 0; i < len; i++) {
      const point = points[i];
      const coeff = coeffs[i];

      assert(point instanceof Point);
      assert(coeff instanceof BN);
      assert(!coeff.red);

      if (i > 0 && point.type !== points[i - 1].type)
        throw new Error('Cannot mix points.');

      // Flip signs if necessary.
      npoints[i] = coeff.isNeg() ? point.neg() : point;

      // Compute max scalar size.
      max = Math.max(max, coeff.bitLength());
    }

    // Multiply and add.
    let acc = this.jpoint();

    for (let i = max - 1; i >= 0; i--) {
      acc = acc.dbl();

      for (let j = 0; j < len; j++) {
        const point = npoints[j];
        const coeff = ncoeffs[j];
        const bit = coeff.utestn(i);

        if (bit === 1)
          acc = acc.add(point);
      }
    }

    return acc;
  }

  _constMul(p, k) {
    assert(p instanceof Point);

    // Must have order.
    if (this.n.isZero())
      return this._simpleMul(p, k);

    // Use Co-Z arithmetic for Weierstrass.
    if (this.type === 'short')
      return this._coZLadderMul(p, k);

    // Otherwise, a regular ladder.
    return this._ladderMul(p, k);
  }

  _ladderMul(p, k) {
    assert(p instanceof Point);
    assert(k instanceof BN);
    assert(!k.red);

    // Generalized Montgomery Ladder.
    //
    // See: Montgomery curves and the Montgomery ladder.
    //   Daniel J. Bernstein, Tanja Lange.
    //   Page 24, Section 4.6.2.
    //   https://eprint.iacr.org/2017/293.pdf
    //
    // Curve must expose some form of unified
    // addition (this is easier said than done
    // for Weierstrass curves). This ensures
    // both branches of the ladder consume
    // the same power and number of cycles.
    //
    // We implement the ladder as a branchless
    // function with a constant time swap.
    //
    // Current cost:
    //
    //   2N * (11M + 8S + 7A + 1*a + 2*4 + 1*3 + 2*2)
    //
    //   N=256 => 5632M + 4096S + 3584A
    //          + 512*a + 1024*4 + 512*3
    //          + 1024*2
    const [sign, bits, exp] = getLadderBits(k, this.q);

    // Clone points (for safe swapping).
    let a = p.toJ().clone();
    let b = this.jpoint().clone();
    let swap = 0;

    // Climb the ladder.
    for (let i = bits - 1; i >= 0; i--) {
      const bit = (exp[i >> 3] >> (i & 7)) & 1;

      // Maybe swap.
      a.swap(b, swap ^ bit);

      // Unified addition.
      a = a.uadd(b);
      b = b.uadd(b);

      swap = bit;
    }

    // Finalize loop.
    a.swap(b, swap);

    // Flip sign retroactively.
    b.swap(b.neg(), sign);

    return b;
  }

  _coZLadderMul(p, k) {
    assert(p instanceof Point);
    assert(k instanceof BN);
    assert(!k.red);

    // Co-Z Montgomery Ladder.
    //
    // See: Scalar Multiplication on Elliptic Curves from Co-Z Arithmetic.
    //   R. Goundar, M. Joye, A. Miyaji, M. Rivain, A. Venelli.
    //   Algorithm 9, Page 6, Section 4.
    //   https://www.matthieurivain.com/files/jcen11b.pdf
    //
    // Multiply with Co-Z arithmetic. This method is
    // 2x faster than our regular unified addition
    // ladder. However, there are some problems with
    // leakage of the key length.
    //
    // There are two issues with this algorithm:
    //
    //   1. The amount of steps in the ladder is not
    //      constant, since we must assume k[n-1]=1
    //      (it follows that k[n]=0). A side effect
    //      of this is that we cannot handle a point
    //      at infinity (k[n-1]=0).
    //
    //   2. On the off chance we pass in a "low"
    //      scalar (lacking several hi bits), there
    //      will be a noticeable difference in cycles.
    //
    // To avoid both of these issues, we _negate_ the
    // scalar in the event that bits < order bits. We
    // allow negative bignums with our implementation,
    // so we also do some extra sign tracking. If we
    // do end up negating a scalar, we negate the
    // resulting point in constant time at the end.
    //
    // Doing this not only solves the point at infinity
    // issue (i.e. N-0=N=0), but it also ensures a scalar
    // is within at least 1 bit of the order (usually).
    //
    // A possibility for a perf improvement involves
    // using the ZACAU method. This is faster assuming
    // a cost of 1S < 1M, but our squaring impl. is
    // identical to our multiplication impl., so we
    // wouldn't get any real benefit.
    //
    // Current cost:
    //
    //   1M + 5S + 8A + 4*2 + 1*8
    //   N * (11M + 3S + 21A + 1*2)
    //
    //   N=256 => 2817M + 773S + 5384A + 256*2 + 4*2 + 1*8
    const [sign, bits, exp] = getCOZBits(k, this.q);

    // Initial double (we assume k[n-1] == 1).
    let [a, b] = p.toJ().zdblu();
    let swap = 0;

    // Climb the ladder.
    for (let i = bits - 2; i >= 0; i--) {
      const bit = (exp[i >> 3] >> (i & 7)) & 1;

      // Maybe swap.
      a.swap(b, swap ^ bit);

      // Co-Z addition.
      [a, b] = b.zaddc(a);
      [b, a] = a.zaddu(b);

      swap = bit;
    }

    // Finalize loop.
    a.swap(b, swap);

    // Adjust sign.
    b.swap(b.neg(), sign);

    return b;
  }

  _fixedNafMul(p, k) {
    assert(p instanceof Point);
    assert(k instanceof BN);
    assert(p.pre);

    // Fixed-base NAF windowing method for point multiplication.
    //
    // See: Guide to Elliptic Curve Cryptography.
    // Algorithm 3.42, Page 105, Section 3.3.

    // Get precomputed doubles.
    const {step, points} = p._getDoubles(0, 0);

    // Get fixed NAF (in a more windowed form).
    const naf = getFixedNAF(k, 1, k.bitLength() + 1, step);

    // Compute steps.
    const I = ((1 << (step + 1)) - (step % 2 === 0 ? 2 : 1)) / 3;

    // Multiply.
    let a = this.jpoint();
    let b = this.jpoint();

    for (let i = I; i > 0; i--) {
      for (let j = 0; j < naf.length; j++) {
        const nafW = naf[j];

        if (nafW === i)
          b = b.add(points[j]);
        else if (nafW === -i)
          b = b.add(points[j].neg());
      }

      a = a.add(b);
    }

    return a;
  }

  _wnafMul(w, p, k) {
    assert(p instanceof Point);
    assert(k instanceof BN);

    // Window NAF method for point multiplication.
    //
    // See: Guide to Elliptic Curve Cryptography.
    // Algorithm 3.36, Page 100, Section 3.3.

    // Precompute window.
    const {width, points} = p._safeNAF(w);

    // Get NAF form.
    const naf = getNAF(k, width, k.bitLength() + 1);

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

      if (z > 0)
        acc = acc.add(points[(z - 1) >> 1]);
      else
        acc = acc.add(points[(-z - 1) >> 1].neg());
    }

    return acc;
  }

  _wnafMulAdd(w, points, coeffs) {
    assert((w >>> 0) === w);
    assert(Array.isArray(points));
    assert(Array.isArray(coeffs));
    assert(points.length === coeffs.length);

    // Multiple point multiplication, also known
    // as "Shamir's trick" (with interleaved NAFs).
    //
    // See: Guide to Elliptic Curve Cryptography.
    // Algorithm 3.48, Page 109, Section 3.3.3.
    // Algorithm 3.51, Page 112, Section 3.3.
    //
    // This is particularly useful for signature
    // verifications and mutiplications after an
    // endomorphism split.
    const length = points.length;
    const wnd = new Array(length);
    const naf = new Array(length);
    const tmp = new Array(length);

    // Check arrays and calculate size.
    let max = 0;

    for (let i = 0; i < length; i++) {
      const point = points[i];
      const coeff = coeffs[i];

      assert(point instanceof Point);
      assert(coeff instanceof BN);

      if (i > 0 && point.type !== points[i - 1].type)
        throw new Error('Cannot mix points.');

      // Avoid sparse arrays.
      wnd[i] = null;
      naf[i] = null;
      tmp[i] = 0;

      // Compute max scalar size.
      max = Math.max(max, coeff.bitLength() + 1);
    }

    // Compute NAFs.
    let ppoint = null;
    let pcoeff = null;
    let len = 0;

    for (let i = 0; i < length; i++) {
      const point = points[i];
      const coeff = coeffs[i];
      const pre = point._getNAF(0);

      // Use precomputation if available.
      if (pre) {
        wnd[len] = pre.points;
        naf[len] = getNAF(coeff, pre.width, max);
        len += 1;
        continue;
      }

      // Save last non-precomputed point.
      if (!ppoint) {
        ppoint = point;
        pcoeff = coeff;
        continue;
      }

      // Compute JSF in NAF form.
      wnd[len] = ppoint._getJNAF(point);
      naf[len] = getJNAF(pcoeff, coeff, max);

      ppoint = null;
      pcoeff = null;

      len += 1;
    }

    // Regular NAF for odd points.
    if (ppoint) {
      const nafw = ppoint._safeNAF(w);

      wnd[len] = nafw.points;
      naf[len] = getNAF(pcoeff, nafw.width, max);

      len += 1;
    }

    // Multiply and add.
    let acc = this.jpoint();

    for (let i = max - 1; i >= 0; i--) {
      let k = 0;

      // Interleave NAFs.
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

        if (z > 0)
          acc = acc.add(wnd[j][(z - 1) >> 1]);
        else
          acc = acc.add(wnd[j][(-z - 1) >> 1].neg());
      }
    }

    return acc;
  }

  _endoWnafMulAdd(points, coeffs) {
    throw new Error('Not implemented.');
  }

  precompute(rng) {
    assert(!this.g.isInfinity(), 'Must have base point.');
    assert(!this.n.isZero(), 'Must have order.');

    this.g.precompute(this.n.bitLength() + 1, rng);
    this.blinding = this._scalarBlinding(rng);

    return this;
  }

  getBlinding() {
    if (!this.blinding)
      return [new BN(1), new BN(1)];

    return this.blinding;
  }

  point(x, y) {
    throw new Error('Not implemented.');
  }

  jpoint(x, y, z) {
    throw new Error('Not implemented.');
  }

  solveX(y) {
    return this.solveX2(y).redSqrt();
  }

  solveX2(y) {
    throw new Error('Not implemented.');
  }

  solveY(x) {
    return this.solveY2(x).redSqrt();
  }

  solveY2(x) {
    throw new Error('Not implemented.');
  }

  validate(point) {
    throw new Error('Not implemented.');
  }

  pointFromX(x, sign) {
    throw new Error('Not implemented.');
  }

  pointFromY(y, sign) {
    throw new Error('Not implemented.');
  }

  pointFromR(x) {
    throw new Error('Not implemented.');
  }

  elligator(r) {
    throw new Error('Not implemented.');
  }

  invert(p) {
    throw new Error('Not implemented.');
  }

  randomScalar(rng) {
    const max = this.n.isZero() ? this.p : this.n;
    return BN.random(rng, 1, max);
  }

  randomField(rng) {
    return BN.random(rng, 1, this.p).toRed(this.red);
  }

  randomPoint(rng) {
    throw new Error('Not implemented.');
  }

  mulAll(points, coeffs) {
    return this.jmulAll(points, coeffs);
  }

  mulAllSimple(points, coeffs) {
    return this.jmulAllSimple(points, coeffs);
  }

  jmulAll(points, coeffs) {
    assert(Array.isArray(points));
    assert(points.length === 0 || (points[0] instanceof Point));

    // Multiply with endomorphism if we're using affine points.
    if (this.endo && points.length > 0 && points[0].type === types.AFFINE)
      return this._endoWnafMulAdd(points, coeffs);

    // Otherwise, a regular Shamir's trick.
    return this._wnafMulAdd(1, points, coeffs);
  }

  jmulAllSimple(points, coeffs) {
    return this._simpleMulAdd(points, coeffs);
  }

  reduce(k) {
    return this.mask.reduce(k);
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

  encodeField(x) {
    assert(x instanceof BN);
    assert(!x.red);

    // See SEC1 (page 12, section 2.3.5).
    return x.encode(this.endian, this.fieldSize);
  }

  decodeField(bytes) {
    assert(Buffer.isBuffer(bytes));

    if (bytes.length !== this.fieldSize)
      throw new Error('Invalid field element size.');

    // See SEC1 (page 13, section 2.3.6).
    return BN.decode(bytes, this.endian);
  }

  encodeScalar(k) {
    assert(k instanceof BN);
    assert(!k.red);

    // See SEC1 (page 13, section 2.3.7).
    return k.encode(this.endian, this.scalarSize);
  }

  decodeScalar(bytes) {
    assert(Buffer.isBuffer(bytes));

    if (bytes.length !== this.scalarSize)
      throw new Error('Invalid scalar size.');

    // See SEC1 (page 14, section 2.3.8).
    return BN.decode(bytes, this.endian);
  }

  encodePoint(point, compact) {
    assert(point instanceof Point);
    return point.encode(compact);
  }

  decodePoint(bytes) {
    throw new Error('Not implemented.');
  }

  encodeUniform(r, rng) {
    assert(r instanceof BN);

    const bits = this.fieldBits;
    const size = (bits + 7) >>> 3;
    const fill = size * 8 - bits;
    const x = r.fromRed();

    if (rng != null && fill !== 0) {
      const mask = BN.randomBits(rng, fill);

      x.iuor(mask.iushln(bits));
    }

    return x.encode(this.endian, size);
  }

  decodeUniform(bytes) {
    assert(Buffer.isBuffer(bytes));

    const bits = this.fieldBits;
    const size = (bits + 7) >>> 3;

    if (bytes.length !== size)
      throw new Error('Invalid elligator size.');

    const x = BN.decode(bytes, this.endian).iumaskn(bits);

    return x.toRed(this.red);
  }

  pointFromJSON(json) {
    throw new Error('Not implemented.');
  }

  toJSON(pre) {
    return {
      id: this.id,
      ossl: this.ossl,
      type: this.type,
      endian: this.endian,
      hash: this.hash,
      prefix: this.prefix ? this.prefix.toString() : null,
      context: this.context,
      iso4: this.iso4,
      prime: this.prime,
      p: this.p.toJSON(),
      a: undefined,
      b: undefined,
      c: undefined,
      d: undefined,
      n: this.n.toJSON(),
      h: this.h.toString(16),
      g: this.g.toJSON(pre),
      endo: this.endo ? this.endo.toJSON() : undefined
    };
  }

  static fromJSON(json) {
    return new this(json);
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
    this.pre = null;
  }

  _init() {
    throw new Error('Not implemented.');
  }

  _getNAF(width) {
    assert((width >>> 0) === width);

    if (this.pre && this.pre.naf)
      return this.pre.naf;

    if (width === 0)
      return null;

    const size = (1 << width) - 1;
    const points = new Array(size);
    const dbl = size === 1 ? null : this.dbl();

    points[0] = this;

    for (let i = 1; i < size; i++)
      points[i] = points[i - 1].add(dbl);

    return new NAF(width, points);
  }

  _safeNAF(width) {
    return this._getNAF(width);
  }

  _getDoubles(step, power) {
    assert((step >>> 0) === step);
    assert((power >>> 0) === power);

    if (this.pre && this.pre.doubles)
      return this.pre.doubles;

    if (step === 0)
      return null;

    const len = Math.ceil(power / step) + 1;
    const points = new Array(len);

    let acc = this;
    let k = 0;

    points[k++] = acc;

    for (let i = 0; i < power; i += step) {
      for (let j = 0; j < step; j++)
        acc = acc.dbl();

      points[k++] = acc;
    }

    assert(k === len);

    return new Doubles(step, points);
  }

  _getBeta() {
    return null;
  }

  _getBlinding(rng) {
    if (this.pre && this.pre.blinding)
      return this.pre.blinding;

    if (!rng)
      return null;

    if (this.curve.n.isZero())
      return null;

    // Pregenerate a random blinding value:
    //
    //   blind = random scalar
    //   unblind = G*blind
    //
    // We intend to subtract the blinding value
    // from scalars before multiplication. We
    // can add the unblinding point once the
    // multiplication is complete.
    for (;;) {
      const blind = this.curve.randomScalar(rng);
      const unblind = this.mul(blind);

      if (unblind.isInfinity())
        continue;

      return new Blinding(blind, unblind);
    }
  }

  _hasDoubles(k) {
    assert(k instanceof BN);

    if (!this.pre || !this.pre.doubles)
      return false;

    const {step, points} = this.pre.doubles;
    const power = k.bitLength() + 1;

    return points.length >= Math.ceil(power / step) + 1;
  }

  _getJNAF(point) {
    assert(point instanceof Point);
    assert(point.type === this.type);

    // Create comb for JSF.
    return [
      this, // 1
      this.add(point), // 3
      this.add(point.neg()), // 5
      point // 7
    ];
  }

  _blind(k, rng) {
    assert(k instanceof BN);
    assert(!k.red);

    // See: Elliptic Curves and Side-Channel Attacks.
    //   Marc Joye.
    //   Page 5, Section 4.
    //   https://pdfs.semanticscholar.org/8d69/9645033e25d74fcfd4cbf07a770d2e943e14.pdf
    if (this.pre && this.pre.blinding) {
      // Multiplier randomization (requires precomp).
      //
      // Blind a multiplication by first subtracting
      // a blinding value from the scalar. Example:
      //
      // Assumptions: b = random blinding value.
      //
      //   B = P*b
      //   Q = P*(k - b) + B
      //
      // Note that Joye describes a different method
      // which computes:
      //
      //   B = G*b (random point)
      //   Q = (P + B)*k - B*k
      //
      // The blinding value and its corresponding
      // point are randomly generated and computed
      // on boot. As long as an attacker is not
      // able to observe the boot, this should give
      // a decent bit of protection against various
      // channel attacks.
      const {blind, unblind} = this.pre.blinding;
      const t = k.sub(blind);

      return [this, t, unblind];
    }

    // Randomization is not possible without
    // an RNG. Do a normal multiplication.
    if (!rng)
      return [this, k, null];

    // If we have no precomputed blinding
    // factor, there are two possibilities
    // for randomization:
    //
    // 1. Randomize the multiplier by adding
    //    a random multiple of N.
    //
    // 2. Re-scale the point itself by a
    //    random factor.
    //
    // The first option can be accomplished
    // with some like:
    //
    //   r = random(1...N) * N
    //   Q = P*(k + r)
    //
    // The second is accomplished with:
    //
    //   a = random(1...P)
    //   R(x) = P(x) * a^2
    //   R(y) = P(y) * a^3
    //   R(z) = P(z) * a
    //   Q = R*k
    //
    // If we have precomputed doubles / naf
    // points, we opt for the first method
    // to avoid randomizing everything.
    if (this.pre) {
      if (this.curve.n.isZero())
        return [this, k, null];

      const b = this.curve.randomScalar(rng);
      const r = b.mul(this.curve.n);
      const t = r.iadd(k);

      return [this, t, null];
    }

    // If there is no precomputation _at all_,
    // we opt for the second method.
    const p = this.randomize(rng);

    return [p, k, null];
  }

  clone() {
    throw new Error('Not implemented.');
  }

  swap(point, flag) {
    throw new Error('Not implemented.');
  }

  precompute(power, rng) {
    assert((power >>> 0) === power);

    if (!this.pre)
      this.pre = new Precomp();

    if (!this.pre.naf)
      this.pre.naf = this._getNAF(8);

    if (!this.pre.doubles)
      this.pre.doubles = this._getDoubles(4, power);

    if (!this.pre.beta)
      this.pre.beta = this._getBeta();

    if (!this.pre.blinding)
      this.pre.blinding = this._getBlinding(rng);

    return this;
  }

  validate() {
    return this.curve.validate(this);
  }

  normalize() {
    return this;
  }

  scale(a) {
    throw new Error('Not implemented.');
  }

  randomize(rng) {
    const z = this.curve.randomField(rng);
    return this.scale(z);
  }

  neg() {
    throw new Error('Not implemented.');
  }

  add(point) {
    throw new Error('Not implemented.');
  }

  dbl() {
    throw new Error('Not implemented.');
  }

  dblp(pow) {
    assert((pow >>> 0) === pow);

    // Repeated doubling. This can
    // be optimized by child classes.
    let r = this;

    for (let i = 0; i < pow; i++)
      r = r.dbl();

    return r;
  }

  trpl() {
    throw new Error('Not implemented.');
  }

  uadd(point) {
    throw new Error('Not implemented.');
  }

  udbl() {
    throw new Error('Not implemented.');
  }

  zaddu(point) {
    throw new Error('Not implemented.');
  }

  zaddc(point) {
    throw new Error('Not implemented.');
  }

  zdblu() {
    throw new Error('Not implemented.');
  }

  ztrplu() {
    throw new Error('Not implemented.');
  }

  diffAdd(p, q) {
    throw new Error('Not implemented.');
  }

  diffAddDbl(p, q) {
    throw new Error('Not implemented.');
  }

  diffTrpl(p) {
    throw new Error('Not implemented.');
  }

  recover() {
    throw new Error('Not implemented.');
  }

  getX() {
    throw new Error('Not implemented.');
  }

  getY() {
    throw new Error('Not implemented.');
  }

  eq(point) {
    throw new Error('Not implemented.');
  }

  isInfinity() {
    throw new Error('Not implemented.');
  }

  hasQuadY() {
    throw new Error('Not implemented.');
  }

  eqX(x) {
    throw new Error('Not implemented.');
  }

  eqXToP(x) {
    throw new Error('Not implemented.');
  }

  isSmall() {
    // Test whether the point is of small order.
    if (this.isInfinity())
      return false;

    // P * H = O (small order point).
    return this.jmulH().isInfinity();
  }

  hasTorsion() {
    // Test whether the point is in a small subgroup.
    if (this.isInfinity())
      return false;

    // P * N != O (point is in a small subgroup).
    return !this.jmul(this.curve.n).isInfinity();
  }

  mul(k) {
    return this.jmul(k);
  }

  mulSimple(k) {
    return this.jmulSimple(k);
  }

  mulBlind(k, rng) {
    return this.jmulBlind(k, rng);
  }

  mulConst(k, rng) {
    return this.jmulConst(k, rng);
  }

  mulAdd(k1, p2, k2) {
    return this.jmulAdd(k1, p2, k2);
  }

  mulAddSimple(k1, p2, k2) {
    return this.jmulAddSimple(k1, p2, k2);
  }

  mulH() {
    return this.jmulH();
  }

  divH() {
    return this.jdivH();
  }

  jmul(k) {
    if (this._hasDoubles(k))
      return this.curve._fixedNafMul(this, k);

    if (this.curve.endo && this.type === types.AFFINE)
      return this.curve._endoWnafMulAdd([this], [k]);

    return this.curve._wnafMul(4, this, k);
  }

  jmulSimple(k) {
    return this.curve._simpleMul(this, k);
  }

  jmulBlind(k, rng = null) {
    const [p, t, unblind] = this._blind(k, rng);
    const q = p.jmul(t);

    if (unblind)
      return q.add(unblind);

    return q;
  }

  jmulConst(k, rng = null) {
    const [p, t, unblind] = this._blind(k, rng);
    const q = this.curve._constMul(p, t);

    if (unblind)
      return q.uadd(unblind);

    return q;
  }

  jmulAdd(k1, p2, k2) {
    if (this.curve.endo && this.type === types.AFFINE)
      return this.curve._endoWnafMulAdd([this, p2], [k1, k2]);

    return this.curve._wnafMulAdd(1, [this, p2], [k1, k2]);
  }

  jmulAddSimple(k1, p2, k2) {
    return this.curve._simpleMulAdd([this, p2], [k1, k2]);
  }

  jmulH() {
    const bits = this.curve.h.bitLength();
    const word = this.curve.h.andln(-1);

    // Optimize for powers of two.
    if (bits <= 26 && (word & (word - 1)) === 0)
      return this.toJ().dblp(bits - 1);

    return this.jmulSimple(this.curve.h);
  }

  jdivH() {
    if (this.curve.n.isZero())
      return this;

    if (this.curve.h.cmpn(1) === 0)
      return this;

    return this.jmul(this.curve.h.invert(this.curve.n));
  }

  toP() {
    return this.normalize();
  }

  toJ() {
    return this;
  }

  encode(compact) {
    throw new Error('Not implemented.');
  }

  static decode(curve, bytes) {
    throw new Error('Not implemented.');
  }

  toJSON(pre) {
    throw new Error('Not implemented.');
  }

  static fromJSON(curve, json) {
    throw new Error('Not implemented.');
  }

  [custom]() {
    return '<Point>';
  }
}

/**
 * ShortCurve
 */

class ShortCurve extends Curve {
  constructor(conf) {
    super('short', conf);

    this.a = BN.fromJSON(conf.a).toRed(this.red);
    this.b = BN.fromJSON(conf.b).toRed(this.red);
    this.i2 = this.two.redInvert();

    this.zeroA = this.a.sign() === 0;
    this.threeA = this.a.cmp(this.three.redNeg()) === 0;

    this._finalize(conf);
  }

  _finalize(conf) {
    super._finalize(conf);

    // Precalculate endomorphism.
    if (conf.endo != null)
      this.endo = Endo.fromJSON(this, conf.endo);
    else
      this.endo = this._getEndomorphism();

    return this;
  }

  _getEndomorphism() {
    // Compute endomorphism.
    //
    // See: Guide to Elliptic Curve Cryptography.
    // Example 3.76, Page 128, Section 3.5.

    // No curve params.
    if (this.n.isZero() || this.g.isInfinity())
      return null;

    // No efficient endomorphism.
    if (!this.zeroA || this.p.modrn(3) !== 1 || this.n.modrn(3) !== 1)
      return null;

    // Solve beta^3 mod p = 1.
    const [b1, b2] = this._getEndoRoots(this.p);

    // Choose the smallest beta.
    const beta = BN.min(b1, b2).toRed(this.red);

    // Solve lambda^3 mod n = 1.
    const [l1, l2] = this._getEndoRoots(this.n);

    // Choose the lambda matching selected beta.
    // Note that P * lambda = (Px * beta, Py).
    const xb = this.g.x.redMul(beta);

    let lambda;

    if (this.g.mul(l1).x.cmp(xb) === 0) {
      lambda = l1;
    } else {
      assert(this.g.mul(l2).x.cmp(xb) === 0);
      lambda = l2;
    }

    // Get basis vectors.
    // Used for balanced length-two representation.
    const basis = this._getEndoBasis(lambda);

    return new Endo(beta, lambda, basis);
  }

  _getEndoRoots(num) {
    // Compute endomorphic cube roots.
    //
    // See: Guide to Elliptic Curve Cryptography.
    // Example 3.76, Page 128, Section 3.5.
    //
    // Also: Faster Point Multiplication on Elliptic Curves.
    // Page 192, Section 2 (Endomorphisms).
    //
    // The above document doesn't fully explain how
    // to derive these and only "hints" at it, as
    // mentioned by Hal Finney[1], but we're basically
    // computing two possible cube roots of 1 here.
    //
    // Note that we could also compute[2]:
    //
    //   beta = 2^((p - 1) / 3) mod p
    //   lambda = 3^((n - 1) / 3) mod n
    //
    // As an extension of Fermat's little theorem:
    //
    //   g^(p - 1) mod p == 1
    //
    // It is suspected[3] this is how Hal Finney[4]
    // computed his original endomorphism roots.
    //
    // @indutny's method for computing cube roots
    // of unity[5] appears to be the method described
    // on wikipedia[6][7].
    //
    // [1] https://bitcointalk.org/index.php?topic=3238.msg45565#msg45565
    // [2] https://crypto.stackexchange.com/a/22739
    // [3] https://bitcoin.stackexchange.com/a/35872
    // [4] https://github.com/halfinney/bitcoin/commit/dc411b5
    // [5] https://en.wikipedia.org/wiki/Cube_root_of_unity
    // [6] https://en.wikipedia.org/wiki/Splitting_field#Cubic_example
    // [7] http://mathworld.wolfram.com/SplittingField.html
    const red = num === this.p ? this.red : BN.mont(num);
    const two = new BN(2).toRed(red);
    const three = new BN(3).toRed(red);

    // Find roots for x^2 + x + 1 in F.
    const half = two.redInvert();
    const nhalf = half.redNeg();

    // S = sqrt(-3) / 2
    const s = three.redINeg().redSqrt().redMul(half);

    // R1 = -(1 / 2) + S
    const r1 = nhalf.redAdd(s).fromRed();

    // R2 = -(1 / 2) - S
    const r2 = nhalf.redISub(s).fromRed();

    return [r1, r2];
  }

  _getEndoBasis(lambda) {
    // Compute endomorphic basis.
    //
    // This essentially computes Cornacchia's algorithm
    // for solving x^2 + dy^2 = m (d = lambda, m = order).
    //
    // https://en.wikipedia.org/wiki/Cornacchia%27s_algorithm
    //
    // See: Guide to Elliptic Curve Cryptography.
    // Algorithm 3.74, Page 127, Section 3.5.
    //
    // Also: Faster Point Multiplication on Elliptic Curves.
    // Page 196, Section 4 (Decomposing K).
    //
    // Balanced length-two representation of a multiplier.
    //
    // 1. Run the extended euclidean algorithm with inputs n
    //    and lambda. The algorithm produces a sequence of
    //    equations si*n + ti*lam = ri where s0=1, t0=0,
    //    r0=n, s1=0, t1=1, r1=lam, and the remainders ri
    //    and are non-negative and strictly decreasing. Let
    //    l be the greatest index for which rl >= sqrt(n).
    const [rl, tl, rl1, tl1, rl2, tl2] = this._egcdSqrt(lambda);

    // 2. Set (a1, b1) <- (rl+1, -tl+1).
    const a1 = rl1;
    const b1 = tl1.neg();

    // 3. If (rl^2 + tl^2) <= (rl+2^2 + tl+2^2)
    //    then set (a2, b2) <- (rl, -tl).
    //    else set (a2, b2) <- (rl+2, -tl+2).
    const lhs = rl.sqr().iadd(tl.sqr());
    const rhs = rl2.sqr().iadd(tl2.sqr());

    let a2, b2;

    if (lhs.cmp(rhs) <= 0) {
      a2 = rl;
      b2 = tl.neg();
    } else {
      a2 = rl2;
      b2 = tl2.neg();
    }

    return [
      new Vector(a1, b1),
      new Vector(a2, b2)
    ];
  }

  _egcdSqrt(lambda) {
    assert(lambda instanceof BN);
    assert(!lambda.red);
    assert(lambda.sign() > 0);
    assert(this.n.sign() > 0);

    // Extended Euclidean algorithm for integers.
    //
    // See: Guide to Elliptic Curve Cryptography.
    // Algorithm 2.19, Page 40, Section 2.2.
    //
    // Also: Faster Point Multiplication on Elliptic Curves.
    // Page 196, Section 4 (Decomposing K).
    //
    // Note that we insert the approximate square
    // root checks as described in algorithm 3.74.
    //
    // Algorithm 2.19 is defined as:
    //
    // 1. u <- a
    //    v <- b
    //
    // 2. x1 <- 1
    //    y1 <- 0
    //    x2 <- 0
    //    y2 <- 1
    //
    // 3. while u != 0 do
    //
    // 3.1. q <- floor(v / u)
    //      r <- v - q * u
    //      x <- x2 - q * x1
    //      y <- y2 - q * y1
    //
    // 3.2. v <- u
    //      u <- r
    //      x2 <- x1
    //      x1 <- x
    //      y2 <- y1
    //      y1 <- y
    //
    // 4. d <- v
    //    x <- x2
    //    y <- y2
    //
    // 5. Return (d, x, y).

    // Start with an approximate square root of n.
    const sqrtn = this.n.ushrn(this.n.bitLength() >>> 1);

    let u = lambda; // r1
    let v = this.n.clone(); // r0
    let x1 = new BN(1); // t1
    let y1 = new BN(0); // t0
    let x2 = new BN(0); // s1
    let y2 = new BN(1); // s0

    // All vectors are roots of: a + b * lambda = 0 (mod n).
    let rl, tl;

    // First vector.
    let rl1, tl1;

    // Inner.
    let i = 0;
    let j = 0;
    let p;

    // Compute EGCD.
    while (!u.isZero() && i < 2) {
      const q = v.quo(u);
      const r = v.sub(q.mul(u));
      const x = x2.sub(q.mul(x1));
      const y = y2.sub(q.mul(y1));

      // Check for r < sqrt(n).
      if (j === 0 && r.cmp(sqrtn) < 0) {
        rl = p;
        tl = x1;
        rl1 = r;
        tl1 = x;
        j = 1; // 1 more round.
      }

      p = r;
      v = u;
      u = r;
      x2 = x1;
      x1 = x;
      y2 = y1;
      y1 = y;

      i += j;
    }

    // Should never happen.
    assert(j !== 0, 'Could not find r < sqrt(n).');

    // Second vector.
    const rl2 = x2;
    const tl2 = x1;

    return [
      rl,
      tl,
      rl1,
      tl1,
      rl2,
      tl2
    ];
  }

  _endoSplit(k) {
    assert(k instanceof BN);
    assert(!k.red);
    assert(!this.n.isZero());

    // Balanced length-two representation of a multiplier.
    //
    // See: Guide to Elliptic Curve Cryptography.
    // Algorithm 3.74, Page 127, Section 3.5.
    //
    // Also note that it is possible to precompute[1]
    // values in order to avoid the round division[2].
    //
    // [1] https://github.com/bitcoin-core/secp256k1/blob/0b70241/src/scalar_impl.h#L259
    // [2] http://conradoplg.cryptoland.net/files/2010/12/jcen12.pdf
    const [v1, v2] = this.endo.basis;

    // 4. Compute c1 = round(b2 * k / n)
    //        and c2 = round(-b1 * k / n).
    const c1 = v2.b.mul(k).divRound(this.n);
    const c2 = v1.b.neg().mul(k).divRound(this.n);

    // 5. Compute k1 = k - c1 * a1 - c2 * a2
    //        and k2 = -c1 * b1 - c2 * b2.
    const p1 = c1.mul(v1.a);
    const p2 = c2.mul(v2.a);
    const q1 = c1.ineg().mul(v1.b);
    const q2 = c2.mul(v2.b);

    // Calculate answer.
    const k1 = k.sub(p1).isub(p2);
    const k2 = q1.isub(q2);

    // 6. Return (k1, k2).
    return [k1, k2];
  }

  _endoBeta(point) {
    assert(point instanceof ShortPoint);
    return [point, point._getBeta()];
  }

  _endoWnafMulAdd(points, coeffs) {
    assert(Array.isArray(points));
    assert(Array.isArray(coeffs));
    assert(points.length === coeffs.length);
    assert(this.endo != null);

    // Point multiplication with efficiently computable endomorphisms.
    //
    // See: Guide to Elliptic Curve Cryptography.
    // Algorithm 3.77, Page 129, Section 3.5.
    //
    // Also: Faster Point Multiplication on Elliptic Curves.
    // Page 193, Section 3 (Using Efficient Endomorphisms).
    //
    // Note it may be possible to do this 4-dimensionally.
    //
    // See: Refinement of the Four-Dimensional GLV Method on Elliptic Curves.
    // Hairong Yi, Yuqing Zhu, and Dongdai Lin.
    // http://www.site.uottawa.ca/~cadams/papers/prepro/paper_19_slides.pdf
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

    return this._wnafMulAdd(1, npoints, ncoeffs);
  }

  point(x, y) {
    return new ShortPoint(this, x, y);
  }

  jpoint(x, y, z) {
    return new JPoint(this, x, y, z);
  }

  solveY2(x) {
    // https://hyperelliptic.org/EFD/g1p/auto-shortw.html
    assert(x instanceof BN);

    // y^2 = x^3 + a * x + b
    const x3 = x.redSqr().redMul(x);
    const y2 = x3.redIAdd(this.b);

    if (!this.zeroA) {
      // Save some cycles for a = -3.
      if (this.threeA)
        y2.redIAdd(x.redMuln(-3));
      else
        y2.redIAdd(this.a.redMul(x));
    }

    return y2;
  }

  validate(point) {
    assert(point instanceof ShortPoint);

    if (point.inf)
      return true;

    const {x, y} = point;
    const y2 = this.solveY2(x);

    return y.redSqr().cmp(y2) === 0;
  }

  pointFromX(x, sign) {
    assert(x instanceof BN);

    if (!x.red)
      x = x.toRed(this.red);

    const y2 = this.solveY2(x);
    const y = y2.redSqrt();

    if (y.redIsOdd() !== Boolean(sign))
      y.redINeg();

    return this.point(x, y);
  }

  pointFromR(x) {
    assert(x instanceof BN);

    if (!x.red)
      x = x.toRed(this.red);

    const y2 = this.solveY2(x);
    const y = y2.redSqrt();

    return this.point(x, y);
  }

  randomPoint(rng) {
    let p;

    for (;;) {
      const x = this.randomField(rng);
      const sign = BN.random(rng, 0, 2);

      try {
        p = this.pointFromX(x, sign.isOdd());
      } catch (e) {
        continue;
      }

      return p;
    }
  }

  mulAll(points, coeffs) {
    return super.mulAll(points, coeffs).toP();
  }

  mulAllSimple(points, coeffs) {
    return super.mulAllSimple(points, coeffs).toP();
  }

  decodePoint(bytes) {
    return ShortPoint.decode(this, bytes);
  }

  pointFromJSON(json) {
    return ShortPoint.fromJSON(this, json);
  }

  toJSON(pre) {
    const json = super.toJSON(pre);
    json.a = this.a.toJSON();
    json.b = this.b.toJSON();
    return json;
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
    this.inf = 1;

    if (x != null)
      this._init(x, y);
  }

  _init(x, y) {
    assert(x instanceof BN);
    assert(y instanceof BN);

    this.x = x;
    this.y = y;

    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);

    if (!this.y.red)
      this.y = this.y.toRed(this.curve.red);

    this.inf = 0;
  }

  _safeNAF(width) {
    assert((width >>> 0) === width);

    if (this.pre && this.pre.naf)
      return this.pre.naf;

    // Avoid inversions.
    if (width > 1)
      return this.toJ()._getNAF(width);

    return this._getNAF(width);
  }

  _getBeta() {
    if (!this.curve.endo)
      return null;

    // Augment the point with our beta value.
    // This is the counterpart to `k2` after
    // the endomorphism split of `k`.
    //
    // Note that if we have precomputation,
    // we have to clone and update all
    // precomputed points below.
    if (this.pre && this.pre.beta)
      return this.pre.beta;

    const xb = this.x.redMul(this.curve.endo.beta);
    const beta = this.curve.point(xb, this.y);

    if (this.pre) {
      beta.pre = this.pre.map((point) => {
        const xb = point.x.redMul(this.curve.endo.beta);
        return this.curve.point(xb, point.y);
      });

      this.pre.beta = beta;
    }

    return beta;
  }

  _getJNAF(point) {
    assert(point instanceof ShortPoint);

    if (this.inf | point.inf)
      return super._getJNAF(point);

    // Create comb for JSF.
    const comb = [
      this, // 1
      null, // 3
      null, // 5
      point // 7
    ];

    // Try to avoid jacobian points, if possible.
    if (this.y.cmp(point.y) === 0) {
      comb[1] = this.add(point);
      comb[2] = this.toJ().add(point.neg());
    } else if (this.y.cmp(point.y.redNeg()) === 0) {
      comb[1] = this.toJ().add(point);
      comb[2] = this.add(point.neg());
    } else {
      comb[1] = this.toJ().add(point);
      comb[2] = this.toJ().add(point.neg());
    }

    return comb;
  }

  clone() {
    if (this.inf)
      return this.curve.point();

    return this.curve.point(this.x.clone(), this.y.clone());
  }

  scale(a) {
    return this.toJ().scale(a);
  }

  neg() {
    // P = O
    if (this.inf)
      return this;

    // -(X1, Y1) = (X1, -Y1)
    return this.curve.point(this.x, this.y.redNeg());
  }

  add(p) {
    // https://hyperelliptic.org/EFD/oldefd/weierstrass.html
    // https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Affine_Coordinates
    // 1I + 2M + 1S + 6A
    assert(p instanceof ShortPoint);

    // O + P = P
    if (this.inf)
      return p;

    // P + O = P
    if (p.inf)
      return this;

    // P + P, P + -P, P + invalid
    if (this.x.cmp(p.x) === 0) {
      // P + -P = O, P + invalid = O
      if (this.y.cmp(p.y) !== 0)
        return this.curve.point();

      // P + P = 2P
      return this.dbl();
    }

    // R = 0 (skip the inverse)
    if (this.y.cmp(p.y) === 0) {
      // X3 = -X1 - X2
      const nx = this.x.redNeg().redISub(p.x);

      // Y3 = -Y1
      const ny = this.y.redNeg();

      return this.curve.point(nx, ny);
    }

    // H = X1 - X2
    const h = this.x.redSub(p.x);

    // R = Y1 - Y2
    const r = this.y.redSub(p.y);

    // L = R / H
    const l = r.redMul(h.redInvert());

    // X3 = L^2 - X1 - X2
    const nx = l.redSqr().redISub(this.x).redISub(p.x);

    // Y3 = L * (X1 - X3) - Y1
    const ny = l.redMul(this.x.redSub(nx)).redISub(this.y);

    return this.curve.point(nx, ny);
  }

  dbl() {
    // https://hyperelliptic.org/EFD/oldefd/weierstrass.html
    // https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Affine_Coordinates
    // 1I + 2M + 2S + 3A + 2*2 + 1*3
    // (implemented as: 1I + 2M + 2S + 5A + 1*2 + 1*3)

    // P = O
    if (this.inf)
      return this;

    // Y1 = 0
    if (this.y.sign() === 0)
      return this.curve.point();

    // XX = X1^2
    const xx = this.x.redSqr();

    // M = 3 * XX + a
    const m = xx.redIMuln(3).redIAdd(this.curve.a);

    // M = 0 (skip the inverse)
    if (m.sign() === 0) {
      // X3 = -X1 - X1
      const nx = this.x.redNeg().redISub(this.x);

      // Y3 = -Y1
      const ny = this.y.redNeg();

      return this.curve.point(nx, ny);
    }

    // Z = 2 * Y1
    const z = this.y.redMuln(2);

    // L = M / Z
    const l = m.redMul(z.redInvert());

    // X3 = L^2 - 2 * X1
    const nx = l.redSqr().redISub(this.x).redISub(this.x);

    // Y3 = L * (X1 - X3) - Y1
    const ny = l.redMul(this.x.redSub(nx)).redISub(this.y);

    return this.curve.point(nx, ny);
  }

  trpl() {
    // Affine tripling formula. Based on:
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#doubling-mdbl-2007-bl
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-madd-1998-cmo
    // 1I + 14M + 7S + 16A + 2*2 + 1*3 + 1*4

    // P = O
    if (this.inf)
      return this;

    // Y1 = 0
    if (this.y.sign() === 0)
      return this;

    // XX = X1^2
    const xx = this.x.redSqr();

    // W = 3 * XX + a
    const w = xx.redMuln(3).redIAdd(this.curve.a);

    // R = 2 * Y1^2
    const r = this.y.redSqr().redIMuln(2);

    // S = 4 * Y1 * R
    const s = this.y.redMul(r).redIMuln(4);

    // RR = R^2
    const rr = r.redSqr();

    // B = (X1 + R)^2 - XX - RR
    const b = r.redIAdd(this.x).redSqr().redISub(xx).redISub(rr);

    // H = W^2 - B - B
    const h = w.redSqr().redISub(b).redISub(b);

    // X = 2 * H * Y1
    const x = h.redMul(this.y).redIMuln(2);

    // Y = W * (B - H) - RR - RR
    const y = w.redMul(b.redISub(h)).redISub(rr).redISub(rr);

    // U = Y1 * S - Y
    const u = this.y.redMul(s).redISub(y);

    // UU = U^2
    const uu = u.redSqr();

    // V = X1 * S - X
    const v = this.x.redMul(s).redISub(x);

    // VV = V^2
    const vv = v.redSqr();

    // VVV = V * VV
    const vvv = vv.redMul(v);

    // K = VV * X
    const k = vv.redMul(x);

    // A = UU * S - VVV - K - K
    const a = uu.redMul(s).redISub(vvv).redISub(k).redISub(k);

    // Z = VVV * S
    const z = vvv.redMul(s);

    // L = 1 / Z
    const l = z.redInvert();

    // X3 = L * V * A
    const nx = l.redMul(v).redMul(a);

    // Y3 = L * (U * (K - A) - VVV * Y)
    const ny = l.redMul(u.redMul(k.redISub(a)).redISub(vvv.redMul(y)));

    return this.curve.point(nx, ny);
  }

  uadd(p) {
    // Unified affine addition (Brier and Joye).
    //
    // Weierstrass Elliptic Curves and Side-Channel Attacks.
    //   Eric Brier, Marc Joye.
    //   Page 5, Section 3.
    //   http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.2.273&rep=rep1&type=pdf
    //
    // Unified Point Addition Formulae and Side-Channel Attacks.
    //   Douglas Stebila, Nicolas Theriault.
    //   Page 4, Section 3.
    //   https://eprint.iacr.org/2005/419.pdf
    //
    // 1I + 3M + 2S + 8A
    assert(p instanceof ShortPoint);

    // O + P = P
    if (this.inf)
      return p;

    // P + O = P
    if (p.inf)
      return this;

    // M = Y1 + Y2
    const m = this.y.redAdd(p.y);

    // A = (X1 + X2)^2
    const a = this.x.redAdd(p.x).redSqr();

    // B = X1 * X2
    const b = this.x.redMul(p.x);

    // R = A - B + a
    const r = a.redISub(b).redIAdd(this.curve.a);

    // M = 0, R = 0: X1 != X2, Y1 = -Y2
    // Generally only happens on endomorphic curves.
    if (m.sign() === 0 && r.sign() === 0) {
      // M = X1 - X2
      m.inject(this.x.redSub(p.x));

      // R = Y1 - Y2
      r.inject(this.y.redSub(p.y));

      assert(m.sign() > 0);
    }

    // M = 0, R != 0: X1 = X2, Y1 = -Y2
    if (m.sign() === 0)
      return this.curve.point();

    // M != 0, R = 0: X1 != X2, Y1 = Y2
    if (r.sign() === 0) {
      assert(this.x.cmp(p.x) !== 0);
      assert(this.y.cmp(p.y) === 0);

      // X3 = -X1 - X2
      const nx = this.x.redNeg().redISub(p.x);

      // Y3 = -Y1
      const ny = this.y.redNeg();

      // Skip the inverse.
      return this.curve.point(nx, ny);
    }

    // L = R / M
    const l = r.redMul(m.redInvert());

    // X3 = L^2 - X1 - X2
    const nx = l.redSqr().redISub(this.x).redISub(p.x);

    // Y3 = L * (X1 - X3) - Y1
    const ny = l.redMul(this.x.redSub(nx)).redISub(this.y);

    return this.curve.point(nx, ny);
  }

  udbl() {
    return this.uadd(this);
  }

  recover(x1, x2) {
    // Brier-Joye Y-coordinate Recovery.
    //
    //   this = base = P - Q = (x, y)
    //   x1 = b = P (x1, y1?)
    //   x2 = a = Q (x2, y2?)
    //
    //   y(P) = (2 * b + (a + x * x1) * (x + x1) - x2 * (x - x1)^2) / (2 * y)
    //
    // See: Weierstrass Elliptic Curves and Side-Channel Attacks.
    //   Eric Brier, Marc Joye.
    //   Proposition 3, Page 7, Section 4.
    //   http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.2.273&rep=rep1&type=pdf
    assert(x1 instanceof BN);
    assert(x2 instanceof BN);

    // P - Q = O (P = Q)
    if (this.inf)
      return this;

    // Y = 0
    if (this.y.sign() === 0)
      return this.curve.point();

    // A = 2 * b
    const a = this.curve.b.redMuln(2);

    // B = a + X * X1
    const b = this.x.redMul(x1).redIAdd(this.curve.a);

    // C = X + X1
    const c = this.x.redAdd(x1);

    // D = A + B * C
    const d = a.redIAdd(b.redMul(c));

    // E = X2 * (X - X1)^2
    const e = x2.redMul(this.x.redSub(x1).redSqr());

    // F = D - E
    const f = d.redISub(e);

    // L = 1 / (2 * Y)
    const l = this.y.redMuln(2).redInvert();

    // X1 = X1
    const nx = x1;

    // Y1 = F * L
    const ny = f.redMul(l);

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

  eq(p) {
    assert(p instanceof ShortPoint);

    // P = Q
    if (this === p)
      return true;

    // P = O
    if (this.inf)
      return p.inf !== 0;

    // Q = O
    if (p.inf)
      return false;

    // X1 = X2, Y1 = Y2
    return this.x.cmp(p.x) === 0
        && this.y.cmp(p.y) === 0;
  }

  isInfinity() {
    // Infinity cannot be represented in
    // the affine space, except by a flag.
    return this.inf !== 0;
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

    return this.getX().imod(this.curve.n).cmp(x) === 0;
  }

  mul(k) {
    return super.mul(k).toP();
  }

  mulSimple(k) {
    return super.mulSimple(k).toP();
  }

  mulBlind(k, rng) {
    return super.mulBlind(k, rng).toP();
  }

  mulConst(k, rng) {
    return super.mulConst(k, rng).toP();
  }

  mulAdd(k1, p2, k2) {
    return super.mulAdd(k1, p2, k2).toP();
  }

  mulAddSimple(k1, p2, k2) {
    return super.mulAddSimple(k1, p2, k2).toP();
  }

  mulH() {
    return super.mulH().toP();
  }

  divH() {
    return super.divH().toP();
  }

  toP() {
    return this;
  }

  toJ() {
    // (X3, Y3, Z3) = (1, 1, 0)
    if (this.inf)
      return this.curve.jpoint();

    // (X3, Y3, Z3) = (X1, Y1, 1)
    return this.curve.jpoint(this.x, this.y, this.curve.one);
  }

  encode(compact) {
    if (compact == null)
      compact = true;

    assert(typeof compact === 'boolean');

    // See SEC1 (page 10, section 2.3.3).
    //
    // For accuracy with openssl:
    //   https://github.com/openssl/openssl/blob/a7f182b/crypto/ec/ec_oct.c#L70
    //   https://github.com/openssl/openssl/blob/a7f182b/crypto/ec/ecp_oct.c#L154
    const {fieldSize} = this.curve;

    // We do not serialize points at infinity.
    if (this.inf)
      throw new Error('Invalid point.');

    // Compressed form (0x02 = even, 0x03 = odd).
    if (compact) {
      const p = Buffer.allocUnsafe(1 + fieldSize);
      const x = this.curve.encodeField(this.getX());

      p[0] = 0x02 | this.y.redIsOdd();
      x.copy(p, 1);

      return p;
    }

    // Uncompressed form (0x04).
    const p = Buffer.allocUnsafe(1 + fieldSize * 2);
    const x = this.curve.encodeField(this.getX());
    const y = this.curve.encodeField(this.getY());

    p[0] = 0x04;
    x.copy(p, 1);
    y.copy(p, 1 + fieldSize);

    return p;
  }

  static decode(curve, bytes) {
    assert(curve instanceof ShortCurve);
    assert(Buffer.isBuffer(bytes));

    // See SEC1 (page 11, section 2.3.4).
    //
    // For accuracy with openssl:
    //   https://github.com/openssl/openssl/blob/a7f182b/crypto/ec/ec_oct.c#L101
    //   https://github.com/openssl/openssl/blob/a7f182b/crypto/ec/ecp_oct.c#L269
    const len = curve.fieldSize;

    if (bytes.length < 1 + len)
      throw new Error('Not a point.');

    // Point forms:
    //
    //   0x00 -> Infinity (openssl, unsupported)
    //   0x02 -> Compressed Even
    //   0x03 -> Compressed Odd
    //   0x04 -> Uncompressed
    //   0x06 -> Hybrid Even (openssl)
    //   0x07 -> Hybrid Odd (openssl)
    //
    // Note that openssl supports serializing points
    // at infinity as {0}. We choose not to support it
    // because it's strange and not terribly useful.
    const form = bytes[0];

    switch (form) {
      case 0x02:
      case 0x03: {
        if (bytes.length !== 1 + len)
          throw new Error('Invalid point size for compressed.');

        const x = curve.decodeField(bytes.slice(1, 1 + len));

        if (x.cmp(curve.p) >= 0)
          throw new Error('Invalid point.');

        const p = curve.pointFromX(x, form === 0x03);

        assert(!p.isInfinity());

        return p;
      }

      case 0x04:
      case 0x06:
      case 0x07: {
        if (bytes.length !== 1 + len * 2)
          throw new Error('Invalid point size for uncompressed.');

        const x = curve.decodeField(bytes.slice(1, 1 + len));
        const y = curve.decodeField(bytes.slice(1 + len, 1 + 2 * len));

        // See: Guide to Elliptic Curve Cryptography.
        // Algorithm 4.3, Page 180, Section 4.
        if (x.cmp(curve.p) >= 0 || y.cmp(curve.p) >= 0)
          throw new Error('Invalid point.');

        // OpenSSL hybrid encoding.
        if (form !== 0x04 && form !== (0x06 | y.isOdd()))
          throw new Error('Invalid hybrid encoding.');

        const p = curve.point(x, y);

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

  toJSON(pre) {
    if (this.inf)
      return [];

    const x = this.getX().toJSON();
    const y = this.getY().toJSON();

    if (pre && this.pre)
      return [x, y, this.pre.toJSON()];

    return [x, y];
  }

  static fromJSON(curve, json) {
    assert(curve instanceof ShortCurve);
    assert(Array.isArray(json));
    assert(json.length === 0
        || json.length === 2
        || json.length === 3);

    if (json.length === 0)
      return curve.point();

    const x = BN.fromJSON(json[0]);
    const y = BN.fromJSON(json[1]);
    const point = curve.point(x, y);

    if (json.length > 2 && json[2] != null)
      point.pre = Precomp.fromJSON(point, json[2]);

    return point;
  }

  [custom]() {
    if (this.inf)
      return '<ShortPoint: Infinity>';

    return '<ShortPoint:'
         + ' x=' + this.x.fromRed().toString(16, 2)
         + ' y=' + this.y.fromRed().toString(16, 2)
         + '>';
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
    this.zOne = 0;

    if (x != null)
      this._init(x, y, z);
  }

  _init(x, y, z) {
    assert(x instanceof BN);
    assert(y instanceof BN);
    assert(z == null || (z instanceof BN));

    this.x = x;
    this.y = y;
    this.z = z || this.curve.one;

    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);

    if (!this.y.red)
      this.y = this.y.toRed(this.curve.red);

    if (!this.z.red)
      this.z = this.z.toRed(this.curve.red);

    this.zOne = this.z.eq(this.curve.one) | 0;
  }

  clone() {
    return this.curve.jpoint(this.x.clone(),
                             this.y.clone(),
                             this.z.clone());
  }

  swap(point, flag) {
    assert(point instanceof JPoint);

    const cond = ((flag >> 31) | (-flag >> 31)) & 1;
    const zOne1 = this.zOne;
    const zOne2 = point.zOne;

    this.x.cswap(point.x, flag);
    this.y.cswap(point.y, flag);
    this.z.cswap(point.z, flag);

    this.zOne = (zOne1 & (cond ^ 1)) | (zOne2 & cond);
    point.zOne = (zOne2 & (cond ^ 1)) | (zOne1 & cond);

    return this;
  }

  validate() {
    // https://hyperelliptic.org/EFD/g1p/auto-shortw.html
    const {a, b} = this.curve;

    // P = O
    if (this.isInfinity())
      return true;

    // Z1 = 1
    if (this.zOne)
      return this.curve.validate(this.toP());

    // y^2 = x^3 + a * z^4 * x + b * z^6
    //
    // Explanation of scaling (term by term):
    //   y^2 = z^3 * 2 = 6
    //   x^3 = z^2 * 3 = 6
    //   a * z^4 * x = z^0 + z^4 + z^2 = 6
    //   b * z^6 = 6
    const y2 = this.y.redSqr();
    const x3 = this.x.redSqr().redMul(this.x);
    const z2 = this.z.redSqr();
    const z4 = z2.redSqr();
    const z6 = z4.redMul(z2);
    const rhs = x3.redIAdd(b.redMul(z6));

    if (!this.curve.zeroA) {
      // Save some cycles for a = -3.
      if (this.curve.threeA)
        rhs.redIAdd(z4.redIMuln(-3).redMul(this.x));
      else
        rhs.redIAdd(a.redMul(z4).redMul(this.x));
    }

    return y2.cmp(rhs) === 0;
  }

  normalize() {
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#scaling-z
    // 1I + 3M + 1S

    // Z = 1
    if (this.zOne)
      return this;

    // P = O
    if (this.isInfinity())
      return this;

    // A = 1 / Z1
    const a = this.z.redInvert();

    // AA = A^2
    const aa = a.redSqr();

    // X3 = X1 * AA
    this.x = this.x.redMul(aa);

    // Y3 = Y1 * AA * A
    this.y = this.y.redMul(aa).redMul(a);

    // Z3 = 1
    this.z = this.curve.one;
    this.zOne = 1;

    return this;
  }

  scale(a) {
    assert(a instanceof BN);

    // P = O
    if (this.isInfinity())
      return this.curve.jpoint();

    // AA = A^2
    const aa = a.redSqr();

    // X3 = X1 * AA
    const nx = this.x.redMul(aa);

    // Y3 = Y1 * AA * A
    const ny = this.y.redMul(aa).redMul(a);

    // Z3 = Z1 * A
    const nz = this.z.redMul(a);

    return this.curve.jpoint(nx, ny, nz);
  }

  neg() {
    // -(X1, Y1, Z1) = (X1, -Y1, Z1)
    return this.curve.jpoint(this.x, this.y.redNeg(), this.z);
  }

  add(p) {
    assert(p instanceof Point);

    if (p.type === types.AFFINE)
      return this._mixedAdd(p);

    return this._add(p);
  }

  _add(p) {
    assert(p instanceof JPoint);

    // O + P = P
    if (this.isInfinity())
      return p;

    // P + O = P
    if (p.isInfinity())
      return this;

    // Z1 = 1, Z2 = 1
    if (this.zOne && p.zOne)
      return this._addAA(p);

    // Z1 = 1
    if (this.zOne)
      return p._addJA(this);

    // Z2 = 1
    if (p.zOne)
      return this._addJA(p);

    return this._addJJ(p);
  }

  _mixedAdd(p) {
    assert(p instanceof ShortPoint);

    // O + P = P
    if (this.isInfinity())
      return p.toJ();

    // P + O = P
    if (p.isInfinity())
      return this;

    // Z1 = 1, Z2 = 1
    if (this.zOne)
      return this._addAA(p);

    return this._addJA(p);
  }

  _addJJ(p) {
    // No assumptions.
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-add-1998-cmo-2
    // 12M + 4S + 6A + 1*2 (implemented as: 12M + 4S + 7A)

    // Z1Z1 = Z1^2
    const z1z1 = this.z.redSqr();

    // Z2Z2 = Z2^2
    const z2z2 = p.z.redSqr();

    // U1 = X1 * Z2Z2
    const u1 = this.x.redMul(z2z2);

    // U2 = X2 * Z1Z1
    const u2 = p.x.redMul(z1z1);

    // S1 = Y1 * Z2 * Z2Z2
    const s1 = this.y.redMul(p.z).redMul(z2z2);

    // S2 = Y2 * Z1 * Z1Z1
    const s2 = p.y.redMul(this.z).redMul(z1z1);

    // H = U2 - U1
    const h = u2.redISub(u1);

    // r = S2 - S1
    const r = s2.redISub(s1);

    // H = 0
    if (h.sign() === 0) {
      if (r.sign() !== 0)
        return this.curve.jpoint();

      return this.dbl();
    }

    // HH = H^2
    const hh = h.redSqr();

    // HHH = H * HH
    const hhh = h.redMul(hh);

    // V = U1 * HH
    const v = u1.redMul(hh);

    // X3 = r^2 - HHH - 2 * V
    const nx = r.redSqr().redISub(hhh).redISub(v).redISub(v);

    // Y3 = r * (V - X3) - S1 * HHH
    const ny = r.redMul(v.redISub(nx)).redISub(s1.redMul(hhh));

    // Z3 = Z1 * Z2 * H
    const nz = this.z.redMul(p.z).redMul(h);

    return this.curve.jpoint(nx, ny, nz);
  }

  _addJA(p) {
    // Assumes Z2 = 1.
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-madd
    // 8M + 3S + 6A + 5*2 (implemented as: 8M + 3S + 7A + 4*2)

    // Z1Z1 = Z1^2
    const z1z1 = this.z.redSqr();

    // U2 = X2 * Z1Z1
    const u2 = p.x.redMul(z1z1);

    // S2 = Y2 * Z1 * Z1Z1
    const s2 = p.y.redMul(this.z).redMul(z1z1);

    // H = U2 - X1
    const h = u2.redISub(this.x);

    // r = 2 * (S2 - Y1)
    const r = s2.redISub(this.y).redIMuln(2);

    // H = 0
    if (h.sign() === 0) {
      if (r.sign() !== 0)
        return this.curve.jpoint();

      return this.dbl();
    }

    // I = (2 * H)^2
    const i = h.redMuln(2).redSqr();

    // J = H * I
    const j = h.redMul(i);

    // V = X1 * I
    const v = this.x.redMul(i);

    // X3 = r^2 - J - 2 * V
    const nx = r.redSqr().redISub(j).redISub(v).redISub(v);

    // Y3 = r * (V - X3) - 2 * Y1 * J
    const ny = r.redMul(v.redISub(nx)).redISub(this.y.redMul(j).redIMuln(2));

    // Z3 = 2 * Z1 * H
    const nz = this.z.redMul(h).redIMuln(2);

    return this.curve.jpoint(nx, ny, nz);
  }

  _addAA(p) {
    // Assumes Z1 = 1, Z2 = 1.
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-mmadd-2007-bl
    // 4M + 2S + 6A + 4*2 + 1*4 (implemented as: 4M + 2S + 7A + 3*2 + 1*4)

    // H = X2 - X1
    const h = p.x.redSub(this.x);

    // r = 2 * (Y2 - Y1)
    const r = p.y.redSub(this.y).redIMuln(2);

    // H = 0
    if (h.sign() === 0) {
      if (r.sign() !== 0)
        return this.curve.jpoint();

      return this.dbl();
    }

    // HH = H^2
    const hh = h.redSqr();

    // I = 4 * HH
    const i = hh.redIMuln(4);

    // J = H * I
    const j = h.redMul(i);

    // V = X1 * I
    const v = this.x.redMul(i);

    // X3 = r^2 - J - 2 * V
    const nx = r.redSqr().redISub(j).redISub(v).redISub(v);

    // Y3 = r * (V - X3) - 2 * Y1 * J
    const ny = r.redMul(v.redISub(nx)).redISub(this.y.redMul(j).redIMuln(2));

    // Z3 = 2 * H
    const nz = h.redIMuln(2);

    return this.curve.jpoint(nx, ny, nz);
  }

  dbl() {
    // P = O
    if (this.isInfinity())
      return this;

    // Y1 = 0
    if (this.y.sign() === 0)
      return this.curve.jpoint();

    // Z1 = 1
    if (this.zOne)
      return this._dblA();

    // a = 0
    if (this.curve.zeroA)
      return this._dbl0();

    // a = -3
    if (this.curve.threeA)
      return this._dbl3();

    return this._dblJ();
  }

  _dblJ() {
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-1998-cmo-2
    // 3M + 6S + 4A + 1*a + 2*2 + 1*3 + 1*4 + 1*8
    // (implemented as: 3M + 6S + 5A + 1*a + 1*2 + 1*3 + 1*4 + 1*8)

    // XX = X1^2
    const xx = this.x.redSqr();

    // YY = Y1^2
    const yy = this.y.redSqr();

    // ZZ = Z1^2
    const zz = this.z.redSqr();

    // S = 4 * X1 * YY
    const s = this.x.redMul(yy).redIMuln(4);

    // M = 3 * XX + a * ZZ^2
    const m = xx.redIMuln(3).redIAdd(this.curve.a.redMul(zz.redSqr()));

    // T = M^2 - 2 * S
    const t = m.redSqr().redISub(s).redISub(s);

    // X3 = T
    const nx = t;

    // Y3 = M * (S - T) - 8 * YY^2
    const ny = m.redMul(s.redISub(t)).redISub(yy.redSqr().redIMuln(8));

    // Z3 = 2 * Y1 * Z1
    const nz = this.y.redMul(this.z).redIMuln(2);

    return this.curve.jpoint(nx, ny, nz);
  }

  _dblA() {
    // Assumes Z = 1.
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-mdbl-2007-bl
    // 1M + 5S + 7A + 3*2 + 1*3 + 1*8
    // (implemented as: 1M + 5S + 8A + 2*2 + 1*3 + 1*8)

    // XX = X1^2
    const xx = this.x.redSqr();

    // YY = Y1^2
    const yy = this.y.redSqr();

    // YYYY = YY^2
    const yyyy = yy.redSqr();

    // + XYY2 = (X1 + YY)^2
    const xyy2 = yy.redIAdd(this.x).redSqr();

    // S = 2 * ((X1 + YY)^2 - XX - YYYY)
    const s = xyy2.redISub(xx).redISub(yyyy).redIMuln(2);

    // M = 3 * XX + a
    const m = xx.redIMuln(3).redIAdd(this.curve.a);

    // T = M^2 - 2 * S
    const t = m.redSqr().redISub(s).redISub(s);

    // X3 = T
    const nx = t;

    // Y3 = M * (S - T) - 8 * YYYY
    const ny = m.redMul(s.redISub(t)).redISub(yyyy.redIMuln(8));

    // Z3 = 2 * Y1
    const nz = this.y.redMuln(2);

    return this.curve.jpoint(nx, ny, nz);
  }

  _dbl0() {
    // Assumes a = 0.
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
    // 2M + 5S + 6A + 3*2 + 1*3 + 1*8
    // (implemented as: 2M + 5S + 7A + 2*2 + 1*3 + 1*8)

    // A = X1^2
    const a = this.x.redSqr();

    // B = Y1^2
    const b = this.y.redSqr();

    // C = B^2
    const c = b.redSqr();

    // + XB2 = (X1 + B)^2
    const xb2 = b.redIAdd(this.x).redSqr();

    // D = 2 * ((X1 + B)^2 - A - C)
    const d = xb2.redISub(a).redISub(c).redIMuln(2);

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

  _dbl3() {
    // Assumes a = -3.
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
    // 3M + 5S + 8A + 1*3 + 1*4 + 2*8
    // (implemented as: 3M + 5S + 8A + 1*2 + 1*3 + 1*4 + 1*8)

    // delta = Z1^2
    const delta = this.z.redSqr();

    // gamma = Y1^2
    const gamma = this.y.redSqr();

    // beta = X1 * gamma
    const beta = this.x.redMul(gamma);

    // + xmdelta = X1 - delta
    const xmdelta = this.x.redSub(delta);

    // + xpdelta = X1 + delta
    const xpdelta = this.x.redAdd(delta);

    // alpha = 3 * (X1 - delta) * (X1 + delta)
    const alpha = xmdelta.redMul(xpdelta).redIMuln(3);

    // + beta4 = 4 * beta
    const beta4 = beta.redIMuln(4);

    // + beta8 = 2 * beta4
    const beta8 = beta4.redMuln(2);

    // + gamma28 = 8 * gamma^2
    const gamma28 = gamma.redSqr().redIMuln(8);

    // X3 = alpha^2 - 8 * beta
    const nx = alpha.redSqr().redISub(beta8);

    // Z3 = (Y1 + Z1)^2 - gamma - delta
    const nz = this.y.redAdd(this.z).redSqr().redISub(gamma).redISub(delta);

    // Y3 = alpha * (4 * beta - X3) - 8 * gamma^2
    const ny = alpha.redMul(beta4.redISub(nx)).redISub(gamma28);

    return this.curve.jpoint(nx, ny, nz);
  }

  dblp(pow) {
    assert((pow >>> 0) === pow);

    // a = 0 or a = -3
    if (this.curve.zeroA || this.curve.threeA)
      return super.dblp(pow);

    // m = 0
    if (pow === 0)
      return this;

    // P = O
    if (this.isInfinity())
      return this;

    return this._dblp(pow);
  }

  _dblp(pow) {
    // Repeated point doubling (Jacobian coordinates).
    //
    // See: Guide to Elliptic Curve Cryptography.
    // Algorithm 3.23, Page 93, Section 3.5.
    //
    // Modified version of:
    //   https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-1998-cmo-2
    //
    // Divergences from the above formula are marked with diff notation.
    //
    // Implemented as:
    //   1M + 2S + 1*2 + N * (4M + 4S + 4A + 1*a + 1*3 + 2*2)
    //   e.g. N = 1 => 5M + 6S + 4A + 1*a + 1*3 + 3*2
    //
    // Repeated doubling also explained here:
    //   https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates
    //
    // Note that the above sources change:
    //   M = 3 * XX + a * ZZZZ
    // To:
    //   M = 3 * (XX - ZZZZ)
    //
    // In order to assume a=-3.
    const {a, i2} = this.curve;

    // Reuse results (y is always y*2).
    let x = this.x;
    let z = this.z;

    // + Y1 = Y1 * 2
    let y = this.y.redMuln(2);

    // + ZZZZ = Z1^4
    let zzzz = z.redPown(4);

    for (let i = 0; i < pow; i++) {
      // Y1 = 0
      if (y.sign() === 0)
        return this.curve.jpoint();

      // XX = X1^2
      const xx = x.redSqr();

      // YY = Y1^2
      const yy = y.redSqr();

      // + YYYY = YY^2
      const yyyy = yy.redSqr();

      // - M = 3 * XX + a * ZZ^2
      // + M = 3 * XX + a * ZZZZ
      const m = xx.redIMuln(3).redIAdd(a.redMul(zzzz));

      // - S = 4 * X1 * YY
      // + S = X1 * YY
      const s = x.redMul(yy);

      // T = M^2 - 2 * S
      const t = m.redSqr().redISub(s).redISub(s);

      // X3 = T
      const nx = t;

      // - Y3 = M * (S - T) - 8 * YY^2
      // + Y3 = M * (S - T) * 2 - YYYY
      const ny = m.redMul(s.redISub(t)).redIMuln(2).redISub(yyyy);

      // Z3 = 2 * Y1 * Z1
      const nz = y.redMul(z);

      // + ZZZZ = ZZZZ * YYYY
      if (i + 1 < pow)
        zzzz = zzzz.redMul(yyyy);

      // + X1 = X3
      x = nx;

      // + Y1 = Y3
      y = ny;

      // + Z1 = Z3
      z = nz;
    }

    return this.curve.jpoint(x, y.redMul(i2), z);
  }

  trpl() {
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#tripling-tpl-2007-bl
    // 5M + 10S + 15A + 1*a + 1*3 + 2*4 + 1*6 + 1*8 + 1*16

    // P = O
    if (this.isInfinity())
      return this;

    // Y1 = 0
    if (this.y.sign() === 0)
      return this;

    // XX = X1^2
    const xx = this.x.redSqr();

    // YY = Y1^2
    const yy = this.y.redSqr();

    // ZZ = Z1^2
    const zz = this.z.redSqr();

    // YYYY = YY^2
    const yyyy = yy.redSqr();

    // M = 3 * XX
    const m = xx.redMuln(3);

    // M = M + a * ZZ^2 (if a != 0)
    if (!this.curve.zeroA) {
      const zzzz = zz.redSqr();

      // Save some cycles for a = -3.
      if (this.curve.threeA)
        m.redIAdd(zzzz.redIMuln(-3));
      else
        m.redIAdd(this.curve.a.redMul(zzzz));
    }

    // MM = M^2
    const mm = m.redSqr();

    // + XYY2 = (X1 + YY)^2
    const xyy2 = this.x.redAdd(yy).redSqr();

    // E = 6 * ((X1 + YY)^2 - XX - YYYY) - MM
    const e = xyy2.redISub(xx).redISub(yyyy).redIMuln(6).redISub(mm);

    // EE = E^2
    const ee = e.redSqr();

    // T = 16 * YYYY
    const t = yyyy.redIMuln(16);

    // U = (M + E)^2 - MM - EE - T
    const u = m.redIAdd(e).redSqr().redISub(mm).redISub(ee).redISub(t);

    // + YYU4 = 4 * YY * U
    const yyu4 = yy.redMul(u).redIMuln(4);

    // + UTU = U * (T - U)
    const utu = u.redMul(t.redISub(u));

    // + EEE = E * EE
    const eee = e.redMul(ee);

    // X3 = 4 * (X1 * EE - 4 * YY * U)
    const nx = this.x.redMul(ee).redISub(yyu4).redIMuln(4);

    // Y3 = 8 * Y1 * (U * (T - U) - E * EE)
    const ny = this.y.redMul(utu.redISub(eee)).redIMuln(8);

    // Z3 = (Z1 + E)^2 - ZZ - EE
    const nz = e.redIAdd(this.z).redSqr().redISub(zz).redISub(ee);

    return this.curve.jpoint(nx, ny, nz);
  }

  uadd(p) {
    assert(p instanceof Point);

    if (p.type === types.AFFINE)
      return this._uadd(p.toJ());

    return this._uadd(p);
  }

  _uadd(p) {
    // Strongly unified jacobian addition (Brier and Joye).
    //
    // Weierstrass Elliptic Curves and Side-Channel Attacks.
    //   Eric Brier, Marc Joye.
    //   Page 6, Section 3.
    //   http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.2.273&rep=rep1&type=pdf
    //
    // Unified Point Addition Formulae and Side-Channel Attacks.
    //   Douglas Stebila, Nicolas Theriault.
    //   Page 4, Section 3.
    //   https://eprint.iacr.org/2005/419.pdf
    //
    // Explicit-Formulas Database
    //   https://hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-2002-bj
    //
    // libsecp256k1
    //   https://github.com/bitcoin-core/secp256k1/blob/ee9e68c/src/group_impl.h#L525
    //
    // The above documents use projective coordinates. The
    // formula below was heavily adapted from libsecp256k1.
    //
    // Note that while this function is branchless, it will
    // not be constant-time until bn.js is rewritten as
    // constant time (bn.js would require require 15 bit
    // limbs, fixed size, and no optimizations in order
    // for this to happen).
    //
    // 11M + 8S + 7A + 1*a + 2*4 + 1*3 + 2*2 (a != 0)
    // 11M + 6S + 6A + 2*4 + 1*3 + 2*2 (a = 0)
    assert(p instanceof JPoint);

    const {zero, one} = this.curve;

    // Z1Z1 = Z1^2
    const z1z1 = this.z.redSqr();

    // Z2Z2 = Z2^2
    const z2z2 = p.z.redSqr();

    // U1 = X1 * Z2Z2
    const u1 = this.x.redMul(z2z2);

    // U2 = X2 * Z1Z1
    const u2 = p.x.redMul(z1z1);

    // S1 = Y1 * Z2Z2 * Z2
    const s1 = this.y.redMul(z2z2).redMul(p.z);

    // S2 = Y2 * Z1Z1 * Z1
    const s2 = p.y.redMul(z1z1).redMul(this.z);

    // Z = Z1 * Z2
    const z = this.z.redMul(p.z);

    // T = U1 + U2
    const t = u1.redAdd(u2);

    // M = S1 + S2
    const m = s1.redAdd(s2);

    // R = T^2 - U1 * U2
    const r = t.redSqr().redISub(u1.redMul(u2));

    // R = R + a * Z^4 (if a != 0)
    if (!this.curve.zeroA) {
      const zzzz = z.redPown(4);

      // Save some cycles for a = -3.
      if (this.curve.threeA)
        r.redIAdd(zzzz.redIMuln(-3));
      else
        r.redIAdd(this.curve.a.redMul(zzzz));
    }

    // Check for degenerate points (x1 != x2, y1 = -y2).
    // Generally only happens on endomorphic curves.
    const degenerate = m.czero() & r.czero();

    // M = U1 - U2 (if degenerate = 1)
    m.cinject(u1.redSub(u2), degenerate);

    // R = S1 - S2 (if degenerate = 1)
    r.cinject(s1.redSub(s2), degenerate);

    // L = M^2
    const l = m.redSqr();

    // G = T * L
    const g = t.redMul(l);

    // LL = L^2
    const ll = l.redSqr();

    // LL = 0 (if degenerate = 1)
    ll.cinject(zero, degenerate);

    // W = R^2
    const w = r.redSqr();

    // F = Z * M
    const f = z.redMul(m);

    // H = 3 * G - 2 * W
    const h = g.redMuln(3).redISub(w.redMuln(2));

    // X3 = 4 * (W - G)
    const nx = w.redISub(g).redIMuln(4);

    // Y3 = 4 * (R * H - LL)
    const ny = r.redMul(h).redISub(ll).redIMuln(4);

    // Z3 = 2 * F
    const nz = f.redIMuln(2);

    // Check for infinity.
    const ai = this.z.czero();
    const bi = p.z.czero();
    const fi = f.czero();
    const ni = fi & (ai ^ 1) & (bi ^ 1);

    // X3 = X1 (if Z2 = 0)
    nx.cinject(this.x, bi);

    // Y3 = Y1 (if Z2 = 0)
    ny.cinject(this.y, bi);

    // Z3 = Z1 (if Z2 = 0)
    nz.cinject(this.z, bi);

    // X3 = X2 (if Z1 = 0)
    nx.cinject(p.x, ai);

    // Y3 = Y2 (if Z1 = 0)
    ny.cinject(p.y, ai);

    // Z3 = Z2 (if Z1 = 0)
    nz.cinject(p.z, ai);

    // X3 = 1 (if Z3 = 0, Z1 != 0, Z2 != 0)
    nx.cinject(one, ni);

    // Y3 = 1 (if Z3 = 0, Z1 != 0, Z2 != 0)
    ny.cinject(one, ni);

    // Z3 = 0 (if Z3 = 0, Z1 != 0, Z2 != 0)
    nz.cinject(zero, ni);

    assert(((ai & bi) ^ 1) | nz.czero());

    return this.curve.jpoint(nx, ny, nz);
  }

  udbl() {
    return this._uadd(this);
  }

  zaddu(p) {
    // Co-Z addition with update (ZADDU).
    // https://www.matthieurivain.com/files/jcen11b.pdf
    // Algorithm 19, Page 15, Appendix C.
    // 5M + 2S + 7A
    assert(p instanceof JPoint);

    // H = X1 - X2
    const h = this.x.redSub(p.x);

    // R = Y1 - Y2
    const r = this.y.redSub(p.y);

    // HH = H^2
    const hh = h.redSqr();

    // V1 = X1 * HH
    const v1 = this.x.redMul(hh);

    // V2 = X2 * HH
    const v2 = p.x.redMul(hh);

    // X4 = V1
    const x4 = v1;

    // X3 = R^2 - V1 - V2
    const x3 = r.redSqr().redISub(v1).redISub(v2);

    // Y4 = Y1 * (V1 - V2)
    const y4 = this.y.redMul(v1.redSub(v2));

    // Y3 = R * (X4 - X3) - Y4
    const y3 = r.redMul(x4.redSub(x3)).redISub(y4);

    // Z4 = Z1 * H
    const z4 = this.z.redMul(h);

    // Z3 = Z4
    const z3 = z4;

    // R = (X3, Y3, Z3)
    // P = (X4, Y4, Z4)
    return [
      this.curve.jpoint(x3, y3, z3),
      this.curve.jpoint(x4, y4, z4)
    ];
  }

  zaddc(p) {
    // Co-Z addition with conjugate (ZADDC).
    // https://www.matthieurivain.com/files/jcen11b.pdf
    // Algorithm 20, Page 15, Appendix C.
    // 6M + 3S + 14A + 1*2
    assert(p instanceof JPoint);

    // H = X1 - X2
    const h = this.x.redSub(p.x);

    // R = Y1 - Y2
    const r = this.y.redSub(p.y);

    // M = Y1 + Y2
    const m = this.y.redAdd(p.y);

    // HH = H^2
    const hh = h.redSqr();

    // V1 = X1 * HH
    const v1 = this.x.redMul(hh);

    // V2 = X2 * HH
    const v2 = p.x.redMul(hh);

    // X4 = (Y1 + Y2)^2 - V1 - V2
    const x4 = m.redSqr().redISub(v1).redISub(v2);

    // X3 = R^2 - V1 - V2
    const x3 = r.redSqr().redISub(v1).redISub(v2);

    // Y = Y1 * (V2 - V1)
    const y = this.y.redMul(v2.redISub(v1));

    // Z = R + 2 * Y2
    const z = p.y.redMuln(2).redIAdd(r);

    // I = V1 - X4
    const i = v1.redISub(x4);

    // J = X4 + I - X3
    const j = x4.redAdd(i).redISub(x3);

    // Y4 = Z * I + Y
    const y4 = z.redMul(i).redIAdd(y);

    // Y3 = R * J + Y
    const y3 = r.redMul(j).redIAdd(y);

    // Z4 = Z1 * H
    const z4 = this.z.redMul(h);

    // Z3 = Z4
    const z3 = z4;

    // R = (X3, Y3, Z3)
    // S = (X4, Y4, Z4)
    return [
      this.curve.jpoint(x3, y3, z3),
      this.curve.jpoint(x4, y4, z4)
    ];
  }

  zdblu() {
    // Co-Z doubling with update (DBLU).
    // https://www.matthieurivain.com/files/jcen11b.pdf
    // Algorithm 21, Page 15, Appendix C.
    //
    // 1M + 5S + 8A + 4*2 + 1*8
    //
    // Note that the original formula assumed Z1=1.
    // We have modified it to allow for scaled points.
    //
    // New Cost: 2M + 5S + 8A + 1*a + 1*3 + 2*2 + 1*8

    // XX = X1^2
    const xx = this.x.redSqr();

    // YY = Y1^2
    const yy = this.y.redSqr();

    // YYYY = YY^2
    const yyyy = yy.redSqr();

    // S = (X1 + YY)^2
    const s = this.x.redAdd(yy).redSqr();

    // M = 3 * XX
    const m = xx.redMuln(3);

    // M = M + a * Z1^4 (if a != 0)
    if (!this.curve.zeroA) {
      const zzzz = this.z.redPown(4);

      // Save some cycles for a = -3.
      if (this.curve.threeA)
        m.redIAdd(zzzz.redIMuln(-3));
      else
        m.redIAdd(this.curve.a.redMul(zzzz));
    }

    // X4 = 2 * (S - XX - YYYY)
    const x4 = s.redISub(xx).redISub(yyyy).redIMuln(2);

    // X3 = M^2 - X4 - X4
    const x3 = m.redSqr().redISub(x4).redISub(x4);

    // Y4 = 8 * YYYY
    const y4 = yyyy.redIMuln(8);

    // Y3 = (X4 - X3) * M - Y4
    const y3 = x4.redSub(x3).redMul(m).redISub(y4);

    // Z4 = 2 * (Y1 * Z1)
    const z4 = this.y.redMul(this.z).redIMuln(2);

    // Z3 = Z4
    const z3 = z4;

    // R = (X3, Y3, Z3)
    // P = (X4, Y4, Z4)
    return [
      this.curve.jpoint(x3, y3, z3),
      this.curve.jpoint(x4, y4, z4)
    ];
  }

  ztrplu() {
    // Co-Z tripling with update (TPLU).
    // https://www.matthieurivain.com/files/jcen11b.pdf
    // Algorithm 22, Page 16, Appendix C.
    // 6M + 7S + 15A + 4*2 + 1*8

    // (R, P) = DBLU(P)
    const [r, p] = this.zdblu();

    // (R, P) = ZADDU(P, R)
    return p.zaddu(r);
  }

  recover(x1, x2) {
    // Brier-Joye Y-coordinate Recovery.
    //
    //   this = base = P - Q = (x, y)
    //   x1 = b = P (x1, y1?)
    //   x2 = a = Q (x2, y2?)
    //
    //   y(P) = (2 * b + (a + x * x1) * (x + x1) - x2 * (x - x1)^2) / (2 * y)
    //
    // See: Weierstrass Elliptic Curves and Side-Channel Attacks.
    //   Eric Brier, Marc Joye.
    //   Proposition 3, Page 7, Section 4.
    //   http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.2.273&rep=rep1&type=pdf
    assert(x1 instanceof BN);
    assert(x2 instanceof BN);

    // P - Q = O (P = Q)
    if (this.isInfinity())
      return this.curve.jpoint();

    // Y = 0
    if (this.y.sign() === 0)
      return this.curve.jpoint();

    // Z1 = 1
    if (this.zOne)
      return this._recoverA(x1, x2);

    return this._recoverJ(x1, x2);
  }

  _recoverJ(x1, x2) {
    // Adapted from Brier and Joye's affine formula.
    // (if someone finds a faster one, let me know).
    // 11M + 3S + 6A + 1*b + 1*a + 2*2

    // ZZ = Z1^2
    const zz = this.z.redSqr();

    // ZZZ = Z1^3
    const zzz = zz.redMul(this.z);

    // ZZZZ = Z1^4
    const zzzz = zzz.redMul(this.z);

    // U1 = X1 * ZZ
    const u1 = x1.redMul(zz);

    // U2 = X2 * ZZ
    const u2 = x2.redMul(zz);

    // A = 2 * b * ZZZZ * ZZ
    const a = this.curve.b.redMul(zzzz).redMul(zz).redIMuln(2);

    // B = X * U1
    const b = this.x.redMul(u1);

    // B = B + a * ZZZZ
    if (!this.curve.zeroA) {
      // Save some cycles for a = -3.
      if (this.curve.threeA)
        b.redIAdd(zzzz.redIMuln(-3));
      else
        b.redIAdd(this.curve.a.redMul(zzzz));
    }

    // C = X + U1
    const c = this.x.redAdd(u1);

    // D = A + B * C
    const d = a.redIAdd(b.redMul(c));

    // E = U2 * (X - U1)^2
    const e = u2.redMul(this.x.redSub(u1).redSqr());

    // F = D - E
    const f = d.redISub(e);

    // L = 2 * Y * ZZZ
    const l = this.y.redMul(zzz).redIMuln(2);

    // LL = L^2
    const ll = l.redSqr();

    // X3 = X1 * LL
    const nx = x1.redMul(ll);

    // Y3 = F * LL
    const ny = f.redMul(ll);

    // Z3 = L
    const nz = l;

    return this.curve.jpoint(nx, ny, nz);
  }

  _recoverA(x1, x2) {
    // 5M + 2S + 5A + 2*2

    // A = 2 * b
    const a = this.curve.b.redMuln(2);

    // B = a + X * X1
    const b = this.x.redMul(x1).redIAdd(this.curve.a);

    // C = X + X1
    const c = this.x.redAdd(x1);

    // D = A + B * C
    const d = a.redIAdd(b.redMul(c));

    // E = X2 * (X - X1)^2
    const e = x2.redMul(this.x.redSub(x1).redSqr());

    // F = D - E
    const f = d.redISub(e);

    // L = 2 * Y
    const l = this.y.redMuln(2);

    // LL = L^2
    const ll = l.redSqr();

    // X3 = X1 * LL
    const nx = x1.redMul(ll);

    // Y3 = F * LL
    const ny = f.redMul(ll);

    // Z3 = L
    const nz = l;

    return this.curve.jpoint(nx, ny, nz);
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

  eq(p) {
    assert(p instanceof JPoint);

    // P = Q
    if (this === p)
      return true;

    // P = O
    if (this.isInfinity())
      return p.isInfinity();

    // Q = O
    if (p.isInfinity())
      return false;

    // Z1 = Z2
    if (this.z.cmp(p.z) === 0) {
      return this.x.cmp(p.x) === 0
          && this.y.cmp(p.y) === 0;
    }

    // X1 * Z2^2 == X2 * Z1^2
    const zz1 = this.z.redSqr();
    const zz2 = p.z.redSqr();
    const x1 = this.x.redMul(zz2);
    const x2 = p.x.redMul(zz1);

    if (x1.cmp(x2) !== 0)
      return false;

    // Y1 * Z2^3 == Y2 * Z1^3
    const zzz1 = zz1.redMul(this.z);
    const zzz2 = zz2.redMul(p.z);
    const y1 = this.y.redMul(zzz2);
    const y2 = p.y.redMul(zzz1);

    return y1.cmp(y2) === 0;
  }

  isInfinity() {
    // Z1 = 0
    return this.z.sign() === 0;
  }

  hasQuadY() {
    // Fails if P = O.
    return this.y.redMul(this.z).redJacobi() === 1;
  }

  eqX(x) {
    assert(x instanceof BN);

    if (this.isInfinity())
      return false;

    // Verify that integer `x` is equal to field
    // element `x` by scaling it by our z coordinate.
    // This optimization is mentioned in and used for
    // bip-schnorr[1]. This avoids having to affinize
    // the resulting point during verification.
    //
    // [1] https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#Optimizations
    const zz = this.z.redSqr();
    const rx = x.toRed(this.curve.red).redMul(zz);

    return this.x.cmp(rx) === 0;
  }

  eqXToP(x) {
    assert(x instanceof BN);
    assert(this.curve.maxwellTrick);

    if (this.isInfinity())
      return false;

    // Similar to the optimization above, this
    // optimization, suggested by Maxwell[1],
    // compares an integer to an X coordinate
    // by scaling it.
    //
    // Since a signature's R value is modulo N
    // in ECDSA, we may be dealing with an R
    // value greater than N in actuality.
    //
    // If the equality check fails, we can
    // scale N itself by Z and add it to the
    // X field element (up until a certain
    // limit) and repeat the check. This
    // function should only be called on low
    // cofactor curves.
    //
    // [1] https://github.com/bitcoin-core/secp256k1/commit/ce7eb6f
    const zz = this.z.redSqr();
    const rx = x.toRed(this.curve.red).redMul(zz);

    if (this.x.cmp(rx) === 0)
      return true;

    const c = x.clone();
    const t = this.curve.redN.redMul(zz);

    for (;;) {
      c.iadd(this.curve.n);

      if (c.cmp(this.curve.p) >= 0)
        return false;

      rx.redIAdd(t);

      if (this.x.cmp(rx) === 0)
        break;
    }

    return true;
  }

  toP() {
    // P = O
    if (this.isInfinity())
      return this.curve.point();

    this.normalize();

    // (X3, Y3) = (X1 / Z1, Y1 / Z1)
    return this.curve.point(this.x, this.y);
  }

  toJ() {
    return this;
  }

  encode(compact) {
    return this.toP().encode(compact);
  }

  static decode(curve, bytes) {
    return ShortPoint.decode(curve, bytes).toJ();
  }

  toJSON(pre) {
    return this.toP().toJSON(pre);
  }

  static fromJSON(curve, json) {
    return ShortPoint.fromJSON(curve, json).toJ();
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
}

/**
 * MontCurve
 */

class MontCurve extends Curve {
  constructor(conf) {
    super('mont', conf);

    this.a = BN.fromJSON(conf.a).toRed(this.red);
    this.b = BN.fromJSON(conf.b).toRed(this.red);
    this.u = BN.fromJSON(conf.u).toRed(this.red);
    this.bi = this.b.redInvert();
    this.i2 = new BN(2).toRed(this.red).redInvert();
    this.i4 = new BN(4).toRed(this.red).redInvert();
    this.a2 = this.a.redAdd(this.two);
    this.a24 = this.a2.redMul(this.i4);
    this.ladder = this.a2.cmp(this.a24.redMuln(4)) === 0;

    this._finalize(conf);
  }

  precompute(rng) {
    // No-op.
    return this;
  }

  point(x, z) {
    return new MontPoint(this, x, z);
  }

  jpoint(x, y, z) {
    assert(x == null && y == null && z == null);
    return this.point();
  }

  solveY2(x) {
    // https://hyperelliptic.org/EFD/g1p/auto-montgom.html
    assert(x instanceof BN);

    // b * y^2 = x^3 + a * x^2 + x
    const x2 = x.redSqr();
    const x3 = x2.redMul(x);
    const by2 = x3.redIAdd(this.a.redMul(x2)).redIAdd(x);
    const y2 = by2.redMul(this.bi);

    return y2;
  }

  validate(point) {
    assert(point instanceof MontPoint);

    if (point.isInfinity())
      return true;

    const x = point.normalize().x;
    const y2 = this.solveY2(x);

    return y2.redJacobi() !== -1;
  }

  pointFromX(x, sign) {
    assert(x instanceof BN);

    if (!x.red)
      x = x.toRed(this.red);

    return this.point(x, this.one);
  }

  pointFromEdwards(point) {
    // Birational equivalence.
    //
    // See: Elliptic Curves for Security.
    //   A. Langley, M. Hamburg, S. Turner.
    //   Section 4.1 & 4.2.
    //   https://tools.ietf.org/html/rfc7748#section-4.1
    //   https://tools.ietf.org/html/rfc7748#section-4.2
    //
    // Also: Montgomery Curves and their arithmetic.
    //   C. Costello, B. Smith.
    //   Page 6, Section 2.5.
    //   https://eprint.iacr.org/2017/212.pdf
    assert(point instanceof EdwardsPoint);

    // P = O
    if (point.isInfinity())
      return this.point();

    // Montgomery `u`, `z`.
    let nx, nz;

    if (point.curve.twisted) {
      // P = (x, 1) = O
      if (point.y.eq(point.z))
        return this.point();

      // P = (0, y) = (0, 0)
      if (point.x.isZero())
        return this.point(this.curve.zero);

      // Birational maps:
      //
      //   u = (1 + y) / (1 - y)
      //   v = sqrt(-a - 2) * u / x
      //
      // Undefined for x = 0 or y = 1.
      nx = point.z.redAdd(point.y);
      nz = point.z.redSub(point.y);
    } else if (point.curve.iso4) {
      // 4-isogeny maps:
      //
      //   u = y^2 / x^2
      //   v = (2 - x^2 - y^2) * y / x^3
      //
      // Should always hold true.
      nx = point.y.redSqr();
      nz = point.x.redSqr();
    } else {
      // P = (x, 1) = O
      if (point.y.eq(point.z))
        return this.point();

      // P = (0, y) = (0, 0)
      if (point.x.isZero())
        return this.point(this.curve.zero);

      // Note: Curve448 is 4-isogenous to Ed448. It
      // is birationally equivalent to an unnamed
      // Edwards curve with d = 39082 / 39081. The
      // RFC linked above mentions it, however it
      // mistakenly lists the wrong base point. It
      // seems as though the maps are incorrect as
      // well: negating `y` appears to fix it.
      //
      // Birational maps:
      //
      //   u = (-y - 1) / (-y + 1)
      //   v = sqrt(a - 2) * u / x
      //
      // Undefined for x = 0 or y = 1.
      nx = point.y.redNeg().redISub(point.z);
      nz = point.y.redNeg().redIAdd(point.z);
    }

    // Montgomery point.
    return this.point(nx.fromRed(), nz.fromRed());
  }

  elligator(r) {
    assert(r instanceof BN);

    // Elligator 2
    //
    // See: Elliptic-curve points indistinguishable from uniform random strings.
    //   D. Bernstein, M. Hamburg, A. Krasnova, T. Lange.
    //   Page 11, Section 5.2.
    //   Page 12, Section 5.3.
    //   https://elligator.cr.yp.to/elligator-20130828.pdf
    //
    // Other Resources:
    //   https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve
    //   https://safecurves.cr.yp.to/ind.html
    //
    // Assumptions:
    //
    //   - Let q be an odd prime power.
    //   - Let A and B be elements of F(q) such that AB(A^2 - 4B) != 0.
    //   - Let u be a non-square in F(q).
    //   - Furthermore vexy != 0 and y^2 = x^3 + Ax^2 + Bx.
    //
    // Map:
    //
    //   f(a) = a^((q - 1) / 2)
    //   v = -A / (1 + u * r^2)
    //   e = f(v^3 + A * v^2 + B * v)
    //   x = e * v - (1 - e) * A / 2
    //   y = -e * sqrt(x^3 + A * x^2 + B * x)
    const lhs = this.a.redNeg();
    const rhs = this.one.redAdd(this.u.redMul(r.redSqr()));

    rhs.cinject(this.one, rhs.czero());

    const v = lhs.redMul(rhs.redFermat());
    const v2 = v.redSqr();
    const v3 = v2.redMul(v);
    const f = v3.redIAdd(this.a.redMul(v2)).redIAdd(this.b.redMul(v));
    const e = f.redPow(this.p.subn(1).iushrn(1));
    const l = this.one.redSub(e).redMul(this.a).redMul(this.i2);
    const x = e.redMul(v).redISub(l);

    return [this.point(x), r.redIsOdd()];
  }

  invert(p, sign) {
    assert(p instanceof MontPoint);

    // Inverting the Map (Elligator 2)
    //
    // Assumptions:
    //
    //   - x != -A.
    //   - If y = 0 then x = 0, and -ux(x + A) is a square in F(q).
    //
    // Map:
    //
    //   r = sqrt(-x / ((x + A) * u)) if y is in F(q / 2)
    //     = sqrt(-(x + A) / (u * x)) otherwise
    const x = p.normalize().x;
    const y = p.getY(sign);

    let lhs, rhs;

    if (y.cmp(this.p.ushrn(1)) < 0) {
      lhs = x.redNeg();
      rhs = x.redAdd(this.a).redMul(this.u);
    } else {
      lhs = x.redAdd(this.a).redINeg();
      rhs = this.u.redMul(x);
    }

    const r = lhs.redMul(rhs.redInvert()).redSqrt();

    if (r.redIsOdd() !== Boolean(sign))
      r.redINeg();

    return r;
  }

  randomPoint(rng) {
    for (;;) {
      const x = this.randomField(rng);
      const p = this.point(x, this.one);

      if (!p.validate())
        continue;

      return p;
    }
  }

  jmulAll(points, coeffs) {
    throw new Error('Not implemented.');
  }

  jmulAllSimple(points, coeffs) {
    throw new Error('Not implemented.');
  }

  decodePoint(bytes) {
    return MontPoint.decode(this, bytes);
  }

  pointFromJSON(json) {
    return MontPoint.fromJSON(this, json);
  }

  toJSON(pre) {
    const json = super.toJSON(pre);
    json.a = this.a.toJSON();
    json.b = this.b.toJSON();
    return json;
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
      this._init(x, z);
  }

  _init(x, z) {
    assert(x instanceof BN);
    assert(z == null || (z instanceof BN));

    this.x = x;
    this.z = z || this.curve.one;

    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);

    if (!this.z.red)
      this.z = this.z.toRed(this.curve.red);
  }

  clone() {
    return this.curve.point(this.x.clone(), this.z.clone());
  }

  swap(point, flag) {
    assert(point instanceof MontPoint);

    this.x.cswap(point.x, flag);
    this.z.cswap(point.z, flag);

    return this;
  }

  precompute(power, rng) {
    // No-op.
    return this;
  }

  normalize() {
    // https://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#scaling-scale
    // 1I + 1M

    // P = O
    if (this.isInfinity())
      return this;

    // Z1 = 1
    if (this.z.cmp(this.curve.one) === 0)
      return this;

    // X3 = X1 / Z1
    this.x = this.x.redMul(this.z.redInvert());

    // Z3 = 1
    this.z = this.curve.one;

    return this;
  }

  scale(a) {
    assert(a instanceof BN);

    // P = O
    if (this.isInfinity())
      return this.curve.point();

    // X3 = X1 * A
    const nx = this.x.redMul(a);

    // Y3 = Y1 * A
    const nz = this.z.redMul(a);

    return this.curve.point(nx, nz);
  }

  neg() {
    // -(X1, Z1) = (X1, Z1)
    return this;
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

    // Z3 = C * (BB + a24 * C)
    const nz = c.redMul(bb.redIAdd(this.curve.a24.redMul(c)));

    return this.curve.point(nx, nz);
  }

  diffAdd(p, q) {
    // https://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#diffadd-dadd-1987-m-3
    // 4M + 2S + 6A
    assert(p instanceof MontPoint);
    assert(q instanceof MontPoint);

    // A = X2 + Z2
    const a = p.x.redAdd(p.z);

    // B = X2 - Z2
    const b = p.x.redSub(p.z);

    // C = X3 + Z3
    const c = q.x.redAdd(q.z);

    // D = X3 - Z3
    const d = q.x.redSub(q.z);

    // DA = D * A
    const da = d.redMul(a);

    // CB = C * B
    const cb = c.redMul(b);

    // X5 = Z1 * (DA + CB)^2
    const nx = this.z.redMul(da.redAdd(cb).redSqr());

    // Z5 = X1 * (DA - CB)^2
    const nz = this.x.redMul(da.redISub(cb).redSqr());

    return this.curve.point(nx, nz);
  }

  diffAddDbl(p, q) {
    // Assumes 4 * a24 = a + 2.
    // https://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#ladder-ladd-1987-m-3
    // Note that we swap P2 and P3 here (for consistency).
    // 6M + 4S + 8A + 1*a24
    assert(p instanceof MontPoint);
    assert(q instanceof MontPoint);

    // 4 * a24 != a + 2
    if (!this.curve.ladder) {
      return [
        this.diffAdd(p, q),
        q.dbl()
      ];
    }

    // A = X2 + Z2
    const a = q.x.redAdd(q.z);

    // AA = A^2
    const aa = a.redSqr();

    // B = X2 - Z2
    const b = q.x.redSub(q.z);

    // BB = B^2
    const bb = b.redSqr();

    // E = AA - BB
    const e = aa.redSub(bb);

    // C = X3 + Z3
    const c = p.x.redAdd(p.z);

    // D = X3 - Z3
    const d = p.x.redSub(p.z);

    // DA = D * A
    const da = d.redMul(a);

    // CB = C * B
    const cb = c.redMul(b);

    // X5 = Z1 * (DA + CB)^2
    const nx = this.z.redMul(da.redAdd(cb).redSqr());

    // Z5 = X1 * (DA - CB)^2
    const nz = this.x.redMul(da.redISub(cb).redSqr());

    // X4 = AA * BB
    const dx = aa.redMul(bb);

    // Z4 = E * (BB + a24 * E)
    const dz = e.redMul(bb.redIAdd(this.curve.a24.redMul(e)));

    return [
      this.curve.point(nx, nz),
      this.curve.point(dx, dz)
    ];
  }

  diffTrpl(p) {
    // Differential Tripling for Montgomery Curves.
    //
    // Elliptic Curve Arithmetic for Cryptography.
    //   Srinivasa Rao Subramanya Rao.
    //   Page 50, Section 3.2.
    //   https://maths-people.anu.edu.au/~brent/pd/Subramanya-thesis.pdf
    //
    // 5S + 5M + 5A + 1*a + 2*4
    assert(p instanceof MontPoint);

    // XX = X2^2
    const xx = p.x.redSqr();

    // ZZ = Z2^2
    const zz = p.z.redSqr();

    // A = (XX - ZZ)^2
    const a = xx.redSub(zz).redSqr();

    // B = a * (X2 * Z2)
    const b = this.curve.a.redMul(p.x.redMul(p.z));

    // C = 4 * ZZ
    const c = zz.redMuln(4);

    // D = 4 * XX
    const d = xx.redMuln(4);

    // E = XX + ZZ + B
    const e = xx.redIAdd(zz).redIAdd(b);

    // F = E * C
    const f = e.redMul(c);

    // G = E * D
    const g = e.redMul(d);

    // H = (A - F)^2
    const h = a.redSub(f).redSqr();

    // I = (A - G)^2
    const i = a.redISub(g).redSqr();

    // X3 = X1 * H
    const nx = this.x.redMul(h);

    // Z3 = Z1 * I
    const nz = this.z.redMul(i);

    return this.curve.point(nx, nz);
  }

  recover(p1, p2, sign) {
    // Okeya-Sakurai Y-coordinate Recovery.
    //
    //   this = base = (x1, y1) = (Xp, Yp)
    //   p1 = b = (x2, z2) = (Xq, Zq)
    //   p2 = a = (x3, z3) = (Xo, Zo)
    //
    // See: Montgomery Curves and their arithmetic.
    //   C. Costello, B. Smith
    //   Algorithm 5, Page 13, Section 4.3
    //   Algorithm 6, Page 14, Section 4.3
    //   https://eprint.iacr.org/2017/212.pdf
    assert(p1 instanceof MontPoint);
    assert(p2 instanceof MontPoint);

    // P = O
    if (this.isInfinity())
      throw new Error('Invalid point.');

    // Could precompute a2/b2 for speed.
    const a2 = this.curve.a.redMuln(2);
    const b2 = this.curve.b.redMuln(2);
    const x1 = this.normalize().x;
    const y1 = this.getY(sign).toRed(this.curve.red);
    const x2 = p1.x;
    const z2 = p1.z;
    const x3 = p2.x;
    const z3 = p2.z;

    // V1 = Xp * Zq
    const a = x1.redMul(z2);

    // V2 = Xq + V1
    const b = x2.redAdd(a);

    // V3 = Xq - V1
    // V3 = V3^2
    // V3 = V3 * Xo
    const c = x2.redSub(a).redSqr().redMul(x3);

    // V1 = 2a * Zq
    const d = a2.redMul(z2);

    // V2 = V2 + V1
    const e = b.redIAdd(d);

    // V4 = Xp * Xq
    // V4 = V4 + Zq
    const f = x1.redMul(x2).redIAdd(z2);

    // V2 = V2 * V4
    const g = e.redMul(f);

    // V1 = V1 * Zq
    const h = d.redMul(z2);

    // V2 = V2 - V1
    // V2 = V2 * Zo
    const i = g.redISub(h).redMul(z3);

    // V1 = 2b * Yp
    // V1 = V1 * Zq
    // V1 = V1 * Zo
    const j = b2.redMul(y1).redMul(z2).redMul(z3);

    // X' = V1 * Xq
    const x = j.redMul(x2);

    // Y' = V2 - V3
    const y = i.redISub(c);

    // Z' = V1 * Zq
    const z = j.redMul(z2);

    // Z' = 0
    if (z.sign() === 0)
      throw new Error('Invalid point.');

    // Zi = 1 / Z'
    const zi = z.redInvert();

    // X = X' * Zi
    const nx = x.redMul(zi);

    // Y = Y' * Zi
    const ny = y.redMul(zi);

    // Sanity check.
    if (!nx.redMul(p1.z).eq(p1.x))
      throw new Error('Invalid point.');

    return [nx, ny];
  }

  getX() {
    if (this.isInfinity())
      throw new Error('Invalid point.');

    this.normalize();

    return this.x.fromRed();
  }

  getY(sign) {
    if (this.isInfinity())
      throw new Error('Invalid point.');

    const x = this.normalize().x;
    const y2 = this.curve.solveY2(x);
    const y = y2.redSqrt();

    if (y.redIsOdd() !== Boolean(sign))
      y.redINeg();

    return y.fromRed();
  }

  eq(p) {
    assert(p instanceof MontPoint);

    // P = Q
    if (this === p)
      return true;

    // P = O
    if (this.isInfinity())
      return p.isInfinity();

    // Q = O
    if (p.isInfinity())
      return false;

    // Z1 = Z2
    if (this.z.cmp(p.z) === 0)
      return this.x.cmp(p.x) === 0;

    // X1 * Z2 == X2 * Z1
    const x1 = this.x.redMul(p.z);
    const x2 = p.x.redMul(this.z);

    return x1.cmp(x2) === 0;
  }

  isInfinity() {
    // Z1 = 0
    return this.z.sign() === 0;
  }

  eqX(x) {
    assert(x instanceof BN);

    if (this.isInfinity())
      return false;

    const rx = x.toRed(this.curve.red).redMul(this.z);

    return this.x.cmp(rx) === 0;
  }

  jmul(k) {
    assert(k instanceof BN);
    assert(!k.red);

    // Multiply with the Montgomery Ladder.
    //
    // Note that any clamping is meant to
    // be done _outside_ of this function.
    //
    // Montgomery Curves and their arithmetic.
    //   C. Costello, B. Smith.
    //   Algorithm 4, Page 12, Section 4.2.
    const bits = k.bitLength();

    let a = this;
    let b = this.curve.point();

    for (let i = bits - 1; i >= 0; i--) {
      const bit = k.utestn(i);

      if (bit === 0)
        [a, b] = this.diffAddDbl(a, b);
      else
        [b, a] = this.diffAddDbl(b, a);
    }

    return b;
  }

  jmulSimple(k) {
    assert(k instanceof BN);
    assert(!k.red);

    // Montgomery Ladder with explicit
    // additions and doubling (testing).
    const bits = k.bitLength();

    let a = this;
    let b = this.curve.point();

    // Climb the ladder.
    for (let i = bits - 1; i >= 0; i--) {
      const bit = k.utestn(i);

      if (bit === 0) {
        a = this.diffAdd(a, b);
        b = b.dbl();
      } else {
        b = this.diffAdd(b, a);
        a = a.dbl();
      }
    }

    return b;
  }

  jmulBlind(k, rng) {
    if (!rng)
      return this.jmul(k);

    // Randomize if available.
    return this.randomize(rng).jmul(k);
  }

  jmulConst(k, rng) {
    assert(k instanceof BN);
    assert(!k.red);

    // Multiply with the Montgomery Ladder.
    //
    // Note that any clamping is meant to
    // be done _outside_ of this function.
    //
    // See: Montgomery Curves and their arithmetic.
    //   C. Costello, B. Smith.
    //   Algorithm 7, Page 16, Section 5.3.
    //   Algorithm 8, Page 16, Section 5.3.
    //   https://eprint.iacr.org/2017/212.pdf
    //
    // Also: Elliptic Curves for Security.
    //   A. Langley, M. Hamburg, S. Turner.
    //   Page 7, Section 5.
    //   https://tools.ietf.org/html/rfc7748#section-5
    const bits = Math.max(k.bitLength(), this.curve.p.bitLength());
    const bytes = (bits + 7) >>> 3;

    // Recode scalar to base256.
    const exp = k.toArray('le', bytes);

    // Randomize if available.
    const point = rng ? this.randomize(rng) : this;

    // Clone points (for safe swapping).
    let a = point.clone();
    let b = this.curve.point().clone();
    let swap = 0;

    // Climb the ladder.
    for (let i = bits - 1; i >= 0; i--) {
      const bit = (exp[i >> 3] >> (i & 7)) & 1;

      // Maybe swap.
      a.swap(b, swap ^ bit);

      // Single coordinate add+double.
      [a, b] = point.diffAddDbl(a, b);

      swap = bit;
    }

    // Finalize loop.
    a.swap(b, swap);

    return b;
  }

  jmulAdd(k1, p2, k2) {
    throw new Error('Not implemented.');
  }

  jmulAddSimple(k1, p2, k2) {
    throw new Error('Not implemented.');
  }

  toP() {
    return this.normalize();
  }

  toJ() {
    return this;
  }

  encode() {
    // See RFC7748 (section 5).
    return this.curve.encodeField(this.getX());
  }

  static decode(curve, bytes) {
    assert(curve instanceof MontCurve);

    // See RFC7748 (section 5).
    const x = curve.decodeField(bytes);

    // We're supposed to ignore the hi bit
    // on montgomery points... I think. If
    // we don't, the X25519 test vectors
    // break, which is pretty convincing
    // evidence. This is a no-op for X448.
    x.iumaskn(curve.fieldBits);

    // Note: montgomery points are meant to be
    // reduced by the prime and do not have to
    // be explicitly validated in order to do
    // the montgomery ladder (see rfc7748,
    // section 5).
    const p = curve.point(x, curve.one);

    assert(!p.isInfinity());

    return p;
  }

  toJSON(pre) {
    if (this.isInfinity())
      return [];

    return [this.getX().toJSON()];
  }

  static fromJSON(curve, json) {
    assert(curve instanceof MontCurve);
    assert(Array.isArray(json));
    assert(json.length === 0
        || json.length === 1
        || json.length === 2);

    if (json.length === 0)
      return curve.point();

    const x = BN.fromJSON(json[0]);
    const p = curve.point(x, curve.one);

    if (json.length > 1) {
      const y = BN.fromJSON(json[1]);
      const e = p.getY(y.isOdd());

      if (y.cmp(e) !== 0)
        throw new Error('Invalid point.');
    }

    return p;
  }

  [custom]() {
    if (this.isInfinity())
      return '<MontPoint: Infinity>';

    return '<MontPoint:'
        + ' x=' + this.x.fromRed().toString(16, 2)
        + ' z=' + this.z.fromRed().toString(16, 2)
        + '>';
  }
}

/**
 * EdwardsCurve
 */

class EdwardsCurve extends Curve {
  constructor(conf) {
    super('edwards', conf);

    this.a = BN.fromJSON(conf.a).toRed(this.red);
    this.c = BN.fromJSON(conf.c).toRed(this.red);
    this.d = BN.fromJSON(conf.d).toRed(this.red);

    this.c2 = this.c.redMuln(2);
    this.cc = this.c.redSqr();
    this.cc2 = this.cc.redMuln(2);
    this.ccd = this.cc.redMul(this.d);
    this.k = this.d.redMuln(2);
    this.smi = -this.d.redNeg().andln(-1);
    this.exp = null;
    this.inv = null;

    this.twisted = this.a.cmp(this.one) !== 0;
    this.extended = this.a.cmp(this.one.redNeg()) === 0;
    this.oneA = this.a.cmp(this.one) === 0;
    this.mOneA = this.a.cmp(this.one.redNeg()) === 0;
    this.oneC = this.c.cmp(this.one) === 0;
    this.smallD = this.prime != null && this.d.redNeg().bitLength() <= 26;

    assert(!this.twisted || this.c.cmp(this.one) === 0);

    this._finalize(conf);
  }

  _mulA(num) {
    assert(num instanceof BN);

    // n * a = n
    if (this.oneA)
      return num.clone();

    // n * a = -n
    if (this.mOneA)
      return num.redNeg();

    return this.a.redMul(num);
  }

  _mulC(num) {
    assert(num instanceof BN);

    // c = 1
    if (this.oneC)
      return num;

    return this.c.redMul(num);
  }

  _mulCC(num) {
    assert(num instanceof BN);

    // c^2 = 1
    if (this.oneC)
      return num;

    return this.cc.redMul(num);
  }

  _mulD(num) {
    assert(num instanceof BN);

    // -d < 0x4000000
    if (this.smallD)
      return num.redMuln(this.smi);

    return this.d.redMul(num);
  }

  _mulCCD(num) {
    // c^2 * d = d
    if (this.oneC)
      return this._mulD(num);

    return this.ccd.redMul(num);
  }

  _solve3mod4(y) {
    // Extra speedup for solving X on Ed448.
    // We combine sqrt(u / v) into one operation.
    //
    // Computes:
    //   x = sqrt((y^2 - 1) / (d * y^2 - 1))
    //
    // With:
    //   u = y^2 - 1
    //   v = d * y^2 - 1
    //   x = (u / v)^((p + 1) / 4)
    //     = u^3 * v * (u^5 * v^3)^((p - 3) / 4) mod p
    //
    // Note that `p` is congruent to 3 mod 4.
    //
    // The same trick applies to Curve1174 and E521.
    //
    // https://tools.ietf.org/html/rfc8032#section-5.2.3
    assert(y instanceof BN);

    if (!this.exp) {
      // E = (p - 3) / 4
      this.exp = this.p.subn(3).iushrn(2);
    }

    // Y2 = Y^2
    const y2 = y.redSqr();

    // V = c^2 * d * Y2 - a
    const v = this._mulCCD(y2).redISub(this.a);

    // U = Y2 - c^2
    const u = y2.redISub(this.cc);

    // U2 = U^2
    const u2 = u.redSqr();

    // U3 = U2 * U
    const u3 = u2.redMul(u);

    // U5 = U3 * U2
    const u5 = u3.redMul(u2);

    // V3 = V^2 * V
    const v3 = v.redSqr().redMul(v);

    // P = U5 * V3 * E
    const p = u5.redMul(v3).redPow(this.exp);

    // X = U3 * V * P
    const x = u3.redMul(v).redMul(p);

    // C = V * X^2
    const c = v.redMul(x.redSqr());

    // C = U
    if (c.cmp(u) === 0)
      return x;

    throw new Error('Invalid point.');
  }

  _solve5mod8(y) {
    // Extra speedup for solving X on Ed25519.
    // We combine sqrt(u / v) into one operation.
    //
    // Computes:
    //   x = sqrt((y^2 - 1) / (d * y^2 + 1))
    //
    // With:
    //   u = y^2 - 1
    //   v = d * y^2 + 1
    //   x = (u / v)^((p + 3) / 8)
    //     = u * v^3 * (u * v^7)^((p - 5) / 8) mod p
    //
    // Note that `p` is congruent to 5 mod 8.
    //
    // This same trick applies to any prime field
    // fulfilling this assumption.
    //
    // For Ed25519, `1 / sqrt(a)` also seems to be
    // acceptable as the value of I (a = -1).
    //
    // https://tools.ietf.org/html/rfc8032#section-5.1.3
    assert(y instanceof BN);

    if (!this.exp) {
      // E = (p - 5) / 8
      this.exp = this.p.subn(5).iushrn(3);

      // I = 2^((p - 1) / 4)
      this.inv = this.two.redPow(this.p.subn(1).iushrn(2));
    }

    // Y2 = Y^2
    const y2 = y.redSqr();

    // V = c^2 * d * Y2 - a
    const v = this._mulCCD(y2).redISub(this.a);

    // U = Y2 - c^2
    const u = y2.redISub(this.cc);

    // V3 = V^2 * V
    const v3 = v.redSqr().redMul(v);

    // V7 = V3^2 * V
    const v7 = v3.redSqr().redMul(v);

    // P = U * V7 * E
    const p = u.redMul(v7).redPow(this.exp);

    // X = U * V3 * P
    const x = u.redMul(v3).redMul(p);

    // C = V * X^2
    const c = v.redMul(x.redSqr());

    // C = U
    if (c.cmp(u) === 0)
      return x;

    // X = X * I if C = -U
    if (c.cmp(u.redINeg()) === 0)
      return x.redMul(this.inv);

    throw new Error('Invalid point.');
  }

  point(x, y, z, t) {
    return new EdwardsPoint(this, x, y, z, t);
  }

  jpoint(x, y, z) {
    assert(x == null && y == null && z == null);
    return this.point();
  }

  solveX(y) {
    // p mod 4 == 3 (p251, p448, p521)
    if (this.p.andln(3) === 3)
      return this._solve3mod4(y);

    // p mod 8 == 5 (p25519)
    if (this.p.andln(7) === 5)
      return this._solve5mod8(y);

    // Compute `x = sqrt(u / v)` slowly.
    return this.solveX2(y).redSqrt();
  }

  solveX2(y) {
    // https://tools.ietf.org/html/rfc8032#section-5.2.3
    // https://tools.ietf.org/html/rfc8032#section-5.1.3
    assert(y instanceof BN);

    // Regular (a=1): x^2 = (y^2 - c^2) / (c^2 * d * y^2 - 1)
    // Twisted (c=1): x^2 = (y^2 - 1) / (d * y^2 - a)
    // Generalized: x^2 = (y^2 - c^2) / (c^2 * d * y^2 - a)
    const y2 = y.redSqr();
    const rhs = this._mulCCD(y2).redISub(this.a);
    const lhs = y2.redISub(this.cc);
    const x2 = lhs.redMul(rhs.redInvert());

    return x2;
  }

  solveY2(x) {
    assert(x instanceof BN);

    // Regular (a=1): y^2 = (c^2 - x^2) / (1 - c^2 * d * x^2)
    // Twisted (c=1): y^2 = (1 - a * x^2) / (1 - d * x^2)
    // Generalized: y^2 = (c^2 - a * x^2) / (1 - c^2 * d * x^2)
    const x2 = x.redSqr();
    const lhs = this.cc.redSub(this._mulA(x2));
    const rhs = this.one.redSub(this._mulCCD(x2));
    const y2 = lhs.redMul(rhs.redInvert());

    return y2;
  }

  validate(point) {
    // https://tools.ietf.org/html/rfc8032#section-3
    // https://hyperelliptic.org/EFD/g1p/auto-edwards.html
    // https://hyperelliptic.org/EFD/g1p/auto-twisted.html
    assert(point instanceof EdwardsPoint);

    // P = O
    if (point.isInfinity())
      return true;

    // Z1 = 1
    if (point.zOne) {
      // Regular (a=1): x^2 + y^2 = c^2 * (1 + d * x^2 * y^2)
      // Twisted (c=1): a * x^2 + y^2 = 1 + d * x^2 * y^2
      // Generalized: a * x^2 + y^2 = c^2 * (1 + d * x^2 * y^2)
      const x2 = point.x.redSqr();
      const y2 = point.y.redSqr();
      const dxy = this._mulD(x2).redMul(y2);
      const lhs = this._mulA(x2).redIAdd(y2);
      const rhs = this._mulCC(this.one.redAdd(dxy));

      return lhs.cmp(rhs) === 0;
    }

    // Regular (a=1): (x^2 + y^2) * z^2 = c^2 * (z^4 + d * x^2 * y^2)
    // Twisted (c=1): (a * x^2 + y^2) * z^2 = z^4 + d * x^2 * y^2
    // Generalized: (a * x^2 + y^2) * z^2 = c^2 * (z^4 + d * x^2 * y^2)
    const x2 = point.x.redSqr();
    const y2 = point.y.redSqr();
    const z2 = point.z.redSqr();
    const z4 = z2.redSqr();
    const dxy = this._mulD(x2).redMul(y2);
    const lhs = this._mulA(x2).redIAdd(y2).redMul(z2);
    const rhs = this._mulCC(z4.redIAdd(dxy));

    return lhs.cmp(rhs) === 0;
  }

  pointFromX(x, sign) {
    assert(x instanceof BN);

    if (!x.red)
      x = x.toRed(this.red);

    const y2 = this.solveY2(x);

    if (y2.isZero() && sign)
      throw new Error('Invalid point.');

    const y = y2.redSqrt();

    if (y.redIsOdd() !== Boolean(sign))
      y.redINeg();

    return this.point(x, y);
  }

  pointFromY(y, sign) {
    assert(y instanceof BN);

    if (!y.red)
      y = y.toRed(this.red);

    const x = this.solveX(y);

    if (x.isZero() && sign)
      throw new Error('Invalid point.');

    if (x.redIsOdd() !== Boolean(sign))
      x.redINeg();

    return this.point(x, y);
  }

  pointFromR(x) {
    assert(x instanceof BN);

    if (!x.red)
      x = x.toRed(this.red);

    const y2 = this.solveY2(x);
    const y = y2.redSqrt();

    return this.point(x, y);
  }

  pointFromMont(point, sign) {
    // Birational equivalence.
    //
    // See: Elliptic Curves for Security.
    //   A. Langley, M. Hamburg, S. Turner.
    //   Section 4.1 & 4.2.
    //   https://tools.ietf.org/html/rfc7748#section-4.1
    //   https://tools.ietf.org/html/rfc7748#section-4.2
    //
    // Also: Montgomery Curves and their arithmetic.
    //   C. Costello, B. Smith.
    //   Page 6, Section 2.5.
    //   https://eprint.iacr.org/2017/212.pdf
    assert(point instanceof MontPoint);

    // P = O
    if (point.isInfinity()) {
      if (sign)
        throw new Error('Invalid point.');
      return this.point();
    }

    // Edwards `y`.
    let ny;

    if (this.twisted) {
      // P = (-1, v) = O
      // P = (u, 0) = (0, -1)
      if (point.x.eq(point.z.redNeg()))
        return this.point();

      // Birational maps:
      //
      //   x = sqrt(-a - 2) * u / v
      //   y = (u - 1) / (u + 1)
      //
      // Undefined for u = -1 or v = 0.
      const y = point.x.redSub(point.z);
      const z = point.x.redAdd(point.z);

      ny = y.redMul(z.redInvert());
    } else if (this.iso4) {
      // 4-isogeny maps (multiplies by cofactor):
      //
      //   x = 4 * v * (u^2 - 1) / (u^4 - 2 * u^2 + 4 * v^2 + 1)
      //   y = -(u^5 - 2 * u^3 - 4 * u * v^2 + u) /
      //        (u^5 - 2 * u^2 * v^2 - 2 * u^3 - 2 * v^2 + u)
      //
      // Should always hold true.
      const p = point.divH().normalize();
      const u = p.x;
      const v = p.curve.solveY(u);

      const u2 = u.redSqr();
      const u3 = u2.redMul(u);
      const u5 = u3.redMul(u2);
      const v2 = v.redSqr();

      const a = u3.redIMuln(2);
      const b = u.redMul(v2).redIMuln(4);
      const c = u2.redMul(v2).redIMuln(2);
      const d = v2.redIMuln(2);

      const y = u5.redSub(a).redISub(b).redIAdd(u).redINeg();
      const z = u5.redISub(c).redISub(a).redISub(d).redIAdd(u);

      ny = y.redMul(z.redInvert());
    } else {
      // P = (1, v) = O
      // P = (u, 0) = (0, 1)
      if (point.x.eq(point.z))
        return this.point();

      // Birational maps:
      //
      //   x = sqrt(a - 2) * u / v
      //   y = -(1 + u) / (1 - u)
      //
      // Undefined for u = 1 or v = 0.
      const y = point.z.redAdd(point.x).redINeg();
      const z = point.z.redSub(point.x);

      ny = y.redMul(z.redInvert());
    }

    // Edwards point.
    return this.pointFromY(ny.fromRed(), sign);
  }

  elligator(curve, r) {
    assert(curve instanceof MontCurve);
    assert(r instanceof BN);
    assert(r.red === this.red);

    const u = r.fromRed().toRed(curve.red);
    const [m, sign] = curve.elligator(u);
    const p = this.pointFromMont(m, sign);

    return p;
  }

  invert(curve, p) {
    assert(curve instanceof MontCurve);

    const m = curve.pointFromEdwards(p);
    const sign = p.getX().isOdd();
    const u = curve.invert(m, sign);
    const r = u.fromRed().toRed(this.red);

    return r;
  }

  randomPoint(rng) {
    let p;

    for (;;) {
      const y = this.randomField(rng);
      const sign = BN.random(rng, 0, 2);

      try {
        p = this.pointFromY(y, sign.isOdd());
      } catch (e) {
        continue;
      }

      return p;
    }
  }

  decodePoint(bytes) {
    return EdwardsPoint.decode(this, bytes);
  }

  pointFromJSON(json) {
    return EdwardsPoint.fromJSON(this, json);
  }

  toJSON(pre) {
    const json = super.toJSON(pre);
    json.a = this.a.toJSON();
    json.c = this.c.toJSON();
    json.d = this.d.toJSON();
    return json;
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
    this.y = this.curve.c;
    this.z = this.curve.one;
    this.t = this.curve.extended ? this.curve.zero : null;
    this.zOne = 1;

    if (x != null)
      this._init(x, y, z, t);
  }

  _init(x, y, z, t) {
    assert(x instanceof BN);
    assert(y instanceof BN);
    assert(z == null || (z instanceof BN));
    assert(t == null || (t instanceof BN));
    assert(this.curve.extended || t == null);

    this.x = x;
    this.y = y;
    this.z = z || this.curve.one;
    this.t = t || null;

    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);

    if (!this.y.red)
      this.y = this.y.toRed(this.curve.red);

    if (!this.z.red)
      this.z = this.z.toRed(this.curve.red);

    if (this.t && !this.t.red)
      this.t = this.t.toRed(this.curve.red);

    this.zOne = this.z.eq(this.curve.one) | 0;

    // Use extended coordinates.
    if (this.curve.extended && !this.t) {
      this.t = this.x.redMul(this.y);
      if (!this.zOne)
        this.t = this.t.redMul(this.z.redInvert());
    }
  }

  clone() {
    const nx = this.x.clone();
    const ny = this.y.clone();
    const nz = this.z.clone();
    const nt = this.t ? this.t.clone() : null;

    return this.curve.point(nx, ny, nz, nt);
  }

  swap(point, flag) {
    assert(point instanceof EdwardsPoint);

    const cond = ((flag >> 31) | (-flag >> 31)) & 1;
    const zOne1 = this.zOne;
    const zOne2 = point.zOne;

    this.x.cswap(point.x, flag);
    this.y.cswap(point.y, flag);
    this.z.cswap(point.z, flag);

    if (this.curve.extended)
      this.t.cswap(point.t, flag);

    this.zOne = (zOne1 & (cond ^ 1)) | (zOne2 & cond);
    point.zOne = (zOne2 & (cond ^ 1)) | (zOne1 & cond);

    return this;
  }

  normalize() {
    // https://hyperelliptic.org/EFD/g1p/auto-edwards-projective.html#scaling-z
    // 1I + 2M (+ 1M if extended)

    // Z1 = 1
    if (this.zOne)
      return this;

    // A = 1 / Z1
    const a = this.z.redInvert();

    // X3 = X1 * A
    this.x = this.x.redMul(a);

    // Y3 = Y1 * A
    this.y = this.y.redMul(a);

    // T3 = T1 * A
    if (this.t)
      this.t = this.t.redMul(a);

    // Z3 = 1
    this.z = this.curve.one;
    this.zOne = 1;

    return this;
  }

  scale(a) {
    assert(a instanceof BN);

    // X3 = X1 * A
    const nx = this.x.redMul(a);

    // Y3 = Y1 * A
    const ny = this.y.redMul(a);

    // Z3 = Z1 * A
    const nz = this.z.redMul(a);

    // T3 = T1 * A
    const nt = this.t ? this.t.redMul(a) : null;

    return this.curve.point(nx, ny, nz, nt);
  }

  neg() {
    // -(X1, Y1, Z1, T1) = (-X1, Y1, Z1, -T1)
    const nx = this.x.redNeg();
    const ny = this.y;
    const nz = this.z;
    const nt = this.t ? this.t.redNeg() : null;

    return this.curve.point(nx, ny, nz, nt);
  }

  add(p) {
    assert(p instanceof EdwardsPoint);

    // P = O
    if (this.isInfinity())
      return p;

    // Q = O
    if (p.isInfinity())
      return this;

    // a = -1
    if (this.curve.extended) {
      // Z1 = 1
      if (this.zOne)
        return p._addExt(this, 0);

      return this._addExt(p, 0);
    }

    // Z1 = 1
    if (this.zOne)
      return p._addProj(this, 0);

    return this._addProj(p, 0);
  }

  _addExt(p, uni) {
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-3
    // 8M + 8A + 1*k + 1*2
    //
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-madd-2008-hwcd-3
    // 7M + 8A + 1*k + 1*2
    const zOne = p.zOne & (uni ^ 1);

    // A = (Y1 - X1) * (Y2 - X2)
    const a = this.y.redSub(this.x).redMul(p.y.redSub(p.x));

    // B = (Y1 + X1) * (Y2 + X2)
    const b = this.y.redAdd(this.x).redMul(p.y.redAdd(p.x));

    // C = T1 * k * T2
    const c = this.t.redMul(this.curve.k).redMul(p.t);

    // D = Z1 * 2 * Z2
    const d = zOne ? this.z.redAdd(this.z) : this.z.redMul(p.z).redIMuln(2);

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

  _addProj(p, uni) {
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#addition-add-2008-bbjlp
    // 10M + 1S + 7A + 1*a + 1*d
    //
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#addition-madd-2008-bbjlp
    // 9M + 1S + 7A + 1*a + 1*d
    //
    // https://hyperelliptic.org/EFD/g1p/auto-edwards-projective.html#addition-add-2007-bl
    // 10M + 1S + 7A + 1*c + 1*d
    const zOne = p.zOne & (uni ^ 1);

    // A = Z1 * Z2
    const a = zOne ? this.z : this.z.redMul(p.z);

    // B = A^2
    const b = a.redSqr();

    // C = X1 * X2
    const c = this.x.redMul(p.x);

    // D = Y1 * Y2
    const d = this.y.redMul(p.y);

    // E = d * C * D
    const e = this.curve._mulD(c).redMul(d);

    // F = B - E
    const f = b.redSub(e);

    // G = B + E
    const g = b.redIAdd(e);

    // + XYXY = (X1 + Y1) * (X2 + Y2)
    const xyxy = this.x.redAdd(this.y).redMul(p.x.redAdd(p.y));

    // X3 = A * F * ((X1 + Y1) * (X2 + Y2) - C - D)
    const nx = xyxy.redISub(c).redISub(d).redMul(a).redMul(f);

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

  dbl() {
    // P = O
    if (this.isInfinity())
      return this;

    // a = -1
    if (this.curve.extended)
      return this._dblExt();

    return this._dblProj();
  }

  _dblExt() {
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

  _dblProj() {
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

        // X3 = (B - C - D) * J
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

  trpl() {
    // P = O
    if (this.isInfinity())
      return this;

    // a = -1
    if (this.curve.extended)
      return this._trplExt();

    return this._trplProj();
  }

  _trplExt() {
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#tripling-tpl-2015-c
    // 11M + 3S + 7A + 1*a + 2*2

    // YY = Y1^2
    const yy = this.y.redSqr();

    // aXX = a * X1^2
    const axx = this.curve._mulA(this.x.redSqr());

    // Ap = YY + aXX
    const ap = yy.redAdd(axx);

    let b;

    if (this.zOne) {
      // B = 2 * (2 - Ap)
      b = this.curve.two.redSub(ap).redIMuln(2);
    } else {
      // B = 2 * (2 * Z1^2 - Ap)
      b = this.z.redSqr().redIMuln(2).redISub(ap).redIMuln(2);
    }

    // xB = aXX * B
    const xb = axx.redMul(b);

    // yB = YY * B
    const yb = yy.redMul(b);

    // AA = Ap * (YY - aXX)
    const aa = ap.redMul(yy.redISub(axx));

    // F = AA - yB
    const f = aa.redSub(yb);

    // G = AA + xB
    const g = aa.redAdd(xb);

    // xE = X1 * (yB + AA)
    const xe = this.x.redMul(yb.redIAdd(aa));

    // yH = Y1 * (xB - AA)
    const yh = this.y.redMul(xb.redISub(aa));

    // zF = Z1 * F
    const zf = this.zOne ? f : this.z.redMul(f);

    // zG = Z1 * G
    const zg = this.zOne ? g : this.z.redMul(g);

    // X3 = xE * zF
    const nx = xe.redMul(zf);

    // Y3 = yH * zG
    const ny = yh.redMul(zg);

    // Z3 = zF * zG
    const nz = zf.redMul(zg);

    // T3 = xE * yH
    const nt = xe.redMul(yh);

    return this.curve.point(nx, ny, nz, nt);
  }

  _trplProj() {
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#tripling-tpl-2015-c
    // 9M + 3S + 7A + 1*a + 2*2
    //
    // https://hyperelliptic.org/EFD/g1p/auto-edwards-projective.html#tripling-tpl-2007-bblp
    // 9M + 4S + 6A + 1*c2 + 1*2

    // XX = X1^2
    const xx = this.x.redSqr();

    // YY = Y1^2
    const yy = this.y.redSqr();

    let nx, ny, nz;

    if (this.curve.twisted) {
      // aXX = a * X1^2
      const axx = this.curve._mulA(xx);

      // Ap = YY + aXX
      const ap = yy.redAdd(axx);

      let b;

      if (this.zOne) {
        // B = 2 * (2 - Ap)
        b = this.curve.two.redSub(ap).redIMuln(2);
      } else {
        // B = 2 * (2 * Z1^2 - Ap)
        b = this.z.redSqr().redIMuln(2).redISub(ap).redIMuln(2);
      }

      // xB = aXX * B
      const xb = axx.redMul(b);

      // yB = YY * B
      const yb = yy.redMul(b);

      // AA = Ap * (YY - aXX)
      const aa = ap.redMul(yy.redISub(axx));

      // F = AA - yB
      const f = aa.redSub(yb);

      // G = AA + xB
      const g = aa.redAdd(xb);

      // X3 = X1 * (yB + AA) * F
      nx = this.x.redMul(yb.redIAdd(aa)).redMul(f);

      // Y3 = Y1 * (xB - AA) * G
      ny = this.y.redMul(xb.redISub(aa)).redMul(g);

      // Z3 = Z1 * F * G
      nz = this.zOne ? f.redMul(g) : this.z.redMul(f).redMul(g);
    } else {
      let zz;

      if (this.zOne) {
        // ZZ = c2^2
        zz = this.curve.c2.redSqr();
      } else {
        // ZZ = (c2 * Z1)^2
        zz = this.curve.c2.redMul(this.z).redSqr();
      }

      // D = XX + YY
      const d = xx.redAdd(yy);

      // DD = D^2
      const dd = d.redSqr();

      // H = 2 * D * (XX - YY)
      const h = d.redMul(xx.redSub(yy)).redIMuln(2);

      // P = DD - YY * ZZ
      const p = dd.redSub(yy.redMul(zz));

      // Q = DD - XX * ZZ
      const q = dd.redSub(xx.redMul(zz));

      // T = H + Q
      const t = h.redAdd(q);

      // U = H - P
      const u = h.redISub(p);

      // X3 = P * U * X1
      nx = p.redMul(u).redMul(this.x);

      // Y3 = Q * T * Y1
      ny = q.redMul(t).redMul(this.y);

      // Z3 = T * U * Z1
      nz = this.zOne ? t.redMul(u) : t.redMul(u).redMul(this.z);
    }

    return this.curve.point(nx, ny, nz);
  }

  uadd(p) {
    assert(p instanceof EdwardsPoint);

    // a = -1
    if (this.curve.extended)
      return this._addExt(p, 1);

    return this._addProj(p, 1);
  }

  udbl() {
    return this.uadd(this);
  }

  getX() {
    this.normalize();
    return this.x.fromRed();
  }

  getY() {
    this.normalize();
    return this.y.fromRed();
  }

  eq(p) {
    assert(p instanceof EdwardsPoint);
    assert(this.z.sign() !== 0);
    assert(p.z.sign() !== 0);

    // P = Q
    if (this === p)
      return true;

    // Z1 = Z2
    if (this.z.cmp(p.z) === 0) {
      return this.x.cmp(p.x) === 0
          && this.y.cmp(p.y) === 0;
    }

    // X1 * Z2 == X2 * Z1
    const x1 = this.x.redMul(p.z);
    const x2 = p.x.redMul(this.z);

    if (x1.cmp(x2) !== 0)
      return false;

    const y1 = this.y.redMul(p.z);
    const y2 = p.y.redMul(this.z);

    return y1.cmp(y2) === 0;
  }

  isInfinity() {
    // The identity element is (0 : c : 1).
    assert(this.z.sign() !== 0);

    // X1 = 0
    if (this.x.sign() !== 0)
      return false;

    // Y1 = Z1 (if c = 1)
    if (this.curve.oneC)
      return this.y.cmp(this.z) === 0;

    // Y1 = c (if Z1 = 1)
    if (this.zOne)
      return this.y.cmp(this.curve.c) === 0;

    // Y1 = c * Z1
    return this.y.cmp(this.curve.c.redMul(this.z)) === 0;
  }

  hasQuadY() {
    return this.y.redMul(this.z).redJacobi() === 1;
  }

  eqX(x) {
    assert(x instanceof BN);
    assert(this.z.sign() !== 0);

    const rx = x.toRed(this.curve.red).redMul(this.z);

    return this.x.cmp(rx) === 0;
  }

  eqXToP(x) {
    assert(x instanceof BN);
    assert(this.curve.maxwellTrick);
    assert(this.z.sign() !== 0);

    const rx = x.toRed(this.curve.red).redMul(this.z);

    if (this.x.cmp(rx) === 0)
      return true;

    const c = x.clone();
    const t = this.curve.redN.redMul(this.z);

    for (;;) {
      c.iadd(this.curve.n);

      if (c.cmp(this.curve.p) >= 0)
        return false;

      rx.redIAdd(t);

      if (this.x.cmp(rx) === 0)
        break;
    }

    return true;
  }

  toP() {
    return this.normalize();
  }

  toJ() {
    return this;
  }

  encode() {
    // See RFC 8032 (section 5.1.2).
    if (this.isInfinity())
      throw new Error('Invalid point.');

    // P = (0, -c) - see below for explanation.
    if (this.curve.iso4 && this.curve.oneC) {
      if (this.x.isZero() && this.y.eq(this.z.redNeg()))
        throw new Error('Invalid point.');
    }

    const y = this.getY();

    // Note: `x` normalized from `getY()` call.
    y.setn(this.curve.signBit, this.x.redIsOdd());

    return this.curve.encodeField(y);
  }

  static decode(curve, bytes) {
    assert(curve instanceof EdwardsCurve);

    // See RFC 8032 (section 5.1.3).
    const y = curve.decodeField(bytes);
    const sign = y.testn(curve.signBit) !== 0;

    y.setn(curve.signBit, 0);

    if (y.cmp(curve.p) >= 0)
      throw new Error('Invalid point.');

    const p = curve.pointFromY(y, sign);

    // Note that it _is_ possible to serialize
    // points at infinity for edwards curves.
    if (p.isInfinity())
      throw new Error('Invalid point.');

    // For compatibility with OpenSSL and
    // Mike Hamburg's Ed448-Goldilocks
    // implementation.
    //
    // Hamburg rejects infinity (0, c),
    // however, the torsion point (0, -c)
    // also behaves like infinity as a
    // result of the 4-isogeny between
    // Ed448 and Curve448.
    //
    // 4-isogeny conversion:
    //
    //   (x=0, y=+c) -> (u=1, z=0)
    //   (x=0, y=-c) -> (u=1, z=0)
    //
    // We artificially reject (0, -c) here
    // for this reason.
    if (curve.iso4 && curve.oneC) {
      if (p.x.isZero() && p.y.eq(p.z.redNeg()))
        throw new Error('Invalid point.');
    }

    return p;
  }

  toJSON(pre) {
    if (this.isInfinity())
      return [];

    const x = this.getX().toJSON();
    const y = this.getY().toJSON();

    if (pre && this.pre)
      return [x, y, this.pre.toJSON()];

    return [x, y];
  }

  static fromJSON(curve, json) {
    assert(curve instanceof EdwardsCurve);
    assert(Array.isArray(json));
    assert(json.length === 0
        || json.length === 2
        || json.length === 3);

    if (json.length === 0)
      return curve.point();

    const x = BN.fromJSON(json[0]);
    const y = BN.fromJSON(json[1]);
    const point = curve.point(x, y);

    if (json.length > 2 && json[2] != null)
      point.pre = Precomp.fromJSON(point, json[2]);

    return point;
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

  reduce(k) {
    assert(k instanceof BN);
    assert(!k.red);

    k.iuand(this.and);
    k.iuor(this.or);

    return k;
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
 * Precomp
 */

class Precomp {
  constructor() {
    this.naf = null;
    this.doubles = null;
    this.blinding = null;
    this.beta = null;
  }

  map(func) {
    assert(typeof func === 'function');

    const out = new this.constructor();

    if (this.naf)
      out.naf = this.naf.map(func);

    if (this.doubles)
      out.doubles = this.doubles.map(func);

    return out;
  }

  toJSON() {
    return {
      naf: this.naf ? this.naf.toJSON() : null,
      doubles: this.doubles ? this.doubles.toJSON() : null,
      blinding: this.blinding ? this.blinding.toJSON() : undefined
    };
  }

  fromJSON(point, json) {
    assert(point instanceof Point);
    assert(json && typeof json === 'object');

    if (json.naf != null)
      this.naf = NAF.fromJSON(point, json.naf);

    if (json.doubles != null)
      this.doubles = Doubles.fromJSON(point, json.doubles);

    if (json.blinding != null)
      this.blinding = Blinding.fromJSON(point, json.blinding);

    return this;
  }

  static fromJSON(point, json) {
    return new this().fromJSON(point, json);
  }
}

/**
 * NAF
 */

class NAF {
  constructor(width, points) {
    this.width = width;
    this.points = points;
  }

  map(func) {
    assert(typeof func === 'function');

    const {width} = this;
    const points = [];

    for (const point of this.points)
      points.push(func(point));

    return new this.constructor(width, points);
  }

  toJSON() {
    return {
      width: this.width,
      points: this.points.slice(1).map((point) => {
        return point.toJSON();
      })
    };
  }

  static fromJSON(point, json) {
    assert(point instanceof Point);
    assert(json && typeof json === 'object');
    assert((json.width >>> 0) === json.width);
    assert(Array.isArray(json.points));

    const {curve} = point;
    const {width} = json;
    const points = [point];

    for (const item of json.points)
      points.push(curve.pointFromJSON(item));

    return new this(width, points);
  }
}

/**
 * Doubles
 */

class Doubles {
  constructor(step, points) {
    this.step = step;
    this.points = points;
  }

  map(func) {
    assert(typeof func === 'function');

    const {step} = this;
    const points = [];

    for (const point of this.points)
      points.push(func(point));

    return new this.constructor(step, points);
  }

  toJSON() {
    return {
      step: this.step,
      points: this.points.slice(1).map((point) => {
        return point.toJSON();
      })
    };
  }

  static fromJSON(point, json) {
    assert(point instanceof Point);
    assert(json && typeof json === 'object');
    assert((json.step >>> 0) === json.step);
    assert(Array.isArray(json.points));

    const {curve} = point;
    const {step} = json;
    const points = [point];

    for (const item of json.points)
      points.push(curve.pointFromJSON(item));

    return new this(step, points);
  }
}

/**
 * Blinding
 */

class Blinding {
  constructor(blind, unblind) {
    this.blind = blind;
    this.unblind = unblind;
  }

  toJSON() {
    return {
      blind: this.blind.toJSON(),
      unblind: this.unblind.toJSON()
    };
  }

  static fromJSON(point, json) {
    assert(point instanceof Point);
    assert(json && typeof json === 'object');

    const {curve} = point;
    const blind = BN.fromJSON(json.blind);
    const unblind = curve.pointFromJSON(json.unblind);

    return new this(blind, unblind);
  }
}

/**
 * Endo
 */

class Endo {
  constructor(beta, lambda, basis) {
    this.beta = beta;
    this.lambda = lambda;
    this.basis = basis;
  }

  toJSON() {
    return {
      beta: this.beta.fromRed().toJSON(),
      lambda: this.lambda.toJSON(),
      basis: [
        this.basis[0].toJSON(),
        this.basis[1].toJSON()
      ]
    };
  }

  static fromJSON(curve, json) {
    assert(curve instanceof Curve);
    assert(json && typeof json === 'object');
    assert(Array.isArray(json.basis));
    assert(json.basis.length === 2);

    const beta = BN.fromJSON(json.beta).toRed(curve.red);
    const lambda = BN.fromJSON(json.lambda);

    const basis = [
      Vector.fromJSON(json.basis[0]),
      Vector.fromJSON(json.basis[1])
    ];

    return new this(beta, lambda, basis);
  }
}

/**
 * Vector
 */

class Vector {
  constructor(a, b) {
    this.a = a;
    this.b = b;
  }

  toJSON() {
    return {
      a: this.a.toJSON(),
      b: this.b.toJSON()
    };
  }

  static fromJSON(json) {
    assert(json && typeof json === 'object');

    const a = BN.fromJSON(json.a);
    const b = BN.fromJSON(json.b);

    return new this(a, b);
  }
}

/**
 * P192
 * https://tinyurl.com/fips-186-2 (page 29)
 * https://tinyurl.com/fips-186-3 (page 88)
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
      iso4: false,
      prime: 'p192',
      s: '3045ae6f c8422f64 ed579528 d38120ea'
       + 'e12196d5',
      c: '3099d2bb bfcb2538 542dcd5f b078b6ef'
       + '5f3d6fe2 c745de65',
      // 2^192 - 2^64 - 1
      p: 'ffffffff ffffffff ffffffff fffffffe'
       + 'ffffffff ffffffff',
      // -3 mod p
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
 * https://tinyurl.com/fips-186-2 (page 30)
 * https://tinyurl.com/fips-186-3 (page 88)
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
      iso4: false,
      prime: 'p224',
      s: 'bd713447 99d5c7fc dc45b59f a3b9ab8f'
       + '6a948bc5',
      c: '5b056c7e 11dd68f4 0469ee7f 3c7a7d74'
       + 'f7d12111 6506d031 218291fb',
      // 2^224 - 2^96 + 1
      p: 'ffffffff ffffffff ffffffff ffffffff'
       + '00000000 00000000 00000001',
      // -3 mod p
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
 * https://tinyurl.com/fips-186-2 (page 31)
 * https://tinyurl.com/fips-186-3 (page 89)
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
      iso4: false,
      prime: null,
      s: 'c49d3608 86e70493 6a6678e1 139d26b7'
       + '819f7e90',
      c: '7efba166 2985be94 03cb055c 75d4f7e0'
       + 'ce8d84a9 c5114abc af317768 0104fa0d',
      // 2^256 - 2^224 + 2^192 + 2^96 - 1
      p: 'ffffffff 00000001 00000000 00000000'
       + '00000000 ffffffff ffffffff ffffffff',
      // -3 mod p
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
 * https://tinyurl.com/fips-186-2 (page 32)
 * https://tinyurl.com/fips-186-3 (page 89)
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
      iso4: false,
      prime: null,
      s: 'a335926a a319a27a 1d00896a 6773a482'
       + '7acdac73',
      c: '79d1e655 f868f02f ff48dcde e14151dd'
       + 'b80643c1 406d0ca1 0dfe6fc5 2009540a'
       + '495e8042 ea5f744f 6e184667 cc722483',
      // 2^384 - 2^128 - 2^96 + 2^32 - 1
      p: 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff fffffffe'
       + 'ffffffff 00000000 00000000 ffffffff',
      // -3 mod p
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
 * https://tinyurl.com/fips-186-2 (page 33)
 * https://tinyurl.com/fips-186-3 (page 90)
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
      iso4: false,
      prime: 'p521',
      s: 'd09e8800 291cb853 96cc6717 393284aa'
       + 'a0da64ba',
      c: '000000b4 8bfa5f42 0a349495 39d2bdfc'
       + '264eeeeb 077688e4 4fbf0ad8 f6d0edb3'
       + '7bd6b533 28100051 8e19f1b9 ffbe0fe9'
       + 'ed8a3c22 00b8f875 e523868c 70c1e5bf'
       + '55bad637',
      // 2^521 - 1
      p: '000001ff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff',
      // -3 mod p
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
 * https://www.secg.org/SEC2-Ver-1.0.pdf (page 15, section 2.7.1)
 * https://www.secg.org/sec2-v2.pdf (page 9, section 2.4.1)
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
      iso4: false,
      prime: 'k256',
      // 2^256 - 2^32 - 977
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
      endo: {
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
      }
    });
  }
}

/**
 * BRAINPOOLP256
 * https://tools.ietf.org/html/rfc5639#section-3.4
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
      iso4: false,
      prime: null,
      s: '757f5958 490cfd47 d7c19bb4 2158d955'
       + '4f7b46bc',
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
 * https://tools.ietf.org/html/rfc5639#section-3.6
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
      iso4: false,
      prime: null,
      s: 'bcfbfa1c 877c5628 4dab79cd 4c2b3293'
       + 'd20e9e5e',
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
 * https://tools.ietf.org/html/rfc5639#section-3.7
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
      iso4: false,
      prime: null,
      s: 'af02ac60 acc93ed8 74422a52 ecb238fe'
       + 'ee5ab6ad',
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

/**
 * X25519
 * https://tools.ietf.org/html/rfc7748#section-4.1
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
      iso4: false,
      prime: 'p25519',
      // 2^255 - 19
      p: '7fffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffed',
      // 486662
      a: '76d06',
      b: '1',
      n: '10000000 00000000 00000000 00000000'
       + '14def9de a2f79cd6 5812631a 5cf5d3ed',
      h: '8',
      u: '2',
      g: [
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000009'].join(''),
        ['20ae19a1 b8a086b4 e01edd2c 7748d14c',
         '923d4d7e 6d7c61b2 29e9c5a2 7eced3d9'].join('')
      ]
    });
  }
}

/**
 * ED25519
 * https://tools.ietf.org/html/rfc8032#section-5.1
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
      iso4: false,
      prime: 'p25519',
      // 2^255 - 19
      p: '7fffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffed',
      a: '-1',
      c: '1',
      // -121665 / 121666 mod p
      d: '52036cee 2b6ffe73 8cc74079 7779e898'
       + '00700a4d 4141d8ab 75eb4dca 135978a3',
      n: '10000000 00000000 00000000 00000000'
       + '14def9de a2f79cd6 5812631a 5cf5d3ed',
      h: '8',
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
 * https://tools.ietf.org/html/rfc7748#section-4.2
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
      iso4: false,
      prime: 'p448',
      // 2^448 - 2^224 - 1
      p: 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff fffffffe ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff',
      // 156326
      a: '262a6',
      b: '1',
      n: '3fffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff 7cca23e9'
       + 'c44edb49 aed63690 216cc272 8dc58f55'
       + '2378c292 ab5844f3',
      h: '4',
      u: '-1',
      g: [
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000005'].join(''),
        ['7d235d12 95f5b1f6 6c98ab6e 58326fce',
         'cbae5d34 f55545d0 60f75dc2 8df3f6ed',
         'b8027e23 46430d21 1312c4b1 50677af7',
         '6fd7223d 457b5b1a'].join('')
      ]
    });
  }
}

/**
 * ED448
 * https://tools.ietf.org/html/rfc8032#section-5.2
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
      iso4: true,
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
      h: '4',
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

/*
 * Scalar Recoding
 */

function getNAF(c, width, max) {
  assert(c instanceof BN);
  assert(!c.red);
  assert((width >>> 0) === width);
  assert((max >>> 0) === max);

  // Computing the NAF of a positive integer.
  //
  // See: Guide to Elliptic Curve Cryptography.
  // Algorithm 3.30, Page 98, Section 3.3.
  //
  // For computing the width-w NAF of a positive integer,
  // See: Algorithm 3.35, Page 100, Section 3.3.
  const naf = new Array(max);
  const size = 1 << (width + 1);
  const k = c.abs();
  const s = c.sign() | 1;

  let i = 0;

  while (!k.isZero()) {
    let z = 0;

    if (k.isOdd()) {
      const mod = k.andln(size - 1);

      if (mod > (size >> 1) - 1)
        z = (size >> 1) - mod;
      else
        z = mod;

      k.isubn(z);
    }

    naf[i++] = z * s;

    // Optimization: shift by word if possible.
    let shift = 1;

    if (!k.isZero() && k.andln(size - 1) === 0)
      shift = width + 1;

    for (let j = 1; j < shift; j++)
      naf[i++] = 0;

    k.iushrn(shift);
  }

  assert(i <= max);

  for (; i < max; i++)
    naf[i] = 0;

  return naf;
}

function getFixedNAF(k, width, max, step) {
  assert((step >>> 0) === step);

  // Recode to NAF.
  const naf = getNAF(k, width, max);

  // Translate into more windowed form.
  const len = Math.ceil(naf.length / step);
  const repr = new Array(len);

  let i = 0;

  for (let j = 0; j < naf.length; j += step) {
    let nafW = 0;

    for (let k = j + step - 1; k >= j; k--)
      nafW = (nafW << 1) + naf[k];

    repr[i++] = nafW;
  }

  assert(i === len);

  return repr;
}

function getJSF(c1, c2, max) {
  assert(c1 instanceof BN);
  assert(c2 instanceof BN);
  assert(!c1.red);
  assert(!c2.red);
  assert((max >>> 0) === max);

  // Joint sparse form.
  //
  // See: Guide to Elliptic Curve Cryptography.
  // Algorithm 3.50, Page 111, Section 3.3.
  const jsf = [new Array(max), new Array(max)];
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
    let u1 = 0;
    let u2 = 0;

    if (m14 === 3)
      m14 = -1;

    if (m24 === 3)
      m24 = -1;

    if (m14 & 1) {
      const m8 = (k1.andln(7) + d1) & 7;

      if ((m8 === 3 || m8 === 5) && m24 === 2)
        u1 = -m14;
      else
        u1 = m14;
    }

    if (m24 & 1) {
      const m8 = (k2.andln(7) + d2) & 7;

      if ((m8 === 3 || m8 === 5) && m14 === 2)
        u2 = -m24;
      else
        u2 = m24;
    }

    jsf[0][i] = u1 * s1;
    jsf[1][i] = u2 * s2;

    // Second phase.
    if (2 * d1 === u1 + 1)
      d1 = 1 - d1;

    if (2 * d2 === u2 + 1)
      d2 = 1 - d2;

    k1.iushrn(1);
    k2.iushrn(1);

    i += 1;
  }

  assert(i <= max);

  for (; i < max; i++) {
    jsf[0][i] = 0;
    jsf[1][i] = 0;
  }

  return jsf;
}

function getJNAF(c1, c2, max) {
  const jsf = getJSF(c1, c2, max);
  const naf = new Array(max);

  // JSF -> NAF conversion.
  for (let i = 0; i < max; i++) {
    const ja = jsf[0][i];
    const jb = jsf[1][i];

    naf[i] = jsfIndex[(ja + 1) * 3 + (jb + 1)];
  }

  return naf;
}

function getLadderBits(k, n) {
  assert(k instanceof BN);
  assert(n instanceof BN);

  // Ensure positive.
  const k0 = k.abs();

  // Inflate scalar.
  const k1 = k0.add(n);
  const k2 = k1.add(n);

  // Get bit lengths.
  const kb = k1.bitLength();
  const nb = n.bitLength();

  // See: Remote Timing Attacks are Still Practical.
  //   B. Brumley, N. Tuveri.
  //   Page 16, Section 6.
  //   https://eprint.iacr.org/2011/232.pdf
  //
  //   k' = k + 2n if ceil(lg(k + n)) <= ceil(lg n),
  //        k + n  otherwise.
  k1.cinject(k2, (kb - nb - 1) >>> 31);

  // Track sign.
  const sign = k.isNeg() & 1;

  // Calculate the new scalar's length.
  const bits = k1.bitLength();

  // Recode scalar to base256.
  const exp = k1.toArray('le');

  return [sign, bits, exp];
}

function getCOZBits(k, n) {
  assert(k instanceof BN);
  assert(n instanceof BN);

  // Ensure positive.
  const u = k.abs().imod(n);

  // Negate scalar.
  const v = n.sub(u);

  // Get bit lengths.
  const nb = n.bitLength();
  const ub = u.bitLength();
  const vb = v.bitLength();

  // Check bits < order bits and bits < neg bits.
  //
  // Logic:
  //
  //   negate = k.bits < n.bits
  //          & k.bits < (n - k).bits
  //          & k.bits != 1
  //          | (n - k).bits == 1
  //
  // The final two are edge cases pertaining to `1`.
  // It appears the Co-Z algorithm cannot handle
  // `-1 mod n`. The cases we handle are:
  //
  //   k = 1 mod n (do not negate)
  //   k = -1 mod n (negate)
  //
  // This means multiplications by `-1 mod n` will
  // be noticeably different in power usage. The
  // same is true of multiplications by `1`.
  const negate = ((ub - nb) >>> 31)
               & ((ub - vb) >>> 31)
               & ((((ub ^ 1) - 1) >>> 31) ^ 1)
               | (((vb ^ 1) - 1) >>> 31);

  // Possibly negate.
  u.cinject(v, negate);

  // Track new sign.
  const sign = k.isNeg() ^ negate;

  // Calculate the new scalar's length.
  const bits = u.bitLength();

  // Recode scalar to base256.
  const exp = u.toArray('le');

  return [sign, bits, exp];
}

/*
 * Helpers
 */

function assert(val, msg) {
  if (!val) {
    const err = new Error(msg || 'Assertion failed');

    if (Error.captureStackTrace)
      Error.captureStackTrace(err, assert);

    throw err;
  }
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

exports.curves = {
  P192,
  P224,
  P256,
  P384,
  P521,
  SECP256K1,
  BRAINPOOLP256,
  BRAINPOOLP384,
  BRAINPOOLP512,
  X25519,
  ED25519,
  X448,
  ED448
};
