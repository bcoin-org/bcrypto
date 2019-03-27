/*!
 * bn.js - big numbers for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/bn.js:
 *   Copyright (c) 2015, Fedor Indutny (MIT License).
 *   https://github.com/indutny/bn.js
 *
 * This software is licensed under the MIT License.
 *
 * Copyright Fedor Indutny, 2015.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

/* eslint valid-typeof: "off" */

'use strict';

const {custom} = require('./internal/custom');
const MAX_SAFE_INTEGER = 9007199254740991n;

/*
 * Constants
 */

// Prime numbers with efficient reduction
const primes = {
  k256: null,
  p224: null,
  p192: null,
  p25519: null,
  p448: null
};

/**
 * BN
 */

class BN {
  constructor(number, base, endian) {
    if (BN.isBN(number))
      return number;

    // Reduction context
    this.n = 0n;
    this.red = null;

    if (number !== null) {
      if (base === 'le' || base === 'be') {
        endian = base;
        base = 10;
      }

      this._init(number || 0, base || 10, endian || 'be');
    }
  }

  get negative() {
    return this.n < 0n ? 1 : 0;
  }

  set negative(val) {
    if ((val & 1) !== this.negative)
      this.n = -this.n;
  }

  get length() {
    return countWords(this.n, 26n);
  }

  _init(number, base, endian) {
    if (typeof number === 'bigint') {
      this.n = number;
      return this;
    }

    if (typeof number === 'number')
      return this._initNumber(number, base, endian);

    if (typeof number === 'object')
      return this._initArray(number, base, endian);

    if (base === 'hex')
      base = 16;

    assert(base === (base | 0) && base >= 2 && base <= 36);

    number = number.toString();

    this._parseBase(number, base);

    if (endian !== 'le')
      return this;

    return this._initArray(this.toArray(), base, endian);
  }

  _initNumber(number, base, endian) {
    assert(number >= -Number.MAX_SAFE_INTEGER);
    assert(number <= Number.MAX_SAFE_INTEGER);

    this.n = BigInt(number);

    if (endian !== 'le')
      return this;

    // Reverse the bytes
    return this._initArray(this.toArray(), base, endian);
  }

  _initArray(number, base, endian) {
    // Perhaps a Uint8Array
    assert(typeof number.length === 'number');

    if (number.length <= 0) {
      this.n = 0n;
      return this;
    }

    let n = 0n;

    if (endian === 'be') {
      for (let i = 0; i < number.length; i++) {
        n <<= 8n;
        n |= BigInt(number[i]);
      }
    } else if (endian === 'le') {
      for (let i = number.length - 1; i >= 0; i--) {
        n <<= 8n;
        n |= BigInt(number[i]);
      }
    }

    this.n = n;

    return this;
  }

  _parseBase(str, base) {
    this.n = fromString(str, base);
    return this;
  }

  copy(dest) {
    dest.n = this.n;
    dest.red = this.red;
  }

  _move(dest) {
    dest.n = this.n;
    dest.red = this.red;
  }

  clone() {
    const r = new BN(null);

    this.copy(r);

    return r;
  }

  _expand(size) {
    return this;
  }

  // Remove leading `0` from `this`
  _strip() {
    return this;
  }

  _normSign() {
    return this;
  }

  toString(base, padding) {
    if (base === 'hex')
      base = 16;

    return toString(this.n, base, padding);
  }

  toNumber() {
    if (this.n > MAX_SAFE_INTEGER)
      assert(false, 'Number can only safely store up to 53 bits');

    return Number(this.n);
  }

  toJSON() {
    return this.toString(16, 2);
  }

  toBuffer(endian, length) {
    return this.toArrayLike(Buffer, endian, length);
  }

  toArray(endian, length) {
    return this.toArrayLike(Array, endian, length);
  }

  toArrayLike(ArrayType, endian, length) {
    const byteLength = this.byteLength();
    const reqLength = length || Math.max(1, byteLength);

    assert(byteLength <= reqLength, 'byte array longer than desired length');
    assert(reqLength > 0, 'Requested array length <= 0');

    const littleEndian = endian === 'le';
    const res = allocate(ArrayType, reqLength);

    let q = this.n;

    if (q < 0n)
      q = -q;

    if (!littleEndian) {
      // Assume big-endian
      for (let i = 0; i < reqLength - byteLength; i++)
        res[i] = 0;

      for (let i = 0; q !== 0n; i++) {
        const b = q & 0xffn;

        q >>= 8n;

        res[reqLength - i - 1] = Number(b);
      }
    } else {
      let i = 0;

      for (; q !== 0n; i++) {
        const b = q & 0xffn;

        q >>= 8n;

        res[i] = Number(b);
      }

      for (; i < reqLength; i++)
        res[i] = 0;
    }

    return res;
  }

  // Return number of used bits in a BN
  bitLength() {
    return bitLength(this.n);
  }

  // Number of trailing zero bits
  zeroBits() {
    return zeroBits(this.n);
  }

  byteLength() {
    return byteLength(this.n);
  }

  toTwos(width) {
    return new BN(toTwos(this.n, width));
  }

  fromTwos(width) {
    return new BN(fromTwos(this.n, width));
  }

  isNeg() {
    return this.n < 0n;
  }

  // Return negative clone of `this`
  neg() {
    return this.clone().ineg();
  }

  ineg() {
    this.n = -this.n;
    return this;
  }

  // Or `num` with `this` in-place
  iuor(num) {
    this.n |= num.n;
    return this;
  }

  ior(num) {
    assert((this.negative | num.negative) === 0);
    return this.iuor(num);
  }

  // Or `num` with `this`
  or(num) {
    return this.clone().ior(num);
  }

  uor(num) {
    return this.clone().iuor(num);
  }

  // And `num` with `this` in-place
  iuand(num) {
    this.n &= num.n;
    return this;
  }

  iand(num) {
    assert((this.negative | num.negative) === 0);
    return this.iuand(num);
  }

  // And `num` with `this`
  and(num) {
    return this.clone().iand(num);
  }

  uand(num) {
    return this.clone().iuand(num);
  }

  // Xor `num` with `this` in-place
  iuxor(num) {
    this.n ^= num.n;
    return this;
  }

  ixor(num) {
    assert((this.negative | num.negative) === 0);
    return this.iuxor(num);
  }

  // Xor `num` with `this`
  xor(num) {
    return this.clone().ixor(num);
  }

  uxor(num) {
    return this.clone().iuxor(num);
  }

  // Not ``this`` with ``width`` bitwidth
  inotn(width) {
    assert(typeof width === 'number' && width >= 0);
    this.n = not(this.n, width);
    return this;
  }

  notn(width) {
    return this.clone().inotn(width);
  }

  // Set `bit` of `this`
  setn(bit, val) {
    assert(typeof bit === 'number' && bit >= 0);
    this.n = setn(this.n, bit, val);
    return this;
  }

  // Add `num` to `this` in-place
  iadd(num) {
    this.n += num.n;
    return this;
  }

  // Add `num` to `this`
  add(num) {
    return this.clone().iadd(num);
  }

  // Subtract `num` from `this` in-place
  isub(num) {
    this.n -= num.n;
    return this;
  }

  // Subtract `num` from `this`
  sub(num) {
    return this.clone().isub(num);
  }

  mulTo(num, out) {
    out.n = this.n * num.n;
    return this;
  }

  // Multiply `this` by `num`
  mul(num) {
    return this.clone().imul(num);
  }

  // Multiply employing FFT
  mulf(num) {
    return this.mul(num);
  }

  // In-place Multiplication
  imul(num) {
    this.n *= num.n;
    return this;
  }

  imuln(num) {
    this.n *= small(num);
    return this;
  }

  muln(num) {
    return this.clone().imuln(num);
  }

  // `this` * `this`
  sqr() {
    return this.mul(this);
  }

  // `this` * `this` in-place
  isqr() {
    return this.imul(this.clone());
  }

  // Math.pow(`this`, `num`)
  pow(num) {
    return new BN(this.n ** num.n);
  }

  // Shift-left in-place
  iushln(bits) {
    assert(typeof bits === 'number' && bits >= 0);
    this.n <<= BigInt(bits);
    return this;
  }

  ishln(bits) {
    // TODO(indutny): implement me
    assert(this.negative === 0);
    return this.iushln(bits);
  }

  // Shift-right in-place
  // NOTE: `hint` is a lowest bit before trailing zeroes
  // NOTE: if `extended` is present - it will be filled with destroyed bits
  iushrn(bits, hint, extended) {
    assert(typeof bits === 'number' && bits >= 0);

    if (extended)
      extended.n = maskn(this.n, bits);

    this.n >>= BigInt(bits);

    return this;
  }

  ishrn(bits, hint, extended) {
    // TODO(indutny): implement me
    assert(this.negative === 0);
    return this.iushrn(bits, hint, extended);
  }

  // Shift-left
  shln(bits) {
    return this.clone().ishln(bits);
  }

  ushln(bits) {
    return this.clone().iushln(bits);
  }

  // Shift-right
  shrn(bits) {
    return this.clone().ishrn(bits);
  }

  ushrn(bits) {
    return this.clone().iushrn(bits);
  }

  // Test if n bit is set
  testn(bit) {
    assert(typeof bit === 'number' && bit >= 0);
    return testn(this.n, bit);
  }

  // Return only lowers bits of number (in-place)
  imaskn(bits) {
    assert(typeof bits === 'number' && bits >= 0);
    assert(this.negative === 0, 'imaskn works only with positive numbers');
    this.n = maskn(this.n, bits);
    return this;
  }

  // Return only lowers bits of number
  maskn(bits) {
    return this.clone().imaskn(bits);
  }

  // Add plain number `num` to `this`
  iaddn(num) {
    this.n += small(num);
    return this;
  }

  // Subtract plain number `num` from `this`
  isubn(num) {
    this.n -= small(num);
    return this;
  }

  addn(num) {
    return this.clone().iaddn(num);
  }

  subn(num) {
    return this.clone().isubn(num);
  }

  iabs() {
    this.n = abs(this.n);
    return this;
  }

  abs() {
    return this.clone().iabs();
  }

  // NOTE: 1) `mode` can be set to `mod` to request mod only,
  //       to `div` to request div only, or be absent to
  //       request both div & mod
  //       2) `positive` is true if unsigned mod is requested
  divmod(num, mode, positive) {
    assert(!num.isZero());

    let div = null;
    let mod = null;

    if (!mode || mode === 'div')
      div = this.div(num);

    if (!mode || mode === 'mod')
      mod = positive ? this.umod(num) : this.mod(num);

    return {
      div,
      mod
    };
  }

  // Find `this` / `num`
  div(num) {
    return new BN(this.n / num.n);
  }

  // Find `this` % `num`
  mod(num) {
    return new BN(this.n % num.n);
  }

  umod(num) {
    return new BN(umod(this.n, num.n));
  }

  // Find Round(`this` / `num`)
  divRound(num) {
    return new BN(divRound(this.n, num.n));
  }

  modrn(num) {
    return modrn(this.n, num);
  }

  // WARNING: DEPRECATED
  modn(num) {
    return this.modrn(num);
  }

  // In-place division by number
  idivn(num) {
    this.n /= small(num);
    return this;
  }

  divn(num) {
    return this.clone().idivn(num);
  }

  egcd(p) {
    const [a, b, gcd] = egcd(this.n, p.n);

    return {
      a: new BN(a),
      b: new BN(b),
      gcd: new BN(gcd)
    };
  }

  gcd(num) {
    return new BN(gcd(this.n, num.n));
  }

  // Invert number in the field F(num)
  invm(num) {
    return new BN(invm(this.n, num.n));
  }

  isEven() {
    return (this.n & 1n) === 0n;
  }

  isOdd() {
    return (this.n & 1n) === 1n;
  }

  // And first word and num
  andln(num) {
    return andln(this.n, num);
  }

  // Increment at the bit position in-line
  bincn(bit) {
    assert(typeof bit === 'number');
    this.n = bincn(this.n, bit);
    return this;
  }

  isZero() {
    return this.n === 0n;
  }

  cmpn(num) {
    return cmpn(this.n, num);
  }

  // Compare two numbers and return:
  // 1 - if `this` > `num`
  // 0 - if `this` == `num`
  // -1 - if `this` < `num`
  cmp(num) {
    return cmp(this.n, num.n);
  }

  // Unsigned comparison
  ucmp(num) {
    return ucmp(this.n, num.n);
  }

  gtn(num) {
    return this.n > small(num);
  }

  gt(num) {
    return this.n > num.n;
  }

  gten(num) {
    return this.n >= small(num);
  }

  gte(num) {
    return this.n >= num.n;
  }

  ltn(num) {
    return this.n < small(num);
  }

  lt(num) {
    return this.n < num.n;
  }

  lten(num) {
    return this.n <= small(num);
  }

  lte(num) {
    return this.n <= num.n;
  }

  eqn(num) {
    return this.n === small(num);
  }

  eq(num) {
    return this.n === num.n;
  }

  toRed(ctx) {
    assert(!this.red, 'Already a number in reduction context');
    assert(this.negative === 0, 'red works only with positives');
    return ctx.convertTo(this)._forceRed(ctx);
  }

  fromRed() {
    assert(this.red, 'fromRed works only with numbers in reduction context');
    return this.red.convertFrom(this);
  }

  _forceRed(ctx) {
    this.red = ctx;
    return this;
  }

  forceRed(ctx) {
    assert(!this.red, 'Already a number in reduction context');
    return this._forceRed(ctx);
  }

  redAdd(num) {
    assert(this.red, 'redAdd works only with red numbers');
    return this.red.add(this, num);
  }

  redIAdd(num) {
    assert(this.red, 'redIAdd works only with red numbers');
    return this.red.iadd(this, num);
  }

  redSub(num) {
    assert(this.red, 'redSub works only with red numbers');
    return this.red.sub(this, num);
  }

  redISub(num) {
    assert(this.red, 'redISub works only with red numbers');
    return this.red.isub(this, num);
  }

  redShl(num) {
    assert(this.red, 'redShl works only with red numbers');
    return this.red.shl(this, num);
  }

  redMul(num) {
    assert(this.red, 'redMul works only with red numbers');
    this.red._verify2(this, num);
    return this.red.mul(this, num);
  }

  redIMul(num) {
    assert(this.red, 'redMul works only with red numbers');
    this.red._verify2(this, num);
    return this.red.imul(this, num);
  }

  redSqr() {
    assert(this.red, 'redSqr works only with red numbers');
    this.red._verify1(this);
    return this.red.sqr(this);
  }

  redISqr() {
    assert(this.red, 'redISqr works only with red numbers');
    this.red._verify1(this);
    return this.red.isqr(this);
  }

  // Square root over p
  redSqrt() {
    assert(this.red, 'redSqrt works only with red numbers');
    this.red._verify1(this);
    return this.red.sqrt(this);
  }

  redInvm() {
    assert(this.red, 'redInvm works only with red numbers');
    this.red._verify1(this);
    return this.red.invm(this);
  }

  // Return negative clone of `this` % `red modulo`
  redNeg() {
    assert(this.red, 'redNeg works only with red numbers');
    this.red._verify1(this);
    return this.red.neg(this);
  }

  redPow(num) {
    assert(this.red && !num.red, 'redPow(normalNum)');
    this.red._verify1(this);
    return this.red.pow(this, num);
  }

  [custom]() {
    return (this.red ? '<BN-R: ' : '<BN: ') + this.toString(16) + '>';
  }

  static isBN(num) {
    return num instanceof BN;
  }

  static max(left, right) {
    if (left.cmp(right) > 0)
      return left;

    return right;
  }

  static min(left, right) {
    if (left.cmp(right) < 0)
      return left;

    return right;
  }

  //
  // A reduce context, could be using montgomery or something better, depending
  // on the `m` itself.
  //
  static red(num) {
    return new Red(num);
  }

  // Exported mostly for testing purposes, use plain name instead
  static _prime(name) {
    // Cached version of prime
    if (primes[name])
      return primes[name];

    let prime;

    if (name === 'k256') {
      prime = new K256();
    } else if (name === 'p224') {
      prime = new P224();
    } else if (name === 'p192') {
      prime = new P192();
    } else if (name === 'p25519') {
      prime = new P25519();
    } else if (name === 'p448') {
      prime = new P448();
    } else {
      throw new Error('Unknown prime ' + name);
    }

    primes[name] = prime;

    return prime;
  }

  static mont(num) {
    return new Red(num);
  }
}

/*
 * Static
 */

BN.BN = BN;
BN.wordSize = 26;

/**
 * MPrime
 * Pseudo-Mersenne prime
 */

class MPrime {
  constructor(name, p) {
    // P = 2 ^ N - K
    this.name = name;
    this.p = new BN(p, 16);
    this.n = this.p.bitLength();
    this.b = BigInt(this.n);
    this.m = (1n << this.b) - 1n;
    this.k = (1n << this.b) - this.p.n;
  }

  ireduce(num) {
    // Assumes that `num` is less than `P^2`
    // num = HI * (2 ^ N - K) + HI * K + LO = HI * K + LO (mod P)
    let r = num.n;
    let t = 0n;

    do {
      t = r & ((1n << this.b) - 1n);
      r >>= this.b;
      r *= this.k;
      r += t;
    } while (r > this.m);

    if (r >= this.p.n)
      r -= this.p.n;

    num.n = r;

    return num;
  }

  split(input, out) {
    input.iushrn(this.n, 0, out);
  }
}

/**
 * K256
 */

class K256 extends MPrime {
  constructor() {
    super('k256', 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff fffffffe fffffc2f');
  }
}

/**
 * P224
 */

class P224 extends MPrime {
  constructor() {
    super('p224', 'ffffffff ffffffff ffffffff ffffffff'
                + '00000000 00000000 00000001');
  }
}

/**
 * P192
 */

class P192 extends MPrime {
  constructor() {
    super('p192', 'ffffffff ffffffff ffffffff'
                + 'fffffffe ffffffff ffffffff');
  }
}

/**
 * P25519
 */

class P25519 extends MPrime {
  constructor() {
    // 2 ^ 255 - 19
    super('25519', '7fffffffffffffff ffffffffffffffff'
                 + 'ffffffffffffffff ffffffffffffffed');
  }
}

/**
 * P448
 */

class P448 extends MPrime {
  constructor() {
    // 2 ** 448 - 2 ** 224 - 1
    super('448', 'ffffffffffffffffffffffffffff'
               + 'fffffffffffffffffffffffffffe'
               + 'ffffffffffffffffffffffffffff'
               + 'ffffffffffffffffffffffffffff');
  }
}

/**
 * Red
 * Base reduction engine
 */

class Red {
  constructor(m) {
    if (typeof m === 'string') {
      const prime = BN._prime(m);
      this.m = prime.p;
      this.prime = prime;
    } else {
      assert(m.gtn(1), 'modulus must be greater than 1');
      this.m = m;
      this.prime = null;
    }
  }

  _verify1(a) {
    assert(a.negative === 0, 'red works only with positives');
    assert(a.red, 'red works only with red numbers');
  }

  _verify2(a, b) {
    assert((a.negative | b.negative) === 0, 'red works only with positives');
    assert(a.red && a.red === b.red,
      'red works only with red numbers');
  }

  BN(n) {
    const bn = new BN(null);
    bn.red = this;
    bn.n = n;
    return bn;
  }

  imod(x) {
    x.n = umod(x.n, this.m.n);
    return x;
  }

  neg(a) {
    if (a.n === 0n)
      return a.clone();

    return this.BN(this.m.n - a.n);
  }

  add(a, b) {
    return this.iadd(a.clone(), b);
  }

  iadd(a, b) {
    this._verify2(a, b);

    a.n += b.n;

    if (a.n > this.m.n)
      a.n -= this.m.n;

    return a;
  }

  sub(a, b) {
    return this.isub(a.clone(), b);
  }

  isub(a, b) {
    this._verify2(a, b);

    a.n -= b.n;

    if (a.n < 0n)
      a.n += this.m.n;

    return a;
  }

  shl(a, num) {
    this._verify1(a);
    return this.imod(a.ushln(num));
  }

  imul(a, b) {
    this._verify2(a, b);
    return this.imod(a.imul(b));
  }

  mul(a, b) {
    this._verify2(a, b);
    return this.imod(a.mul(b));
  }

  isqr(a) {
    return this.imul(a, a.clone());
  }

  sqr(a) {
    return this.mul(a, a);
  }

  sqrt(x) {
    return this.BN(modSqrt(x.n, this.m.n));
  }

  invm(x) {
    const inv = invmp(x.n, this.m.n);
    return this.imod(this.BN(inv));
  }

  pow(x, y) {
    return this.BN(modPow(x.n, y.n, this.m.n));
  }

  convertTo(num) {
    return num.umod(this.m);
  }

  convertFrom(num) {
    const res = num.clone();
    res.red = null;
    return res;
  }
}

/*
 * Helpers
 */

function assert(val, msg) {
  if (!val)
    throw new Error(msg || 'Assertion failed');
}

function allocate(ArrayType, size) {
  if (ArrayType.allocUnsafe)
    return ArrayType.allocUnsafe(size);

  return new ArrayType(size);
}

function small(num) {
  assert(Number.isSafeInteger(num));

  if (num < 0)
    assert(num > -0x4000000, 'Number is too big');
  else
    assert(num < 0x4000000, 'Number is too big');

  return BigInt(num);
}

function zeroBits(x) {
  if (x === 0n)
    return 0;

  if (x < 0n)
    x = -x;

  let i = 0;

  while ((x & 1n) === 0n) {
    i += 1;
    x >>= 1n;
  }

  return i;
}

function countWords(x, w) {
  if (x === 0n)
    return 0;

  if (x < 0n)
    x = -x;

  let i = 0;

  while (x > 0n) {
    i += 1;
    x >>= w;
  }

  return i;
}

function bitLength(x) {
  return countWords(x, 1n);
}

function byteLength(x) {
  return countWords(x, 8n);
}

function abs(x) {
  return x < 0n ? -x : x;
}

function mask(width) {
  return (1n << BigInt(width)) - 1n;
}

function maskn(x, width) {
  return x & mask(width);
}

function not(x, width) {
  return x ^ mask(width);
}

function testn(x, bit) {
  return (x & (1n << BigInt(bit))) !== 0n;
}

function toTwos(x, width) {
  if (x < 0n)
    return not(-x, width) + 1n;

  return x;
}

function fromTwos(x, width) {
  if (testn(x, width - 1))
    return -(not(x, width) + 1n);

  return x;
}

function setn(x, bit, val) {
  if (val)
    x |= (1n << BigInt(bit));
  else
    x &= ~(1n << BigInt(bit));
  return x;
}

function div(x, y) {
  if ((x < 0n) !== (y < 0n)) {
    if (x % y !== 0n)
      return (x / y) - 1n;
  }

  return x / y;
}

function mod(x, y) {
  x %= y;

  if (y < 0n) {
    if (x > 0n)
      x += y;
  } else {
    if (x < 0n)
      x += y;
  }

  return x;
}

function umod(x, y) {
  x %= y;

  if (x < 0n) {
    if (y > 0n)
      x += y;
    else
      x -= y;
  }

  return x;
}

function divRound(x, y) {
  let q = x / y;
  let r = x % y;

  // Fast case - exact division
  if (r === 0n)
    return q;

  if (q < 0n)
    r -= y;

  const h = y >> 1n;

  // Round down
  if (r < h)
    return q;

  if ((y & 1n) === 1n && r === h)
    return q;

  // Round up
  if (q < 0n)
    q -= 1n;
  else
    q += 1n;

  return q;
}

function modrn(x, y) {
  y = BigInt(y);

  let z = x % y;

  if ((x < 0n) !== (y < 0n))
    z = -z;

  return Number(z);
}

function andln(x, y) {
  return Number(x & BigInt(y));
}

function bincn(x, bit) {
  let neg = false;

  bit = BigInt(bit);

  if (x < 0) {
    neg = true;
    x = -x;
  }

  const d = x & ((1n << bit) - 1n);

  x >>= bit;
  x += 1n;
  x <<= bit;
  x |= d;

  if (neg)
    x = -x;

  return x;
}

function cmpn(x, y) {
  return cmp(x, small(y));
}

function cmp(x, y) {
  if (x < y)
    return -1;

  if (x > y)
    return 1;

  return 0;
}

function ucmp(x, y) {
  if (x < 0n)
    x = -x;

  if (y < 0n)
    y = -y;

  return cmp(x, y);
}

function gcd(x, y) {
  if (x < 0n)
    x = -x;

  if (y < 0n)
    y = -y;

  while (y !== 0n)
    [x, y] = [y, mod(x, y)];

  return x;
}

function egcd(x, y) {
  assert(y > 0n);

  let s = 0n;
  let os = 1n;
  let t = 1n;
  let ot = 0n;
  let r = y;
  let or = x;

  while (r !== 0n) {
    const q = div(or, r);

    [or, r] = [r, or - q * r];
    [os, s] = [s, os - q * s];
    [ot, t] = [t, ot - q * t];
  }

  return [os, ot, or];
}

function invm(x, y) {
  return umod(egcd(x, y)[0], y);
}

function inverse(x, n) {
  x = mod(x, n);

  let t = 0n;
  let nt = 1n;
  let r = n;
  let nr = x;

  while (nr !== 0n) {
    const q = div(r, nr);

    [t, nt] = [nt, t - q * nt];
    [r, nr] = [nr, r - q * nr];
  }

  if (r > 1n)
    throw new Error('Not invertible.');

  return mod(t, n);
}

// https://github.com/golang/go/blob/aadaec5/src/math/big/int.go#L754
function jacobi(x, y) {
  if (y === 0n || (y & 1n) === 0n)
    throw new Error('jacobi: `y` must be odd.');

  // See chapter 2, section 2.4:
  // http://yacas.sourceforge.net/Algo.book.pdf
  let a = x;
  let b = y;
  let j = 1;

  if (b < 0n) {
    if (a < 0n)
      j = -1;
    b = -b;
  }

  for (;;) {
    if (b === 1n)
      return j;

    if (a === 0n)
      return 0;

    a = mod(a, b);

    if (a === 0n)
      return 0;

    const s = zeroBits(a);

    if (s & 1) {
      const bmod8 = b & 7n;

      if (bmod8 === 3n || bmod8 === 5n)
        j = -j;
    }

    const c = a >> BigInt(s);

    if ((b & 3n) === 3n && (c & 3n) === 3n)
      j = -j;

    a = b;
    b = c;
  }
}

// https://github.com/golang/go/blob/c86d464/src/math/big/int.go#L906
function modSqrt(x, p) {
  switch (jacobi(x, p)) {
    case -1:
      throw new Error('X is not a square mod P.');
    case 0:
      return 0n;
    case 1:
      break;
  }

  if (x < 0n || x >= p)
    x = mod(x, p);

  let s = p - 1n;

  const e = BigInt(zeroBits(s));

  s >>= e;

  let n = 2n;

  while (jacobi(n, p) !== -1)
    n += 1n;

  let y = 0n;
  let b = 0n;
  let g = 0n;

  y = s + 1n;
  y >>= 1n;
  y = modPow(x, y, p);
  b = modPow(x, s, p);
  g = modPow(n, s, p);

  let r = e;
  let t = 0n;

  for (;;) {
    let m = 0n;

    t = b;

    while (t !== 1n) {
      t = mod(t * t, p);
      m += 1n;
    }

    if (m === 0n)
      break;

    t = 1n << (r - m - 1n);
    t = modPow(g, t, p);
    g = mod(t * t, p);
    y = mod(y * t, p);
    b = mod(b * g, p);
    r = m;
  }

  return y;
}

function modPow(x, y, m) {
  if (m === 0n)
    throw new Error('Cannot divide by zero.');

  if (m === 1n)
    return 0n;

  if (x === 0n)
    return 0n;

  // GMP behavior.
  if (y < 0n) {
    x = inverse(x, m);
    y = -y;
  } else {
    x = mod(x, m);
  }

  let r = 1n;

  while (y > 0n) {
    if ((y & 1n) === 1n)
      r = mod(r * x, m);

    y >>= 1n;
    x = mod(x * x, m);
  }

  return r;
}

function invmp(x, p) {
  assert(p > 0n);

  if (x < 0n)
    x = mod(x, p);

  let x1 = 1n;
  let x2 = 0n;
  let y = p;

  while (x > 1n && y > 1n) {
    let i = zeroBits(x);

    if (i > 0) {
      x >>= BigInt(i);

      while (i-- > 0) {
        if (x1 & 1n)
          x1 += p;

        x1 >>= 1n;
      }
    }

    let j = zeroBits(y);

    if (j > 0) {
      y >>= BigInt(j);

      while (j-- > 0) {
        if (x2 & 1n)
          x2 += p;

        x2 >>= 1n;
      }
    }

    if (x >= y) {
      x -= y;
      x1 -= x2;
    } else {
      y -= x;
      x2 -= x1;
    }
  }

  let res;

  if (x === 1n)
    res = x1;
  else
    res = x2;

  if (res < 0n)
    res += p;

  return res;
}

function toString(num, base, pad) {
  if (base == null)
    base = 10;

  if (pad == null)
    pad = 0;

  if (pad === 0)
    pad = 1;

  assert(typeof num === 'bigint');
  assert((base >>> 0) === base, String(base));
  assert((pad >>> 0) === pad);

  if (base < 2 || base > 36)
    throw new RangeError('Base ranges between 2 and 36.');

  let neg = false;

  if (num < 0n) {
    neg = true;
    num = -num;
  }

  let str = num.toString(base);

  while (str.length % pad)
    str = '0' + str;

  if (neg)
    str = '-' + str;

  return str;
}

function fromString(str, base) {
  assert(typeof str === 'string');
  assert((base >>> 0) === base);

  if (base < 2 || base > 36)
    throw new RangeError('Base ranges between 2 and 36.');

  if (isFastBase(base))
    return fromStringFast(str, base);

  let neg = false;
  let i = 0;

  for (; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    switch (ch) {
      case 0x09: // '\t'
      case 0x0a: // '\n'
      case 0x0d: // '\r'
      case 0x20: // ' '
        continue;
    }

    break;
  }

  if (i < str.length && str[i] === '-') {
    neg = true;
    i += 1;
  }

  const big = BigInt(base);

  let num = 0n;

  for (; i < str.length; i++) {
    let ch = str.charCodeAt(i);

    switch (ch) {
      case 0x09: // '\t'
      case 0x0a: // '\n'
      case 0x0d: // '\r'
      case 0x20: // ' '
        continue;
    }

    if (ch >= 0x30 && ch <= 0x39)
      ch -= 0x30;
    else if (ch >= 0x41 && ch <= 0x5a)
      ch -= 0x41 - 10;
    else if (ch >= 0x61 && ch <= 0x7a)
      ch -= 0x61 - 10;
    else
      ch = base;

    if (ch >= base)
      throw new Error('Invalid string (parse error).');

    num *= big;
    num += BigInt(ch);
  }

  if (neg)
    num = -num;

  return num;
}

function isFastBase(base) {
  switch (base) {
    case 2:
    case 8:
    case 10:
    case 16:
      return true;
  }
  return false;
}

function fromStringFast(str, base) {
  let neg = false;
  let num;

  str = str.replace(/[\t\n\r ]/g, '');

  if (str.length > 0 && str[0] === '-') {
    str = str.substring(1);
    neg = true;
  }

  if (str.length === 0)
    throw new Error('Invalid string (bad length).');

  switch (base) {
    case 2:
      str = '0b' + str;
      break;
    case 8:
      str = '0o' + str;
      break;
    case 10:
      if (str.length > 1) {
        const ch = str.charCodeAt(1);
        if (ch < 0x30 || ch > 0x39)
          throw new Error('Invalid string (parse error).');
      }
      break;
    case 16:
      str = '0x' + str;
      break;
    default:
      throw new Error('Invalid base.');
  }

  try {
    num = BigInt(str);
  } catch (e) {
    throw new Error('Invalid string (parse error).');
  }

  if (neg)
    num = -num;

  return num;
}

/*
 * Expose
 */

module.exports = BN;
