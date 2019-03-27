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
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   https://github.com/golang/go/blob/master/src/math/big/int.go
 *   https://github.com/golang/go/blob/master/src/math/big/nat.go
 */

/* eslint valid-typeof: "off" */

'use strict';

const {custom} = require('../internal/custom');

/*
 * Constants
 */

const MAX_SAFE_INTEGER = 9007199254740991n;

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
  constructor(num, base, endian) {
    if (BN.isBN(num))
      return num;

    this.n = 0n;
    this.red = null;

    this.from(num, base, endian);
  }

  /*
   * Compat
   */

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

  /*
   * Addition
   */

  iadd(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    this.n += num.n;
    return this;
  }

  iaddn(num) {
    enforce(isSMI(num), 'num', 'smi');
    this.n += BigInt(num);
    return this;
  }

  add(num) {
    return this.clone().iadd(num);
  }

  addn(num) {
    return this.clone().iaddn(num);
  }

  /*
   * Subtraction
   */

  isub(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    this.n -= num.n;
    return this;
  }

  isubn(num) {
    enforce(isSMI(num), 'num', 'smi');
    this.n -= BigInt(num);
    return this;
  }

  sub(num) {
    return this.clone().isub(num);
  }

  subn(num) {
    return this.clone().isubn(num);
  }

  /*
   * Multiplication
   */

  mulTo(num, out) {
    enforce(BN.isBN(num), 'num', 'bignum');
    enforce(BN.isBN(out), 'out', 'bignum');
    out.n = this.n * num.n;
    return this;
  }

  imul(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    this.n *= num.n;
    return this;
  }

  imuln(num) {
    enforce(isSMI(num), 'num', 'smi');
    this.n *= BigInt(num);
    return this;
  }

  mul(num) {
    return this.clone().imul(num);
  }

  muln(num) {
    return this.clone().imuln(num);
  }

  mulf(num) {
    return this.mul(num);
  }

  /*
   * Division
   */

  divmod(num, mode, positive) {
    enforce(BN.isBN(num), 'num', 'bignum');
    enforce(mode == null || typeof mode === 'string', 'mode', 'string');
    enforce(positive == null || typeof positive === 'boolean',
            'positive', 'boolean');

    if (mode != null && mode !== 'div' && mode !== 'mod')
      throw new TypeError('"mode" must be "div" or "mod".');

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

  idiv(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    this.n /= num.n;
    return this;
  }

  idivn(num) {
    enforce(isSMI(num), 'num', 'smi');
    this.n /= BigInt(num);
    return this;
  }

  div(num) {
    return this.clone().idiv(num);
  }

  divn(num) {
    return this.clone().idivn(num);
  }

  /*
   * Round Division
   */

  divRound(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    return new BN(divRound(this.n, num.n));
  }

  /*
   * Modulo
   */

  imod(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    this.n %= num.n;
    return this;
  }

  imodn(num) {
    enforce(isSMI(num), 'num', 'smi');
    this.n %= BigInt(num);
    return this;
  }

  mod(num) {
    return this.clone().imod(num);
  }

  modn(num) {
    // Alias to modrn for now.
    return this.modrn(num);
  }

  modrn(num) {
    enforce(isSMI(num), 'num', 'smi');
    return modrn(this.n, num);
  }

  /*
   * Unsigned Modulo
   */

  iumod(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    this.n = umod(this.n, num.n);
    return this;
  }

  iumodn(num) {
    enforce(isSMI(num), 'num', 'smi');
    this.n = umod(this.n, BigInt(num));
    return this;
  }

  umod(num) {
    return this.clone().iumod(num);
  }

  umodn(num) {
    // Alias to umodrn for now.
    return this.umodrn(num);
  }

  umodrn(num) {
    enforce(isSMI(num), 'num', 'smi');
    return umodrn(this.n, num);
  }

  /*
   * Exponentiation
   */

  ipow(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    this.n = this.n ** num.n;
    return this;
  }

  ipown(num) {
    enforce(isSMI(num), 'num', 'smi');
    this.n = this.n ** BigInt(num);
    return this;
  }

  pow(num) {
    return this.clone().ipow(num);
  }

  pown(num) {
    return this.clone().ipown(num);
  }

  isqr() {
    this.n *= this.n;
    return this;
  }

  sqr() {
    return this.clone().isqr();
  }

  isqrt() {
    range(this.negative === 0, 'isqrt');
    this.n = sqrt(this.n);
    return this;
  }

  sqrt() {
    return this.clone().isqrt();
  }

  /*
   * AND
   */

  iand(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    range((this.negative | num.negative) === 0, 'iand');
    this.n &= num.n;
    return this;
  }

  iandn(num) {
    enforce(isSMI(num), 'num', 'smi');
    range((this.negative | (num < 0)) === 0, 'iandn');
    this.n &= BigInt(num);
    return this;
  }

  and(num) {
    return this.clone().iand(num);
  }

  andn(num) {
    return this.clone().iandn(num);
  }

  /*
   * Unsigned AND
   */

  iuand(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    this.n &= num.n;
    return this;
  }

  iuandn(num) {
    enforce(isSMI(num), 'num', 'smi');
    this.n &= BigInt(num);
    return this;
  }

  uand(num) {
    return this.clone().uand(num);
  }

  uandn(num) {
    return this.clone().iuandn(num);
  }

  /*
   * OR
   */

  ior(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    range((this.negative | num.negative) === 0, 'ior');
    this.n |= num.n;
    return this;
  }

  iorn(num) {
    enforce(isSMI(num), 'num', 'smi');
    range((this.negative | (num < 0)) === 0, 'iorn');
    this.n |= BigInt(num);
    return this;
  }

  or(num) {
    return this.clone().ior(num);
  }

  orn(num) {
    return this.clone().iorn(num);
  }

  /*
   * Unsigned OR
   */

  iuor(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    this.n |= num.n;
    return this;
  }

  iuorn(num) {
    enforce(isSMI(num), 'num', 'smi');
    this.n |= BigInt(num.n);
    return this;
  }

  uor(num) {
    return this.clone().iuor(num);
  }

  uorn(num) {
    return this.clone().iuorn(num);
  }

  /*
   * XOR
   */

  ixor(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    range((this.negative | num.negative) === 0, 'ixor');
    this.n ^= num.n;
    return this;
  }

  ixorn(num) {
    enforce(isSMI(num), 'num', 'smi');
    range((this.negative | (num < 0)) === 0, 'ixorn');
    this.n ^= BigInt(num);
    return this;
  }

  xor(num) {
    return this.clone().ixor(num);
  }

  xorn(num) {
    return this.clone().ixorn(num);
  }

  /*
   * Unsigned XOR
   */

  iuxor(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    this.n ^= num.n;
    return this;
  }

  iuxorn(num) {
    enforce(isSMI(num), 'num', 'smi');
    this.n ^= BigInt(num);
    return this;
  }

  uxor(num) {
    return this.clone().ixor(num);
  }

  uxorn(num) {
    return this.clone().iuxorn(num);
  }

  /*
   * NOT
   */

  inotn(width) {
    enforce(isInteger(width), 'width', 'integer');
    range(width >= 0, 'inotn');
    this.n = notn(this.n, width);
    return this;
  }

  notn(width) {
    return this.clone().inotn(width);
  }

  /*
   * Left Shift
   */

  ishl(num) {
    enforce(BN.isBN(num), 'bits', 'bignum');
    range((this.negative | num.negative) === 0, 'ishl');
    this.n <<= num.n;
    return this;
  }

  ishln(bits) {
    enforce(isInteger(bits), 'bits', 'integer');
    range((this.negative | (bits < 0)) === 0, 'ishln');
    this.n <<= BigInt(bits);
    return this;
  }

  shl(num) {
    return this.clone().ishl(num);
  }

  shln(bits) {
    return this.clone().ishln(bits);
  }

  /*
   * Unsigned Left Shift
   */

  iushl(num) {
    enforce(BN.isBN(num), 'bits', 'bignum');
    range(num.negative === 0, 'iushl');
    this.n <<= num.n;
    return this;
  }

  iushln(bits) {
    enforce(isInteger(bits), 'bits', 'integer');
    range(bits >= 0, 'iushln');
    this.n <<= BigInt(bits);
    return this;
  }

  ushl(num) {
    return this.clone().iushl(num);
  }

  ushln(bits) {
    return this.clone().iushln(bits);
  }

  /*
   * Right Shift
   */

  ishr(num) {
    enforce(BN.isBN(num), 'bits', 'bignum');
    range((this.negative | num.negative) === 0, 'ishr');
    this.n >>= num.n;
    return this;
  }

  ishrn(bits) {
    enforce(isInteger(bits), 'bits', 'integer');
    range((this.negative | (bits < 0)) === 0, 'ishrn');
    this.n >>= BigInt(bits);
    return this;
  }

  shr(num) {
    return this.clone().ishr(num);
  }

  shrn(bits) {
    return this.clone().ishrn(bits);
  }

  /*
   * Unsigned Right Shift
   */

  iushr(num) {
    enforce(BN.isBN(num), 'bits', 'bignum');
    range(num.negative === 0, 'iushr');
    this.n >>= num.n;
    return this;
  }

  iushrn(bits) {
    enforce(isInteger(bits), 'bits', 'integer');
    range(bits >= 0, 'iushrn');
    this.n >>= BigInt(bits);
    return this;
  }

  ushr(num) {
    return this.clone().iushr(num);
  }

  ushrn(bits) {
    return this.clone().iushrn(bits);
  }

  /*
   * Bit Manipulation
   */

  setn(bit, val) {
    enforce(isInteger(bit), 'bit', 'integer');
    range(bit >= 0, 'setn');
    this.n = setn(this.n, bit, val);
    return this;
  }

  testn(bit) {
    enforce(isInteger(bit), 'bit', 'integer');
    range(bit >= 0, 'testn');
    return testn(this.n, bit);
  }

  imaskn(bits) {
    enforce(isInteger(bits), 'bits', 'integer');
    range((this.negative | (bits < 0)) === 0, 'imaskn');
    this.n = maskn(this.n, bits);
    return this;
  }

  maskn(bits) {
    return this.clone().imaskn(bits);
  }

  andln(num) {
    enforce(isInteger(num), 'num', 'integer');
    return andln(this.n, num);
  }

  bincn(bit) {
    enforce(isInteger(bit), 'bit', 'integer');
    this.n = bincn(this.n, bit);
    return this;
  }

  /*
   * Negation
   */

  ineg() {
    this.n = -this.n;
    return this;
  }

  neg() {
    return this.clone().ineg();
  }

  iabs() {
    this.n = abs(this.n);
    return this;
  }

  abs() {
    return this.clone().iabs();
  }

  /*
   * Comparison
   */

  cmp(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    return cmp(this.n, num.n);
  }

  cmpn(num) {
    enforce(isSMI(num), 'num', 'smi');
    return cmpn(this.n, num);
  }

  eq(num) {
    return this.cmp(num) === 0;
  }

  eqn(num) {
    return this.cmpn(num) === 0;
  }

  gt(num) {
    return this.cmp(num) > 0;
  }

  gtn(num) {
    return this.cmpn(num) > 0;
  }

  gte(num) {
    return this.cmp(num) >= 0;
  }

  gten(num) {
    return this.cmpn(num) >= 0;
  }

  lt(num) {
    return this.cmp(num) < 0;
  }

  ltn(num) {
    return this.cmpn(num) < 0;
  }

  lte(num) {
    return this.cmp(num) <= 0;
  }

  lten(num) {
    return this.cmpn(num) <= 0;
  }

  isZero() {
    return this.n === 0n;
  }

  isNeg() {
    return this.n < 0n;
  }

  isOdd() {
    return (this.n & 1n) === 1n;
  }

  isEven() {
    return (this.n & 1n) === 0n;
  }

  /*
   * Unsigned Comparisons
   */

  ucmp(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    return ucmp(this.n, num.n);
  }

  /*
   * Number Theoretic Functions
   */

  jacobi(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    return jacobi(this.n, num.n);
  }

  gcd(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    return new BN(gcd(this.n, num.n));
  }

  egcd(p) {
    enforce(BN.isBN(p), 'p', 'bignum');
    range(p.n >= 1n, 'egcd');

    const [a, b, gcd] = egcd(this.n, p.n);

    return [new BN(a), new BN(b), new BN(gcd)];
  }

  invm(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    range(num.n >= 1n, 'invm');
    return new BN(invm(this.n, num.n));
  }

  invp(p) {
    enforce(BN.isBN(p), 'p', 'bignum');
    range(p.n >= 1n, 'invp');
    return new BN(invp(this.n, p.n));
  }

  ipowm(y, m) {
    enforce(BN.isBN(y), 'y', 'bignum');
    enforce(BN.isBN(m), 'm', 'bignum');
    range(m.n >= 1n, 'ipowm');

    this.n = powm(this.n, y.n, m.n);

    return this;
  }

  ipowmn(y, m) {
    enforce(isSMI(y), 'y', 'smi');
    enforce(BN.isBN(m), 'm', 'bignum');
    range(m.n >= 1n, 'ipowmn');

    this.n = powm(this.n, BigInt(y), m.n);

    return this;
  }

  powm(y, m) {
    return this.clone().ipowm(y, m);
  }

  powmn(y, m) {
    return this.clone().ipowmn(y, m);
  }

  isqrtp(p) {
    enforce(BN.isBN(p), 'p', 'bignum');
    range(p.n >= 1n, 'isqrtp');
    this.n = sqrtp(this.n, p.n);
    return this;
  }

  sqrtp(p) {
    return this.clone().isqrtp(p);
  }

  isqrtpq(p, q) {
    enforce(BN.isBN(p), 'p', 'bignum');
    enforce(BN.isBN(q), 'q', 'bignum');

    range(p.n >= 1n, 'isqrtpq');
    range(q.n >= 1n, 'isqrtpq');

    this.n = sqrtpq(this.n, p.n, q.n);

    return this;
  }

  sqrtpq(p, q) {
    return this.clone().isqrtpq(p, q);
  }

  /*
   * Twos Complement
   */

  toTwos(width) {
    enforce(isInteger(width), 'width', 'integer');
    return new BN(toTwos(this.n, width));
  }

  fromTwos(width) {
    enforce(isInteger(width), 'width', 'integer');
    return new BN(fromTwos(this.n, width));
  }

  /*
   * Reduction Context
   */

  toRed(ctx) {
    enforce(ctx instanceof Red, 'ctx', 'reduction context');

    if (this.red)
      throw new Error('Already in reduction context.');

    range(this.negative === 0, 'toRed');

    return ctx.convertTo(this)._forceRed(ctx);
  }

  fromRed() {
    red(this.red, 'fromRed');
    return this.red.convertFrom(this);
  }

  forceRed(ctx) {
    if (this.red)
      throw new Error('Already in reduction context.');

    return this._forceRed(ctx);
  }

  redAdd(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redAdd');
    return this.red.add(this, num);
  }

  redIAdd(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redIAdd');
    return this.red.iadd(this, num);
  }

  redSub(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redSub');
    return this.red.sub(this, num);
  }

  redISub(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redISub');
    return this.red.isub(this, num);
  }

  redShl(num) {
    enforce(isInteger(num), 'num', 'integer');
    red(this.red, 'redShl');
    return this.red.shl(this, num);
  }

  redIShl(num) {
    this.redShl(num)._move(this);
    return this;
  }

  redMul(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redMul');
    this.red._verify2(this, num);
    return this.red.mul(this, num);
  }

  redIMul(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redIMul');
    this.red._verify2(this, num);
    return this.red.imul(this, num);
  }

  redSqr() {
    red(this.red, 'redSqr');
    this.red._verify1(this);
    return this.red.sqr(this);
  }

  redISqr() {
    red(this.red, 'redISqr');
    this.red._verify1(this);
    return this.red.isqr(this);
  }

  redSqrt() {
    red(this.red, 'redSqrt');
    this.red._verify1(this);
    return this.red.sqrt(this);
  }

  redISqrt() {
    this.redSqrt()._move(this);
    return this;
  }

  redInvm() {
    red(this.red, 'redInvm');
    this.red._verify1(this);
    return this.red.invm(this);
  }

  redNeg() {
    red(this.red, 'redNeg');
    this.red._verify1(this);
    return this.red.neg(this);
  }

  redINeg() {
    this.redNeg()._move(this);
    return this;
  }

  redPow(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redPow');

    if (num.red)
      throw new Error('redPow must be used with non-reduced numbers.');

    this.red._verify1(this);

    return this.red.pow(this, num);
  }

  redIPow(num) {
    this.redPow(num)._move(this);
    return this;
  }

  /*
   * Internal
   */

  _move(dest) {
    dest.n = this.n;
    dest.red = this.red;
  }

  _expand(size) {
    return this;
  }

  _strip() {
    return this;
  }

  _normSign() {
    return this;
  }

  _forceRed(ctx) {
    this.red = ctx;
    return this;
  }

  /*
   * Helpers
   */

  clone() {
    const n = new this.constructor();
    return n.inject(this);
  }

  copy(dest) {
    dest.inject(this);
  }

  inject(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    this.n = num.n;
    this.red = num.red;

    return this;
  }

  set(num, endian) {
    if (endian == null)
      endian = 'be';

    enforce(isInteger(num), 'num', 'integer');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    this.n = BigInt(num);

    if (endian === 'le')
      this.swap();

    return this;
  }

  swap() {
    const neg = this.n < 0n;

    this.fromArray(this.toBuffer('be'), 'le');

    if (neg)
      this.n = -this.n;

    return this;
  }

  byteLength() {
    return byteLength(this.n);
  }

  bitLength() {
    return bitLength(this.n);
  }

  zeroBits() {
    return zeroBits(this.n);
  }

  isSafe() {
    return this.n <= MAX_SAFE_INTEGER
        && this.n >= -MAX_SAFE_INTEGER;
  }

  [custom]() {
    let prefix = 'BN';

    if (this.red)
      prefix = 'BN-R';

    return `<${prefix}: ${this.toString(10)}>`;
  }

  /*
   * Conversion
   */

  toNumber() {
    if (!this.isSafe())
      throw new RangeError('Number can only safely store up to 53 bits.');

    return Number(this.n);
  }

  toDouble() {
    return Number(this.n);
  }

  toBigInt() {
    return this.n;
  }

  toBool() {
    return this.n !== 0n;
  }

  toString(base, padding) {
    return toString(this.n, base, padding);
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
    if (endian == null)
      endian = 'be';

    if (length == null)
      length = 0;

    enforce(typeof ArrayType === 'function', 'ArrayType', 'function');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');
    enforce((length >>> 0) === length, 'length', 'integer');

    const byteLength = this.byteLength();
    const reqLength = length || Math.max(1, byteLength);

    if (byteLength > reqLength)
      throw new RangeError('Byte array longer than desired length.');

    if (reqLength <= 0)
      throw new RangeError('Requested array length <= 0.');

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

  /*
   * Instantiation
   */

  fromNumber(num, endian) {
    return this.set(num, endian);
  }

  fromDouble(num, endian) {
    enforce(typeof num === 'number', 'num', 'double');

    if (!isFinite(num))
      num >>>= 0;

    return this.fromString(num.toString(), endian);
  }

  fromBigInt(num, endian) {
    if (endian == null)
      endian = 'be';

    enforce(typeof num === 'bigint', 'num', 'bigint');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    this.n = num;

    if (endian === 'le')
      this.swap();

    return this;
  }

  fromBool(value) {
    enforce(typeof value === 'boolean', 'value', 'boolean');
    return this.set(value ? 1 : 0);
  }

  fromString(str, base, endian) {
    if (base === 'le' || base === 'be')
      [base, endian] = [endian, base];

    if (endian == null)
      endian = 'be';

    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    this.n = fromString(str, base);

    if (endian === 'le')
      this.swap();

    return this;
  }

  fromJSON(json) {
    return this.fromString(json, 16);
  }

  fromBN(num) {
    return this.inject(num);
  }

  fromArray(data, endian) {
    if (endian == null)
      endian = 'be';

    enforce(data && typeof data.length === 'number', 'data', 'array-like');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    if (data.length <= 0) {
      this.n = 0n;
      return this;
    }

    let n = 0n;

    if (endian === 'be') {
      for (let i = 0; i < data.length; i++) {
        n <<= 8n;
        n |= BigInt(data[i]);
      }
    } else if (endian === 'le') {
      for (let i = data.length - 1; i >= 0; i--) {
        n <<= 8n;
        n |= BigInt(data[i]);
      }
    }

    this.n = n;

    return this;
  }

  fromBuffer(data, endian) {
    enforce(Buffer.isBuffer(data), 'data', 'buffer');
    return this.fromArray(data, endian);
  }

  from(num, base, endian) {
    if (num == null)
      return this;

    if (base === 'le' || base === 'be')
      [base, endian] = [endian, base];

    if (typeof num === 'number')
      return this.fromNumber(num, endian);

    if (typeof num === 'bigint')
      return this.fromBigInt(num, endian);

    if (typeof num === 'string')
      return this.fromString(num, base, endian);

    if (typeof num === 'object') {
      if (BN.isBN(num))
        return this.fromBN(num, endian);

      if (typeof num.length === 'number')
        return this.fromArray(num, endian);
    }

    if (typeof num === 'boolean')
      return this.fromBool(num);

    throw new TypeError('Non-numeric object passed to BN.');
  }

  /*
   * Static Methods
   */

  static min(a, b) {
    return a.cmp(b) < 0 ? a : b;
  }

  static max(a, b) {
    return a.cmp(b) > 0 ? a : b;
  }

  static sort(a, b) {
    return a.cmp(b);
  }

  static red(num) {
    return new Red(num);
  }

  static mont(num) {
    return new Red(num);
  }

  static _prime(name) {
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

  static pow(num, exp) {
    return new this().fromNumber(num).ipown(exp);
  }

  static shift(num, bits) {
    return new this().fromNumber(num).ishln(bits);
  }

  static fromNumber(num, endian) {
    return new this().fromNumber(num, endian);
  }

  static fromDouble(num, endian) {
    return new this().fromDouble(num, endian);
  }

  static fromBigInt(num, endian) {
    return new this().fromBigInt(num, endian);
  }

  static fromBool(value) {
    return new this().fromBool(value);
  }

  static fromString(str, base, endian) {
    return new this().fromString(str, base, endian);
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

  static fromBN(num) {
    return new this().fromBN(num);
  }

  static fromArray(data, endian) {
    return new this().fromBN(data, endian);
  }

  static fromBuffer(data, endian) {
    return new this().fromBuffer(data, endian);
  }

  static from(num, base, endian) {
    return new this().from(num, base, endian);
  }

  static isBN(obj) {
    return obj instanceof BN;
  }
}

/*
 * Static
 */

BN.BN = BN;
BN.wordSize = 26;
BN.native = 1;

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
    out.n = input.n & mask(this.b);
    input.n >>= this.b;
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
    super('p25519', '7fffffffffffffff ffffffffffffffff'
                  + 'ffffffffffffffff ffffffffffffffed');
  }
}

/**
 * P448
 */

class P448 extends MPrime {
  constructor() {
    // 2 ^ 448 - 2 ^ 224 - 1
    super('p448', 'ffffffffffffffffffffffffffff'
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
      enforce(BN.isBN(m), 'm', 'bignum');

      if (m.n <= 1n)
        throw new RangeError('Modulus must be greater than 1.');

      this.m = m;
      this.prime = null;
    }
  }

  _verify1(a) {
    range(a.negative === 0, 'red', this._verify1);
    assert(a.red, 'Red works only with red numbers.', this._verify1);
  }

  _verify2(a, b) {
    range((a.negative | b.negative) === 0, 'red', this._verify2);
    assert(a.red && a.red === b.red,
           'Red works only with red numbers.',
           this._verify2);
  }

  BN(n) {
    const bn = new BN();
    bn.n = n;
    bn.red = this;
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
    return this.BN(sqrtp(x.n, this.m.n));
  }

  invm(x) {
    const inv = invp(x.n, this.m.n);
    return this.imod(this.BN(inv));
  }

  pow(x, y) {
    return this.BN(powm(x.n, y.n, this.m.n));
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

function assert(val, msg, start) {
  if (!val) {
    const err = new Error(msg || 'Assertion failed');

    if (Error.captureStackTrace)
      Error.captureStackTrace(err, start || assert);

    throw err;
  }
}

function enforce(value, name, type, start) {
  if (!value) {
    const err = new TypeError(`'${name}' must be a(n) ${type}.`);

    if (Error.captureStackTrace)
      Error.captureStackTrace(err, start || enforce);

    throw err;
  }
}

function range(value, name, start) {
  if (!value) {
    const err = new TypeError(`'${name}' only works with positive numbers.`);

    if (Error.captureStackTrace)
      Error.captureStackTrace(err, start || range);

    throw err;
  }
}

function red(value, name, start) {
  if (!value) {
    const err = new Error(`'${name}' only works with red numbers.`);

    if (Error.captureStackTrace)
      Error.captureStackTrace(err, start || red);

    throw err;
  }
}

function isInteger(num) {
  return Number.isSafeInteger(num);
}

function isSMI(num) {
  return isInteger(num)
      && num >= -0x3ffffff
      && num <= 0x3ffffff;
}

function allocate(ArrayType, size) {
  if (ArrayType.allocUnsafe)
    return ArrayType.allocUnsafe(size);

  return new ArrayType(size);
}

/*
 * Internal
 */

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

function notn(x, width) {
  return x ^ mask(width);
}

function testn(x, bit) {
  return (x & (1n << BigInt(bit))) !== 0n;
}

function toTwos(x, width) {
  if (x < 0n)
    return notn(-x, width) + 1n;

  return x;
}

function fromTwos(x, width) {
  if (testn(x, width - 1))
    return -(notn(x, width) + 1n);

  return x;
}

function setn(x, bit, val) {
  if (val)
    x |= (1n << BigInt(bit));
  else
    x &= ~(1n << BigInt(bit));

  return x;
}

function umod(x, y) {
  x %= y;

  if (x < 0n)
    x += abs(y);

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
  return Number(x % BigInt(y));
}

function umodrn(x, y) {
  // FIXME: doesn't match umod behavior exactly.
  return Number(abs(x) % abs(BigInt(y)));
}

function andln(x, y) {
  return Number(x & BigInt(y));
}

function bincn(x, bit) {
  const neg = x < 0n;

  if (neg)
    x = -x;

  const b = BigInt(bit);
  const d = x & ((1n << b) - 1n);

  x >>= b;
  x += 1n;
  x <<= b;
  x |= d;

  if (neg)
    x = -x;

  return x;
}

function cmpn(x, y) {
  return cmp(x, BigInt(y));
}

function cmp(x, y) {
  if (x < y)
    return -1;

  if (x > y)
    return 1;

  return 0;
}

function ucmp(x, y) {
  return cmp(abs(x), abs(y));
}

function gcd(x, y) {
  x = abs(x);
  y = abs(y);

  while (y !== 0n)
    [x, y] = [y, x % y];

  return x;
}

function egcd(x, y) {
  assert(y > 0n);

  if (x < 0n)
    x = umod(x, y);

  let s = 0n;
  let os = 1n;
  let t = 1n;
  let ot = 0n;
  let r = y;
  let or = x;

  while (r !== 0n) {
    const q = or / r;

    [or, r] = [r, or - q * r];
    [os, s] = [s, os - q * s];
    [ot, t] = [t, ot - q * t];
  }

  assert(x * os + y * ot === or);

  return [os, ot, or];
}

function invm(x, y) {
  return umod(egcd(x, y)[0], y);
}

function inverse(x, y) {
  assert(y > 0n);

  if (x < 0n)
    x = umod(x, y);

  let t = 0n;
  let nt = 1n;
  let r = y;
  let nr = x;

  while (nr !== 0n) {
    const q = r / nr;

    [t, nt] = [nt, t - q * nt];
    [r, nr] = [nr, r - q * nr];
  }

  if (r > 1n)
    throw new Error('Not invertible.');

  return t % y;
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

  if (a < 0n)
    a = umod(a, b);

  for (;;) {
    if (b === 1n)
      return j;

    if (a === 0n)
      return 0;

    a %= b;

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
function sqrtp(x, p) {
  assert(p > 0n);

  switch (jacobi(x, p)) {
    case -1:
      throw new Error('X is not a square mod P.');
    case 0:
      return 0n;
    case 1:
      break;
  }

  if (x < 0n)
    x = umod(x, p);

  if ((p & 3n) === 3n) {
    const e = (p + 1n) >> 2n;
    return powm(x, e, p);
  }

  if ((p & 7n) === 5n) {
    const e = p >> 3n;
    const t = x << 1n;
    const a = powm(t, e, p);

    let b = 0n;

    b = a * a;
    b %= p;

    b *= t;
    b %= p;

    b -= 1n;
    b *= x;
    b %= p;

    b *= a;
    b %= p;

    return b;
  }

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
  y = powm(x, y, p);
  b = powm(x, s, p);
  g = powm(n, s, p);

  let r = e;
  let t = 0n;

  for (;;) {
    let m = 0n;

    t = b;

    while (t !== 1n) {
      t = (t * t) % p;
      m += 1n;
    }

    if (m === 0n)
      break;

    // assert(m !== r);

    t = 1n << (r - m - 1n);
    t = powm(g, t, p);
    g = (t * t) % p;
    y = (y * t) % p;
    b = (b * g) % p;
    r = m;
  }

  // if (y > (p >> 1n))
  //   y = p - y;

  return y;
}

function sqrtpq(x, p, q) {
  assert(p > 0n);
  assert(q > 0n);

  const sp = sqrtp(x, p);
  const sq = sqrtp(x, q);
  const [mp, mq] = egcd(p, q);

  return (sq * mp * p + sp * mq * q) % (p * q);
}

function powm(x, y, m) {
  assert(m > 0n);

  if (m === 1n)
    return 0n;

  if (x === 0n)
    return 0n;

  // GMP behavior.
  if (y < 0n) {
    x = inverse(x, m);
    y = -y;
  } else {
    x %= m;
  }

  let r = 1n;

  while (y > 0n) {
    if ((y & 1n) === 1n)
      r = (r * x) % m;

    y >>= 1n;
    x = (x * x) % m;
  }

  return r;
}

function invp(x, p) {
  assert(p > 0n);

  if (x < 0n)
    x = umod(x, p);

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

// https://github.com/golang/go/blob/aadaec5/src/math/big/nat.go#L1335
function sqrt(x) {
  assert(x >= 0n);

  // See https://members.loria.fr/PZimmermann/mca/pub226.html.
  let r = 1n;

  r <<= BigInt((bitLength(x) >>> 1) + 1);

  for (;;) {
    let z = x / r;
    z += r;
    z >>= 1n;

    if (z >= r)
      break;

    r = z;
  }

  return r;
}

/*
 * Parsing
 */

function getBase(base) {
  if (base == null)
    return 10;

  if (typeof base === 'number')
    return base;

  switch (base) {
    case 'bin':
      return 2;
    case 'oct':
      return 8;
    case 'dec':
      return 10;
    case 'hex':
      return 16;
  }

  return 0;
}

function toString(num, base, padding) {
  base = getBase(base);

  if (padding == null)
    padding = 0;

  if (padding === 0)
    padding = 1;

  enforce((base >>> 0) === base, 'base', 'integer');
  enforce((padding >>> 0) === padding, 'padding', 'integer');

  if (base < 2 || base > 36)
    throw new RangeError('Base ranges between 2 and 36.');

  let neg = false;

  if (num < 0n) {
    neg = true;
    num = -num;
  }

  let str = num.toString(base);

  while (str.length % padding)
    str = '0' + str;

  if (neg)
    str = '-' + str;

  return str;
}

function fromString(str, base) {
  base = getBase(base);

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
