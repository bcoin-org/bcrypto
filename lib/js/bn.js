/*!
 * bn.js - big numbers for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/bn.js:
 *   Copyright (c) 2015, Fedor Indutny (MIT License).
 *   https://github.com/indutny/bn.js
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009, The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Parts of this software are based on openssl/openssl:
 *   Copyright (c) 1998-2018, The OpenSSL Project (Apache License v2.0).
 *   Copyright (c) 1995-1998, Eric A. Young, Tim J. Hudson. All rights reserved.
 *   https://github.com/openssl/openssl
 *
 * Parts of this software are based on libgmp:
 *   Copyright (c) 1991-1997, 1999-2014, Free Software Foundation, Inc.
 *   https://gmplib.org/
 *
 * Parts of this software are based on v8/v8:
 *   Copyright (c) 2017, The V8 Project Authors (BSD-Style License).
 *   https://github.com/v8/v8
 *
 * Resources:
 *   https://github.com/indutny/bn.js/blob/master/lib/bn.js
 *   https://github.com/golang/go/blob/master/src/math/big/int.go
 *   https://github.com/golang/go/blob/master/src/math/big/nat.go
 *   https://github.com/openssl/openssl/tree/master/crypto/bn
 *   https://github.com/gnutls/nettle/blob/master/mini-gmp.c
 *   https://github.com/v8/v8/blob/master/src/objects/bigint.cc
 */

/* eslint valid-typeof: "off" */

'use strict';

const {custom} = require('../internal/custom');

/*
 * Constants
 */

const zeros = [
  '',
  '0',
  '00',
  '000',
  '0000',
  '00000',
  '000000',
  '0000000',
  '00000000',
  '000000000',
  '0000000000',
  '00000000000',
  '000000000000',
  '0000000000000',
  '00000000000000',
  '000000000000000',
  '0000000000000000',
  '00000000000000000',
  '000000000000000000',
  '0000000000000000000',
  '00000000000000000000',
  '000000000000000000000',
  '0000000000000000000000',
  '00000000000000000000000',
  '000000000000000000000000',
  '0000000000000000000000000'
];

const groupSizes = [
  0x00, 0x19, 0x10, 0x0c, 0x0b, 0x0a,
  0x09, 0x08, 0x08, 0x07, 0x07, 0x07,
  0x07, 0x06, 0x06, 0x06, 0x06, 0x06,
  0x06, 0x06, 0x05, 0x05, 0x05, 0x05,
  0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
  0x05, 0x05, 0x05, 0x05, 0x05, 0x05
];

const groupBases = [
  0x00000000, 0x02000000, 0x0290d741, 0x01000000,
  0x02e90edd, 0x039aa400, 0x0267bf47, 0x01000000,
  0x0290d741, 0x00989680, 0x012959c3, 0x0222c000,
  0x03bd7765, 0x0072e440, 0x00adcea1, 0x01000000,
  0x01704f61, 0x0206fc40, 0x02cddcf9, 0x03d09000,
  0x003e5185, 0x004ea360, 0x006235f7, 0x00798000,
  0x009502f9, 0x00b54ba0, 0x00daf26b, 0x01069c00,
  0x0138f9ad, 0x0172c9e0, 0x01b4d89f, 0x02000000,
  0x025528a1, 0x02b54a20, 0x03216b93, 0x039aa400
];

const primes = {
  p192: null,
  p224: null,
  p521: null,
  k256: null,
  p25519: null,
  p448: null
};

const modes = {
  NONE: 0,
  QUO: 1,
  REM: 2,
  BOTH: 3,
  EUCLID: 4,
  ALL: 7
};

const HAS_BIGINT = typeof BigInt === 'function';

/**
 * BN
 */

class BN {
  constructor(num, base, endian) {
    this.words = [0];
    this.length = 1;
    this.negative = 0;
    this.red = null;
    this.from(num, base, endian);
  }

  /*
   * Addition
   */

  iadd(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    // negative + positive
    if (this.negative !== 0 && num.negative === 0) {
      this.negative = 0;
      this.isub(num);
      this.negative ^= 1;
      return this._normalize();
    }

    // positive + negative
    if (this.negative === 0 && num.negative !== 0) {
      num.negative = 0;
      const r = this.isub(num);
      num.negative = 1;
      return r._normalize();
    }

    // a.length > b.length
    let a = this;
    let b = num;

    if (a.length < b.length)
      [a, b] = [b, a];

    let carry = 0;
    let i = 0;

    if (a !== this)
      this._alloc(a.length);

    for (; i < b.length; i++) {
      const r = (a.words[i] | 0) + (b.words[i] | 0) + carry;

      this.words[i] = r & 0x3ffffff;

      carry = r >>> 26;
    }

    for (; carry !== 0 && i < a.length; i++) {
      const r = (a.words[i] | 0) + carry;

      this.words[i] = r & 0x3ffffff;

      carry = r >>> 26;
    }

    this.length = a.length;

    if (carry !== 0) {
      this._alloc(this.length + 1);
      this.words[this.length++] = carry;
    } else if (a !== this) {
      // Copy the rest of the words.
      for (; i < a.length; i++)
        this.words[i] = a.words[i];
    }

    // Note: we shouldn't need to strip here.
    return this;
  }

  iaddn(num) {
    enforce(isSMI(num), 'num', 'smi');

    if (num < 0)
      return this.isubn(-num);

    // Possible sign change.
    if (this.negative !== 0) {
      if (this.length === 1 && (this.words[0] | 0) <= num) {
        this.words[0] = num - (this.words[0] | 0);
        this.negative = 0;
        return this;
      }

      this.negative = 0;
      this.isubn(num);
      this.negative = 1;

      return this;
    }

    // Add without checks.
    return this._iaddn(num);
  }

  _iaddn(num) {
    this.words[0] += num;

    if (this.words[0] < 0x4000000)
      return this;

    // Carry.
    let i = 0;

    this._alloc(this.length + 1);

    this.words[this.length] = 0;

    for (; i < this.length && this.words[i] >= 0x4000000; i++) {
      this.words[i] -= 0x4000000;
      this.words[i + 1] += 1;
    }

    this.length = Math.max(this.length, i + 1);

    // Note: we shouldn't need to strip here.
    return this;
  }

  add(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (num.negative !== 0 && this.negative === 0) {
      num.negative = 0;
      const res = this.sub(num);
      num.negative ^= 1;
      return res;
    }

    if (num.negative === 0 && this.negative !== 0) {
      this.negative = 0;
      const res = num.sub(this);
      this.negative = 1;
      return res;
    }

    if (this.length > num.length)
      return this.clone().iadd(num);

    return num.clone().iadd(this);
  }

  addn(num) {
    return this.clone().iaddn(num);
  }

  /*
   * Subtraction
   */

  isub(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    // this - (-num) = this + num
    if (num.negative !== 0) {
      num.negative = 0;
      const r = this.iadd(num);
      num.negative = 1;
      return r._normalize();
    }

    // -this - num = -(this + num)
    if (this.negative !== 0) {
      this.negative = 0;
      this.iadd(num);
      this.negative = 1;
      return this._normalize();
    }

    // At this point both numbers are positive.
    const cmp = this.ucmp(num);

    // Optimization - zeroify.
    if (cmp === 0) {
      this.negative = 0;
      this.length = 1;
      this.words[0] = 0;
      return this;
    }

    // a > b
    let a = this;
    let b = num;

    if (cmp < 0)
      [a, b] = [b, a];

    let carry = 0;
    let i = 0;

    if (a !== this)
      this._alloc(a.length);

    for (; i < b.length; i++) {
      const r = (a.words[i] | 0) - (b.words[i] | 0) + carry;
      carry = r >> 26;
      this.words[i] = r & 0x3ffffff;
    }

    for (; carry !== 0 && i < a.length; i++) {
      const r = (a.words[i] | 0) + carry;
      carry = r >> 26;
      this.words[i] = r & 0x3ffffff;
    }

    // Copy rest of the words.
    if (carry === 0 && i < a.length && a !== this) {
      for (; i < a.length; i++)
        this.words[i] = a.words[i];
    }

    this.length = Math.max(this.length, i);

    if (a !== this)
      this.negative = 1;

    return this._strip();
  }

  isubn(num) {
    enforce(isSMI(num), 'num', 'smi');

    if (num < 0)
      return this.iaddn(-num);

    if (this.negative !== 0) {
      this.negative = 0;
      this.iaddn(num);
      this.negative = 1;
      return this;
    }

    // Subtract without checks.
    return this._isubn(num);
  }

  _isubn(num) {
    this.words[0] -= num;

    if (this.words[0] >= 0)
      return this;

    if (this.length === 1) {
      this.words[0] = -this.words[0];
      this.negative = 1;
      return this;
    }

    // Carry.
    this._alloc(this.length + 1);

    for (let i = 0; i < this.length && this.words[i] < 0; i++) {
      this.words[i] += 0x4000000;
      this.words[i + 1] -= 1;
    }

    this.words[this.length] = 0;

    return this._strip();
  }

  sub(num) {
    return this.clone().isub(num);
  }

  subn(num) {
    return this.clone().isubn(num);
  }

  /*
   * Multiplication Engine
   */

  _mul(num, out) {
    enforce(BN.isBN(num), 'num', 'bignum');
    enforce(BN.isBN(out), 'out', 'bignum');

    if (this.length === 10 && num.length === 10)
      return comb10MulTo(this, num, out);

    const len = this.length + num.length;

    if (len < 63)
      return smallMulTo(this, num, out);

    if (len < 1024)
      return bigMulTo(this, num, out);

    return jumboMulTo(this, num, out);
  }

  /*
   * Multiplication
   */

  imul(num) {
    return this.mul(num)._move(this);
  }

  imuln(num) {
    enforce(isSMI(num), 'num', 'smi');

    const neg = (num < 0) | 0;

    if (neg)
      num = -num;

    // Carry.
    let carry = 0;

    for (let i = 0; i < this.length; i++) {
      const w = this.words[i] * num;
      const lo = (w & 0x3ffffff) + (carry & 0x3ffffff);

      carry >>= 26;
      carry += (w / 0x4000000) | 0;
      carry += lo >>> 26;

      this.words[i] = lo & 0x3ffffff;
    }

    this.negative ^= neg;

    if (carry !== 0) {
      this._alloc(this.length + 1);
      this.words[this.length++] = carry;
    } else {
      this._strip();
    }

    return this;
  }

  mul(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    const len = this.length + num.length;
    const out = new BN();

    out.words = new Array(len);

    for (let i = 0; i < len; i ++)
      out.words[i] = 0;

    return this._mul(num, out);
  }

  muln(num) {
    return this.clone().imuln(num);
  }

  /*
   * Division Engine
   */

  _div(num, flags) {
    enforce(BN.isBN(num), 'num', 'bignum');
    assert((flags & modes.ALL) === flags);
    assert(flags !== modes.NONE);

    const a = this;
    const b = num;

    nonzero(!b.isZero());

    if (a.isZero())
      return [new BN(0), new BN(0)];

    const as = a.negative;
    const bs = b.negative;

    a.negative = 0;
    b.negative = 0;

    let q = null;
    let r = null;

    if (a.length < b.length || a.cmp(b) < 0) {
      q = new BN(0);
      r = a.clone();
    } else if (b.length === 1) {
      if (flags & modes.QUO)
        q = a.quon(b.words[0]);

      if (flags & modes.REM)
        r = a.remn(b.words[0]);
    } else {
      [q, r] = a._wordDiv(b, flags);
    }

    a.negative = as;
    b.negative = bs;

    if (flags & modes.QUO) {
      q.negative = a.negative ^ b.negative;
      q._normalize();
    }

    if (flags & modes.REM) {
      r.negative = a.negative;
      r._normalize();
    }

    if (flags & modes.EUCLID) {
      if (flags & modes.QUO) {
        assert((flags & modes.REM) !== 0);

        if (r.negative !== 0) {
          if (b.negative !== 0)
            q.iaddn(1);
          else
            q.isubn(1);
        }
      }

      if (flags & modes.REM) {
        if (r.negative !== 0) {
          if (b.negative !== 0)
            r.isub(b);
          else
            r.iadd(b);
        }
      }
    }

    return [q, r];
  }

  _wordDiv(num, flags) {
    let shift = this.length - num.length;
    let a = this.clone();
    let b = num;

    // Normalize.
    let bhi = b.words[b.length - 1] | 0;

    const bhiBits = countBits(bhi);

    shift = 26 - bhiBits;

    if (shift !== 0) {
      b = b.ushln(shift);
      a.iushln(shift);
      bhi = b.words[b.length - 1] | 0;
    }

    // Initialize quotient.
    const m = a.length - b.length;
    assert(m >= 0);

    let q = null;

    if (flags & modes.QUO) {
      q = new BN(0);
      q.length = m + 1;
      q.words = new Array(q.length);

      for (let i = 0; i < q.length; i++)
        q.words[i] = 0;
    }

    const diff = a.clone()._ishlnsubmul(b, 1, m);

    if (diff.negative === 0) {
      a = diff;
      if (q)
        q.words[m] = 1;
    }

    for (let j = m - 1; j >= 0; j--) {
      const ahi = a.words[b.length + j];
      const alo = a.words[b.length + j - 1];

      let qj = Math.min(((ahi * 0x4000000 + alo) / bhi) | 0, 0x3ffffff);

      a._ishlnsubmul(b, qj, j);

      while (a.negative !== 0) {
        qj -= 1;

        a.negative = 0;
        a._ishlnsubmul(b, 1, j);

        if (!a.isZero())
          a.negative ^= 1;
      }

      if (q)
        q.words[j] = qj;
    }

    if (q)
      q._strip();

    a._strip();

    // Denormalize.
    if ((flags & modes.REM) && shift !== 0)
      a.iushrn(shift);

    return [q, a];
  }

  _ishlnsubmul(num, mul, shift) {
    const len = num.length + shift;

    this._expand(len);

    let carry = 0;
    let i = 0;
    let w;

    for (; i < num.length; i++) {
      w = (this.words[i + shift] | 0) + carry;
      const right = num.words[i] * mul;
      w -= right & 0x3ffffff;
      carry = (w >> 26) - ((right / 0x4000000) | 0);
      this.words[i + shift] = w & 0x3ffffff;
    }

    for (; i < this.length - shift; i++) {
      w = (this.words[i + shift] | 0) + carry;
      carry = w >> 26;
      this.words[i + shift] = w & 0x3ffffff;
    }

    if (carry === 0)
      return this._strip();

    // Subtraction overflow.
    assert(carry === -1);
    carry = 0;

    for (i = 0; i < this.length; i++) {
      w = -(this.words[i] | 0) + carry;
      carry = w >> 26;
      this.words[i] = w & 0x3ffffff;
    }

    this.negative = 1;

    return this._strip();
  }

  /*
   * Truncation Division + Modulo
   */

  quorem(num) {
    return this._div(num, modes.BOTH);
  }

  /*
   * Truncation Division
   */

  iquo(num) {
    return this.quo(num)._move(this);
  }

  iquon(num) {
    enforce(isSMI(num), 'num', 'smi');
    nonzero(num !== 0);

    const neg = (num < 0) | 0;

    if (neg)
      num = -num;

    let carry = 0;

    for (let i = this.length - 1; i >= 0; i--) {
      const w = (this.words[i] | 0) + carry * 0x4000000;

      this.words[i] = (w / num) | 0;

      carry = w % num;
    }

    this.negative ^= neg;

    return this._strip();
  }

  quo(num) {
    return this._div(num, modes.QUO)[0];
  }

  quon(num) {
    return this.clone().iquon(num);
  }

  /*
   * Truncation Modulo
   */

  irem(num) {
    return this.rem(num)._move(this);
  }

  iremn(num) {
    let m = this.remrn(num);

    if (m < 0)
      m = -m;

    this.words[0] = m;
    this.length = 1;

    return this._normalize();
  }

  rem(num) {
    return this._div(num, modes.REM)[1];
  }

  remn(num) {
    return this.clone().iremn(num);
  }

  remrn(num) {
    enforce(isSMI(num), 'num', 'smi');
    nonzero(num !== 0);

    if (num < 0)
      num = -num;

    const p = (1 << 26) % num;

    let acc = 0;

    for (let i = this.length - 1; i >= 0; i--)
      acc = (p * acc + (this.words[i] | 0)) % num;

    return this.negative ? (-acc | 0) : acc;
  }

  /*
   * Euclidean Division + Modulo
   */

  divmod(num) {
    return this._div(num, modes.BOTH | modes.EUCLID);
  }

  /*
   * Euclidean Division
   */

  idiv(num) {
    return this.div(num)._move(this);
  }

  idivn(num) {
    if (this.negative === 0)
      return this.iquon(num);

    const r = this.remrn(num);

    this.iquon(num);

    if (r < 0) {
      if (num < 0)
        this.iaddn(1);
      else
        this.isubn(1);
    }

    return this;
  }

  div(num) {
    return this._div(num, modes.BOTH | modes.EUCLID)[0];
  }

  divn(num) {
    return this.clone().idivn(num);
  }

  /*
   * Euclidean Modulo
   */

  imod(num) {
    if (this.ucmp(num) < 0) {
      if (this.negative !== 0) {
        if (num.negative !== 0)
          this.isub(num);
        else
          this.iadd(num);
      }
      return this;
    }

    return this.mod(num)._move(this);
  }

  imodn(num) {
    this.words[0] = this.modrn(num);
    this.length = 1;
    this.negative = 0;
    return this;
  }

  mod(num) {
    return this._div(num, modes.REM | modes.EUCLID)[1];
  }

  modn(num) {
    return this.clone().imodn(num);
  }

  modrn(num) {
    enforce(isSMI(num), 'num', 'smi');

    let r = this.remrn(num);

    if (r < 0) {
      if (num < 0)
        r -= num;
      else
        r += num;
    }

    return r;
  }

  /*
   * Round Division
   */

  divRound(num) {
    const [q, r] = this.quorem(num);

    // Fast case - exact division.
    if (r.isZero())
      return q;

    const bit = num.words[0] & 1;

    num.iushrn(1);

    const cmp = r.ucmp(num);

    num.iushln(1);

    num.words[0] |= bit;

    // Round down.
    if (cmp < 0 || (num.isOdd() && cmp === 0))
      return q;

    // Round up.
    if (this.negative ^ num.negative)
      return q.isubn(1);

    return q.iaddn(1);
  }

  /*
   * Exponentiation
   */

  ipow(num) {
    return this.pow(num)._move(this);
  }

  ipown(num) {
    return this.pown(num)._move(this);
  }

  pow(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    const w = toBitArray(num);

    if (w.length === 0)
      return new BN(1);

    // Skip leading zeroes.
    let res = this;
    let i = 0;

    for (; i < w.length; i++, res = res.sqr()) {
      if (w[i] !== 0)
        break;
    }

    if (++i < w.length) {
      for (let q = res.sqr(); i < w.length; i++, q = q.sqr()) {
        if (w[i] === 0)
          continue;

        res = res.mul(q);
      }
    }

    return res;
  }

  pown(num) {
    enforce(isSMI(num), 'num', 'smi');

    if (num === 2)
      return this.sqr();

    let x = this;
    let y = Math.abs(num);
    let r = new BN(1);

    while (y > 0) {
      if (y & 1)
        r = r.mul(x);

      y >>>= 1;
      x = x.sqr();
    }

    return r;
  }

  isqr() {
    return this.imul(this);
  }

  sqr() {
    return this.mul(this);
  }

  /*
   * Roots
   */

  _rootrem(pow, rem) {
    enforce((pow >>> 0) === pow, 'num', 'uint32');

    if (pow === 0)
      throw new RangeError('Zeroth root.');

    if (~pow & this.negative)
      throw new RangeError('Negative with even root.');

    if (this.ucmpn(1) <= 0)
      return [this.clone(), new BN(0)];

    let u = new BN(0);
    let t = BN.shift(1, this.bitLength() / pow + 1 | 0);
    let v, r;

    if (this.negative !== 0)
      t.ineg();

    if (pow === 2) {
      do {
        u = t;
        t = this.quo(u);
        t.iadd(u);
        t.iushrn(1);
      } while (t.ucmp(u) < 0);
    } else {
      do {
        u = t;
        t = u.pown(pow - 1);
        t = this.quo(t);
        v = u.muln(pow - 1);
        t.iadd(v);
        t = t.quon(pow);
      } while (t.ucmp(u) < 0);
    }

    if (rem) {
      t = u.pown(pow);
      r = this.sub(t);
    }

    return [u, r];
  }

  rootrem(pow) {
    return this._rootrem(pow, 1);
  }

  iroot(pow) {
    return this.root(pow)._move(this);
  }

  root(pow) {
    return this._rootrem(pow, 0)[0];
  }

  isPower(pow) {
    enforce((pow >>> 0) === pow, 'num', 'uint32');

    if (pow === 0 || (~pow & this.negative))
      return false;

    const [, r] = this.rootrem(pow);

    return r.sign() === 0;
  }

  sqrtrem() {
    return this.rootrem(2);
  }

  isqrt() {
    return this.sqrt()._move(this);
  }

  sqrt() {
    return this.root(2);
  }

  isSquare() {
    if (this.sign() === 0)
      return true;

    return this.isPower(2);
  }

  /*
   * AND
   */

  iand(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    let x = this;
    let y = num;

    if (x === y)
      return x;

    if ((x.negative | y.negative) === 0)
      return x.iuand(y);

    if ((x.negative & y.negative) === 1) {
      // (-x) & (-y) == ~(x-1) & ~(y-1)
      //             == ~((x-1) | (y-1))
      //             == -(((x-1) | (y-1)) + 1)
      //             == (-x+1) || (-y+1) - 1
      y.iaddn(1);
      x.iaddn(1).iuor(y).isubn(1);
      y.isubn(1);
      return x;
    }

    // Assume x is the positive number.
    if (x.negative !== 0)
      [x, y] = [y.clone(), x];

    // x & (-y) == x & ~(y-1)
    //          == x & ~(y-1)
    //          == x && ~(-y+1)
    const width = x.bitLength();

    y.iaddn(1).inotn(width);
    x.iuand(y);
    y.inotn(width).isubn(1);

    return x._move(this);
  }

  iandn(num) {
    enforce(isSMI(num), 'num', 'smi');

    if ((this.negative | (num < 0)) !== 0)
      return this.iand(new BN(num));

    this.words[0] &= num;
    this.length = 1;

    return this;
  }

  and(num) {
    return this.clone().iand(num);
  }

  andn(num) {
    return this.clone().iandn(num);
  }

  andrn(num) {
    enforce(isSMI(num), 'num', 'smi');

    if ((this.negative | (num < 0)) !== 0) {
      const n = this.iand(new BN(num));

      if (n.length > 1)
        throw new RangeError('Number exceeds 26 bits.');

      return n.negative !== 0 ? -n.words[0] : n.words[0];
    }

    return this.words[0] & num;
  }

  /*
   * Unsigned AND
   */

  iuand(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    this.length = Math.min(this.length, num.length);

    for (let i = 0; i < this.length; i++)
      this.words[i] &= num.words[i];

    return this._strip();
  }

  iuandn(num) {
    enforce(isSMI(num), 'num', 'smi');

    this.words[0] &= Math.abs(num);
    this.length = 1;

    return this._normalize();
  }

  uand(num) {
    return this.clone().iuand(num);
  }

  uandn(num) {
    return this.clone().iuandn(num);
  }

  uandrn(num) {
    enforce(isSMI(num), 'num', 'smi');

    const n = this.words[0] & Math.abs(num);

    return this.negative !== 0 ? (-n | 0) : n;
  }

  /*
   * OR
   */

  ior(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    let x = this;
    let y = num;

    if (x === y)
      return x;

    if ((x.negative | y.negative) === 0)
      return x.iuor(y);

    if ((x.negative & y.negative) === 1) {
      // (-x) | (-y) == ~(x-1) | ~(y-1)
      //             == ~((x-1) & (y-1))
      //             == -(((x-1) & (y-1)) + 1)
      //             == ((-x+1) && (-y+1)) - 1
      y.iaddn(1);
      x.iaddn(1);
      x.iuand(y).isubn(1);
      y.isubn(1);
      return x;
    }

    // Assume x is the positive number.
    y = y.clone();

    if (x.negative !== 0)
      [x, y] = [y, x];

    // x | (-y) == x | ~(y-1)
    //          == ~((y-1) & ~x)
    //          == -(((y-1) & ~x) + 1)
    //          == ((-y+1) && ~x) - 1
    y.iaddn(1);
    x.inotn(y.bitLength());
    y.iuand(x);
    y.isubn(1);

    return y._move(this);
  }

  iorn(num) {
    enforce(isSMI(num), 'num', 'smi');

    if ((this.negative | (num < 0)) !== 0)
      return this.ior(new BN(num));

    this.words[0] |= num;

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

    this._expand(num.length);

    for (let i = 0; i < num.length; i++)
      this.words[i] |= num.words[i];

    return this._strip();
  }

  iuorn(num) {
    enforce(isSMI(num), 'num', 'smi');

    this.words[0] |= Math.abs(num);

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

    let x = this;
    let y = num;

    if (x === y) {
      x.words[0] = 0;
      x.length = 1;
      x.negative = 0;
      return x;
    }

    if ((x.negative | y.negative) === 0)
      return x.iuxor(y);

    if ((x.negative & y.negative) === 1) {
      // (-x) ^ (-y) == ~(x-1) ^ ~(y-1)
      //             == (x-1) ^ (y-1)
      //             == -((-x+1) ^^ (-y+1))
      x.iaddn(1);
      y.iaddn(1);
      x.iuxor(y);
      x.ineg();
      y.isubn(1);
      return x;
    }

    // Assume x is the positive number.
    if (x.negative !== 0)
      [x, y] = [y.clone(), x];

    // x ^ (-y) == x ^ ~(y-1)
    //          == ~(x ^ (y-1))
    //          == -((x ^ (y-1)) + 1)
    //          == -((x ^^ (-y+1)) + 1)
    y.iaddn(1);
    x.iuxor(y);
    x.iaddn(1);
    x.ineg();
    y.isubn(1);

    return x._move(this);
  }

  ixorn(num) {
    enforce(isSMI(num), 'num', 'smi');

    if ((this.negative | (num < 0)) !== 0)
      return this.ixor(new BN(num));

    this.words[0] ^= num;

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

    let a = this;
    let b = num;

    if (a.length < b.length)
      [a, b] = [b, a];

    let i = 0;

    for (; i < b.length; i++)
      this.words[i] = a.words[i] ^ b.words[i];

    if (a !== this) {
      this._alloc(a.length);

      for (; i < a.length; i++)
        this.words[i] = a.words[i];
    }

    this.length = a.length;

    return this._strip();
  }

  iuxorn(num) {
    enforce(isSMI(num), 'num', 'smi');

    this.words[0] ^= Math.abs(num);

    return this._normalize();
  }

  uxor(num) {
    return this.clone().iuxor(num);
  }

  uxorn(num) {
    return this.clone().iuxorn(num);
  }

  /*
   * NOT
   */

  inot() {
    if (this.negative !== 0) {
      // ~(-x) == ~(~(x-1)) == x-1
      this.ineg().isubn(1);
    } else {
      // ~x == -x-1 == -(x+1)
      this.iaddn(1).ineg();
    }
    return this;
  }

  not() {
    return this.clone().inot();
  }

  inotn(width) {
    enforce((width >>> 0) === width, 'width', 'uint32');

    const r = width % 26;

    let s = Math.ceil(width / 26);
    let i = 0;

    // Extend the buffer with leading zeroes.
    this._expand(s);

    if (r > 0)
      s -= 1;

    // Handle complete words.
    for (; i < s; i++)
      this.words[i] ^= 0x3ffffff;

    // Handle the residue.
    if (r > 0)
      this.words[i] ^= (1 << r) - 1;

    // And remove leading zeroes.
    return this._strip();
  }

  notn(width) {
    return this.clone().inotn(width);
  }

  /*
   * Left Shift
   */

  ishl(num) {
    enforce(BN.isBN(num), 'bits', 'bignum');
    enforce(num.bitLength() <= 32, 'bits', 'uint32');
    return this.ishln(num.toNumber());
  }

  ishln(bits) {
    return this.iushln(bits);
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
    enforce(num.bitLength() <= 32, 'bits', 'uint32');
    return this.iushln(num.toNumber());
  }

  iushln(bits) {
    enforce((bits >>> 0) === bits, 'bits', 'uint32');

    const r = bits % 26;
    const s = (bits - r) / 26;
    const mask = ((1 << r) - 1) << (26 - r);

    if (r !== 0) {
      let carry = 0;

      for (let i = 0; i < this.length; i++) {
        const ncarry = this.words[i] & mask;
        const c = ((this.words[i] | 0) - ncarry) << r;

        this.words[i] = c | carry;

        carry = ncarry >>> (26 - r);
      }

      if (carry !== 0) {
        this._alloc(this.length + 1);
        this.words[this.length++] = carry;
      }
    }

    if (s !== 0) {
      this._alloc(this.length + s);

      for (let i = this.length - 1; i >= 0; i--)
        this.words[i + s] = this.words[i];

      for (let i = 0; i < s; i++)
        this.words[i] = 0;

      this.length += s;
    }

    return this._strip();
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
    enforce(num.bitLength() <= 32, 'bits', 'uint32');
    return this.ishrn(num.toNumber());
  }

  ishrn(bits) {
    enforce((bits >>> 0) === bits, 'bits', 'uint32');

    if (this.negative !== 0) {
      // (-x) >> y == ~(x-1) >> y
      //           == ~((x-1) >> y)
      //           == -(((x-1) >> y) + 1)
      this.negative = 0;
      this.isubn(1);
      this.iushrn(bits);
      this.iaddn(1);
      this.negative = 1;
      return this;
    }

    return this.iushrn(bits);
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
    enforce(num.bitLength() <= 32, 'bits', 'uint32');
    return this.iushrn(num.toNumber());
  }

  iushrn(bits) {
    enforce((bits >>> 0) === bits, 'bits', 'uint32');
    return this._split(bits, null);
  }

  _split(bits, output) {
    const r = bits % 26;
    const s = Math.min((bits - r) / 26, this.length);
    const mask = (1 << r) - 1;

    // Extended mode, copy masked part.
    if (output) {
      output._alloc(s);

      for (let i = 0; i < s; i++)
        output.words[i] = this.words[i];

      output.length = s;
    }

    if (s === 0) {
      // No-op, we should not move anything at all.
    } else if (this.length > s) {
      this.length -= s;
      for (let i = 0; i < this.length; i++)
        this.words[i] = this.words[i + s];
    } else {
      this.words[0] = 0;
      this.length = 1;
    }

    let carry = 0;

    for (let i = this.length - 1; i >= 0; i--) {
      const word = this.words[i] | 0;

      this.words[i] = (carry << (26 - r)) | (word >>> r);

      carry = word & mask;
    }

    // Push carried bits as a mask.
    if (output) {
      if (carry !== 0) {
        output._alloc(output.length + 1);
        output.words[output.length++] = carry;
      } else {
        if (output.length === 0)
          output.words[output.length++] = 0;

        output._strip();
      }
    }

    return this._strip();
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
    const negative = this.negative;

    if (negative !== 0) {
      this.iaddn(1);
      val = !val;
    }

    this.usetn(bit, val);

    if (negative !== 0)
      this.isubn(1);

    return this;
  }

  usetn(bit, val) {
    enforce((bit >>> 0) === bit, 'bit', 'uint32');

    const r = bit % 26;
    const s = (bit - r) / 26;

    this._expand(s + 1);

    if (val)
      this.words[s] |= (1 << r);
    else
      this.words[s] &= ~(1 << r);

    return this._strip();
  }

  testn(bit) {
    enforce((bit >>> 0) === bit, 'bit', 'uint32');

    const r = bit % 26;
    const s = (bit - r) / 26;

    // Fast case: bit is much higher than all existing words.
    if (this.length <= s)
      return this.negative;

    // Check bit and return.
    const w = this.words[s];
    const val = (w >> r) & 1;

    if (this.negative !== 0) {
      if (r > 0 && (w & ((1 << r) - 1)))
        return val ^ 1;

      let j = s;

      while (j--) {
        if (this.words[j] > 0)
          return val ^ 1;
      }
    }

    return val;
  }

  utestn(bit) {
    enforce((bit >>> 0) === bit, 'bit', 'uint32');

    const r = bit % 26;
    const s = (bit - r) / 26;

    // Fast case: bit is much higher than all existing words.
    if (this.length <= s)
      return 0;

    // Check bit and return.
    return (this.words[s] >> r) & 1;
  }

  imaskn(bits) {
    enforce((bits >>> 0) === bits, 'bits', 'uint32');

    if (this.negative !== 0) {
      this.iaddn(1).inotn(bits + 1);
      this.negative = 0;
    }

    return this.iumaskn(bits);
  }

  maskn(bits) {
    return this.clone().imaskn(bits);
  }

  iumaskn(bits) {
    enforce((bits >>> 0) === bits, 'bits', 'uint32');

    const r = bits % 26;

    let s = (bits - r) / 26;

    if (this.length <= s)
      return this;

    if (r !== 0)
      s += 1;

    this.length = Math.min(s, this.length);

    if (r !== 0)
      this.words[this.length - 1] &= (1 << r) - 1;

    if (this.length === 0)
      this.words[this.length++] = 0;

    return this._strip();
  }

  umaskn(bits) {
    return this.clone().iumaskn(bits);
  }

  andln(num) {
    return this.words[0] & num;
  }

  /*
   * Negation
   */

  ineg() {
    if (!this.isZero())
      this.negative ^= 1;

    return this;
  }

  neg() {
    return this.clone().ineg();
  }

  iabs() {
    this.negative = 0;
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

    if (this.negative !== num.negative)
      return num.negative - this.negative;

    const res = this.ucmp(num);

    if (this.negative !== 0)
      return -res | 0;

    return res;
  }

  cmpn(num) {
    enforce(isSMI(num), 'num', 'smi');

    const negative = (num < 0) | 0;

    if (this.negative !== negative)
      return negative - this.negative;

    const res = this.ucmpn(num);

    if (this.negative !== 0)
      return -res | 0;

    return res;
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

  sign() {
    if (this.negative !== 0)
      return -1;

    if (this.length === 1 && this.words[0] === 0)
      return 0;

    return 1;
  }

  isZero() {
    return this.length === 1 && this.words[0] === 0;
  }

  isNeg() {
    return this.negative !== 0;
  }

  isOdd() {
    return (this.words[0] & 1) === 1;
  }

  isEven() {
    return (this.words[0] & 1) === 0;
  }

  /*
   * Unsigned Comparison
   */

  ucmp(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (this.length < num.length)
      return -1;

    if (this.length > num.length)
      return 1;

    for (let i = this.length - 1; i >= 0; i--) {
      const a = this.words[i] | 0;
      const b = num.words[i] | 0;

      if (a === b)
        continue;

      return (a > b) - (a < b);
    }

    return 0;
  }

  ucmpn(num) {
    enforce(isSMI(num), 'num', 'smi');

    if (this.length > 1)
      return 1;

    const w = this.words[0];

    if (num < 0)
      num = -num;

    return (w > num) - (w < num);
  }

  /*
   * Number Theoretic Functions
   */

  legendre(num) {
    const red = HAS_BIGINT ? BN.red(num) : BN.mont(num);
    return this.toRed(red).redLegendre();
  }

  jacobi(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (num.isZero() || num.isEven())
      throw new Error('jacobi: `num` must be odd.');

    // See chapter 2, section 2.4:
    // http://yacas.sourceforge.net/Algo.book.pdf
    let a = this._cloneNormal();
    let b = num._cloneNormal();
    let j = 1;

    if (b.isNeg()) {
      if (a.isNeg())
        j = -1;
      b.ineg();
    }

    for (;;) {
      if (b.cmpn(1) === 0)
        return j;

      if (a.isZero())
        return 0;

      a = a.imod(b);

      if (a.isZero())
        return 0;

      const s = a.zeroBits();

      if (s & 1) {
        const bmod8 = b.andln(7);

        if (bmod8 === 3 || bmod8 === 5)
          j = -j;
      }

      const c = a.iushrn(s);

      if (b.andln(3) === 3 && c.andln(3) === 3)
        j = -j;

      a = b;
      b = c;
    }
  }

  kronecker(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    const table = [
      0,  1, 0, -1,
      0, -1, 0,  1
    ];

    let a = this._cloneNormal();
    let b = num._cloneNormal();
    let s = 1;

    if (b.isZero())
      return a.ucmpn(1) === 0 ? s : 0;

    if (!a.isOdd() && !b.isOdd())
      return 0;

    const z = b.zeroBits();

    b.iushrn(z);

    if (z & 1)
      s = table[a.andln(7)];

    if (b.isNeg()) {
      if (a.isNeg())
        s = -s;
      b.ineg();
    }

    for (;;) {
      if (a.isZero())
        return b.cmpn(1) === 0 ? s : 0;

      const z = a.zeroBits();

      a.iushrn(z);

      if (z & 1)
        s *= table[b.andln(7)];

      const w = a.words[0] ^ (a.negative * 0x3ffffff);

      if (w & b.words[0] & 2)
        s = -s;

      b.imod(a);

      [a, b] = [b, a];

      b.negative = 0;
    }
  }

  igcd(num) {
    return this.gcd(num)._move(this);
  }

  gcd(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (this.isZero())
      return num.abs();

    if (num.isZero())
      return this.abs();

    let a = this.clone();
    let b = num.clone();
    let shift = 0;

    a.negative = 0;
    b.negative = 0;

    // Remove common factor of two.
    for (; a.isEven() && b.isEven(); shift++) {
      a.iushrn(1);
      b.iushrn(1);
    }

    for (;;) {
      while (a.isEven())
        a.iushrn(1);

      while (b.isEven())
        b.iushrn(1);

      const r = a.cmp(b);

      if (r < 0) {
        // Swap `a` and `b` to make `a` always bigger than `b`.
        [a, b] = [b, a];
      } else if (r === 0 || b.cmpn(1) === 0) {
        break;
      }

      a.isub(b);
    }

    return b.iushln(shift);
  }

  ilcm(num) {
    return this.lcm(num)._move(this);
  }

  lcm(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (this.isZero() || num.isZero())
      return new BN(0);

    return this.quo(this.gcd(num)).mul(num).iabs();
  }

  egcd(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (this.isZero()) {
      return [
        new BN(0),
        new BN(num.sign()),
        num.abs()
      ];
    }

    if (num.isZero()) {
      return [
        new BN(this.sign()),
        new BN(0),
        this.abs()
      ];
    }

    const x = this.clone();
    const y = num.clone();

    x.negative = 0;
    y.negative = 0;

    // A * x + B * y = x
    const A = new BN(1);
    const B = new BN(0);

    // C * x + D * y = y
    const C = new BN(0);
    const D = new BN(1);

    let g = 0;

    while (x.isEven() && y.isEven()) {
      x.iushrn(1);
      y.iushrn(1);
      g += 1;
    }

    const yp = y.clone();
    const xp = x.clone();

    while (!x.isZero()) {
      let i = 0;

      for (let im = 1; (x.words[0] & im) === 0 && i < 26; im <<= 1)
        i += 1;

      if (i > 0) {
        x.iushrn(i);

        while (i > 0) {
          if (A.isOdd() || B.isOdd()) {
            A.iadd(yp);
            B.isub(xp);
          }

          A.iushrn(1);
          B.iushrn(1);

          i -= 1;
        }
      }

      let j = 0;

      for (let jm = 1; (y.words[0] & jm) === 0 && j < 26; jm <<= 1)
        j += 1;

      if (j > 0) {
        y.iushrn(j);

        while (j > 0) {
          if (C.isOdd() || D.isOdd()) {
            C.iadd(yp);
            D.isub(xp);
          }

          C.iushrn(1);
          D.iushrn(1);

          j -= 1;
        }
      }

      if (x.cmp(y) >= 0) {
        x.isub(y);
        A.isub(C);
        B.isub(D);
      } else {
        y.isub(x);
        C.isub(A);
        D.isub(B);
      }
    }

    if (this.negative !== 0)
      C.ineg();

    if (num.negative !== 0)
      D.ineg();

    return [C, D, y.iushln(g)];
  }

  iinvert(num) {
    return this.invert(num)._move(this);
  }

  invert(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    range(num.sign() > 0, 'invert');

    if (num.cmpn(1) === 0)
      throw new RangeError('Not invertible.');

    const [s,, g] = this.egcd(num);

    if (g.cmpn(1) !== 0)
      throw new RangeError('Not invertible.');

    return s.imod(num);
  }

  ifermat(num) {
    return this.fermat(num)._move(this);
  }

  fermat(num) {
    const red = HAS_BIGINT ? BN.red(num) : BN.mont(num);
    return this.toRed(red).redFermat().fromRed();
  }

  ipowm(y, m, mont) {
    return this.powm(y, m, mont)._move(this);
  }

  powm(y, m, mont) {
    const red = !HAS_BIGINT && mont ? BN.mont(m) : BN.red(m);
    return this.toRed(red).redPow(y).fromRed();
  }

  ipowmn(y, m, mont) {
    return this.powmn(y, m, mont)._move(this);
  }

  powmn(y, m, mont) {
    const red = mont ? BN.mont(m) : BN.red(m);
    return this.toRed(red).redPown(y).fromRed();
  }

  isqrtm(p) {
    return this.sqrtm(p)._move(this);
  }

  sqrtm(p) {
    enforce(BN.isBN(p), 'p', 'bignum');

    let red;

    if (p.andln(3) === 3 || p.andln(7) === 5) {
      // Probably not worth the setup.
      red = BN.red(p);
    } else {
      red = BN.mont(p);
    }

    return this.toRed(red).redSqrt().fromRed();
  }

  isqrtpq(p, q) {
    return this.sqrtpq(p, q)._move(this);
  }

  sqrtpq(p, q) {
    const sp = this.sqrtm(p);
    const sq = this.sqrtm(q);
    const [mp, mq] = p.egcd(q);
    const lhs = sq.mul(mp).mul(p);
    const rhs = sp.mul(mq).mul(q);
    const n = p.mul(q);

    return lhs.iadd(rhs).imod(n);
  }

  /*
   * Primality Testing
   */

  isPrime(rng, reps, limit) {
    enforce((reps >>> 0) === reps, 'reps', 'uint32');

    if (!this.isPrimeMR(rng, reps + 1, true))
      return false;

    if (!this.isPrimeLucas(limit))
      return false;

    return true;
  }

  isPrimeMR(rng, reps, force2 = false) {
    enforce((reps >>> 0) === reps, 'reps', 'uint32');
    enforce(reps > 0, 'reps', 'integer');
    enforce(typeof force2 === 'boolean', 'force2', 'boolean');

    const n = this;

    if (n.cmpn(7) < 0) {
      if (n.cmpn(2) === 0 || n.cmpn(3) === 0 || n.cmpn(5) === 0)
        return true;
      return false;
    }

    if (n.isEven())
      return false;

    const nm1 = n.subn(1);
    const nm3 = nm1.subn(2);
    const k = nm1.zeroBits();
    const q = nm1.ushrn(k);

    const red = BN.red(n);
    const rnm1 = nm1.toRed(red);
    const rone = new BN(1).toRed(red);

    // Miller-Rabin primality test.
next:
    for (let i = 0; i < reps; i++) {
      let x;

      if (i === reps - 1 && force2) {
        x = new BN(2);
      } else {
        x = BN.random(rng, 0, nm3);
        x.iaddn(2);
      }

      let y = x.toRed(red).redPow(q);

      if (y.cmp(rone) === 0 || y.cmp(rnm1) === 0)
        continue;

      for (let j = 1; j < k; j++) {
        y = y.redSqr();

        if (y.cmp(rnm1) === 0)
          continue next;

        if (y.cmp(rone) === 0)
          return false;
      }

      return false;
    }

    return true;
  }

  isPrimeLucas(limit = 0) {
    enforce((limit >>> 0) === limit, 'limit', 'uint32');

    const n = this;

    // Ignore 0 and 1.
    if (n.cmpn(1) <= 0)
      return false;

    // Two is the only even prime.
    if (n.isEven())
      return n.cmpn(2) === 0;

    // Baillie-OEIS "method C" for choosing D, P, Q.
    // See: https://oeis.org/A217719/a217719.txt.
    let p = 3;

    for (;;) {
      if (p > 10000) {
        // Thought to be impossible.
        throw new Error(`Cannot find (D/n) = -1 for ${n.toString(10)}.`);
      }

      if (limit > 0 && p > limit) {
        // It's thought to be impossible for `p`
        // to be larger than 10,000, but fail
        // on anything higher than a limit to
        // prevent DoS attacks. `p` never seems
        // to be higher than 30 in practice.
        return false;
      }

      const d = new BN(p * p - 4);
      const j = d.jacobi(n);

      if (j === -1)
        break;

      if (j === 0)
        return n.cmpn(p + 2) === 0;

      if (p === 40) {
        if (n.isSquare())
          return false;
      }

      p += 1;
    }

    // Check for Grantham definition of
    // "extra strong Lucas pseudoprime".
    const s = n.addn(1);
    const r = s.zeroBits();
    const nm2 = n.subn(2);

    let x = new BN(2);
    let y = new BN(p);

    s.iushrn(r);

    for (let i = s.bitLength(); i >= 0; i--) {
      if (s.testn(i)) {
        x = x.mul(y).iadd(n).isubn(p).imod(n);
        y = y.sqr().iadd(nm2).imod(n);
      } else {
        y = y.mul(x).iadd(n).isubn(p).imod(n);
        x = x.sqr().iadd(nm2).imod(n);
      }
    }

    if (x.cmpn(2) === 0 || x.cmp(nm2) === 0) {
      let a = x.muln(p);
      let b = y.ushln(1);

      if (a.cmp(b) < 0)
        [a, b] = [b, a];

      if (a.isub(b).imod(n).isZero())
        return true;
    }

    for (let t = 0; t < r - 1; t++) {
      if (x.isZero())
        return true;

      if (x.cmpn(2) === 0)
        return false;

      x = x.sqr().isubn(2).imod(n);
    }

    return false;
  }

  /*
   * Twos Complement
   */

  toTwos(width) {
    if (this.negative !== 0)
      return this.abs().inotn(width).iaddn(1);

    return this.clone();
  }

  fromTwos(width) {
    enforce((width >>> 0) === width, 'width', 'uint32');
    range(width > 0, 'width');

    if (this.testn(width - 1))
      return this.notn(width).iaddn(1).ineg();

    return this.clone();
  }

  /*
   * Reduction Context
   */

  toRed(ctx) {
    enforce(ctx instanceof Red, 'ctx', 'reduction context');

    if (this.red)
      throw new Error('Already in reduction context.');

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

  redIAdd(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redIAdd');
    return this.red.iadd(this, num);
  }

  redAdd(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redAdd');
    return this.red.add(this, num);
  }

  redIAddn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redIAddn');
    return this.red.iaddn(this, num);
  }

  redAddn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redAddn');
    return this.red.addn(this, num);
  }

  redISub(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redISub');
    return this.red.isub(this, num);
  }

  redSub(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redSub');
    return this.red.sub(this, num);
  }

  redISubn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redISubn');
    return this.red.isubn(this, num);
  }

  redSubn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redSubn');
    return this.red.subn(this, num);
  }

  redIMul(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redIMul');
    return this.red.imul(this, num);
  }

  redMul(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redMul');
    return this.red.mul(this, num);
  }

  redIMuln(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redIMuln');
    return this.red.imuln(this, num);
  }

  redMuln(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redMuln');
    return this.red.muln(this, num);
  }

  redISqr() {
    red(this.red, 'redISqr');
    return this.red.isqr(this);
  }

  redSqr() {
    red(this.red, 'redSqr');
    return this.red.sqr(this);
  }

  redIShl(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redIShl');
    nonred(!num.red, 'redIShl');
    return this.red.ishl(this, num);
  }

  redShl(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redShl');
    nonred(!num.red, 'redShl');
    return this.red.shl(this, num);
  }

  redIShln(num) {
    enforce((num >>> 0) === num, 'num', 'uint32');
    red(this.red, 'redIShln');
    return this.red.ishln(this, num);
  }

  redShln(num) {
    enforce((num >>> 0) === num, 'num', 'uint32');
    red(this.red, 'redShln');
    return this.red.shln(this, num);
  }

  redINeg() {
    red(this.red, 'redINeg');
    return this.red.ineg(this);
  }

  redNeg() {
    red(this.red, 'redNeg');
    return this.red.neg(this);
  }

  redCmp(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redCmp');
    return this.red.cmp(this, num);
  }

  redCmpn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redCmpn');
    return this.red.cmpn(this, num);
  }

  redIsOdd() {
    red(this.red, 'redIsOdd');
    return this.red.isOdd(this);
  }

  redIsEven() {
    red(this.red, 'redIsEven');
    return this.red.isEven(this);
  }

  redISqrt() {
    red(this.red, 'redISqrt');
    return this.red.isqrt(this);
  }

  redSqrt() {
    red(this.red, 'redSqrt');
    return this.red.sqrt(this);
  }

  redIInvert() {
    red(this.red, 'redIInvert');
    return this.red.iinvert(this);
  }

  redInvert() {
    red(this.red, 'redInvert');
    return this.red.invert(this);
  }

  redIFermat() {
    red(this.red, 'redIFermat');
    return this.red.ifermat(this);
  }

  redFermat() {
    red(this.red, 'redFermat');
    return this.red.fermat(this);
  }

  redLegendre() {
    red(this.red, 'redLegendre');
    return this.red.legendre(this);
  }

  redJacobi() {
    red(this.red, 'redJacobi');
    return this.red.jacobi(this);
  }

  redKronecker() {
    red(this.red, 'redKronecker');
    return this.red.kronecker(this);
  }

  redIPow(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redIPow');
    nonred(!num.red, 'redIPow');
    return this.red.ipow(this, num);
  }

  redPow(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redPow');
    nonred(!num.red, 'redPow');
    return this.red.pow(this, num);
  }

  redIPown(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redIPown');
    return this.red.ipown(this, num);
  }

  redPown(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redPown');
    return this.red.pown(this, num);
  }

  /*
   * Internal
   */

  _move(dest) {
    dest.words = this.words;
    dest.length = this.length;
    dest.negative = this.negative;
    dest.red = this.red;
    return dest;
  }

  _alloc(size) {
    while (this.words.length < size)
      this.words.push(0);

    return this;
  }

  _expand(size) {
    this._alloc(size);

    while (this.length < size)
      this.words[this.length++] = 0;

    return this;
  }

  _strip() {
    while (this.length > 1 && this.words[this.length - 1] === 0)
      this.length -= 1;

    return this._normalize();
  }

  _normalize() {
    assert(this.length > 0);

    // -0 = 0
    if (this.length === 1 && this.words[0] === 0)
      this.negative = 0;

    return this;
  }

  _check() {
    // We never have a zero length number.
    assert(this.length > 0);

    if (this.length === 1) {
      // Must be normalized.
      if (this.words[0] === 0)
        assert(this.negative === 0);
      return this;
    }

    // Must be stripped.
    assert(this.words[this.length - 1] !== 0);

    return this;
  }

  _invertp(p) {
    enforce(BN.isBN(p), 'p', 'bignum');
    assert(this.negative === 0);
    assert(p.sign() > 0);

    if (this.isZero() || p.cmpn(1) === 0)
      throw new RangeError('Not invertible.');

    const a = this.clone();
    const b = p.clone();
    const x1 = new BN(1);
    const x2 = new BN(0);
    const delta = b.clone();

    while (a.cmpn(1) > 0 && b.cmpn(1) > 0) {
      let i = 0;

      for (let im = 1; (a.words[0] & im) === 0 && i < 26; im <<= 1)
        i += 1;

      if (i > 0) {
        a.iushrn(i);

        while (i > 0) {
          if (x1.isOdd())
            x1.iadd(delta);

          x1.iushrn(1);

          i -= 1;
        }
      }

      let j = 0;

      for (let jm = 1; (b.words[0] & jm) === 0 && j < 26; jm <<= 1)
        j += 1;

      if (j > 0) {
        b.iushrn(j);

        while (j > 0) {
          if (x2.isOdd())
            x2.iadd(delta);

          x2.iushrn(1);

          j -= 1;
        }
      }

      if (a.cmp(b) >= 0) {
        a.isub(b);
        x1.isub(x2);
      } else {
        b.isub(a);
        x2.isub(x1);
      }
    }

    let res;

    if (a.cmpn(1) === 0)
      res = x1;
    else
      res = x2;

    if (res.sign() < 0)
      res.iadd(p);

    return res;
  }

  _cloneNormal() {
    return this.red ? this.fromRed() : this.clone();
  }

  _forceRed(ctx) {
    this.red = ctx;
    return this;
  }

  /*
   * Helpers
   */

  clone() {
    return new BN().inject(this);
  }

  inject(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    this.words = new Array(num.length);

    for (let i = 0; i < num.length; i++)
      this.words[i] = num.words[i];

    this.length = num.length;
    this.negative = num.negative;
    this.red = num.red;

    return this;
  }

  set(num, endian) {
    return this.fromNumber(num, endian);
  }

  swap(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    const x = this;
    const y = num;

    [x.words, y.words] = [y.words, x.words];
    [x.length, y.length] = [y.length, x.length];
    [x.negative, y.negative] = [y.negative, x.negative];
    [x.red, y.red] = [y.red, x.red];

    return x;
  }

  reverse() {
    const neg = this.negative;

    this.fromBuffer(this.toBuffer('be'), 'le');
    this.negative = neg;

    return this;
  }

  byteLength() {
    return Math.ceil(this.bitLength() / 8);
  }

  bitLength() {
    const w = this.words[this.length - 1];
    const hi = countBits(w);
    return (this.length - 1) * 26 + hi;
  }

  zeroBits() {
    if (this.isZero())
      return 0;

    let r = 0;

    for (let i = 0; i < this.length; i++) {
      const b = zeroBits(this.words[i]);

      r += b;

      if (b !== 26)
        break;
    }

    return r;
  }

  isSafe() {
    if (this.length <= 2)
      return true;

    if (this.length === 3 && this.words[2] === 0x01)
      return true;

    return false;
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
    let num = this.words[0];

    if (this.length === 2) {
      num += this.words[1] * 0x4000000;
    } else if (this.length === 3 && this.words[2] === 0x01) {
      // Note: at this stage it is known that the top bit is set.
      num += 0x10000000000000 + (this.words[1] * 0x4000000);
    } else if (this.length > 2) {
      throw new RangeError('Number can only safely store up to 53 bits.');
    }

    return this.negative !== 0 ? -num : num;
  }

  toDouble() {
    let num = 0;

    for (let i = this.length - 1; i >= 0; i--)
      num = (num * 0x4000000) + this.words[i];

    return this.negative !== 0 ? -num : num;
  }

  valueOf() {
    return this.toDouble();
  }

  toBigInt() {
    if (!HAS_BIGINT)
      throw new Error('BigInt is not supported!');

    const s52 = BigInt(52);
    const s26 = BigInt(26);

    let i = this.length - 1;
    let num = BigInt(0);

    for (; i >= 1; i -= 2) {
      const hi = this.words[i] * 0x4000000;
      const lo = this.words[i - 1];

      num = (num << s52) | BigInt(hi + lo);
    }

    if (i >= 0)
      num = (num << s26) | BigInt(this.words[0]);

    return this.negative !== 0 ? -num : num;
  }

  toBool() {
    return !this.isZero();
  }

  toString(base, padding) {
    base = getBase(base);

    if (padding == null)
      padding = 0;

    if (padding === 0)
      padding = 1;

    enforce((base >>> 0) === base, 'base', 'uint32');
    enforce((padding >>> 0) === padding, 'padding', 'uint32');

    if (base < 2 || base > 36)
      throw new RangeError('Base ranges between 2 and 36.');

    this._check();

    if (base === 16) {
      let out = '';
      let off = 0;
      let carry = 0;

      for (let i = 0; i < this.length; i++) {
        const w = this.words[i];
        const word = (((w << off) | carry) & 0xffffff).toString(16);

        carry = (w >>> (24 - off)) & 0xffffff;

        if (carry !== 0 || i !== this.length - 1)
          out = zeros[6 - word.length] + word + out;
        else
          out = word + out;

        off += 2;

        if (off >= 26) {
          off -= 26;
          i -= 1;
        }
      }

      if (carry !== 0)
        out = carry.toString(16) + out;

      while (out.length % padding !== 0)
        out = '0' + out;

      if (this.negative !== 0)
        out = '-' + out;

      return out;
    }

    const groupSize = groupSizes[base - 1];
    const groupBase = groupBases[base - 1];
    const c = this.clone();

    let out = '';

    c.negative = 0;

    while (!c.isZero()) {
      const r = c.remrn(groupBase).toString(base);

      c.iquon(groupBase);

      if (!c.isZero())
        out = zeros[groupSize - r.length] + r + out;
      else
        out = r + out;
    }

    if (this.isZero())
      out = '0';

    while (out.length % padding !== 0)
      out = '0' + out;

    if (this.negative !== 0)
      out = '-' + out;

    return out;
  }

  toJSON() {
    return this.toString(16, 2);
  }

  toArray(endian, length) {
    return this.toArrayLike(Array, endian, length);
  }

  toBuffer(endian, length) {
    return this.toArrayLike(Buffer, endian, length);
  }

  toArrayLike(ArrayType, endian, length) {
    if (endian == null)
      endian = 'be';

    if (length == null)
      length = 0;

    enforce(typeof ArrayType === 'function', 'ArrayType', 'function');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');
    enforce((length >>> 0) === length, 'length', 'uint32');

    this._check();

    const bytes = this.byteLength();
    const size = length || Math.max(1, bytes);

    if (bytes > size)
      throw new RangeError('Byte array longer than desired length.');

    const res = allocate(ArrayType, size);
    const q = this.clone();

    if (endian === 'be') {
      let i = size - 1;

      while (!q.isZero()) {
        res[i--] = q.words[0] & 0xff;
        q.iushrn(8);
      }

      for (; i >= 0; i--)
        res[i] = 0x00;
    } else {
      let i = 0;

      while (!q.isZero()) {
        res[i++] = q.words[0] & 0xff;
        q.iushrn(8);
      }

      for (; i < size; i++)
        res[i] = 0x00;
    }

    return res;
  }

  encode(endian, length) {
    return this.toBuffer(endian, length);
  }

  /*
   * Instantiation
   */

  of(num, endian) {
    return this.fromNumber(num, endian);
  }

  fromNumber(num, endian) {
    if (endian == null)
      endian = 'be';

    enforce(isInteger(num), 'num', 'integer');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    const neg = (num < 0) | 0;

    if (neg)
      num = -num;

    if (num < 0x4000000) {
      this.words = [num & 0x3ffffff];
      this.length = 1;
    } else if (num < 0x10000000000000) {
      this.words = [
        num & 0x3ffffff,
        (num / 0x4000000) & 0x3ffffff
      ];
      this.length = 2;
    } else {
      this.words = [
        num & 0x3ffffff,
        (num / 0x4000000) & 0x3ffffff,
        1
      ];
      this.length = 3;
    }

    this.negative = neg;

    if (endian === 'le')
      this.reverse();

    return this;
  }

  fromDouble(num, endian) {
    if (endian == null)
      endian = 'be';

    enforce(typeof num === 'number', 'num', 'double');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    if (!isFinite(num))
      num = 0;

    const neg = (num <= -1) | 0;

    if (num < 0)
      num = -num;

    num = Math.floor(num);

    this.words = [];

    while (num > 0) {
      const lo = num % 0x4000000;
      const hi = (num - lo) / 0x4000000;

      this.words.push(lo);

      num = hi;
    }

    if (this.words.length === 0)
      this.words.push(0);

    this.length = this.words.length;
    this.negative = neg;

    if (endian === 'le')
      this.reverse();

    return this;
  }

  fromBigInt(num, endian) {
    if (endian == null)
      endian = 'be';

    enforce(typeof num === 'bigint', 'num', 'bigint');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    if (!HAS_BIGINT)
      throw new Error('BigInt is not supported!');

    const zero = BigInt(0);
    const mask = BigInt(0x3ffffff);
    const shift = BigInt(26);

    const neg = (num < zero) | 0;

    if (neg)
      num = -num;

    this.words = [];

    while (num > zero) {
      this.words.push(Number(num & mask));
      num >>= shift;
    }

    if (this.words.length === 0)
      this.words.push(0);

    this.length = this.words.length;
    this.negative = neg;

    if (endian === 'le')
      this.reverse();

    return this;
  }

  fromBool(value) {
    enforce(typeof value === 'boolean', 'value', 'boolean');
    return this.set(value ? 1 : 0);
  }

  fromString(str, base, endian) {
    if (base === 'le' || base === 'be')
      [base, endian] = [endian, base];

    base = getBase(base);

    if (endian == null)
      endian = 'be';

    enforce(typeof str === 'string', 'string', 'string');
    enforce((base >>> 0) === base, 'base', 'uint32');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    if (base < 2 || base > 36)
      throw new Error('Base ranges between 2 and 36.');

    str = str.replace(/[\t\n\r ]/g, '');

    let start = 0;

    if (str.length > 0 && str.charCodeAt(0) === 0x2d)
      start = 1;

    if (base === 16)
      this._fromHex(str, start);
    else
      this._fromBase(str, base, start);

    this.negative = start;

    this._strip();

    if (endian === 'le')
      this.reverse();

    return this;
  }

  _fromHex(str, start) {
    // Create possibly bigger array to ensure that it fits the number.
    this.length = Math.max(2, Math.ceil((str.length - start) / 6));
    this.words = new Array(this.length);

    for (let i = 0; i < this.length; i++)
      this.words[i] = 0;

    // Scan 24-bit chunks and add them to the number.
    let off = 0;
    let i = str.length - 6;
    let j = 0;

    for (; i >= start; i -= 6) {
      const w = parseHex(str, i, i + 6);

      this.words[j] |= (w << off) & 0x3ffffff;

      // `0x3fffff` is intentional here, 26bits max shift + 24bit hex limb.
      this.words[j + 1] |= (w >>> (26 - off)) & 0x3fffff;

      off += 24;

      if (off >= 26) {
        off -= 26;
        j += 1;
      }
    }

    if (i + 6 !== start) {
      const w = parseHex(str, start, i + 6);

      this.words[j] |= (w << off) & 0x3ffffff;
      this.words[j + 1] |= (w >>> (26 - off)) & 0x3fffff;
    }

    return this._strip();
  }

  _fromBase(str, base, start) {
    // Initialize as zero.
    this.words = [0];
    this.length = 1;
    this.negative = 0;

    // Find length of limb in base.
    let limbLen = 0;
    let limbPow = 1;

    for (; limbPow <= 0x3ffffff; limbPow *= base)
      limbLen += 1;

    limbLen -= 1;
    limbPow = (limbPow / base) | 0;

    const total = str.length - start;
    const mod = total % limbLen;
    const end = Math.min(total, total - mod) + start;

    let word = 0;
    let i = start;

    for (; i < end; i += limbLen) {
      word = parseBase(str, i, i + limbLen, base);

      this.imuln(limbPow);
      this._iaddn(word);
    }

    if (mod !== 0) {
      let pow = 1;

      word = parseBase(str, i, str.length, base);

      for (i = 0; i < mod; i++)
        pow *= base;

      this.imuln(pow);
      this._iaddn(word);
    }

    return this;
  }

  fromJSON(json) {
    return this.fromString(json, 16);
  }

  fromBN(num) {
    return this.inject(num);
  }

  fromArray(data, endian) {
    enforce(Array.isArray(data), 'data', 'array');
    return this.fromArrayLike(data, endian);
  }

  fromBuffer(data, endian) {
    enforce(Buffer.isBuffer(data), 'data', 'buffer');
    return this.fromArrayLike(data, endian);
  }

  fromArrayLike(data, endian) {
    if (endian == null)
      endian = 'be';

    enforce(data && typeof data.length === 'number', 'data', 'array-like');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    if (data.length <= 0) {
      this.words = [0];
      this.length = 1;
      this.negative = 0;
      return this;
    }

    this.length = Math.max(2, Math.ceil(data.length / 3));
    this.words = new Array(this.length);
    this.negative = 0;

    for (let i = 0; i < this.length; i++)
      this.words[i] = 0;

    const left = data.length % 3;

    let off = 0;
    let j = 0;
    let w = 0;

    if (endian === 'be') {
      for (let i = data.length - 1; i >= 2; i -= 3) {
        const w = data[i] | (data[i - 1] << 8) | (data[i - 2] << 16);

        this.words[j] |= (w << off) & 0x3ffffff;
        this.words[j + 1] = (w >>> (26 - off)) & 0x3ffffff;

        off += 24;

        if (off >= 26) {
          off -= 26;
          j += 1;
        }
      }

      switch (left) {
        case 2:
          w = data[1] | (data[0] << 8);
          break;
        case 1:
          w = data[0];
          break;
      }
    } else {
      const len = data.length - left;

      for (let i = 0; i < len; i += 3) {
        const w = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16);

        this.words[j] |= (w << off) & 0x3ffffff;
        this.words[j + 1] = (w >>> (26 - off)) & 0x3ffffff;

        off += 24;

        if (off >= 26) {
          off -= 26;
          j += 1;
        }
      }

      switch (left) {
        case 2:
          w = data[len] | (data[len + 1] << 8);
          break;
        case 1:
          w = data[len];
          break;
      }
    }

    if (left > 0) {
      this.words[j] |= (w << off) & 0x3ffffff;
      this.words[j + 1] = (w >>> (26 - off)) & 0x3ffffff;
    }

    return this._strip();
  }

  decode(data, endian) {
    return this.fromBuffer(data, endian);
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
        return this.fromArrayLike(num, endian);
    }

    if (typeof num === 'boolean')
      return this.fromBool(num);

    throw new TypeError('Non-numeric object passed to BN.');
  }

  /*
   * Static Methods
   */

  static min(a, b) {
    enforce(BN.isBN(a), 'a', 'bignum');
    return a.cmp(b) < 0 ? a : b;
  }

  static max(a, b) {
    enforce(BN.isBN(a), 'a', 'bignum');
    return a.cmp(b) > 0 ? a : b;
  }

  static cmp(a, b) {
    enforce(BN.isBN(a), 'a', 'bignum');
    return a.cmp(b);
  }

  static ucmp(a, b) {
    enforce(BN.isBN(a), 'a', 'bignum');
    return a.ucmp(b);
  }

  static red(num) {
    return new Red(num);
  }

  static mont(num) {
    return new Mont(num);
  }

  static _prime(name) {
    if (primes[name])
      return primes[name];

    let prime;

    if (name === 'p192')
      prime = new P192();
    else if (name === 'p224')
      prime = new P224();
    else if (name === 'p521')
      prime = new P521();
    else if (name === 'k256')
      prime = new K256();
    else if (name === 'p25519')
      prime = new P25519();
    else if (name === 'p448')
      prime = new P448();
    else
      throw new Error('Unknown prime ' + name);

    primes[name] = prime;

    return prime;
  }

  static pow(num, exp) {
    if (num === 2)
      return BN.shift(1, exp);

    return new BN().fromNumber(num).ipown(exp);
  }

  static shift(num, bits) {
    if (num === 1)
      return new BN(0).usetn(bits, 1);

    return new BN().fromNumber(num).ishln(bits);
  }

  static mask(bits) {
    return BN.shift(1, bits).isubn(1);
  }

  static randomBits(rng, bits) {
    enforce(rng != null, 'rng', 'rng');
    enforce((bits >>> 0) === bits, 'bits', 'uint32');

    if (typeof rng === 'object') {
      enforce(typeof rng.randomBytes === 'function', 'rng', 'rng');

      const size = (bits + 7) >>> 3;
      const total = size * 8;
      const bytes = rng.randomBytes(size);

      enforce(Buffer.isBuffer(bytes), 'bytes', 'buffer');

      if (bytes.length !== size)
        throw new RangeError('Invalid number of bytes returned from RNG.');

      const num = BN.fromBuffer(bytes);

      if (total > bits)
        num.iushrn(total - bits);

      return num;
    }

    enforce(typeof rng === 'function', 'rng', 'rng');

    const num = rng(bits);

    enforce(BN.isBN(num), 'num', 'bignum');
    range(num.negative === 0, 'RNG');
    nonred(!num.red, 'RNG');

    if (num.bitLength() > bits)
      throw new RangeError('Invalid number of bits returned from RNG.');

    return num;
  }

  static random(rng, min, max) {
    min = BN.cast(min, 16);
    max = BN.cast(max, 16);

    if (min.cmp(max) > 0)
      throw new RangeError('Minimum cannot be greater than maximum.');

    const space = max.sub(min).iabs();
    const bits = space.bitLength();

    if (bits === 0)
      return min.clone();

    for (;;) {
      const num = BN.randomBits(rng, bits);

      // Maximum is _exclusive_!
      if (num.cmp(space) >= 0)
        continue;

      // Minimum is _inclusive_!
      num.iadd(min);

      return num;
    }
  }

  static of(num, endian) {
    return new BN().of(num, endian);
  }

  static fromNumber(num, endian) {
    return new BN().fromNumber(num, endian);
  }

  static fromDouble(num, endian) {
    return new BN().fromDouble(num, endian);
  }

  static fromBigInt(num, endian) {
    return new BN().fromBigInt(num, endian);
  }

  static fromBool(value) {
    return new BN().fromBool(value);
  }

  static fromString(str, base, endian) {
    return new BN().fromString(str, base, endian);
  }

  static fromJSON(json) {
    return new BN().fromJSON(json);
  }

  static fromBN(num) {
    return new BN().fromBN(num);
  }

  static fromArray(data, endian) {
    return new BN().fromArray(data, endian);
  }

  static fromBuffer(data, endian) {
    return new BN().fromBuffer(data, endian);
  }

  static fromArrayLike(data, endian) {
    return new BN().fromArrayLike(data, endian);
  }

  static decode(data, endian) {
    return new BN().decode(data, endian);
  }

  static from(num, base, endian) {
    return new BN().from(num, base, endian);
  }

  static cast(num, base, endian) {
    if (BN.isBN(num))
      return num;

    return new BN(num, base, endian);
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
BN.native = 0;

/**
 * Prime
 */

class Prime {
  constructor(name, p) {
    // P = 2 ^ N - K
    this.name = name;
    this.p = new BN(p, 16);
    this.n = this.p.bitLength();
    this.k = BN.shift(1, this.n).isub(this.p);
    this.tmp = this._tmp();
  }

  _tmp() {
    const tmp = new BN();

    tmp.words = new Array(Math.ceil(this.n / 13));

    for (let i = 0; i < tmp.words.length; i++)
      tmp.words[i] = 0;

    return tmp;
  }

  ireduce(num) {
    // Assumes that `num` is less than `P^2`:
    // num = HI * (2 ^ N - K) + HI * K + LO = HI * K + LO (mod P)
    let r = num;
    let rlen;

    assert(r.negative === 0);
    assert(r.length <= this.p.length * 2);

    if (r.length < this.p.length)
      return r;

    do {
      this.split(r, this.tmp);
      r = this.imulK(r);
      r = r.iadd(this.tmp);
      rlen = r.bitLength();
    } while (rlen > this.n);

    const cmp = rlen < this.n ? -1 : r.ucmp(this.p);

    if (cmp === 0) {
      r.words[0] = 0;
      r.length = 1;
    } else if (cmp > 0) {
      r.isub(this.p);
    } else {
      // Note: we shouldn't need to strip here.
    }

    return r;
  }

  split(input, out) {
    input._split(this.n, out);
  }

  imulK(num) {
    return num.imul(this.k);
  }
}

/**
 * P192
 */

class P192 extends Prime {
  constructor() {
    super('p192', 'ffffffff ffffffff ffffffff fffffffe'
                + 'ffffffff ffffffff');
  }

  imulK(num) {
    // K = 0x10000000000000001
    const n = num.clone();
    return num.iushln(64).iadd(n);
  }
}

/**
 * P224
 */

class P224 extends Prime {
  constructor() {
    super('p224', 'ffffffff ffffffff ffffffff ffffffff'
                + '00000000 00000000 00000001');
  }

  imulK(num) {
    // K = 0xffffffffffffffffffffffff
    const n = num.clone();
    return num.iushln(96).isub(n);
  }
}

/**
 * P521
 */

class P521 extends Prime {
  constructor() {
    super('p521', '000001ff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff');
  }

  imulK(num) {
    // K = 0x01
    return num;
  }
}

/**
 * K256
 */

class K256 extends Prime {
  constructor() {
    super('k256', 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff fffffffe fffffc2f');
  }

  split(input, output) {
    // 256 = 9 * 26 + 22
    const mask = 0x3fffff;
    const outLen = Math.min(input.length, 9);

    output._alloc(outLen + 1);

    for (let i = 0; i < outLen; i++)
      output.words[i] = input.words[i];

    output.length = outLen;

    if (input.length <= 9) {
      output._strip();
      input.words[0] = 0;
      input.length = 1;
      return;
    }

    // Shift by 9 limbs.
    let prev = input.words[9];
    let i = 10;

    output.words[output.length++] = prev & mask;
    output._strip();

    for (; i < input.length; i++) {
      const next = input.words[i] | 0;
      input.words[i - 10] = ((next & mask) << 4) | (prev >>> 22);
      prev = next;
    }

    prev >>>= 22;
    input.words[i - 10] = prev;

    if (prev === 0 && input.length > 10)
      input.length -= 10;
    else
      input.length -= 9;

    input._strip(); // Unsure if we need this.
  }

  imulK(num) {
    // K = 0x1000003d1 = [0x40, 0x3d1]
    num._expand(num.length + 2);

    // Bounded at: 0x40 * 0x3ffffff + 0x3d0 = 0x100000390
    let lo = 0;

    for (let i = 0; i < num.length; i++) {
      const w = num.words[i] | 0;
      lo += w * 0x3d1;
      num.words[i] = lo & 0x3ffffff;
      lo = w * 0x40 + ((lo / 0x4000000) | 0);
    }

    // Fast length reduction.
    if (num.words[num.length - 1] === 0) {
      num.length -= 1;
      if (num.words[num.length - 1] === 0)
        num.length -= 1;
    }

    // Note: we shouldn't need to strip here.
    return num;
  }
}

/**
 * P25519
 */

class P25519 extends Prime {
  constructor() {
    // 2^255 - 19
    super('p25519', '7fffffff ffffffff ffffffff ffffffff'
                  + 'ffffffff ffffffff ffffffff ffffffed');
  }

  imulK(num) {
    // K = 0x13
    let carry = 0;

    for (let i = 0; i < num.length; i++) {
      let hi = (num.words[i] | 0) * 0x13 + carry;

      const lo = hi & 0x3ffffff;

      hi >>>= 26;

      num.words[i] = lo;
      carry = hi;
    }

    if (carry !== 0) {
      num._alloc(num.length + 1);
      num.words[num.length++] = carry;
    }

    // Note: we shouldn't need to strip here.
    return num;
  }
}

/**
 * P448
 */

class P448 extends Prime {
  constructor() {
    // 2^448 - 2^224 - 1
    super('p448', 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff fffffffe ffffffff'
                + 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff');
  }

  imulK(num) {
    // K = 0x100000000000000000000000000000000000000000000000000000001
    const n = num.clone();
    return num.iushln(224).iadd(n);
  }
}

/**
 * Reduction Engine
 */

class Red {
  constructor(m) {
    let prime = null;

    if (typeof m === 'string') {
      prime = BN._prime(m);
      m = prime.p;
    }

    enforce(BN.isBN(m), 'm', 'bignum');
    nonred(!m.red, 'reduction');
    range(m.sign() > 0, 'reduction');

    this.m = m;
    this.mb = null;
    this.prime = prime;
  }

  _verify1(a) {
    range(a.negative === 0, 'red');
    red(a.red != null, 'red');
  }

  _verify2(a, b) {
    range((a.negative | b.negative) === 0, 'red');
    red(a.red != null && a.red === b.red, 'red');
  }

  convertTo(num) {
    return num.mod(this.m);
  }

  convertFrom(num) {
    const res = num.clone();
    res.red = null;
    return res;
  }

  imod(a) {
    if (this.prime)
      return this.prime.ireduce(a)._forceRed(this);

    return a.imod(this.m)._forceRed(this);
  }

  iadd(a, b) {
    this._verify2(a, b);

    a.iadd(b);

    if (a.cmp(this.m) >= 0)
      a.isub(this.m);

    return a;
  }

  add(a, b) {
    this._verify2(a, b);

    const res = a.add(b);

    if (res.cmp(this.m) >= 0)
      res.isub(this.m);

    return res._forceRed(this);
  }

  iaddn(a, num) {
    this._verify1(a);

    if (num < 0)
      return this.isubn(a, -num);

    if (this.m.length === 1)
      num %= this.m.words[0];

    a._iaddn(num);

    if (a.cmp(this.m) >= 0)
      a.isub(this.m);

    return a;
  }

  addn(a, num) {
    return this.iaddn(a.clone(), num);
  }

  isub(a, b) {
    this._verify2(a, b);

    a.isub(b);

    if (a.sign() < 0)
      a.iadd(this.m);

    return a;
  }

  sub(a, b) {
    this._verify2(a, b);

    const res = a.sub(b);

    if (res.sign() < 0)
      res.iadd(this.m);

    return res._forceRed(this);
  }

  isubn(a, num) {
    this._verify1(a);

    if (num < 0)
      return this.iaddn(a, -num);

    if (this.m.length === 1)
      num %= this.m.words[0];

    a._isubn(num);

    if (a.sign() < 0)
      a.iadd(this.m);

    return a;
  }

  subn(a, num) {
    return this.isubn(a.clone(), num);
  }

  imul(a, b) {
    this._verify2(a, b);
    return this.imod(a.imul(b));
  }

  mul(a, b) {
    this._verify2(a, b);
    return this.imod(a.mul(b));
  }

  _imuln(a, num) {
    if (this.m.length === 1)
      num %= this.m.words[0];

    return this.imod(a.imuln(num));
  }

  imuln(a, num) {
    this._verify1(a);

    if (a.isZero())
      return a;

    if (num === 0) {
      a.words[0] = 0;
      a.length = 1;
      return a;
    }

    const neg = num < 0;

    if (neg)
      num = -num;

    if (num <= 16) {
      // Compute with additions.
      const log = countBits(num) - 1;
      const rem = num & ~(1 << log);
      const c = rem !== 0 ? a.clone() : null;

      for (let i = 0; i < log; i++)
        this.iadd(a, a);

      for (let i = 0; i < rem; i++)
        this.iadd(a, c);
    } else {
      this._imuln(a, num);
    }

    if (neg)
      this.ineg(a);

    return a;
  }

  muln(a, num) {
    return this.imuln(a.clone(), num);
  }

  isqr(a) {
    return this.imul(a, a);
  }

  sqr(a) {
    return this.mul(a, a);
  }

  ishl(a, num) {
    this._verify1(a);
    return this.imod(a.iushl(num));
  }

  shl(a, num) {
    return this.ishl(a.clone(), num);
  }

  ishln(a, num) {
    this._verify1(a);
    return this.imod(a.iushln(num));
  }

  shln(a, num) {
    this._verify1(a);
    return this.imod(a.ushln(num));
  }

  ineg(a) {
    this._verify1(a);

    if (!a.isZero()) {
      a.isub(this.m);
      a.ineg();
    }

    return a;
  }

  neg(a) {
    this._verify1(a);

    if (a.isZero())
      return a.clone();

    return this.m.sub(a)._forceRed(this);
  }

  cmp(a, b) {
    this._verify2(a, b);
    return a.ucmp(b);
  }

  cmpn(a, num) {
    this._verify1(a);

    if (this.m.length === 1) {
      num %= this.m.words[0];

      if (num < 0)
        num += this.m.words[0];

      return a.ucmpn(num);
    }

    if (num < 0) {
      this.m._isubn(-num);

      const cmp = a.ucmp(this.m);

      this.m._iaddn(-num);

      return cmp;
    }

    return a.ucmpn(num);
  }

  isOdd(a) {
    this._verify1(a);
    return a.isOdd();
  }

  isEven(a) {
    this._verify1(a);
    return a.isEven();
  }

  isqrt(x) {
    return this.sqrt(x)._move(x);
  }

  sqrt(x) {
    this._verify1(x);

    switch (this.jacobi(x)) {
      case -1:
        throw new Error('X is not a square mod P.');
      case 0:
        return new BN(0)._forceRed(this);
      case 1:
        break;
    }

    // Fast case (mod 4 == 3).
    if (this.m.andln(3) === 3) {
      const e = this.m.addn(1).iushrn(2);
      return this.pow(x, e);
    }

    const one = new BN(1).toRed(this);

    // Fast case (mod 8 == 5).
    if (this.m.andln(7) === 5) {
      const e = this.m.ushrn(3);
      const t = this.add(x, x);
      const a = this.pow(t, e);

      let b = this.sqr(a);

      b = this.mul(b, t);
      b = this.isub(b, one);
      b = this.mul(b, x);
      b = this.mul(b, a);

      return b;
    }

    const s = this.m.subn(1);
    const e = s.zeroBits();

    s.iushrn(e);

    const n = new BN(2).toRed(this);

    while (this.jacobi(n) !== -1)
      this.iadd(n, one);

    let b = this.pow(x, s);
    let g = this.pow(n, s);
    let y = this.pow(x, s.iaddn(1).iushrn(1));
    let k = e;

    for (;;) {
      let t = b;
      let m = 0;

      while (t.cmp(one) !== 0) {
        t = this.sqr(t);
        m += 1;
      }

      if (m === 0)
        break;

      assert(m !== k);

      t = BN.shift(1, k - m - 1);
      t = this.pow(g, t);
      g = this.sqr(t);
      y = this.mul(y, t);
      b = this.mul(b, g);
      k = m;
    }

    return y;
  }

  iinvert(a) {
    return this.invert(a)._move(a);
  }

  invert(a) {
    this._verify1(a);

    if (this.prime) {
      const inv = a._invertp(this.m);

      if (inv.negative !== 0) {
        inv.negative = 0;
        this.imod(inv);
        this.ineg(inv);
      } else {
        this.imod(inv);
      }

      return inv;
    }

    return a.invert(this.m)._forceRed(this);
  }

  ifermat(a) {
    return this.fermat(a)._move(a);
  }

  fermat(a) {
    this._verify1(a);

    if (a.isZero() || this.m.cmpn(1) === 0)
      throw new RangeError('Not invertible.');

    // Invert using fermat's little theorem.
    return this.pow(a, this.m.subn(2));
  }

  legendre(a) {
    this._verify1(a);

    if (this.m.isEven())
      throw new Error('legendre: `num` must be odd.');

    // Euler's criterion.
    const s = this.pow(a, this.m.subn(1).iushrn(1));

    if (s.isZero())
      return 0;

    const one = new BN(1).toRed(this);

    if (s.cmp(one) === 0)
      return 1;

    if (this.iadd(s, one).isZero())
      return -1;

    throw new Error('Invalid prime.');
  }

  jacobi(a) {
    this._verify1(a);
    return a.jacobi(this.m);
  }

  kronecker(a) {
    this._verify1(a);
    return a.kronecker(this.m);
  }

  ipow(a, num) {
    return this.pow(a, num)._move(a);
  }

  powBig(a, num) {
    if (this.mb === null)
      this.mb = this.m.toBigInt();

    const x = a.toBigInt();
    const r = powBig(x, num, this.mb);

    return BN.fromBigInt(r)._forceRed(this);
  }

  pow(a, num) {
    this._verify1(a);

    if (num.isZero())
      return new BN(1).toRed(this);

    // GMP behavior.
    if (num.isNeg())
      a = this.invert(a);

    if (num.ucmpn(1) === 0)
      return a.clone();

    if (HAS_BIGINT && !this.prime)
      return this.powBig(a, num);

    if (num.length === 1)
      return this.pown(a, num.words[0]);

    const windowSize = 4;
    const wnd = new Array(1 << windowSize);

    wnd[0] = new BN(1).toRed(this);
    wnd[1] = a;

    for (let i = 2; i < wnd.length; i++)
      wnd[i] = this.mul(wnd[i - 1], a);

    let res = wnd[0];
    let current = 0;
    let currentLen = 0;
    let start = num.bitLength() % 26;

    if (start === 0)
      start = 26;

    for (let i = num.length - 1; i >= 0; i--) {
      const word = num.words[i];

      for (let j = start - 1; j >= 0; j--) {
        const bit = (word >> j) & 1;

        if (res !== wnd[0])
          res = this.sqr(res);

        if (bit === 0 && current === 0) {
          currentLen = 0;
          continue;
        }

        current <<= 1;
        current |= bit;
        currentLen += 1;

        if (currentLen !== windowSize && (i !== 0 || j !== 0))
          continue;

        res = this.mul(res, wnd[current]);
        currentLen = 0;
        current = 0;
      }

      start = 26;
    }

    return res;
  }

  ipown(a, num) {
    return this.pown(a, num)._move(a);
  }

  pown(a, num) {
    this._verify1(a);

    let x = a;
    let y = num;
    let r = new BN(1).toRed(this);

    if (y < 0) {
      x = this.invert(x);
      y = -y;
    }

    while (y > 0) {
      if (y & 1)
        r = this.mul(r, x);

      y >>>= 1;
      x = this.sqr(x);
    }

    return r;
  }

  [custom]() {
    return `<Red: ${this.m.toString(10)}>`;
  }
}

/**
 * Montgomery Method Engine
 */

class Mont extends Red {
  constructor(m) {
    super(m);

    this.prime = null;
    this.n = this.m.bitLength();

    if (this.n % 26 !== 0)
      this.n += 26 - (this.n % 26);

    this.r = BN.shift(1, this.n);
    this.r2 = this.imod(this.r.sqr());
    this.ri = this.r._invertp(this.m).imod(this.m);
    this.mi = this.r.sub(this.ri.mul(this.r).isubn(1).div(this.m).imod(this.r));
    this.rib = null;
  }

  convertTo(num) {
    return this.imod(num.ushln(this.n));
  }

  convertFrom(num) {
    const r = this.imod(num.mul(this.ri));
    r.red = null;
    return r;
  }

  iaddn(a, num) {
    return this.iadd(a, this.convertTo(new BN(num)));
  }

  isubn(a, num) {
    return this.isub(a, this.convertTo(new BN(num)));
  }

  imul(a, b) {
    return this.mul(a, b)._move(a);
  }

  mul(a, b) {
    this._verify2(a, b);

    if (a.isZero() || b.isZero())
      return new BN(0)._forceRed(this);

    const t = a.mul(b);
    const c = t.umaskn(this.n).mul(this.mi).iumaskn(this.n).mul(this.m);
    const u = t.isub(c).iushrn(this.n);

    if (u.sign() < 0)
      u.iadd(this.m);
    else if (u.cmp(this.m) >= 0)
      u.isub(this.m);

    return u._forceRed(this);
  }

  _imuln(a, num) {
    return this.imul(a, this.convertTo(new BN(num)));
  }

  cmpn(a, num) {
    this._verify1(a);
    return a.ucmp(this.convertTo(new BN(num)));
  }

  isOdd(a) {
    this._verify1(a);
    return this.convertFrom(a).isOdd();
  }

  isEven(a) {
    this._verify1(a);
    return this.convertFrom(a).isEven();
  }

  invert(a) {
    this._verify1(a);

    // (AR)^-1 * R^2 = (A^-1 * R^-1) * R^2 = A^-1 * R
    return this.imod(a._invertp(this.m).mul(this.r2));
  }

  powBig(a, num) {
    if (this.mb === null)
      this.mb = this.m.toBigInt();

    if (this.rib === null)
      this.rib = this.ri.toBigInt();

    const x = (a.toBigInt() * this.rib) % this.mb;
    const r = powBig(x, num, this.mb);
    const z = (r << BigInt(this.n)) % this.mb;

    return BN.fromBigInt(z)._forceRed(this);
  }
}

/*
 * Helpers
 */

function makeError(Error, msg, start) {
  const err = new Error(msg);

  if (Error.captureStackTrace)
    Error.captureStackTrace(err, start);

  return err;
}

function assert(value, message) {
  if (!value) {
    const msg = message || 'Assertion failed.';
    throw makeError(Error, msg, assert);
  }
}

function enforce(value, name, type) {
  if (!value) {
    const msg = `"${name}" must be a(n) ${type}.`;
    throw makeError(TypeError, msg, enforce);
  }
}

function range(value, name) {
  if (!value) {
    const msg = `"${name}" only works with positive numbers.`;
    throw makeError(RangeError, msg, range);
  }
}

function red(value, name) {
  if (!value) {
    const msg = `"${name}" only works with red numbers.`;
    throw makeError(TypeError, msg, red);
  }
}

function nonred(value, name) {
  if (!value) {
    const msg = `"${name}" only works with normal numbers.`;
    throw makeError(TypeError, msg, nonred);
  }
}

function nonzero(value) {
  if (!value) {
    const msg = 'Cannot divide by zero.';
    throw makeError(RangeError, msg, nonzero);
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

/*
 * Internal
 */

function toBitArray(num) {
  const w = new Array(num.bitLength());

  for (let bit = 0; bit < w.length; bit++) {
    const wbit = bit % 26;
    const off = (bit - wbit) / 26;

    w[bit] = (num.words[off] >>> wbit) & 1;
  }

  return w;
}

function countBits(w) {
  if (Math.clz32)
    return 32 - Math.clz32(w);

  let t = w;
  let r = 0;

  if (t >= 0x1000) {
    r += 13;
    t >>>= 13;
  }

  if (t >= 0x40) {
    r += 7;
    t >>>= 7;
  }

  if (t >= 0x8) {
    r += 4;
    t >>>= 4;
  }

  if (t >= 0x02) {
    r += 2;
    t >>>= 2;
  }

  return r + t;
}

function zeroBits(w) {
  // Shortcut.
  if (w === 0)
    return 26;

  let t = w;
  let r = 0;

  if ((t & 0x1fff) === 0) {
    r += 13;
    t >>>= 13;
  }

  if ((t & 0x7f) === 0) {
    r += 7;
    t >>>= 7;
  }

  if ((t & 0xf) === 0) {
    r += 4;
    t >>>= 4;
  }

  if ((t & 0x3) === 0) {
    r += 2;
    t >>>= 2;
  }

  if ((t & 0x1) === 0)
    r += 1;

  return r;
}

function parseHex(str, start, end) {
  const len = Math.min(str.length, end);

  let r = 0;
  let z = 0;

  for (let i = start; i < len; i++) {
    const c = str.charCodeAt(i) - 48;

    r <<= 4;

    let b;

    if (c >= 49 && c <= 54) {
      // 'a' - 'f'
      b = c - 49 + 0xa;
    } else if (c >= 17 && c <= 22) {
      // 'A' - 'F'
      b = c - 17 + 0xa;
    } else {
      // '0' - '9'
      b = c;
    }

    r |= b;
    z |= b;
  }

  if (z & 0xfff0)
    throw new Error('Invalid string.');

  return r;
}

function parseBase(str, start, end, mul) {
  const len = Math.min(str.length, end);

  let r = 0;
  let b = 0;

  for (let i = start; i < len; i++) {
    const c = str.charCodeAt(i) - 48;

    r *= mul;

    if (c >= 49) {
      // 'a'
      b = c - 49 + 0xa;
    } else if (c >= 17) {
      // 'A'
      b = c - 17 + 0xa;
    } else {
      // '0' - '9'
      b = c;
    }

    if (c < 0 || c > 207 || b >= mul)
      throw new Error('Invalid string.');

    r += b;
  }

  return r;
}

/*
 * Exponentiation (bigint)
 */

function powBig(x, y, m) {
  let r = BigInt(1);
  let b = countBits(y.words[y.length - 1]);

  for (let i = y.length - 1; i >= 0; i--) {
    const w = y.words[i];

    for (let j = b - 1; j >= 0; j--) {
      r = (r * r) % m;

      if ((w >> j) & 1)
        r = (r * x) % m;
    }

    b = 26;
  }

  return r;
}

/*
 * Multiplication
 */

function smallMulTo(self, num, out) {
  const len = self.length + num.length;

  out.negative = self.negative ^ num.negative;
  out._alloc(len);
  out.length = len;

  // Peel one iteration (compiler can't
  // do it, because of code complexity).
  const a = self.words[0];
  const b = num.words[0];
  const r = a * b;
  const lo = r & 0x3ffffff;

  let carry = (r / 0x4000000) | 0;
  let k = 1;

  out.words[0] = lo;

  for (; k < out.length - 1; k++) {
    // Sum all words with the same
    // `i + j = k` and accumulate
    // `ncarry`, note that ncarry
    // could be >= 0x3ffffff.
    let ncarry = carry >>> 26;
    let rword = carry & 0x3ffffff;

    const min = Math.max(0, k - self.length + 1);
    const max = Math.min(k, num.length - 1);

    for (let j = min; j <= max; j++) {
      const i = k - j;
      const a = self.words[i];
      const b = num.words[j];
      const r = a * b + rword;

      ncarry += (r / 0x4000000) | 0;
      rword = r & 0x3ffffff;
    }

    out.words[k] = rword | 0;
    carry = ncarry | 0;
  }

  if (carry !== 0)
    out.words[k] = carry | 0;
  else
    out.length -= 1;

  return out._strip();
}

function bigMulTo(self, num, out) {
  const len = self.length + num.length;

  out.negative = self.negative ^ num.negative;
  out._alloc(len);
  out.length = len;

  let carry = 0;
  let hncarry = 0;
  let k = 0;

  for (; k < out.length - 1; k++) {
    // Sum all words with the same
    // `i + j = k` and accumulate
    // `ncarry`, note that ncarry
    // could be >= 0x3ffffff.
    let ncarry = hncarry;

    hncarry = 0;

    let rword = carry & 0x3ffffff;

    const min = Math.max(0, k - self.length + 1);
    const max = Math.min(k, num.length - 1);

    for (let j = min; j <= max; j++) {
      const i = k - j;
      const a = self.words[i];
      const b = num.words[j];
      const r = a * b;

      let lo = r & 0x3ffffff;

      ncarry = (ncarry + ((r / 0x4000000) | 0)) | 0;
      lo = (lo + rword) | 0;
      rword = lo & 0x3ffffff;
      ncarry = (ncarry + (lo >>> 26)) | 0;

      hncarry += ncarry >>> 26;
      ncarry &= 0x3ffffff;
    }

    out.words[k] = rword;
    carry = ncarry;
    ncarry = hncarry;
  }

  if (carry !== 0)
    out.words[k] = carry;
  else
    out.length -= 1;

  return out._strip();
}

function jumboMulTo(x, y, out) {
  // v8 has a 2147483519 bit max (~256mb).
  if (!HAS_BIGINT || x.length + y.length > 82595519)
    return bigMulTo(x, y, out);

  const zero = BigInt(0);
  const mask = BigInt(0x3ffffff);
  const shift = BigInt(26);

  let z = x.toBigInt() * y.toBigInt();

  const neg = (z < zero) | 0;

  if (neg)
    z = -z;

  let i = 0;

  while (z > zero) {
    out.words[i++] = Number(z & mask);
    z >>= shift;
  }

  if (i === 0)
    out.words[i++] = 0;

  out.length = i;
  out.negative = neg;

  return out;
}

function comb10MulTo(self, num, out) {
  const a = self.words;
  const b = num.words;
  const o = out.words;
  const a0 = a[0] | 0;
  const al0 = a0 & 0x1fff;
  const ah0 = a0 >>> 13;
  const a1 = a[1] | 0;
  const al1 = a1 & 0x1fff;
  const ah1 = a1 >>> 13;
  const a2 = a[2] | 0;
  const al2 = a2 & 0x1fff;
  const ah2 = a2 >>> 13;
  const a3 = a[3] | 0;
  const al3 = a3 & 0x1fff;
  const ah3 = a3 >>> 13;
  const a4 = a[4] | 0;
  const al4 = a4 & 0x1fff;
  const ah4 = a4 >>> 13;
  const a5 = a[5] | 0;
  const al5 = a5 & 0x1fff;
  const ah5 = a5 >>> 13;
  const a6 = a[6] | 0;
  const al6 = a6 & 0x1fff;
  const ah6 = a6 >>> 13;
  const a7 = a[7] | 0;
  const al7 = a7 & 0x1fff;
  const ah7 = a7 >>> 13;
  const a8 = a[8] | 0;
  const al8 = a8 & 0x1fff;
  const ah8 = a8 >>> 13;
  const a9 = a[9] | 0;
  const al9 = a9 & 0x1fff;
  const ah9 = a9 >>> 13;
  const b0 = b[0] | 0;
  const bl0 = b0 & 0x1fff;
  const bh0 = b0 >>> 13;
  const b1 = b[1] | 0;
  const bl1 = b1 & 0x1fff;
  const bh1 = b1 >>> 13;
  const b2 = b[2] | 0;
  const bl2 = b2 & 0x1fff;
  const bh2 = b2 >>> 13;
  const b3 = b[3] | 0;
  const bl3 = b3 & 0x1fff;
  const bh3 = b3 >>> 13;
  const b4 = b[4] | 0;
  const bl4 = b4 & 0x1fff;
  const bh4 = b4 >>> 13;
  const b5 = b[5] | 0;
  const bl5 = b5 & 0x1fff;
  const bh5 = b5 >>> 13;
  const b6 = b[6] | 0;
  const bl6 = b6 & 0x1fff;
  const bh6 = b6 >>> 13;
  const b7 = b[7] | 0;
  const bl7 = b7 & 0x1fff;
  const bh7 = b7 >>> 13;
  const b8 = b[8] | 0;
  const bl8 = b8 & 0x1fff;
  const bh8 = b8 >>> 13;
  const b9 = b[9] | 0;
  const bl9 = b9 & 0x1fff;
  const bh9 = b9 >>> 13;

  let c = 0;
  let lo, mid, hi;

  out.negative = self.negative ^ num.negative;
  out._alloc(20);
  out.length = 19;

  /* k = 0 */
  lo = Math.imul(al0, bl0);
  mid = Math.imul(al0, bh0);
  mid = (mid + Math.imul(ah0, bl0)) | 0;
  hi = Math.imul(ah0, bh0);

  let w0 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w0 >>> 26)) | 0;
  w0 &= 0x3ffffff;

  /* k = 1 */
  lo = Math.imul(al1, bl0);
  mid = Math.imul(al1, bh0);
  mid = (mid + Math.imul(ah1, bl0)) | 0;
  hi = Math.imul(ah1, bh0);
  lo = (lo + Math.imul(al0, bl1)) | 0;
  mid = (mid + Math.imul(al0, bh1)) | 0;
  mid = (mid + Math.imul(ah0, bl1)) | 0;
  hi = (hi + Math.imul(ah0, bh1)) | 0;

  let w1 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w1 >>> 26)) | 0;
  w1 &= 0x3ffffff;

  /* k = 2 */
  lo = Math.imul(al2, bl0);
  mid = Math.imul(al2, bh0);
  mid = (mid + Math.imul(ah2, bl0)) | 0;
  hi = Math.imul(ah2, bh0);
  lo = (lo + Math.imul(al1, bl1)) | 0;
  mid = (mid + Math.imul(al1, bh1)) | 0;
  mid = (mid + Math.imul(ah1, bl1)) | 0;
  hi = (hi + Math.imul(ah1, bh1)) | 0;
  lo = (lo + Math.imul(al0, bl2)) | 0;
  mid = (mid + Math.imul(al0, bh2)) | 0;
  mid = (mid + Math.imul(ah0, bl2)) | 0;
  hi = (hi + Math.imul(ah0, bh2)) | 0;

  let w2 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w2 >>> 26)) | 0;
  w2 &= 0x3ffffff;

  /* k = 3 */
  lo = Math.imul(al3, bl0);
  mid = Math.imul(al3, bh0);
  mid = (mid + Math.imul(ah3, bl0)) | 0;
  hi = Math.imul(ah3, bh0);
  lo = (lo + Math.imul(al2, bl1)) | 0;
  mid = (mid + Math.imul(al2, bh1)) | 0;
  mid = (mid + Math.imul(ah2, bl1)) | 0;
  hi = (hi + Math.imul(ah2, bh1)) | 0;
  lo = (lo + Math.imul(al1, bl2)) | 0;
  mid = (mid + Math.imul(al1, bh2)) | 0;
  mid = (mid + Math.imul(ah1, bl2)) | 0;
  hi = (hi + Math.imul(ah1, bh2)) | 0;
  lo = (lo + Math.imul(al0, bl3)) | 0;
  mid = (mid + Math.imul(al0, bh3)) | 0;
  mid = (mid + Math.imul(ah0, bl3)) | 0;
  hi = (hi + Math.imul(ah0, bh3)) | 0;

  let w3 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w3 >>> 26)) | 0;
  w3 &= 0x3ffffff;

  /* k = 4 */
  lo = Math.imul(al4, bl0);
  mid = Math.imul(al4, bh0);
  mid = (mid + Math.imul(ah4, bl0)) | 0;
  hi = Math.imul(ah4, bh0);
  lo = (lo + Math.imul(al3, bl1)) | 0;
  mid = (mid + Math.imul(al3, bh1)) | 0;
  mid = (mid + Math.imul(ah3, bl1)) | 0;
  hi = (hi + Math.imul(ah3, bh1)) | 0;
  lo = (lo + Math.imul(al2, bl2)) | 0;
  mid = (mid + Math.imul(al2, bh2)) | 0;
  mid = (mid + Math.imul(ah2, bl2)) | 0;
  hi = (hi + Math.imul(ah2, bh2)) | 0;
  lo = (lo + Math.imul(al1, bl3)) | 0;
  mid = (mid + Math.imul(al1, bh3)) | 0;
  mid = (mid + Math.imul(ah1, bl3)) | 0;
  hi = (hi + Math.imul(ah1, bh3)) | 0;
  lo = (lo + Math.imul(al0, bl4)) | 0;
  mid = (mid + Math.imul(al0, bh4)) | 0;
  mid = (mid + Math.imul(ah0, bl4)) | 0;
  hi = (hi + Math.imul(ah0, bh4)) | 0;

  let w4 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w4 >>> 26)) | 0;
  w4 &= 0x3ffffff;

  /* k = 5 */
  lo = Math.imul(al5, bl0);
  mid = Math.imul(al5, bh0);
  mid = (mid + Math.imul(ah5, bl0)) | 0;
  hi = Math.imul(ah5, bh0);
  lo = (lo + Math.imul(al4, bl1)) | 0;
  mid = (mid + Math.imul(al4, bh1)) | 0;
  mid = (mid + Math.imul(ah4, bl1)) | 0;
  hi = (hi + Math.imul(ah4, bh1)) | 0;
  lo = (lo + Math.imul(al3, bl2)) | 0;
  mid = (mid + Math.imul(al3, bh2)) | 0;
  mid = (mid + Math.imul(ah3, bl2)) | 0;
  hi = (hi + Math.imul(ah3, bh2)) | 0;
  lo = (lo + Math.imul(al2, bl3)) | 0;
  mid = (mid + Math.imul(al2, bh3)) | 0;
  mid = (mid + Math.imul(ah2, bl3)) | 0;
  hi = (hi + Math.imul(ah2, bh3)) | 0;
  lo = (lo + Math.imul(al1, bl4)) | 0;
  mid = (mid + Math.imul(al1, bh4)) | 0;
  mid = (mid + Math.imul(ah1, bl4)) | 0;
  hi = (hi + Math.imul(ah1, bh4)) | 0;
  lo = (lo + Math.imul(al0, bl5)) | 0;
  mid = (mid + Math.imul(al0, bh5)) | 0;
  mid = (mid + Math.imul(ah0, bl5)) | 0;
  hi = (hi + Math.imul(ah0, bh5)) | 0;

  let w5 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w5 >>> 26)) | 0;
  w5 &= 0x3ffffff;

  /* k = 6 */
  lo = Math.imul(al6, bl0);
  mid = Math.imul(al6, bh0);
  mid = (mid + Math.imul(ah6, bl0)) | 0;
  hi = Math.imul(ah6, bh0);
  lo = (lo + Math.imul(al5, bl1)) | 0;
  mid = (mid + Math.imul(al5, bh1)) | 0;
  mid = (mid + Math.imul(ah5, bl1)) | 0;
  hi = (hi + Math.imul(ah5, bh1)) | 0;
  lo = (lo + Math.imul(al4, bl2)) | 0;
  mid = (mid + Math.imul(al4, bh2)) | 0;
  mid = (mid + Math.imul(ah4, bl2)) | 0;
  hi = (hi + Math.imul(ah4, bh2)) | 0;
  lo = (lo + Math.imul(al3, bl3)) | 0;
  mid = (mid + Math.imul(al3, bh3)) | 0;
  mid = (mid + Math.imul(ah3, bl3)) | 0;
  hi = (hi + Math.imul(ah3, bh3)) | 0;
  lo = (lo + Math.imul(al2, bl4)) | 0;
  mid = (mid + Math.imul(al2, bh4)) | 0;
  mid = (mid + Math.imul(ah2, bl4)) | 0;
  hi = (hi + Math.imul(ah2, bh4)) | 0;
  lo = (lo + Math.imul(al1, bl5)) | 0;
  mid = (mid + Math.imul(al1, bh5)) | 0;
  mid = (mid + Math.imul(ah1, bl5)) | 0;
  hi = (hi + Math.imul(ah1, bh5)) | 0;
  lo = (lo + Math.imul(al0, bl6)) | 0;
  mid = (mid + Math.imul(al0, bh6)) | 0;
  mid = (mid + Math.imul(ah0, bl6)) | 0;
  hi = (hi + Math.imul(ah0, bh6)) | 0;

  let w6 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w6 >>> 26)) | 0;
  w6 &= 0x3ffffff;

  /* k = 7 */
  lo = Math.imul(al7, bl0);
  mid = Math.imul(al7, bh0);
  mid = (mid + Math.imul(ah7, bl0)) | 0;
  hi = Math.imul(ah7, bh0);
  lo = (lo + Math.imul(al6, bl1)) | 0;
  mid = (mid + Math.imul(al6, bh1)) | 0;
  mid = (mid + Math.imul(ah6, bl1)) | 0;
  hi = (hi + Math.imul(ah6, bh1)) | 0;
  lo = (lo + Math.imul(al5, bl2)) | 0;
  mid = (mid + Math.imul(al5, bh2)) | 0;
  mid = (mid + Math.imul(ah5, bl2)) | 0;
  hi = (hi + Math.imul(ah5, bh2)) | 0;
  lo = (lo + Math.imul(al4, bl3)) | 0;
  mid = (mid + Math.imul(al4, bh3)) | 0;
  mid = (mid + Math.imul(ah4, bl3)) | 0;
  hi = (hi + Math.imul(ah4, bh3)) | 0;
  lo = (lo + Math.imul(al3, bl4)) | 0;
  mid = (mid + Math.imul(al3, bh4)) | 0;
  mid = (mid + Math.imul(ah3, bl4)) | 0;
  hi = (hi + Math.imul(ah3, bh4)) | 0;
  lo = (lo + Math.imul(al2, bl5)) | 0;
  mid = (mid + Math.imul(al2, bh5)) | 0;
  mid = (mid + Math.imul(ah2, bl5)) | 0;
  hi = (hi + Math.imul(ah2, bh5)) | 0;
  lo = (lo + Math.imul(al1, bl6)) | 0;
  mid = (mid + Math.imul(al1, bh6)) | 0;
  mid = (mid + Math.imul(ah1, bl6)) | 0;
  hi = (hi + Math.imul(ah1, bh6)) | 0;
  lo = (lo + Math.imul(al0, bl7)) | 0;
  mid = (mid + Math.imul(al0, bh7)) | 0;
  mid = (mid + Math.imul(ah0, bl7)) | 0;
  hi = (hi + Math.imul(ah0, bh7)) | 0;

  let w7 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w7 >>> 26)) | 0;
  w7 &= 0x3ffffff;

  /* k = 8 */
  lo = Math.imul(al8, bl0);
  mid = Math.imul(al8, bh0);
  mid = (mid + Math.imul(ah8, bl0)) | 0;
  hi = Math.imul(ah8, bh0);
  lo = (lo + Math.imul(al7, bl1)) | 0;
  mid = (mid + Math.imul(al7, bh1)) | 0;
  mid = (mid + Math.imul(ah7, bl1)) | 0;
  hi = (hi + Math.imul(ah7, bh1)) | 0;
  lo = (lo + Math.imul(al6, bl2)) | 0;
  mid = (mid + Math.imul(al6, bh2)) | 0;
  mid = (mid + Math.imul(ah6, bl2)) | 0;
  hi = (hi + Math.imul(ah6, bh2)) | 0;
  lo = (lo + Math.imul(al5, bl3)) | 0;
  mid = (mid + Math.imul(al5, bh3)) | 0;
  mid = (mid + Math.imul(ah5, bl3)) | 0;
  hi = (hi + Math.imul(ah5, bh3)) | 0;
  lo = (lo + Math.imul(al4, bl4)) | 0;
  mid = (mid + Math.imul(al4, bh4)) | 0;
  mid = (mid + Math.imul(ah4, bl4)) | 0;
  hi = (hi + Math.imul(ah4, bh4)) | 0;
  lo = (lo + Math.imul(al3, bl5)) | 0;
  mid = (mid + Math.imul(al3, bh5)) | 0;
  mid = (mid + Math.imul(ah3, bl5)) | 0;
  hi = (hi + Math.imul(ah3, bh5)) | 0;
  lo = (lo + Math.imul(al2, bl6)) | 0;
  mid = (mid + Math.imul(al2, bh6)) | 0;
  mid = (mid + Math.imul(ah2, bl6)) | 0;
  hi = (hi + Math.imul(ah2, bh6)) | 0;
  lo = (lo + Math.imul(al1, bl7)) | 0;
  mid = (mid + Math.imul(al1, bh7)) | 0;
  mid = (mid + Math.imul(ah1, bl7)) | 0;
  hi = (hi + Math.imul(ah1, bh7)) | 0;
  lo = (lo + Math.imul(al0, bl8)) | 0;
  mid = (mid + Math.imul(al0, bh8)) | 0;
  mid = (mid + Math.imul(ah0, bl8)) | 0;
  hi = (hi + Math.imul(ah0, bh8)) | 0;

  let w8 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w8 >>> 26)) | 0;
  w8 &= 0x3ffffff;

  /* k = 9 */
  lo = Math.imul(al9, bl0);
  mid = Math.imul(al9, bh0);
  mid = (mid + Math.imul(ah9, bl0)) | 0;
  hi = Math.imul(ah9, bh0);
  lo = (lo + Math.imul(al8, bl1)) | 0;
  mid = (mid + Math.imul(al8, bh1)) | 0;
  mid = (mid + Math.imul(ah8, bl1)) | 0;
  hi = (hi + Math.imul(ah8, bh1)) | 0;
  lo = (lo + Math.imul(al7, bl2)) | 0;
  mid = (mid + Math.imul(al7, bh2)) | 0;
  mid = (mid + Math.imul(ah7, bl2)) | 0;
  hi = (hi + Math.imul(ah7, bh2)) | 0;
  lo = (lo + Math.imul(al6, bl3)) | 0;
  mid = (mid + Math.imul(al6, bh3)) | 0;
  mid = (mid + Math.imul(ah6, bl3)) | 0;
  hi = (hi + Math.imul(ah6, bh3)) | 0;
  lo = (lo + Math.imul(al5, bl4)) | 0;
  mid = (mid + Math.imul(al5, bh4)) | 0;
  mid = (mid + Math.imul(ah5, bl4)) | 0;
  hi = (hi + Math.imul(ah5, bh4)) | 0;
  lo = (lo + Math.imul(al4, bl5)) | 0;
  mid = (mid + Math.imul(al4, bh5)) | 0;
  mid = (mid + Math.imul(ah4, bl5)) | 0;
  hi = (hi + Math.imul(ah4, bh5)) | 0;
  lo = (lo + Math.imul(al3, bl6)) | 0;
  mid = (mid + Math.imul(al3, bh6)) | 0;
  mid = (mid + Math.imul(ah3, bl6)) | 0;
  hi = (hi + Math.imul(ah3, bh6)) | 0;
  lo = (lo + Math.imul(al2, bl7)) | 0;
  mid = (mid + Math.imul(al2, bh7)) | 0;
  mid = (mid + Math.imul(ah2, bl7)) | 0;
  hi = (hi + Math.imul(ah2, bh7)) | 0;
  lo = (lo + Math.imul(al1, bl8)) | 0;
  mid = (mid + Math.imul(al1, bh8)) | 0;
  mid = (mid + Math.imul(ah1, bl8)) | 0;
  hi = (hi + Math.imul(ah1, bh8)) | 0;
  lo = (lo + Math.imul(al0, bl9)) | 0;
  mid = (mid + Math.imul(al0, bh9)) | 0;
  mid = (mid + Math.imul(ah0, bl9)) | 0;
  hi = (hi + Math.imul(ah0, bh9)) | 0;

  let w9 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w9 >>> 26)) | 0;
  w9 &= 0x3ffffff;

  /* k = 10 */
  lo = Math.imul(al9, bl1);
  mid = Math.imul(al9, bh1);
  mid = (mid + Math.imul(ah9, bl1)) | 0;
  hi = Math.imul(ah9, bh1);
  lo = (lo + Math.imul(al8, bl2)) | 0;
  mid = (mid + Math.imul(al8, bh2)) | 0;
  mid = (mid + Math.imul(ah8, bl2)) | 0;
  hi = (hi + Math.imul(ah8, bh2)) | 0;
  lo = (lo + Math.imul(al7, bl3)) | 0;
  mid = (mid + Math.imul(al7, bh3)) | 0;
  mid = (mid + Math.imul(ah7, bl3)) | 0;
  hi = (hi + Math.imul(ah7, bh3)) | 0;
  lo = (lo + Math.imul(al6, bl4)) | 0;
  mid = (mid + Math.imul(al6, bh4)) | 0;
  mid = (mid + Math.imul(ah6, bl4)) | 0;
  hi = (hi + Math.imul(ah6, bh4)) | 0;
  lo = (lo + Math.imul(al5, bl5)) | 0;
  mid = (mid + Math.imul(al5, bh5)) | 0;
  mid = (mid + Math.imul(ah5, bl5)) | 0;
  hi = (hi + Math.imul(ah5, bh5)) | 0;
  lo = (lo + Math.imul(al4, bl6)) | 0;
  mid = (mid + Math.imul(al4, bh6)) | 0;
  mid = (mid + Math.imul(ah4, bl6)) | 0;
  hi = (hi + Math.imul(ah4, bh6)) | 0;
  lo = (lo + Math.imul(al3, bl7)) | 0;
  mid = (mid + Math.imul(al3, bh7)) | 0;
  mid = (mid + Math.imul(ah3, bl7)) | 0;
  hi = (hi + Math.imul(ah3, bh7)) | 0;
  lo = (lo + Math.imul(al2, bl8)) | 0;
  mid = (mid + Math.imul(al2, bh8)) | 0;
  mid = (mid + Math.imul(ah2, bl8)) | 0;
  hi = (hi + Math.imul(ah2, bh8)) | 0;
  lo = (lo + Math.imul(al1, bl9)) | 0;
  mid = (mid + Math.imul(al1, bh9)) | 0;
  mid = (mid + Math.imul(ah1, bl9)) | 0;
  hi = (hi + Math.imul(ah1, bh9)) | 0;

  let w10 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w10 >>> 26)) | 0;
  w10 &= 0x3ffffff;

  /* k = 11 */
  lo = Math.imul(al9, bl2);
  mid = Math.imul(al9, bh2);
  mid = (mid + Math.imul(ah9, bl2)) | 0;
  hi = Math.imul(ah9, bh2);
  lo = (lo + Math.imul(al8, bl3)) | 0;
  mid = (mid + Math.imul(al8, bh3)) | 0;
  mid = (mid + Math.imul(ah8, bl3)) | 0;
  hi = (hi + Math.imul(ah8, bh3)) | 0;
  lo = (lo + Math.imul(al7, bl4)) | 0;
  mid = (mid + Math.imul(al7, bh4)) | 0;
  mid = (mid + Math.imul(ah7, bl4)) | 0;
  hi = (hi + Math.imul(ah7, bh4)) | 0;
  lo = (lo + Math.imul(al6, bl5)) | 0;
  mid = (mid + Math.imul(al6, bh5)) | 0;
  mid = (mid + Math.imul(ah6, bl5)) | 0;
  hi = (hi + Math.imul(ah6, bh5)) | 0;
  lo = (lo + Math.imul(al5, bl6)) | 0;
  mid = (mid + Math.imul(al5, bh6)) | 0;
  mid = (mid + Math.imul(ah5, bl6)) | 0;
  hi = (hi + Math.imul(ah5, bh6)) | 0;
  lo = (lo + Math.imul(al4, bl7)) | 0;
  mid = (mid + Math.imul(al4, bh7)) | 0;
  mid = (mid + Math.imul(ah4, bl7)) | 0;
  hi = (hi + Math.imul(ah4, bh7)) | 0;
  lo = (lo + Math.imul(al3, bl8)) | 0;
  mid = (mid + Math.imul(al3, bh8)) | 0;
  mid = (mid + Math.imul(ah3, bl8)) | 0;
  hi = (hi + Math.imul(ah3, bh8)) | 0;
  lo = (lo + Math.imul(al2, bl9)) | 0;
  mid = (mid + Math.imul(al2, bh9)) | 0;
  mid = (mid + Math.imul(ah2, bl9)) | 0;
  hi = (hi + Math.imul(ah2, bh9)) | 0;

  let w11 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w11 >>> 26)) | 0;
  w11 &= 0x3ffffff;

  /* k = 12 */
  lo = Math.imul(al9, bl3);
  mid = Math.imul(al9, bh3);
  mid = (mid + Math.imul(ah9, bl3)) | 0;
  hi = Math.imul(ah9, bh3);
  lo = (lo + Math.imul(al8, bl4)) | 0;
  mid = (mid + Math.imul(al8, bh4)) | 0;
  mid = (mid + Math.imul(ah8, bl4)) | 0;
  hi = (hi + Math.imul(ah8, bh4)) | 0;
  lo = (lo + Math.imul(al7, bl5)) | 0;
  mid = (mid + Math.imul(al7, bh5)) | 0;
  mid = (mid + Math.imul(ah7, bl5)) | 0;
  hi = (hi + Math.imul(ah7, bh5)) | 0;
  lo = (lo + Math.imul(al6, bl6)) | 0;
  mid = (mid + Math.imul(al6, bh6)) | 0;
  mid = (mid + Math.imul(ah6, bl6)) | 0;
  hi = (hi + Math.imul(ah6, bh6)) | 0;
  lo = (lo + Math.imul(al5, bl7)) | 0;
  mid = (mid + Math.imul(al5, bh7)) | 0;
  mid = (mid + Math.imul(ah5, bl7)) | 0;
  hi = (hi + Math.imul(ah5, bh7)) | 0;
  lo = (lo + Math.imul(al4, bl8)) | 0;
  mid = (mid + Math.imul(al4, bh8)) | 0;
  mid = (mid + Math.imul(ah4, bl8)) | 0;
  hi = (hi + Math.imul(ah4, bh8)) | 0;
  lo = (lo + Math.imul(al3, bl9)) | 0;
  mid = (mid + Math.imul(al3, bh9)) | 0;
  mid = (mid + Math.imul(ah3, bl9)) | 0;
  hi = (hi + Math.imul(ah3, bh9)) | 0;

  let w12 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w12 >>> 26)) | 0;
  w12 &= 0x3ffffff;

  /* k = 13 */
  lo = Math.imul(al9, bl4);
  mid = Math.imul(al9, bh4);
  mid = (mid + Math.imul(ah9, bl4)) | 0;
  hi = Math.imul(ah9, bh4);
  lo = (lo + Math.imul(al8, bl5)) | 0;
  mid = (mid + Math.imul(al8, bh5)) | 0;
  mid = (mid + Math.imul(ah8, bl5)) | 0;
  hi = (hi + Math.imul(ah8, bh5)) | 0;
  lo = (lo + Math.imul(al7, bl6)) | 0;
  mid = (mid + Math.imul(al7, bh6)) | 0;
  mid = (mid + Math.imul(ah7, bl6)) | 0;
  hi = (hi + Math.imul(ah7, bh6)) | 0;
  lo = (lo + Math.imul(al6, bl7)) | 0;
  mid = (mid + Math.imul(al6, bh7)) | 0;
  mid = (mid + Math.imul(ah6, bl7)) | 0;
  hi = (hi + Math.imul(ah6, bh7)) | 0;
  lo = (lo + Math.imul(al5, bl8)) | 0;
  mid = (mid + Math.imul(al5, bh8)) | 0;
  mid = (mid + Math.imul(ah5, bl8)) | 0;
  hi = (hi + Math.imul(ah5, bh8)) | 0;
  lo = (lo + Math.imul(al4, bl9)) | 0;
  mid = (mid + Math.imul(al4, bh9)) | 0;
  mid = (mid + Math.imul(ah4, bl9)) | 0;
  hi = (hi + Math.imul(ah4, bh9)) | 0;

  let w13 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w13 >>> 26)) | 0;
  w13 &= 0x3ffffff;

  /* k = 14 */
  lo = Math.imul(al9, bl5);
  mid = Math.imul(al9, bh5);
  mid = (mid + Math.imul(ah9, bl5)) | 0;
  hi = Math.imul(ah9, bh5);
  lo = (lo + Math.imul(al8, bl6)) | 0;
  mid = (mid + Math.imul(al8, bh6)) | 0;
  mid = (mid + Math.imul(ah8, bl6)) | 0;
  hi = (hi + Math.imul(ah8, bh6)) | 0;
  lo = (lo + Math.imul(al7, bl7)) | 0;
  mid = (mid + Math.imul(al7, bh7)) | 0;
  mid = (mid + Math.imul(ah7, bl7)) | 0;
  hi = (hi + Math.imul(ah7, bh7)) | 0;
  lo = (lo + Math.imul(al6, bl8)) | 0;
  mid = (mid + Math.imul(al6, bh8)) | 0;
  mid = (mid + Math.imul(ah6, bl8)) | 0;
  hi = (hi + Math.imul(ah6, bh8)) | 0;
  lo = (lo + Math.imul(al5, bl9)) | 0;
  mid = (mid + Math.imul(al5, bh9)) | 0;
  mid = (mid + Math.imul(ah5, bl9)) | 0;
  hi = (hi + Math.imul(ah5, bh9)) | 0;

  let w14 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w14 >>> 26)) | 0;
  w14 &= 0x3ffffff;

  /* k = 15 */
  lo = Math.imul(al9, bl6);
  mid = Math.imul(al9, bh6);
  mid = (mid + Math.imul(ah9, bl6)) | 0;
  hi = Math.imul(ah9, bh6);
  lo = (lo + Math.imul(al8, bl7)) | 0;
  mid = (mid + Math.imul(al8, bh7)) | 0;
  mid = (mid + Math.imul(ah8, bl7)) | 0;
  hi = (hi + Math.imul(ah8, bh7)) | 0;
  lo = (lo + Math.imul(al7, bl8)) | 0;
  mid = (mid + Math.imul(al7, bh8)) | 0;
  mid = (mid + Math.imul(ah7, bl8)) | 0;
  hi = (hi + Math.imul(ah7, bh8)) | 0;
  lo = (lo + Math.imul(al6, bl9)) | 0;
  mid = (mid + Math.imul(al6, bh9)) | 0;
  mid = (mid + Math.imul(ah6, bl9)) | 0;
  hi = (hi + Math.imul(ah6, bh9)) | 0;

  let w15 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w15 >>> 26)) | 0;
  w15 &= 0x3ffffff;

  /* k = 16 */
  lo = Math.imul(al9, bl7);
  mid = Math.imul(al9, bh7);
  mid = (mid + Math.imul(ah9, bl7)) | 0;
  hi = Math.imul(ah9, bh7);
  lo = (lo + Math.imul(al8, bl8)) | 0;
  mid = (mid + Math.imul(al8, bh8)) | 0;
  mid = (mid + Math.imul(ah8, bl8)) | 0;
  hi = (hi + Math.imul(ah8, bh8)) | 0;
  lo = (lo + Math.imul(al7, bl9)) | 0;
  mid = (mid + Math.imul(al7, bh9)) | 0;
  mid = (mid + Math.imul(ah7, bl9)) | 0;
  hi = (hi + Math.imul(ah7, bh9)) | 0;

  let w16 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w16 >>> 26)) | 0;
  w16 &= 0x3ffffff;

  /* k = 17 */
  lo = Math.imul(al9, bl8);
  mid = Math.imul(al9, bh8);
  mid = (mid + Math.imul(ah9, bl8)) | 0;
  hi = Math.imul(ah9, bh8);
  lo = (lo + Math.imul(al8, bl9)) | 0;
  mid = (mid + Math.imul(al8, bh9)) | 0;
  mid = (mid + Math.imul(ah8, bl9)) | 0;
  hi = (hi + Math.imul(ah8, bh9)) | 0;

  let w17 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w17 >>> 26)) | 0;
  w17 &= 0x3ffffff;

  /* k = 18 */
  lo = Math.imul(al9, bl9);
  mid = Math.imul(al9, bh9);
  mid = (mid + Math.imul(ah9, bl9)) | 0;
  hi = Math.imul(ah9, bh9);

  let w18 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w18 >>> 26)) | 0;
  w18 &= 0x3ffffff;

  o[0] = w0;
  o[1] = w1;
  o[2] = w2;
  o[3] = w3;
  o[4] = w4;
  o[5] = w5;
  o[6] = w6;
  o[7] = w7;
  o[8] = w8;
  o[9] = w9;
  o[10] = w10;
  o[11] = w11;
  o[12] = w12;
  o[13] = w13;
  o[14] = w14;
  o[15] = w15;
  o[16] = w16;
  o[17] = w17;
  o[18] = w18;

  if (c !== 0) {
    o[19] = c;
    out.length += 1;
  }

  // Note: we shouldn't need to strip here.
  return out;
}

// Polyfill comb.
if (!Math.imul)
  comb10MulTo = smallMulTo;

/*
 * Expose
 */

module.exports = BN;
