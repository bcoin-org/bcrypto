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

'use strict';

const {custom} = require('./internal/custom');

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
  0, 0,
  25, 16, 12, 11, 10, 9, 8,
  8, 7, 7, 7, 7, 6, 6,
  6, 6, 6, 6, 6, 5, 5,
  5, 5, 5, 5, 5, 5, 5,
  5, 5, 5, 5, 5, 5, 5
];

const groupBases = [
  0, 0,
  33554432, 43046721, 16777216, 48828125, 60466176, 40353607, 16777216,
  43046721, 10000000, 19487171, 35831808, 62748517, 7529536, 11390625,
  16777216, 24137569, 34012224, 47045881, 64000000, 4084101, 5153632,
  6436343, 7962624, 9765625, 11881376, 14348907, 17210368, 20511149,
  24300000, 28629151, 33554432, 39135393, 45435424, 52521875, 60466176
];

// Prime numbers with efficient reduction
const primes = {
  k256: null,
  p224: null,
  p192: null,
  p25519: null
};

/**
 * BN
 */

class BN {
  constructor(number, base, endian) {
    if (BN.isBN(number))
      return number;

    this.negative = 0;
    this.words = null;
    this.length = 0;

    // Reduction context
    this.red = null;

    if (number !== null) {
      if (base === 'le' || base === 'be') {
        endian = base;
        base = 10;
      }

      this._init(number || 0, base || 10, endian || 'be');
    }
  }

  _init(number, base, endian) {
    if (typeof number === 'number')
      return this._initNumber(number, base, endian);

    if (typeof number === 'object')
      return this._initArray(number, base, endian);

    if (base === 'hex')
      base = 16;

    assert(base === (base | 0) && base >= 2 && base <= 36);

    number = number.toString().replace(/\s+/g, '');

    let start = 0;

    if (number[0] === '-')
      start++;

    if (base === 16)
      this._parseHex(number, start);
    else
      this._parseBase(number, base, start);

    if (number[0] === '-')
      this.negative = 1;

    this._strip();

    if (endian !== 'le')
      return undefined;

    return this._initArray(this.toArray(), base, endian);
  }

  _initNumber(number, base, endian) {
    if (number < 0) {
      this.negative = 1;
      number = -number;
    }

    if (number < 0x4000000) {
      this.words = [number & 0x3ffffff];
      this.length = 1;
    } else if (number < 0x10000000000000) {
      this.words = [
        number & 0x3ffffff,
        (number / 0x4000000) & 0x3ffffff
      ];
      this.length = 2;
    } else {
      assert(number < 0x20000000000000); // 2 ^ 53 (unsafe)
      this.words = [
        number & 0x3ffffff,
        (number / 0x4000000) & 0x3ffffff,
        1
      ];
      this.length = 3;
    }

    if (endian !== 'le')
      return;

    // Reverse the bytes
    this._initArray(this.toArray(), base, endian);
  }

  _initArray(number, base, endian) {
    // Perhaps a Uint8Array
    assert(typeof number.length === 'number');

    if (number.length <= 0) {
      this.words = [0];
      this.length = 1;
      return this;
    }

    this.length = Math.ceil(number.length / 3);
    this.words = new Array(this.length);

    for (let i = 0; i < this.length; i++)
      this.words[i] = 0;

    let off = 0;

    if (endian === 'be') {
      for (let i = number.length - 1, j = 0; i >= 0; i -= 3) {
        const w = number[i] | (number[i - 1] << 8) | (number[i - 2] << 16);

        this.words[j] |= (w << off) & 0x3ffffff;
        this.words[j + 1] = (w >>> (26 - off)) & 0x3ffffff;

        off += 24;

        if (off >= 26) {
          off -= 26;
          j++;
        }
      }
    } else if (endian === 'le') {
      for (let i = 0, j = 0; i < number.length; i += 3) {
        const w = number[i] | (number[i + 1] << 8) | (number[i + 2] << 16);

        this.words[j] |= (w << off) & 0x3ffffff;
        this.words[j + 1] = (w >>> (26 - off)) & 0x3ffffff;

        off += 24;

        if (off >= 26) {
          off -= 26;
          j++;
        }
      }
    }

    return this._strip();
  }

  _parseHex(number, start) {
    // Create possibly bigger array to ensure that it fits the number
    this.length = Math.ceil((number.length - start) / 6);
    this.words = new Array(this.length);

    for (let i = 0; i < this.length; i++)
      this.words[i] = 0;

    // Scan 24-bit chunks and add them to the number
    let off = 0;
    let i = number.length - 6;
    let j = 0;

    for (; i >= start; i -= 6) {
      const w = parseHex(number, i, i + 6);

      this.words[j] |= (w << off) & 0x3ffffff;
      // NOTE: `0x3fffff` is intentional here, 26bits max shift + 24bit hex limb
      this.words[j + 1] |= w >>> (26 - off) & 0x3fffff;

      off += 24;

      if (off >= 26) {
        off -= 26;
        j++;
      }
    }

    if (i + 6 !== start) {
      const w = parseHex(number, start, i + 6);

      this.words[j] |= (w << off) & 0x3ffffff;
      this.words[j + 1] |= w >>> (26 - off) & 0x3fffff;
    }

    this._strip();
  }

  _parseBase(number, base, start) {
    // Initialize as zero
    this.words = [0];
    this.length = 1;

    // Find length of limb in base
    let limbLen = 0;
    let limbPow = 1;

    for (; limbPow <= 0x3ffffff; limbPow *= base)
      limbLen++;

    limbLen--;
    limbPow = (limbPow / base) | 0;

    const total = number.length - start;
    const mod = total % limbLen;
    const end = Math.min(total, total - mod) + start;

    let word = 0;
    let i = start;

    for (; i < end; i += limbLen) {
      word = parseBase(number, i, i + limbLen, base);

      this.imuln(limbPow);

      if (this.words[0] + word < 0x4000000)
        this.words[0] += word;
      else
        this._iaddn(word);
    }

    if (mod !== 0) {
      let pow = 1;

      word = parseBase(number, i, number.length, base);

      for (i = 0; i < mod; i++)
        pow *= base;

      this.imuln(pow);

      if (this.words[0] + word < 0x4000000)
        this.words[0] += word;
      else
        this._iaddn(word);
    }
  }

  copy(dest) {
    dest.words = new Array(this.length);

    for (let i = 0; i < this.length; i++)
      dest.words[i] = this.words[i];

    dest.length = this.length;
    dest.negative = this.negative;
    dest.red = this.red;
  }

  _move(dest) {
    dest.words = this.words;
    dest.length = this.length;
    dest.negative = this.negative;
    dest.red = this.red;
  }

  clone() {
    const r = new BN(null);

    this.copy(r);

    return r;
  }

  _expand(size) {
    while (this.length < size)
      this.words[this.length++] = 0;

    return this;
  }

  // Remove leading `0` from `this`
  _strip() {
    while (this.length > 1 && this.words[this.length - 1] === 0)
      this.length--;

    return this._normSign();
  }

  _normSign() {
    // -0 = 0
    if (this.length === 1 && this.words[0] === 0)
      this.negative = 0;

    return this;
  }

  toString(base, padding) {
    base = base || 10;
    padding = padding | 0 || 1;

    if (base === 16 || base === 'hex') {
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
          i--;
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

    if (base === (base | 0) && base >= 2 && base <= 36) {
      let out = '';

      // const groupSize = Math.floor(BN.wordSize * Math.LN2 / Math.log(base));
      const groupSize = groupSizes[base];

      // const groupBase = Math.pow(base, groupSize);
      const groupBase = groupBases[base];

      let c = this.clone();

      c.negative = 0;

      while (!c.isZero()) {
        const r = c.modrn(groupBase).toString(base);

        c = c.idivn(groupBase);

        if (!c.isZero())
          out = zeros[groupSize - r.length] + r + out;
        else
          out = r + out;
      }

      if (this.isZero())
        out = '0' + out;

      while (out.length % padding !== 0)
        out = '0' + out;

      if (this.negative !== 0)
        out = '-' + out;

      return out;
    }

    throw new Error('Base should be between 2 and 36');
  }

  toNumber() {
    let ret = this.words[0];

    if (this.length === 2) {
      ret += this.words[1] * 0x4000000;
    } else if (this.length === 3 && this.words[2] === 0x01) {
      // NOTE: at this stage it is known that the top bit is set
      ret += 0x10000000000000 + (this.words[1] * 0x4000000);
    } else if (this.length > 2) {
      assert(false, 'Number can only safely store up to 53 bits');
    }

    return (this.negative !== 0) ? -ret : ret;
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

    this._strip();

    const littleEndian = endian === 'le';
    const res = allocate(ArrayType, reqLength);
    const q = this.clone();

    if (!littleEndian) {
      // Assume big-endian
      for (let i = 0; i < reqLength - byteLength; i++)
        res[i] = 0;

      for (let i = 0; !q.isZero(); i++) {
        const b = q.andln(0xff);

        q.iushrn(8);

        res[reqLength - i - 1] = b;
      }
    } else {
      let i = 0;

      for (; !q.isZero(); i++) {
        const b = q.andln(0xff);

        q.iushrn(8);

        res[i] = b;
      }

      for (; i < reqLength; i++)
        res[i] = 0;
    }

    return res;
  }

  _countBits(w) {
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

  _zeroBits(w) {
    // Short-cut
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
      r++;

    return r;
  }

  // Return number of used bits in a BN
  bitLength() {
    const w = this.words[this.length - 1];
    const hi = this._countBits(w);
    return (this.length - 1) * 26 + hi;
  }

  // Number of trailing zero bits
  zeroBits() {
    if (this.isZero())
      return 0;

    let r = 0;

    for (let i = 0; i < this.length; i++) {
      const b = this._zeroBits(this.words[i]);

      r += b;

      if (b !== 26)
        break;
    }

    return r;
  }

  byteLength() {
    return Math.ceil(this.bitLength() / 8);
  }

  toTwos(width) {
    if (this.negative !== 0)
      return this.abs().inotn(width).iaddn(1);

    return this.clone();
  }

  fromTwos(width) {
    if (this.testn(width - 1))
      return this.notn(width).iaddn(1).ineg();

    return this.clone();
  }

  isNeg() {
    return this.negative !== 0;
  }

  // Return negative clone of `this`
  neg() {
    return this.clone().ineg();
  }

  ineg() {
    if (!this.isZero())
      this.negative ^= 1;

    return this;
  }

  // Or `num` with `this` in-place
  iuor(num) {
    while (this.length < num.length)
      this.words[this.length++] = 0;

    for (let i = 0; i < num.length; i++)
      this.words[i] = this.words[i] | num.words[i];

    return this._strip();
  }

  ior(num) {
    assert((this.negative | num.negative) === 0);
    return this.iuor(num);
  }

  // Or `num` with `this`
  or(num) {
    if (this.length > num.length)
      return this.clone().ior(num);

    return num.clone().ior(this);
  }

  uor(num) {
    if (this.length > num.length)
      return this.clone().iuor(num);

    return num.clone().iuor(this);
  }

  // And `num` with `this` in-place
  iuand(num) {
    // b = min-length(num, this)
    let b;

    if (this.length > num.length)
      b = num;
    else
      b = this;

    for (let i = 0; i < b.length; i++)
      this.words[i] = this.words[i] & num.words[i];

    this.length = b.length;

    return this._strip();
  }

  iand(num) {
    assert((this.negative | num.negative) === 0);
    return this.iuand(num);
  }

  // And `num` with `this`
  and(num) {
    if (this.length > num.length)
      return this.clone().iand(num);

    return num.clone().iand(this);
  }

  uand(num) {
    if (this.length > num.length)
      return this.clone().iuand(num);

    return num.clone().iuand(this);
  }

  // Xor `num` with `this` in-place
  iuxor(num) {
    // a.length > b.length
    let i = 0;
    let a;
    let b;

    if (this.length > num.length) {
      a = this;
      b = num;
    } else {
      a = num;
      b = this;
    }

    for (; i < b.length; i++)
      this.words[i] = a.words[i] ^ b.words[i];

    if (this !== a) {
      for (; i < a.length; i++) {
        this.words[i] = a.words[i];
      }
    }

    this.length = a.length;

    return this._strip();
  }

  ixor(num) {
    assert((this.negative | num.negative) === 0);
    return this.iuxor(num);
  }

  // Xor `num` with `this`
  xor(num) {
    if (this.length > num.length)
      return this.clone().ixor(num);

    return num.clone().ixor(this);
  }

  uxor(num) {
    if (this.length > num.length)
      return this.clone().iuxor(num);

    return num.clone().iuxor(this);
  }

  // Not ``this`` with ``width`` bitwidth
  inotn(width) {
    assert(typeof width === 'number' && width >= 0);

    const bitsLeft = width % 26;

    let bytesNeeded = Math.ceil(width / 26) | 0;
    let i = 0;

    // Extend the buffer with leading zeroes
    this._expand(bytesNeeded);

    if (bitsLeft > 0)
      bytesNeeded--;

    // Handle complete words
    for (; i < bytesNeeded; i++)
      this.words[i] = ~this.words[i] & 0x3ffffff;

    // Handle the residue
    if (bitsLeft > 0)
      this.words[i] = ~this.words[i] & (0x3ffffff >> (26 - bitsLeft));

    // And remove leading zeroes
    return this._strip();
  }

  notn(width) {
    return this.clone().inotn(width);
  }

  // Set `bit` of `this`
  setn(bit, val) {
    assert(typeof bit === 'number' && bit >= 0);

    const off = (bit / 26) | 0;
    const wbit = bit % 26;

    this._expand(off + 1);

    if (val)
      this.words[off] = this.words[off] | (1 << wbit);
    else
      this.words[off] = this.words[off] & ~(1 << wbit);

    return this._strip();
  }

  // Add `num` to `this` in-place
  iadd(num) {
    // negative + positive
    if (this.negative !== 0 && num.negative === 0) {
      this.negative = 0;
      this.isub(num);
      this.negative ^= 1;
      return this._normSign();
    }

    // positive + negative
    if (this.negative === 0 && num.negative !== 0) {
      num.negative = 0;
      const r = this.isub(num);
      num.negative = 1;
      return r._normSign();
    }

    // a.length > b.length
    let a, b;
    if (this.length > num.length) {
      a = this;
      b = num;
    } else {
      a = num;
      b = this;
    }

    let carry = 0;
    let i = 0;

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
      this.words[this.length] = carry;
      this.length++;
    } else if (a !== this) {
      // Copy the rest of the words
      for (; i < a.length; i++)
        this.words[i] = a.words[i];
    }

    return this;
  }

  // Add `num` to `this`
  add(num) {
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

  // Subtract `num` from `this` in-place
  isub(num) {
    // this - (-num) = this + num
    if (num.negative !== 0) {
      num.negative = 0;
      const r = this.iadd(num);
      num.negative = 1;
      return r._normSign();
    }

    // -this - num = -(this + num)
    if (this.negative !== 0) {
      this.negative = 0;
      this.iadd(num);
      this.negative = 1;
      return this._normSign();
    }

    // At this point both numbers are positive
    const cmp = this.cmp(num);

    // Optimization - zeroify
    if (cmp === 0) {
      this.negative = 0;
      this.length = 1;
      this.words[0] = 0;
      return this;
    }

    // a > b
    let a, b;
    if (cmp > 0) {
      a = this;
      b = num;
    } else {
      a = num;
      b = this;
    }

    let carry = 0;
    let i = 0;

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

    // Copy rest of the words
    if (carry === 0 && i < a.length && a !== this) {
      for (; i < a.length; i++)
        this.words[i] = a.words[i];
    }

    this.length = Math.max(this.length, i);

    if (a !== this)
      this.negative = 1;

    return this._strip();
  }

  // Subtract `num` from `this`
  sub(num) {
    return this.clone().isub(num);
  }

  mulTo(num, out) {
    if (this.length === 10 && num.length === 10)
      return comb10MulTo(this, num, out);

    const len = this.length + num.length;

    if (len < 63)
      return smallMulTo(this, num, out);

    if (len < 1024)
      return bigMulTo(this, num, out);

    return jumboMulTo(this, num, out);
  }

  // Multiply `this` by `num`
  mul(num) {
    const out = new BN(null);
    out.words = new Array(this.length + num.length);
    return this.mulTo(num, out);
  }

  // Multiply employing FFT
  mulf(num) {
    const out = new BN(null);
    out.words = new Array(this.length + num.length);
    return jumboMulTo(this, num, out);
  }

  // In-place Multiplication
  imul(num) {
    return this.clone().mulTo(num, this);
  }

  imuln(num) {
    const isNegNum = num < 0;

    if (isNegNum)
      num = -num;

    assert(typeof num === 'number');
    assert(num < 0x4000000);

    // Carry
    let carry = 0;
    let i = 0;

    for (; i < this.length; i++) {
      const w = (this.words[i] | 0) * num;
      const lo = (w & 0x3ffffff) + (carry & 0x3ffffff);

      carry >>= 26;
      carry += (w / 0x4000000) | 0;

      // NOTE: lo is 27bit maximum
      carry += lo >>> 26;

      this.words[i] = lo & 0x3ffffff;
    }

    if (carry !== 0) {
      this.words[i] = carry;
      this.length++;
    }

    return isNegNum ? this.ineg() : this;
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
    const w = toBitArray(num);

    if (w.length === 0)
      return new BN(1);

    // Skip leading zeroes
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

  // Shift-left in-place
  iushln(bits) {
    assert(typeof bits === 'number' && bits >= 0);

    const r = bits % 26;
    const s = (bits - r) / 26;
    const carryMask = (0x3ffffff >>> (26 - r)) << (26 - r);

    if (r !== 0) {
      let carry = 0;
      let i = 0;

      for (; i < this.length; i++) {
        const newCarry = this.words[i] & carryMask;
        const c = ((this.words[i] | 0) - newCarry) << r;

        this.words[i] = c | carry;

        carry = newCarry >>> (26 - r);
      }

      if (carry) {
        this.words[i] = carry;
        this.length++;
      }
    }

    if (s !== 0) {
      for (let i = this.length - 1; i >= 0; i--)
        this.words[i + s] = this.words[i];

      for (let i = 0; i < s; i++)
        this.words[i] = 0;

      this.length += s;
    }

    return this._strip();
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

    let h = 0;

    if (hint)
      h = (hint - (hint % 26)) / 26;

    const r = bits % 26;
    const s = Math.min((bits - r) / 26, this.length);
    const mask = 0x3ffffff ^ ((0x3ffffff >>> r) << r);
    const maskedWords = extended;

    h -= s;
    h = Math.max(0, h);

    // Extended mode, copy masked part
    if (maskedWords) {
      for (let i = 0; i < s; i++)
        maskedWords.words[i] = this.words[i];

      maskedWords.length = s;
    }

    if (s === 0) {
      // No-op, we should not move anything at all
    } else if (this.length > s) {
      this.length -= s;
      for (let i = 0; i < this.length; i++) {
        this.words[i] = this.words[i + s];
      }
    } else {
      this.words[0] = 0;
      this.length = 1;
    }

    let carry = 0;

    for (let i = this.length - 1; i >= 0 && (carry !== 0 || i >= h); i--) {
      const word = this.words[i] | 0;

      this.words[i] = (carry << (26 - r)) | (word >>> r);

      carry = word & mask;
    }

    // Push carried bits as a mask
    if (maskedWords && carry !== 0)
      maskedWords.words[maskedWords.length++] = carry;

    if (this.length === 0) {
      this.words[0] = 0;
      this.length = 1;
    }

    return this._strip();
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

    const r = bit % 26;
    const s = (bit - r) / 26;
    const q = 1 << r;

    // Fast case: bit is much higher than all existing words
    if (this.length <= s)
      return false;

    // Check bit and return
    const w = this.words[s];

    return (w & q) !== 0;
  }

  // Return only lowers bits of number (in-place)
  imaskn(bits) {
    assert(typeof bits === 'number' && bits >= 0);

    const r = bits % 26;

    let s = (bits - r) / 26;

    assert(this.negative === 0, 'imaskn works only with positive numbers');

    if (this.length <= s)
      return this;

    if (r !== 0)
      s++;

    this.length = Math.min(s, this.length);

    if (r !== 0) {
      const mask = 0x3ffffff ^ ((0x3ffffff >>> r) << r);

      this.words[this.length - 1] &= mask;
    }

    return this._strip();
  }

  // Return only lowers bits of number
  maskn(bits) {
    return this.clone().imaskn(bits);
  }

  // Add plain number `num` to `this`
  iaddn(num) {
    assert(typeof num === 'number');
    assert(num < 0x4000000);

    if (num < 0)
      return this.isubn(-num);

    // Possible sign change
    if (this.negative !== 0) {
      if (this.length === 1 && (this.words[0] | 0) < num) {
        this.words[0] = num - (this.words[0] | 0);
        this.negative = 0;
        return this;
      }

      this.negative = 0;
      this.isubn(num);
      this.negative = 1;

      return this;
    }

    // Add without checks
    return this._iaddn(num);
  }

  _iaddn(num) {
    this.words[0] += num;

    // Carry
    let i = 0;

    for (; i < this.length && this.words[i] >= 0x4000000; i++) {
      this.words[i] -= 0x4000000;

      if (i === this.length - 1)
        this.words[i + 1] = 1;
      else
        this.words[i + 1]++;
    }

    this.length = Math.max(this.length, i + 1);

    return this;
  }

  // Subtract plain number `num` from `this`
  isubn(num) {
    assert(typeof num === 'number');
    assert(num < 0x4000000);

    if (num < 0)
      return this.iaddn(-num);

    if (this.negative !== 0) {
      this.negative = 0;
      this.iaddn(num);
      this.negative = 1;
      return this;
    }

    this.words[0] -= num;

    if (this.length === 1 && this.words[0] < 0) {
      this.words[0] = -this.words[0];
      this.negative = 1;
    } else {
      // Carry
      for (let i = 0; i < this.length && this.words[i] < 0; i++) {
        this.words[i] += 0x4000000;
        this.words[i + 1] -= 1;
      }
    }

    return this._strip();
  }

  addn(num) {
    return this.clone().iaddn(num);
  }

  subn(num) {
    return this.clone().isubn(num);
  }

  iabs() {
    this.negative = 0;

    return this;
  }

  abs() {
    return this.clone().iabs();
  }

  _ishlnsubmul(num, mul, shift) {
    const len = num.length + shift;

    this._expand(len);

    let carry = 0;
    let i = 0;
    let w;

    for (; i < num.length; i++) {
      w = (this.words[i + shift] | 0) + carry;
      const right = (num.words[i] | 0) * mul;
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

    // Subtraction overflow
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

  _wordDiv(num, mode) {
    let shift = this.length - num.length;
    let a = this.clone();
    let b = num;

    // Normalize
    let bhi = b.words[b.length - 1] | 0;

    const bhiBits = this._countBits(bhi);

    shift = 26 - bhiBits;

    if (shift !== 0) {
      b = b.ushln(shift);
      a.iushln(shift);
      bhi = b.words[b.length - 1] | 0;
    }

    // Initialize quotient
    const m = a.length - b.length;

    let q;

    if (mode !== 'mod') {
      q = new BN(null);
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
      let qj = (a.words[b.length + j] | 0) * 0x4000000
             + (a.words[b.length + j - 1] | 0);

      // NOTE: (qj / bhi) is (0x3ffffff * 0x4000000 + 0x3ffffff) / 0x2000000 max
      // (0x7ffffff)
      qj = Math.min((qj / bhi) | 0, 0x3ffffff);

      a._ishlnsubmul(b, qj, j);

      while (a.negative !== 0) {
        qj--;

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

    // Denormalize
    if (mode !== 'div' && shift !== 0)
      a.iushrn(shift);

    return {
      div: q || null,
      mod: a
    };
  }

  // NOTE: 1) `mode` can be set to `mod` to request mod only,
  //       to `div` to request div only, or be absent to
  //       request both div & mod
  //       2) `positive` is true if unsigned mod is requested
  divmod(num, mode, positive) {
    assert(!num.isZero());

    if (this.isZero()) {
      return {
        div: new BN(0),
        mod: new BN(0)
      };
    }

    let div = null;
    let mod = null;

    if (this.negative !== 0 && num.negative === 0) {
      const res = this.neg().divmod(num, mode);

      if (mode !== 'mod')
        div = res.div.neg();

      if (mode !== 'div') {
        mod = res.mod.neg();
        if (positive && mod.negative !== 0) {
          mod.iadd(num);
        }
      }

      return {
        div: div,
        mod: mod
      };
    }

    if (this.negative === 0 && num.negative !== 0) {
      const res = this.divmod(num.neg(), mode);

      if (mode !== 'mod') {
        div = res.div.neg();
      }

      return {
        div: div,
        mod: res.mod
      };
    }

    if ((this.negative & num.negative) !== 0) {
      const res = this.neg().divmod(num.neg(), mode);

      if (mode !== 'div') {
        mod = res.mod.neg();
        if (positive && mod.negative !== 0) {
          mod.isub(num);
        }
      }

      return {
        div: res.div,
        mod: mod
      };
    }

    // Both numbers are positive at this point

    // Strip both numbers to approximate shift value
    if (num.length > this.length || this.cmp(num) < 0) {
      return {
        div: new BN(0),
        mod: this
      };
    }

    // Very short reduction
    if (num.length === 1) {
      if (mode === 'div') {
        return {
          div: this.divn(num.words[0]),
          mod: null
        };
      }

      if (mode === 'mod') {
        return {
          div: null,
          mod: new BN(this.modrn(num.words[0]))
        };
      }

      return {
        div: this.divn(num.words[0]),
        mod: new BN(this.modrn(num.words[0]))
      };
    }

    return this._wordDiv(num, mode);
  }

  // Find `this` / `num`
  div(num) {
    return this.divmod(num, 'div', false).div;
  }

  // Find `this` % `num`
  mod(num) {
    return this.divmod(num, 'mod', false).mod;
  }

  umod(num) {
    return this.divmod(num, 'mod', true).mod;
  }

  // Find Round(`this` / `num`)
  divRound(num) {
    const dm = this.divmod(num);

    // Fast case - exact division
    if (dm.mod.isZero())
      return dm.div;

    const mod = dm.div.negative !== 0 ? dm.mod.isub(num) : dm.mod;

    const half = num.ushrn(1);
    const r2 = num.andln(1);
    const cmp = mod.cmp(half);

    // Round down
    if (cmp < 0 || r2 === 1 && cmp === 0)
      return dm.div;

    // Round up
    return dm.div.negative !== 0 ? dm.div.isubn(1) : dm.div.iaddn(1);
  }

  modrn(num) {
    const isNegNum = num < 0;

    if (isNegNum)
      num = -num;

    assert(num <= 0x3ffffff);

    const p = (1 << 26) % num;

    let acc = 0;

    for (let i = this.length - 1; i >= 0; i--)
      acc = (p * acc + (this.words[i] | 0)) % num;

    return isNegNum ? -acc : acc;
  }

  // WARNING: DEPRECATED
  modn(num) {
    return this.modrn(num);
  }

  // In-place division by number
  idivn(num) {
    const isNegNum = num < 0;

    if (isNegNum)
      num = -num;

    assert(num <= 0x3ffffff);

    let carry = 0;

    for (let i = this.length - 1; i >= 0; i--) {
      const w = (this.words[i] | 0) + carry * 0x4000000;

      this.words[i] = (w / num) | 0;

      carry = w % num;
    }

    this._strip();

    return isNegNum ? this.ineg() : this;
  }

  divn(num) {
    return this.clone().idivn(num);
  }

  egcd(p) {
    assert(p.negative === 0);
    assert(!p.isZero());

    let x = this;

    const y = p.clone();

    if (x.negative !== 0)
      x = x.umod(p);
    else
      x = x.clone();

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
      ++g;
    }

    const yp = y.clone();
    const xp = x.clone();

    while (!x.isZero()) {
      let i = 0;

      for (let im = 1; (x.words[0] & im) === 0 && i < 26; im <<= 1)
        i++;

      if (i > 0) {
        x.iushrn(i);

        while (i-- > 0) {
          if (A.isOdd() || B.isOdd()) {
            A.iadd(yp);
            B.isub(xp);
          }

          A.iushrn(1);
          B.iushrn(1);
        }
      }

      let j = 0;

      for (let jm = 1; (y.words[0] & jm) === 0 && j < 26; jm <<= 1)
        j++;

      if (j > 0) {
        y.iushrn(j);

        while (j-- > 0) {
          if (C.isOdd() || D.isOdd()) {
            C.iadd(yp);
            D.isub(xp);
          }

          C.iushrn(1);
          D.iushrn(1);
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

    return {
      a: C,
      b: D,
      gcd: y.iushln(g)
    };
  }

  // This is reduced incarnation of the binary EEA
  // above, designated to invert members of the
  // _prime_ fields F(p) at a maximal speed
  _invmp(p) {
    assert(p.negative === 0);
    assert(!p.isZero());

    let a = this;

    const b = p.clone();

    if (a.negative !== 0)
      a = a.umod(p);
    else
      a = a.clone();

    const x1 = new BN(1);
    const x2 = new BN(0);

    const delta = b.clone();

    while (a.cmpn(1) > 0 && b.cmpn(1) > 0) {
      let i = 0;

      for (let im = 1; (a.words[0] & im) === 0 && i < 26; im <<= 1)
        i++;

      if (i > 0) {
        a.iushrn(i);
        while (i-- > 0) {
          if (x1.isOdd())
            x1.iadd(delta);

          x1.iushrn(1);
        }
      }

      let j = 0;

      for (let jm = 1; (b.words[0] & jm) === 0 && j < 26; jm <<= 1)
        j++;

      if (j > 0) {
        b.iushrn(j);

        while (j-- > 0) {
          if (x2.isOdd())
            x2.iadd(delta);

          x2.iushrn(1);
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

    if (res.cmpn(0) < 0)
      res.iadd(p);

    return res;
  }

  gcd(num) {
    if (this.isZero())
      return num.abs();

    if (num.isZero())
      return this.abs();

    let a = this.clone();
    let b = num.clone();
    let shift = 0;

    a.negative = 0;
    b.negative = 0;

    // Remove common factor of two
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
        // Swap `a` and `b` to make `a` always bigger than `b`
        [a, b] = [b, a];
      } else if (r === 0 || b.cmpn(1) === 0) {
        break;
      }

      a.isub(b);
    }

    return b.iushln(shift);
  }

  // Invert number in the field F(num)
  invm(num) {
    return this.egcd(num).a.umod(num);
  }

  isEven() {
    return (this.words[0] & 1) === 0;
  }

  isOdd() {
    return (this.words[0] & 1) === 1;
  }

  // And first word and num
  andln(num) {
    return this.words[0] & num;
  }

  // Increment at the bit position in-line
  bincn(bit) {
    assert(typeof bit === 'number');

    const r = bit % 26;
    const s = (bit - r) / 26;
    const q = 1 << r;

    // Fast case: bit is much higher than all existing words
    if (this.length <= s) {
      this._expand(s + 1);
      this.words[s] |= q;
      return this;
    }

    // Add bit and propagate, if needed
    let carry = q;
    let i = s;

    for (; carry !== 0 && i < this.length; i++) {
      let w = this.words[i] | 0;

      w += carry;
      carry = w >>> 26;
      w &= 0x3ffffff;

      this.words[i] = w;
    }

    if (carry !== 0) {
      this.words[i] = carry;
      this.length++;
    }

    return this;
  }

  isZero() {
    return this.length === 1 && this.words[0] === 0;
  }

  cmpn(num) {
    const negative = num < 0;

    if (this.negative !== 0 && !negative)
      return -1;

    if (this.negative === 0 && negative)
      return 1;

    this._strip();

    let res;

    if (this.length > 1) {
      res = 1;
    } else {
      if (negative) {
        num = -num;
      }

      assert(num <= 0x3ffffff, 'Number is too big');

      const w = this.words[0] | 0;

      if (w === num)
        res = 0;
      else
        res = w < num ? -1 : 1;
    }

    if (this.negative !== 0)
      return -res | 0;

    return res;
  }

  // Compare two numbers and return:
  // 1 - if `this` > `num`
  // 0 - if `this` == `num`
  // -1 - if `this` < `num`
  cmp(num) {
    if (this.negative !== 0 && num.negative === 0)
      return -1;

    if (this.negative === 0 && num.negative !== 0)
      return 1;

    const res = this.ucmp(num);

    if (this.negative !== 0)
      return -res | 0;

    return res;
  }

  // Unsigned comparison
  ucmp(num) {
    // At this point both numbers have the same sign
    if (this.length > num.length)
      return 1;

    if (this.length < num.length)
      return -1;

    let res = 0;

    for (let i = this.length - 1; i >= 0; i--) {
      const a = this.words[i] | 0;
      const b = num.words[i] | 0;

      if (a === b)
        continue;

      if (a < b)
        res = -1;
      else if (a > b)
        res = 1;

      break;
    }

    return res;
  }

  gtn(num) {
    return this.cmpn(num) === 1;
  }

  gt(num) {
    return this.cmp(num) === 1;
  }

  gten(num) {
    return this.cmpn(num) >= 0;
  }

  gte(num) {
    return this.cmp(num) >= 0;
  }

  ltn(num) {
    return this.cmpn(num) === -1;
  }

  lt(num) {
    return this.cmp(num) === -1;
  }

  lten(num) {
    return this.cmpn(num) <= 0;
  }

  lte(num) {
    return this.cmp(num) <= 0;
  }

  eqn(num) {
    return this.cmpn(num) === 0;
  }

  eq(num) {
    return this.cmp(num) === 0;
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
    return new Mont(num);
  }
}

/*
 * Static
 */

BN.BN = BN;
BN.wordSize = 26;

/**
 * FFTM
 * Cooley-Tukey algorithm for FFT. Slightly revisited
 * to rely on looping instead of recursion.
 */

class FFTM {
  constructor(x, y) {
    this.x = x;
    this.y = y;
  }

  makeRBT(N) {
    const l = BN.prototype._countBits(N) - 1;
    const t = new Array(N);

    for (let i = 0; i < N; i++)
      t[i] = this.revBin(i, l, N);

    return t;
  }

  // Returns binary-reversed representation of `x`
  revBin(x, l, N) {
    if (x === 0 || x === N - 1)
      return x;

    let rb = 0;

    for (let i = 0; i < l; i++) {
      rb |= (x & 1) << (l - i - 1);
      x >>= 1;
    }

    return rb;
  }

  // Performs "tweedling" phase, therefore 'emulating'
  // behaviour of the recursive algorithm
  permute(rbt, rws, iws, rtws, itws, N) {
    for (let i = 0; i < N; i++) {
      rtws[i] = rws[rbt[i]];
      itws[i] = iws[rbt[i]];
    }
  }

  transform(rws, iws, rtws, itws, N, rbt) {
    this.permute(rbt, rws, iws, rtws, itws, N);

    for (let s = 1; s < N; s <<= 1) {
      const l = s << 1;

      const rtwdf = Math.cos(2 * Math.PI / l);
      const itwdf = Math.sin(2 * Math.PI / l);

      for (let p = 0; p < N; p += l) {
        let rtwdf_ = rtwdf;
        let itwdf_ = itwdf;

        for (let j = 0; j < s; j++) {
          const re = rtws[p + j];
          const ie = itws[p + j];

          let ro = rtws[p + j + s];
          let io = itws[p + j + s];

          let rx = rtwdf_ * ro - itwdf_ * io;

          io = rtwdf_ * io + itwdf_ * ro;
          ro = rx;

          rtws[p + j] = re + ro;
          itws[p + j] = ie + io;

          rtws[p + j + s] = re - ro;
          itws[p + j + s] = ie - io;

          if (j !== l) {
            rx = rtwdf * rtwdf_ - itwdf * itwdf_;

            itwdf_ = rtwdf * itwdf_ + itwdf * rtwdf_;
            rtwdf_ = rx;
          }
        }
      }
    }
  }

  guessLen13b(n, m) {
    let N = Math.max(m, n) | 1;
    let i = 0;

    const odd = N & 1;

    for (N = N / 2 | 0; N; N = N >>> 1)
      i++;

    return 1 << i + 1 + odd;
  }

  conjugate(rws, iws, N) {
    if (N <= 1)
      return;

    for (let i = 0; i < N / 2; i++) {
      let t = rws[i];

      rws[i] = rws[N - i - 1];
      rws[N - i - 1] = t;

      t = iws[i];

      iws[i] = -iws[N - i - 1];
      iws[N - i - 1] = -t;
    }
  }

  normalize13b(ws, N) {
    let carry = 0;

    for (let i = 0; i < N / 2; i++) {
      const w = Math.round(ws[2 * i + 1] / N) * 0x2000
              + Math.round(ws[2 * i] / N)
              + carry;

      ws[i] = w & 0x3ffffff;

      if (w < 0x4000000)
        carry = 0;
      else
        carry = w / 0x4000000 | 0;
    }

    return ws;
  }

  convert13b(ws, len, rws, N) {
    let carry = 0;

    for (let i = 0; i < len; i++) {
      carry = carry + (ws[i] | 0);

      rws[2 * i] = carry & 0x1fff;
      carry = carry >>> 13;

      rws[2 * i + 1] = carry & 0x1fff;
      carry = carry >>> 13;
    }

    // Pad with zeroes
    for (let i = 2 * len; i < N; ++i)
      rws[i] = 0;

    assert(carry === 0);
    assert((carry & ~0x1fff) === 0);
  }

  stub(N) {
    const ph = new Array(N);

    for (let i = 0; i < N; i++)
      ph[i] = 0;

    return ph;
  }

  mulp(x, y, out) {
    const N = 2 * this.guessLen13b(x.length, y.length);
    const rbt = this.makeRBT(N);
    const _ = this.stub(N);

    const rws = new Array(N);
    const rwst = new Array(N);
    const iwst = new Array(N);

    const nrws = new Array(N);
    const nrwst = new Array(N);
    const niwst = new Array(N);

    const rmws = out.words;
    rmws.length = N;

    this.convert13b(x.words, x.length, rws, N);
    this.convert13b(y.words, y.length, nrws, N);

    this.transform(rws, _, rwst, iwst, N, rbt);
    this.transform(nrws, _, nrwst, niwst, N, rbt);

    for (let i = 0; i < N; i++) {
      const rx = rwst[i] * nrwst[i] - iwst[i] * niwst[i];
      iwst[i] = rwst[i] * niwst[i] + iwst[i] * nrwst[i];
      rwst[i] = rx;
    }

    this.conjugate(rwst, iwst, N);
    this.transform(rwst, iwst, rmws, _, N, rbt);
    this.conjugate(rmws, _, N);
    this.normalize13b(rmws, N);

    out.negative = x.negative ^ y.negative;
    out.length = x.length + y.length;

    return out._strip();
  }
}

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
    this.k = new BN(1).iushln(this.n).isub(this.p);

    this.tmp = this._tmp();
  }

  _tmp() {
    const tmp = new BN(null);
    tmp.words = new Array(Math.ceil(this.n / 13));
    return tmp;
  }

  ireduce(num) {
    // Assumes that `num` is less than `P^2`
    // num = HI * (2 ^ N - K) + HI * K + LO = HI * K + LO (mod P)
    let r = num;
    let rlen;

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
      r._strip();
    }

    return r;
  }

  split(input, out) {
    input.iushrn(this.n, 0, out);
  }

  imulK(num) {
    return num.imul(this.k);
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

  split(input, output) {
    // 256 = 9 * 26 + 22
    const mask = 0x3fffff;
    const outLen = Math.min(input.length, 9);

    for (let i = 0; i < outLen; i++)
      output.words[i] = input.words[i];

    output.length = outLen;

    if (input.length <= 9) {
      input.words[0] = 0;
      input.length = 1;
      return;
    }

    // Shift by 9 limbs
    let prev = input.words[9];
    let i = 10;

    output.words[output.length++] = prev & mask;

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
  }

  imulK(num) {
    // K = 0x1000003d1 = [ 0x40, 0x3d1 ]
    num.words[num.length] = 0;
    num.words[num.length + 1] = 0;
    num.length += 2;

    // bounded at: 0x40 * 0x3ffffff + 0x3d0 = 0x100000390
    let lo = 0;

    for (let i = 0; i < num.length; i++) {
      const w = num.words[i] | 0;
      lo += w * 0x3d1;
      num.words[i] = lo & 0x3ffffff;
      lo = w * 0x40 + ((lo / 0x4000000) | 0);
    }

    // Fast length reduction
    if (num.words[num.length - 1] === 0) {
      num.length--;
      if (num.words[num.length - 1] === 0)
        num.length--;
    }

    return num;
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

    if (carry !== 0)
      num.words[num.length++] = carry;

    return num;
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

  imod(a) {
    if (this.prime)
      return this.prime.ireduce(a)._forceRed(this);

    a.umod(this.m)._forceRed(this)._move(a);

    return a;
  }

  neg(a) {
    if (a.isZero())
      return a.clone();

    return this.m.sub(a)._forceRed(this);
  }

  add(a, b) {
    this._verify2(a, b);

    const res = a.add(b);

    if (res.cmp(this.m) >= 0)
      res.isub(this.m);

    return res._forceRed(this);
  }

  iadd(a, b) {
    this._verify2(a, b);

    const res = a.iadd(b);

    if (res.cmp(this.m) >= 0)
      res.isub(this.m);

    return res;
  }

  sub(a, b) {
    this._verify2(a, b);

    const res = a.sub(b);

    if (res.cmpn(0) < 0)
      res.iadd(this.m);

    return res._forceRed(this);
  }

  isub(a, b) {
    this._verify2(a, b);

    const res = a.isub(b);

    if (res.cmpn(0) < 0)
      res.iadd(this.m);

    return res;
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

  sqrt(a) {
    if (a.isZero())
      return a.clone();

    const mod3 = this.m.andln(3);

    assert(mod3 % 2 === 1);

    // Fast case
    if (mod3 === 3) {
      const pow = this.m.add(new BN(1)).iushrn(2);
      return this.pow(a, pow);
    }

    // Tonelli-Shanks algorithm (Totally unoptimized and slow)
    //
    // Find Q and S, that Q * 2 ^ S = (P - 1)
    const q = this.m.subn(1);

    let s = 0;

    while (!q.isZero() && q.andln(1) === 0) {
      s++;
      q.iushrn(1);
    }

    assert(!q.isZero());

    const one = new BN(1).toRed(this);
    const nOne = one.redNeg();

    // Find quadratic non-residue
    // NOTE: Max is such because of generalized Riemann hypothesis.
    const lpow = this.m.subn(1).iushrn(1);
    const bits = this.m.bitLength();
    const z = new BN(2 * bits * bits).toRed(this);

    while (this.pow(z, lpow).cmp(nOne) !== 0)
      z.redIAdd(nOne);

    let c = this.pow(z, q);
    let r = this.pow(a, q.addn(1).iushrn(1));
    let t = this.pow(a, q);
    let m = s;

    while (t.cmp(one) !== 0) {
      let tmp = t;
      let i = 0;

      for (; tmp.cmp(one) !== 0; i++)
        tmp = tmp.redSqr();

      assert(i < m);

      const b = this.pow(c, new BN(1).iushln(m - i - 1));

      r = r.redMul(b);
      c = b.redSqr();
      t = t.redMul(c);
      m = i;
    }

    return r;
  }

  invm(a) {
    const inv = a._invmp(this.m);

    if (inv.negative !== 0) {
      inv.negative = 0;
      return this.imod(inv).redNeg();
    }

    return this.imod(inv);
  }

  pow(a, num) {
    if (num.isZero())
      return new BN(1).toRed(this);

    if (num.cmpn(1) === 0)
      return a.clone();

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
        currentLen++;

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

  convertTo(num) {
    const r = num.umod(this.m);

    return r === num ? r.clone() : r;
  }

  convertFrom(num) {
    const res = num.clone();
    res.red = null;
    return res;
  }
}

/**
 * Mont
 * Montgomery method engine
 */

class Mont extends Red {
  constructor(m) {
    super(m);

    this.shift = this.m.bitLength();

    if (this.shift % 26 !== 0)
      this.shift += 26 - (this.shift % 26);

    this.r = new BN(1).iushln(this.shift);
    this.r2 = this.imod(this.r.sqr());
    this.rinv = this.r._invmp(this.m);

    this.minv = this.rinv.mul(this.r).isubn(1).div(this.m);
    this.minv = this.minv.umod(this.r);
    this.minv = this.r.sub(this.minv);
  }

  convertTo(num) {
    return this.imod(num.ushln(this.shift));
  }

  convertFrom(num) {
    const r = this.imod(num.mul(this.rinv));
    r.red = null;
    return r;
  }

  imul(a, b) {
    if (a.isZero() || b.isZero()) {
      a.words[0] = 0;
      a.length = 1;
      return a;
    }

    const t = a.imul(b);
    const c = t.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m);
    const u = t.isub(c).iushrn(this.shift);

    let res = u;

    if (u.cmp(this.m) >= 0)
      res = u.isub(this.m);
    else if (u.cmpn(0) < 0)
      res = u.iadd(this.m);

    return res._forceRed(this);
  }

  mul(a, b) {
    if (a.isZero() || b.isZero())
      return new BN(0)._forceRed(this);

    const t = a.mul(b);
    const c = t.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m);
    const u = t.isub(c).iushrn(this.shift);

    let res = u;

    if (u.cmp(this.m) >= 0)
      res = u.isub(this.m);
    else if (u.cmpn(0) < 0)
      res = u.iadd(this.m);

    return res._forceRed(this);
  }

  invm(a) {
    // (AR)^-1 * R^2 = (A^-1 * R^-1) * R^2 = A^-1 * R
    const res = this.imod(a._invmp(this.m).mul(this.r2));
    return res._forceRed(this);
  }
}

/*
 * Helpers
 */

function assert(val, msg) {
  if (!val)
    throw new Error(msg || 'Assertion failed');
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

  assert(!(z & 0xf0), 'Invalid character in ' + str);

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

    assert(c >= 0 && b < mul, 'Invalid character');

    r += b;
  }

  return r;
}

function allocate(ArrayType, size) {
  if (ArrayType.allocUnsafe)
    return ArrayType.allocUnsafe(size);

  return new ArrayType(size);
}

function toBitArray(num) {
  const w = new Array(num.bitLength());

  for (let bit = 0; bit < w.length; bit++) {
    const off = (bit / 26) | 0;
    const wbit = bit % 26;

    w[bit] = (num.words[off] & (1 << wbit)) >>> wbit;
  }

  return w;
}

/*
 * Multiplication
 */

function smallMulTo(self, num, out) {
  out.negative = num.negative ^ self.negative;

  let len = (self.length + num.length) | 0;

  out.length = len;

  len = (len - 1) | 0;

  // Peel one iteration (compiler can't do it, because of code complexity)
  let a = self.words[0] | 0;
  let b = num.words[0] | 0;
  let r = a * b;

  const lo = r & 0x3ffffff;

  let carry = (r / 0x4000000) | 0;
  let k = 1;

  out.words[0] = lo;

  for (; k < len; k++) {
    // Sum all words with the same `i + j = k` and accumulate `ncarry`,
    // note that ncarry could be >= 0x3ffffff
    let ncarry = carry >>> 26;
    let rword = carry & 0x3ffffff;

    const maxJ = Math.min(k, num.length - 1);

    for (let j = Math.max(0, k - self.length + 1); j <= maxJ; j++) {
      const i = (k - j) | 0;

      a = self.words[i] | 0;
      b = num.words[j] | 0;
      r = a * b + rword;
      ncarry += (r / 0x4000000) | 0;
      rword = r & 0x3ffffff;
    }

    out.words[k] = rword | 0;
    carry = ncarry | 0;
  }

  if (carry !== 0)
    out.words[k] = carry | 0;
  else
    out.length--;

  return out._strip();
}

// TODO(indutny): it may be reasonable to omit it for users who don't need
// to work with 256-bit numbers, otherwise it gives 20% improvement for 256-bit
// multiplication (like elliptic secp256k1).
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
  let lo;
  let mid;
  let hi;

  out.negative = self.negative ^ num.negative;
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
    out.length++;
  }

  return out;
}

// Polyfill comb
if (!Math.imul)
  comb10MulTo = smallMulTo;

function bigMulTo(self, num, out) {
  out.negative = num.negative ^ self.negative;
  out.length = self.length + num.length;

  let carry = 0;
  let hncarry = 0;
  let k = 0;

  for (; k < out.length - 1; k++) {
    // Sum all words with the same `i + j = k` and accumulate `ncarry`,
    // note that ncarry could be >= 0x3ffffff
    let ncarry = hncarry;

    hncarry = 0;

    let rword = carry & 0x3ffffff;

    const maxJ = Math.min(k, num.length - 1);

    for (let j = Math.max(0, k - self.length + 1); j <= maxJ; j++) {
      const i = k - j;
      const a = self.words[i] | 0;
      const b = num.words[j] | 0;
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
    out.length--;

  return out._strip();
}

function jumboMulTo(self, num, out) {
  const fftm = new FFTM();
  return fftm.mulp(self, num, out);
}

/*
 * Expose
 */

module.exports = BN;
