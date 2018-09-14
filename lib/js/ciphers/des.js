/*!
 * des.js - DES for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/des.js:
 *   Copyright (c) 2015, Fedor Indutny (MIT License).
 *   https://github.com/indutny/des.js
 *
 * Resources:
 *   https://github.com/indutny/des.js/tree/master/lib/des
 */

'use strict';

const assert = require('bsert');

/*
 * Constants
 */

const PC2 = new Uint8Array([
  // inL => outL
  14, 11, 17, 4, 27, 23, 25, 0,
  13, 22, 7, 18, 5, 9, 16, 24,
  2, 20, 12, 21, 1, 8, 15, 26,

  // inR => outR
  15, 4, 25, 19, 9, 1, 26, 16,
  5, 11, 23, 8, 12, 7, 17, 0,
  22, 3, 10, 14, 6, 20, 27, 24
]);

const S = new Uint8Array([
  14, 0, 4, 15, 13, 7, 1, 4, 2, 14, 15, 2, 11, 13, 8, 1,
  3, 10, 10, 6, 6, 12, 12, 11, 5, 9, 9, 5, 0, 3, 7, 8,
  4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11, 7,
  15, 5, 12, 11, 9, 3, 7, 14, 3, 10, 10, 0, 5, 6, 0, 13,

  15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14,
  9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5, 11, 10, 5,
  0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2,
  5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9,

  10, 13, 0, 7, 9, 0, 14, 9, 6, 3, 3, 4, 15, 6, 5, 10,
  1, 2, 13, 8, 12, 5, 7, 14, 11, 12, 4, 11, 2, 15, 8, 1,
  13, 1, 6, 10, 4, 13, 9, 0, 8, 6, 15, 9, 3, 8, 0, 7,
  11, 4, 1, 15, 2, 14, 12, 3, 5, 11, 10, 5, 14, 2, 7, 12,

  7, 13, 13, 8, 14, 11, 3, 5, 0, 6, 6, 15, 9, 0, 10, 3,
  1, 4, 2, 7, 8, 2, 5, 12, 11, 1, 12, 10, 4, 14, 15, 9,
  10, 3, 6, 15, 9, 0, 0, 6, 12, 10, 11, 1, 7, 13, 13, 8,
  15, 9, 1, 4, 3, 5, 14, 11, 5, 12, 2, 7, 8, 2, 4, 14,

  2, 14, 12, 11, 4, 2, 1, 12, 7, 4, 10, 7, 11, 13, 6, 1,
  8, 5, 5, 0, 3, 15, 15, 10, 13, 3, 0, 9, 14, 8, 9, 6,
  4, 11, 2, 8, 1, 12, 11, 7, 10, 1, 13, 14, 7, 2, 8, 13,
  15, 6, 9, 15, 12, 0, 5, 9, 6, 10, 3, 4, 0, 5, 14, 3,

  12, 10, 1, 15, 10, 4, 15, 2, 9, 7, 2, 12, 6, 9, 8, 5,
  0, 6, 13, 1, 3, 13, 4, 14, 14, 0, 7, 11, 5, 3, 11, 8,
  9, 4, 14, 3, 15, 2, 5, 12, 2, 9, 8, 5, 12, 15, 3, 10,
  7, 11, 0, 14, 4, 1, 10, 7, 1, 6, 13, 0, 11, 8, 6, 13,

  4, 13, 11, 0, 2, 11, 14, 7, 15, 4, 0, 9, 8, 1, 13, 10,
  3, 14, 12, 3, 9, 5, 7, 12, 5, 2, 10, 15, 6, 8, 1, 6,
  1, 6, 4, 11, 11, 13, 13, 8, 12, 1, 3, 4, 7, 10, 14, 7,
  10, 9, 15, 5, 6, 0, 8, 15, 0, 14, 5, 2, 9, 3, 2, 12,

  13, 1, 2, 15, 8, 13, 4, 8, 6, 10, 15, 3, 11, 7, 1, 4,
  10, 12, 9, 5, 3, 6, 14, 11, 5, 0, 0, 14, 12, 9, 7, 2,
  7, 2, 11, 1, 4, 14, 1, 7, 9, 4, 12, 10, 14, 8, 2, 13,
  0, 15, 6, 12, 10, 9, 13, 0, 15, 3, 3, 5, 5, 6, 8, 11
]);

const PERMUTE = new Uint8Array([
  16, 25, 12, 11, 3, 20, 4, 15, 31, 17, 9, 6, 27, 14, 1, 22,
  30, 24, 8, 18, 0, 5, 29, 23, 13, 19, 2, 26, 10, 21, 28, 7
]);

const SHIFT = new Uint8Array([
  1, 1, 2, 2, 2, 2, 2, 2,
  1, 2, 2, 2, 2, 2, 2, 1
]);

/**
 * DES
 */

class DES {
  constructor() {
    this.block = new Uint32Array(2);
    this.keys = new Uint32Array(16 * 2);
  }

  get blockSize() {
    return 8;
  }

  init(key) {
    assert(Buffer.isBuffer(key));
    assert(key.length === 8);
    return this.derive(key);
  }

  encrypt(input, ipos, output, opos) {
    return this.crypt(input, ipos, output, opos, true);
  }

  decrypt(input, ipos, output, opos) {
    return this.crypt(input, ipos, output, opos, false);
  }

  destroy() {
    for (let i = 0; i < 2; i++)
      this.block[i] = 0;

    for (let i = 0; i < 32; i++)
      this.keys[i] = 0;

    return this;
  }

  derive(key) {
    let kL = readU32(key, 0);
    let kR = readU32(key, 4);

    pc1(kL, kR, this.block, 0);
    kL = this.block[0];
    kR = this.block[1];

    for (let i = 0; i < this.keys.length; i += 2) {
      const shift = SHIFT[i >>> 1];
      kL = r28shl(kL, shift);
      kR = r28shl(kR, shift);
      pc2(kL, kR, this.keys, i);
    }

    return this;
  }

  crypt(input, ipos, output, opos, encrypt) {
    let l = readU32(input, ipos);
    let r = readU32(input, ipos + 4);

    // Initial Permutation
    ip(l, r, this.block, 0);

    l = this.block[0];
    r = this.block[1];

    if (encrypt)
      this.encipher(l, r, this.block, 0);
    else
      this.decipher(l, r, this.block, 0);

    l = this.block[0];
    r = this.block[1];

    writeU32(output, l, opos);
    writeU32(output, r, opos + 4);

    return this;
  }

  encipher(lStart, rStart, out, off) {
    let l = lStart;
    let r = rStart;

    // Apply f() x16 times
    for (let i = 0; i < this.keys.length; i += 2) {
      let keyL = this.keys[i];
      let keyR = this.keys[i + 1];

      // f(r, k)
      expand(r, this.block, 0);

      keyL ^= this.block[0];
      keyR ^= this.block[1];

      const s = substitute(keyL, keyR);
      const f = permute(s);
      const t = r;

      r = (l ^ f) >>> 0;
      l = t;
    }

    // Reverse Initial Permutation
    rip(r, l, out, off);

    return this;
  }

  decipher(lStart, rStart, out, off) {
    let l = rStart;
    let r = lStart;

    // Apply f() x16 times
    for (let i = this.keys.length - 2; i >= 0; i -= 2) {
      let keyL = this.keys[i];
      let keyR = this.keys[i + 1];

      // f(r, k)
      expand(l, this.block, 0);

      keyL ^= this.block[0];
      keyR ^= this.block[1];

      const s = substitute(keyL, keyR);
      const f = permute(s);
      const t = l;

      l = (r ^ f) >>> 0;
      r = t;
    }

    // Reverse Initial Permutation
    rip(l, r, out, off);

    return this;
  }
}

/**
 * EDE
 */

class EDE {
  constructor() {
    this.x = new DES();
    this.y = new DES();
  }

  get blockSize() {
    return 8;
  }

  init(key) {
    assert(Buffer.isBuffer(key));
    assert(key.length === 16);

    const k1 = key.slice(0, 8);
    const k2 = key.slice(8, 16);

    this.x.init(k1);
    this.y.init(k2);

    return this;
  }

  encrypt(input, ipos, output, opos) {
    this.x.encrypt(input, ipos, output, opos);
    this.y.decrypt(output, opos, output, opos);
    this.x.encrypt(output, opos, output, opos);
    return this;
  }

  decrypt(input, ipos, output, opos) {
    this.x.decrypt(input, ipos, output, opos);
    this.y.encrypt(output, opos, output, opos);
    this.x.decrypt(output, opos, output, opos);
    return this;
  }

  destroy() {
    this.x.destroy();
    this.y.destroy();
    return this;
  }
}

/**
 * EDE3
 */

class EDE3 {
  constructor() {
    this.x = new DES();
    this.y = new DES();
    this.z = new DES();
  }

  get blockSize() {
    return 8;
  }

  init(key) {
    assert(Buffer.isBuffer(key));
    assert(key.length === 24);

    const k1 = key.slice(0, 8);
    const k2 = key.slice(8, 16);
    const k3 = key.slice(16, 24);

    this.x.init(k1);
    this.y.init(k2);
    this.z.init(k3);

    return this;
  }

  encrypt(input, ipos, output, opos) {
    this.x.encrypt(input, ipos, output, opos);
    this.y.decrypt(output, opos, output, opos);
    this.z.encrypt(output, opos, output, opos);
    return this;
  }

  decrypt(input, ipos, output, opos) {
    this.z.decrypt(input, ipos, output, opos);
    this.y.encrypt(output, opos, output, opos);
    this.x.decrypt(output, opos, output, opos);
    return this;
  }

  destroy() {
    this.x.destroy();
    this.y.destroy();
    this.z.destroy();
    return this;
  }
}

/*
 * Helpers
 */

function ip(inL, inR, out, off) {
  let outL = 0;
  let outR = 0;

  for (let i = 6; i >= 0; i -= 2) {
    for (let j = 0; j <= 24; j += 8) {
      outL <<= 1;
      outL |= (inR >>> (j + i)) & 1;
    }

    for (let j = 0; j <= 24; j += 8) {
      outL <<= 1;
      outL |= (inL >>> (j + i)) & 1;
    }
  }

  for (let i = 6; i >= 0; i -= 2) {
    for (let j = 1; j <= 25; j += 8) {
      outR <<= 1;
      outR |= (inR >>> (j + i)) & 1;
    }

    for (let j = 1; j <= 25; j += 8) {
      outR <<= 1;
      outR |= (inL >>> (j + i)) & 1;
    }
  }

  out[off + 0] = outL >>> 0;
  out[off + 1] = outR >>> 0;
}

function rip(inL, inR, out, off) {
  let outL = 0;
  let outR = 0;

  for (let i = 0; i < 4; i++) {
    for (let j = 24; j >= 0; j -= 8) {
      outL <<= 1;
      outL |= (inR >>> (j + i)) & 1;
      outL <<= 1;
      outL |= (inL >>> (j + i)) & 1;
    }
  }

  for (let i = 4; i < 8; i++) {
    for (let j = 24; j >= 0; j -= 8) {
      outR <<= 1;
      outR |= (inR >>> (j + i)) & 1;
      outR <<= 1;
      outR |= (inL >>> (j + i)) & 1;
    }
  }

  out[off + 0] = outL >>> 0;
  out[off + 1] = outR >>> 0;
}

function pc1(inL, inR, out, off) {
  let outL = 0;
  let outR = 0;

  // 7, 15, 23, 31, 39, 47, 55, 63
  // 6, 14, 22, 30, 39, 47, 55, 63
  // 5, 13, 21, 29, 39, 47, 55, 63
  // 4, 12, 20, 28
  for (let i = 7; i >= 5; i--) {
    for (let j = 0; j <= 24; j += 8) {
      outL <<= 1;
      outL |= (inR >> (j + i)) & 1;
    }

    for (let j = 0; j <= 24; j += 8) {
      outL <<= 1;
      outL |= (inL >> (j + i)) & 1;
    }
  }

  for (let j = 0; j <= 24; j += 8) {
    outL <<= 1;
    outL |= (inR >> (j + 4)) & 1;
  }

  // 1, 9, 17, 25, 33, 41, 49, 57
  // 2, 10, 18, 26, 34, 42, 50, 58
  // 3, 11, 19, 27, 35, 43, 51, 59
  // 36, 44, 52, 60
  for (let i = 1; i <= 3; i++) {
    for (let j = 0; j <= 24; j += 8) {
      outR <<= 1;
      outR |= (inR >> (j + i)) & 1;
    }

    for (let j = 0; j <= 24; j += 8) {
      outR <<= 1;
      outR |= (inL >> (j + i)) & 1;
    }
  }

  for (let j = 0; j <= 24; j += 8) {
    outR <<= 1;
    outR |= (inL >> (j + 4)) & 1;
  }

  out[off + 0] = outL >>> 0;
  out[off + 1] = outR >>> 0;
}

function r28shl(num, shift) {
  return ((num << shift) & 0xfffffff) | (num >>> (28 - shift));
}

function pc2(inL, inR, out, off) {
  let outL = 0;
  let outR = 0;

  const len = PC2.length >>> 1;

  for (let i = 0; i < len; i++) {
    outL <<= 1;
    outL |= (inL >>> PC2[i]) & 0x1;
  }

  for (let i = len; i < PC2.length; i++) {
    outR <<= 1;
    outR |= (inR >>> PC2[i]) & 0x1;
  }

  out[off + 0] = outL >>> 0;
  out[off + 1] = outR >>> 0;
}

function expand(r, out, off) {
  let outL = 0;
  let outR = 0;

  outL = ((r & 1) << 5) | (r >>> 27);

  for (let i = 23; i >= 15; i -= 4) {
    outL <<= 6;
    outL |= (r >>> i) & 0x3f;
  }

  for (let i = 11; i >= 3; i -= 4) {
    outR |= (r >>> i) & 0x3f;
    outR <<= 6;
  }

  outR |= ((r & 0x1f) << 1) | (r >>> 31);

  out[off + 0] = outL >>> 0;
  out[off + 1] = outR >>> 0;
}

function substitute(inL, inR) {
  let out = 0;

  for (let i = 0; i < 4; i++) {
    const b = (inL >>> (18 - i * 6)) & 0x3f;
    const sb = S[i * 0x40 + b];

    out <<= 4;
    out |= sb;
  }

  for (let i = 0; i < 4; i++) {
    const b = (inR >>> (18 - i * 6)) & 0x3f;
    const sb = S[4 * 0x40 + i * 0x40 + b];

    out <<= 4;
    out |= sb;
  }

  return out >>> 0;
}

function permute(num) {
  let out = 0;

  for (let i = 0; i < PERMUTE.length; i++) {
    out <<= 1;
    out |= (num >>> PERMUTE[i]) & 1;
  }

  return out >>> 0;
}

function readU32(data, off) {
  return (data[off++] * 0x1000000
    + data[off++] * 0x10000
    + data[off++] * 0x100
    + data[off]);
}

function writeU32(dst, num, off) {
  dst[off++] = num >>> 24;
  dst[off++] = num >>> 16;
  dst[off++] = num >>> 8;
  dst[off++] = num;
  return off;
}

/*
 * Expose
 */

exports.DES = DES;
exports.EDE = EDE;
exports.EDE3 = EDE3;
