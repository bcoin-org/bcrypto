/*!
 * ripemd160.js - RIPEMD160 implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 * Parts of this software based on hash.js.
 */

'use strict';

const assert = require('assert');
const HMAC = require('../hmac');

/*
 * Constants
 */

const DESC = Buffer.alloc(8, 0x00);
const PADDING = Buffer.alloc(64, 0x00);

PADDING[0] = 0x80;

const r = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
  3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
  1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
  4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
];

const rh = [
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
  6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
  15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
  8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
  12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
];

const s = [
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
  7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
  11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
  11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
  9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
];

const sh = [
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
  9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
  9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
  15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
  8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
];

let ctx = null;

/**
 * RIPEMD160
 */

class RIPEMD160 {
  /**
   * Create a RIPEMD160 context.
   * @constructor
   */

  constructor() {
    this.s = new Uint32Array(5);
    this.w = new Uint32Array(16);
    this.block = Buffer.allocUnsafe(64);
    this.bytes = 0;
  }

  /**
   * Initialize RIPEMD160 context.
   * @returns {RIPEMD160}
   */

  init() {
    this.s[0] = 0x67452301;
    this.s[1] = 0xefcdab89;
    this.s[2] = 0x98badcfe;
    this.s[3] = 0x10325476;
    this.s[4] = 0xc3d2e1f0;
    this.bytes = 0;
    return this;
  }

  /**
   * Update RIPEMD160 context.
   * @param {Buffer} data
   */

  update(data) {
    assert(Buffer.isBuffer(data));
    this._update(data, data.length);
    return this;
  }

  /**
   * Finalize RIPEMD160 context.
   * @returns {Buffer}
   */

  final() {
    return this._final(Buffer.allocUnsafe(20));
  }

  /**
   * Update RIPEMD160 context.
   * @private
   * @param {Buffer} data
   * @param {Number} len
   */

  _update(data, len) {
    let size = this.bytes & 0x3f;
    let pos = 0;

    this.bytes += len;

    if (size > 0) {
      let want = 64 - size;

      if (want > len)
        want = len;

      for (let i = 0; i < want; i++)
        this.block[size + i] = data[i];

      size += want;
      len -= want;
      pos += want;

      if (size < 64)
        return;

      this.transform(this.block, 0);
    }

    while (len >= 64) {
      this.transform(data, pos);
      pos += 64;
      len -= 64;
    }

    for (let i = 0; i < len; i++)
      this.block[i] = data[pos + i];
  }

  /**
   * Finalize RIPEMD160 context.
   * @private
   * @param {Buffer} out
   * @returns {Buffer}
   */

  _final(out) {
    const pos = this.bytes % 64;
    const len = this.bytes * 8;

    writeU32(DESC, len, 0);
    writeU32(DESC, len * (1 / 0x100000000), 4);

    this._update(PADDING, 1 + ((119 - pos) % 64));
    this._update(DESC, 8);

    for (let i = 0; i < 5; i++) {
      writeU32(out, this.s[i], i * 4);
      this.s[i] = 0;
    }

    for (let i = 0; i < 16; i++)
      this.w[i] = 0;

    for (let i = 0; i < 64; i++)
      this.block[i] = 0;

    return out;
  }

  /**
   * Transform RIPEMD160 block.
   * @param {Buffer} chunk
   * @param {Number} pos
   */

  transform(chunk, pos) {
    const w = this.w;

    let A = this.s[0];
    let B = this.s[1];
    let C = this.s[2];
    let D = this.s[3];
    let E = this.s[4];
    let Ah = A;
    let Bh = B;
    let Ch = C;
    let Dh = D;
    let Eh = E;

    for (let i = 0; i < 16; i++)
      w[i] = readU32(chunk, pos + i * 4);

    for (let j = 0; j < 80; j++) {
      let a = A + f(j, B, C, D) + w[r[j]] + K(j);
      let b = rotl32(a, s[j]);
      let T = b + E;
      A = E;
      E = D;
      D = rotl32(C, 10);
      C = B;
      B = T;

      a = Ah + f(79 - j, Bh, Ch, Dh) + w[rh[j]] + Kh(j);
      b = rotl32(a, sh[j]);
      T = b + Eh;
      Ah = Eh;
      Eh = Dh;
      Dh = rotl32(Ch, 10);
      Ch = Bh;
      Bh = T;
    }

    const T = this.s[1] + C + Dh;

    this.s[1] = this.s[2] + D + Eh;
    this.s[2] = this.s[3] + E + Ah;
    this.s[3] = this.s[4] + A + Bh;
    this.s[4] = this.s[0] + B + Ch;
    this.s[0] = T;

    this.s[0] >>>= 0;
    this.s[1] >>>= 0;
    this.s[2] >>>= 0;
    this.s[3] >>>= 0;
    this.s[4] >>>= 0;
  }

  static hash() {
    return new RIPEMD160();
  }

  static hmac() {
    return new HMAC(RIPEMD160, 64);
  }

  static digest(data) {
    return ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 20);
    assert(Buffer.isBuffer(right) && right.length === 20);
    return ctx.init().update(left).update(right).final();
  }

  static mac(data, key) {
    return this.hmac().init(key).update(data).final();
  }
}

ctx = new RIPEMD160();

function rotl32(w, b) {
  return (w << b) | (w >>> (32 - b));
}

function f(j, x, y, z) {
  if (j <= 15)
    return x ^ y ^ z;

  if (j <= 31)
    return (x & y) | ((~x) & z);

  if (j <= 47)
    return (x | (~y)) ^ z;

  if (j <= 63)
    return (x & z) | (y & (~z));

  return x ^ (y | (~z));
}

function K(j) {
  if (j <= 15)
    return 0x00000000;

  if (j <= 31)
    return 0x5a827999;

  if (j <= 47)
    return 0x6ed9eba1;

  if (j <= 63)
    return 0x8f1bbcdc;

  return 0xa953fd4e;
}

function Kh(j) {
  if (j <= 15)
    return 0x50a28be6;

  if (j <= 31)
    return 0x5c4dd124;

  if (j <= 47)
    return 0x6d703ef3;

  if (j <= 63)
    return 0x7a6d76e9;

  return 0x00000000;
}

function writeU32(buf, value, offset) {
  buf[offset + 3] = value >>> 24;
  buf[offset + 2] = (value >> 16) & 0xff;
  buf[offset + 1] = (value >> 8) & 0xff;
  buf[offset] = value & 0xff;
}

function readU32(buf, offset) {
  return ((buf[offset + 3] & 0xff) * 0x1000000)
    + (((buf[offset + 2] & 0xff) << 16)
    | ((buf[offset + 1] & 0xff) << 8)
    | (buf[offset] & 0xff));
}

/*
 * Expose
 */

module.exports = RIPEMD160;
