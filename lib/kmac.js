/*!
 * kmac.js - KMAC implementation for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
 *   - https://github.com/XKCP/XKCP/blob/8f447eb/lib/high/Keccak/SP800-185/SP800-185.inc
 *   - https://github.com/XKCP/XKCP/blob/8f447eb/lib/high/Keccak/SP800-185/SP800-185.c
 *   - https://github.com/XKCP/XKCP/blob/8f447eb/tests/UnitTests/testSP800-185.c
 *   - https://github.com/emn178/js-sha3/blob/master/src/sha3.js
 */

'use strict';

const assert = require('bsert');
const Keccak = require('./keccak');

/*
 * Constants
 */

const PREFIX = Buffer.from('KMAC', 'binary');
const EMPTY = Buffer.alloc(0);
const ZEROES = Buffer.alloc(168, 0x00);

/*
 * KMAC
 */

class KMAC {
  constructor(bits = 128) {
    assert((bits >>> 0) === bits);
    assert(bits === 128 || bits === 256);
    this.bits = bits;
    this.ctx = new Keccak();
  }

  init(key, pers = null) {
    if (pers == null)
      pers = EMPTY;

    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(pers));

    this.ctx.init(this.bits);

    const size = (1600 - this.bits * 2) / 8;

    this.bytePad([PREFIX, pers], size);
    this.bytePad([key], size);

    return this;
  }

  update(data) {
    this.ctx.update(data);
    return this;
  }

  final() {
    const len = (this.bits * 2) / 8;
    this.rightEncode(len * 8);
    return this.ctx.final(0x04, len);
  }

  bytePad(items, w) {
    assert(Array.isArray(items));
    assert((w >>> 0) === w);
    assert(w > 0);

    let z = this.leftEncode(w);

    for (const x of items)
      z += this.encodeString(x);

    const left = w - (z % w);

    if (left === w)
      return z;

    z += this.zeroPad(left);

    return z;
  }

  encodeString(s) {
    assert(Buffer.isBuffer(s));

    const n = this.leftEncode(s.length * 8);

    this.update(s);

    return n + s.length;
  }

  zeroPad(size) {
    assert((size >>> 0) === size);
    assert(size <= 168);

    const buf = ZEROES.slice(0, size);

    this.update(buf);

    return buf.length;
  }

  leftEncode(x) {
    assert((x >>> 0) === x);
    assert(x >= 0 && x < 22040);

    let v = x;
    let n = 0;

    while (v && n < 4) {
      n += 1;
      v >>>= 8;
    }

    if (n === 0)
      n = 1;

    const buf = Buffer.allocUnsafe(n + 1);

    for (let i = 1; i <= n; i++)
      buf[i] = x >>> (8 * (n - i));

    buf[0] = n;

    this.update(buf);

    return buf.length;
  }

  rightEncode(x) {
    assert((x >>> 0) === x);
    assert(x >= 0 && x < 22040);

    let v = x;
    let n = 0;

    while (v && n < 4) {
      n += 1;
      v >>>= 8;
    }

    if (n === 0)
      n = 1;

    const buf = Buffer.allocUnsafe(n + 1);

    for (let i = 1; i <= n; i++)
      buf[i - 1] = x >>> (8 * (n - i));

    buf[n] = n;

    this.update(buf);

    return buf.length;
  }
}

/*
 * Expose
 */

module.exports = KMAC;
