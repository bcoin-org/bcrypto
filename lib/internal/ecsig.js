/*!
 * ecsig.js - EC signatures for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');

/*
 * Constants
 */

const EMPTY = Buffer.alloc(1, 0x00);

/**
 * ECSignature
 */

class ECSignature {
  constructor() {
    this.r = EMPTY;
    this.s = EMPTY;
  }

  encode(size) {
    assert((size >>> 0) === size);
    assert(size < 0x7e);
    assert(this.r.length === size);
    assert(this.s.length === size);

    const raw = Buffer.allocUnsafe(size * 2);

    this.r.copy(raw, 0);
    this.s.copy(raw, size);

    return raw;
  }

  decode(data, size) {
    assert(Buffer.isBuffer(data));
    assert((size >>> 0) === size);
    assert(data.length === size * 2);

    this.r = data.slice(0, size);
    this.s = data.slice(size, size * 2);

    return this;
  }

  toDER(size) {
    assert((size >>> 0) === size);
    assert(size < 0x7e);
    assert(this.r.length === size);
    assert(this.s.length === size);

    const r = trimZeroes(this.r);
    const s = trimZeroes(this.s);

    const seq = 2 + r.length + 2 + s.length;
    const wide = seq >= 0x80 ? 1 : 0;
    const len = 2 + wide + seq;
    const buf = Buffer.allocUnsafe(len);

    let p = 0;

    buf[p++] = 0x30;

    if (wide)
      buf[p++] = 0x81;

    buf[p++] = seq;
    buf[p++] = 0x02;
    buf[p++] = r.length;

    p += r.copy(buf, p);

    buf[p++] = 0x02;
    buf[p++] = s.length;

    p += s.copy(buf, p);

    assert(p === len);

    return buf;
  }

  fromDER(data, size) {
    assert(Buffer.isBuffer(data));
    assert((size >>> 0) === size);

    let len = 0;
    let pos = 0;
    let rlen = 0;
    let slen = 0;
    let r = null;
    let s = null;

    // Sequence tag byte.
    assert(pos + 1 <= data.length);
    assert(data[pos] === 0x30);
    pos += 1;

    // Sequence length bytes.
    assert(pos + 1 <= data.length);
    len = data[pos];
    pos += 1;

    if (len & 0x80) {
      len -= 0x80;
      assert(pos + len <= data.length);
      pos += len;
    }

    // Integer tag byte for R.
    assert(pos + 1 <= data.length);
    assert(data[pos] === 0x02);
    pos += 1;

    // Integer length for R.
    assert(pos + 1 <= data.length);
    len = data[pos];
    pos += 1;

    if (len & 0x80) {
      len -= 0x80;

      assert(pos + len <= data.length);

      while (len > 0 && data[pos] === 0x00) {
        len -= 1;
        pos += 1;
      }

      assert(len <= 6);

      while (len > 0) {
        rlen *= 0x100;
        rlen += data[pos];
        len -= 1;
        pos += 1;
      }
    } else {
      rlen = len;
    }

    // Ignore leading zeroes in R.
    assert(pos + rlen <= data.length);

    while (rlen > 0 && data[pos] === 0x00) {
      rlen -= 1;
      pos += 1;
    }

    if (rlen > size)
      r = Buffer.alloc(size, 0x00);
    else
      r = data.slice(pos, pos + rlen);

    pos += rlen;

    // Integer tag byte for S.
    assert(pos + 1 <= data.length);
    assert(data[pos] === 0x02);
    pos += 1;

    // Integer length for S.
    assert(pos + 1 <= data.length);
    len = data[pos];
    pos += 1;

    if (len & 0x80) {
      len -= 0x80;

      assert(pos + len <= data.length);

      while (len > 0 && data[pos] === 0x00) {
        len -= 1;
        pos += 1;
      }

      assert(len <= 6);

      while (len > 0) {
        slen *= 0x100;
        slen += data[pos];
        len -= 1;
        pos += 1;
      }
    } else {
      slen = len;
    }

    // Ignore leading zeroes in S.
    assert(pos + slen <= data.length);

    while (slen > 0 && data[pos] === 0x00) {
      slen -= 1;
      pos += 1;
    }

    if (slen > size)
      s = Buffer.alloc(size, 0x00);
    else
      s = data.slice(pos, pos + slen);

    pos += slen;

    this.r = leftPad(r, size);
    this.s = leftPad(s, size);

    return this;
  }

  static decode(data, size) {
    return new this().decode(data, size);
  }

  static fromDER(data, size) {
    return new this().fromDER(data, size);
  }
}

/*
 * API
 */

function fromDER(raw, size) {
  const sig = ECSignature.fromDER(raw, size);
  return sig.encode(size);
}

function toDER(raw, size) {
  const sig = ECSignature.decode(raw, size);
  return sig.toDER(size);
}

function normalize(raw, size) {
  const sig = ECSignature.fromDER(raw, size);
  return sig.toDER(size);
}

function isLowValue(val, half) {
  assert(Buffer.isBuffer(val));
  assert(Buffer.isBuffer(half));
  assert(val.length === half.length);

  let i = 0;

  for (; i < val.length; i++) {
    if (val[i] !== 0)
      break;
  }

  if (i === val.length)
    return false;

  return val.compare(half) <= 0;
}

function isLowDER(raw, size, half) {
  assert(Buffer.isBuffer(raw));
  assert((size >>> 0) === size);
  assert(Buffer.isBuffer(half));

  let sig;

  try {
    sig = ECSignature.fromDER(raw, size);
  } catch (e) {
    return false;
  }

  return isLowValue(sig.s, half);
}

function isLowS(raw, size, half) {
  assert(Buffer.isBuffer(raw));
  assert((size >>> 0) === size);
  assert(Buffer.isBuffer(half));

  let sig;

  try {
    sig = ECSignature.decode(raw, size);
  } catch (e) {
    return false;
  }

  return isLowValue(sig.s, half);
}

/*
 * Helpers
 */

function leftPad(val, size) {
  assert(Buffer.isBuffer(val));
  assert((size >>> 0) === size);
  assert(val.length <= size);

  if (val.length === size)
    return val;

  const buf = Buffer.allocUnsafe(size);
  const pos = size - val.length;

  buf.fill(0x00, 0, pos);
  val.copy(buf, pos);

  return buf;
}

function _trimZeroes(buf) {
  assert(Buffer.isBuffer(buf));
  assert(buf.length > 0);

  for (let i = 0; i < buf.length; i++) {
    if (buf[i] !== 0x00)
      return buf.slice(i);
  }

  return buf.slice(-1);
}

function trimZeroes(buf) {
  const val = _trimZeroes(buf);

  if (val[0] & 0x80) {
    const out = Buffer.allocUnsafe(1 + val.length);
    out[0] = 0x00;
    val.copy(out, 1);
    return out;
  }

  return val;
}

/*
 * Expose
 */

exports.ECSignature = ECSignature;
exports.fromDER = fromDER;
exports.toDER = toDER;
exports.normalize = normalize;
exports.isLowValue = isLowValue;
exports.isLowDER = isLowDER;
exports.isLowS = isLowS;
