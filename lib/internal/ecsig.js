/*!
 * ecsig.js - EC signatures for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const bio = require('bufio');
const der = require('./der');

/**
 * ECSignature
 */

class ECSignature extends bio.Struct {
  constructor() {
    super();
    this.r = null;
    this.s = null;
  }

  _assert(size) {
    assert((size >>> 0) === size);
    assert(Buffer.isBuffer(this.r) && this.r.length === size);
    assert(Buffer.isBuffer(this.s) && this.s.length === size);
  }

  getSize(size) {
    assert((size >>> 0) === size);
    return size * 2;
  }

  write(bw, size) {
    assert(bw);
    this._assert(size);

    bw.writeBytes(this.r);
    bw.writeBytes(this.s);

    return bw;
  }

  read(br, size) {
    assert(br);
    assert((size >>> 0) === size);

    this.r = br.readBytes(size);
    this.s = br.readBytes(size);

    return this;
  }

  encode(size) {
    this._assert(size);

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

  getBodySize() {
    let size = 0;

    size += der.sizeInt(this.r);
    size += der.sizeInt(this.s);

    return size;
  }

  getDERSize() {
    let size = this.getBodySize();
    size += der.sizeSeq(size);
    return size;
  }

  toDER(size) {
    this._assert(size);

    const bodySize = this.getBodySize();
    const derSize = der.sizeSeq(bodySize) + bodySize;
    const bw = bio.write(derSize);

    der.writeSeq(bw, bodySize);
    der.writeInt(bw, this.r);
    der.writeInt(bw, this.s);

    return bw.render();
  }

  _parseDER(data, size, strict) {
    assert(Buffer.isBuffer(data));
    assert((size >>> 0) === size);
    assert(typeof strict === 'boolean');

    const br = bio.read(data);
    const sr = der.readSeq(br, strict);
    const r = der.readInt(sr, strict);
    const s = der.readInt(sr, strict);

    this.r = leftPad(r, size, strict);
    this.s = leftPad(s, size, strict);

    if (strict) {
      if (br.left() !== 0 || sr.left() !== 0)
        throw new Error('Unexpected trailing bytes.');
    }

    return this;
  }

  fromDER(data, size) {
    return this._parseDER(data, size, true);
  }

  fromLax(data, size) {
    return this._parseDER(data, size, false);
  }

  static fromDER(data, size) {
    return new this().fromDER(data, size);
  }

  static fromLax(data, size) {
    return new this().fromLax(data, size);
  }
}

/*
 * API
 */

function fromDER(raw, size) {
  const sig = ECSignature.fromDER(raw, size);
  return sig.encode(size);
}

function fromLax(raw, size) {
  const sig = ECSignature.fromLax(raw, size);
  return sig.encode(size);
}

function toDER(raw, size) {
  const sig = ECSignature.decode(raw, size);
  return sig.toDER(size);
}

function reencode(raw, size) {
  const sig = ECSignature.fromLax(raw, size);
  return sig.toDER(size);
}

function isStrictDER(raw, size) {
  assert(Buffer.isBuffer(raw));
  assert((size >>> 0) === size);

  try {
    ECSignature.fromDER(raw, size);
    return true;
  } catch (e) {
    return false;
  }
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

function leftPad(val, size, strict = false) {
  assert(Buffer.isBuffer(val));
  assert((size >>> 0) === size);
  assert(typeof strict === 'boolean');

  if (val.length > size) {
    if (strict)
      throw new Error('Invalid value size.');
    return val.slice(0, size);
  }

  if (val.length === size)
    return val;

  const buf = Buffer.allocUnsafe(size);
  const pos = size - val.length;

  buf.fill(0x00, 0, pos);
  val.copy(buf, pos);

  return buf;
}

/*
 * Expose
 */

exports.ECSignature = ECSignature;
exports.fromDER = fromDER;
exports.fromLax = fromLax;
exports.toDER = toDER;
exports.reencode = reencode;
exports.isStrictDER = isStrictDER;
exports.isLowValue = isLowValue;
exports.isLowDER = isLowDER;
exports.isLowS = isLowS;
