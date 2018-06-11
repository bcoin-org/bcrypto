/*!
 * der.js - DER encoding for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const bio = require('bufio');

/*
 * Constants
 */

const ZERO = Buffer.from([0x00]);
const SEQ = 0x10;
const INT = 0x02;

/*
 * Reading
 */

function readField(br, strict = false) {
  assert(br && typeof strict === 'boolean');

  let type = br.readU8();

  const primitive = (type & 0x20) === 0;

  if ((type & 0x1f) === 0x1f) {
    let oct = type;

    type = 0;

    while (oct & 0x80) {
      oct = br.readU8();
      type <<= 7;
      type |= oct & 0x7f;
    }

    if (strict) {
      if ((type & 0x1f) !== 0x1f)
        throw new Error('Non-minimal type.');
    }
  } else {
    type &= 0x1f;
  }

  const size = readSize(br, primitive, strict);

  return {
    type,
    primitive,
    size
  };
}

function readSize(br, primitive, strict = false) {
  let size = br.readU8();

  // Indefinite form
  if (!primitive && size === 0x80)
    throw new Error('Indefinite size.');

  // Definite form
  if ((size & 0x80) === 0) {
    // Short form
    return size;
  }

  // Long form
  const bytes = size & 0x7f;

  if (bytes > 2) // Should be 3.
    throw new Error('Length octet is too long.');

  size = 0;
  for (let i = 0; i < bytes; i++) {
    size <<= 8;
    size |= br.readU8();
  }

  if (strict) {
    let valid = true;

    switch (bytes) {
      case 3:
        valid = size > 0xffff;
        break;
      case 2:
        valid = size > 0xff;
        break;
      case 1:
        valid = (size & 0x80) !== 0;
        break;
      case 0:
        valid = false;
        break;
    }

    if (!valid)
      throw new Error('Non-minimal size.');
  }

  return size;
}

function readSeq(br, strict = false) {
  const tag = readField(br, strict);

  if (tag.primitive || tag.type !== SEQ)
    throw new Error(`Unexpected tag: ${tag.type}.`);

  let size = tag.size;

  if (!strict && br.left() < size)
    size = br.left();

  return br.readChild(size);
}

function readInt(br, strict = false) {
  const tag = readField(br, strict);

  if (!tag.primitive || tag.type !== INT)
    throw new Error(`Unexpected tag: ${tag.type}.`);

  let size = tag.size;

  if (!strict && br.left() < size)
    size = br.left();

  return decodeInteger(br.readBytes(size), strict);
}

/*
 * Writing
 */

function sizeRaw(size, len) {
  assert((size >>> 0) === size);
  assert((len >>> 0) === len);

  if (size <= 0x7f)
    return 1 + 1 + len;

  if (size <= 0xff)
    return 1 + 1 + 1 + len;

  assert(size <= 0xffff);

  return 1 + 1 + 2 + len;
}

function writeRaw(bw, type, size, buf) {
  assert(bw);
  assert((type >>> 0) === type);
  assert((size >>> 0) === size);
  assert(!buf || Buffer.isBuffer(buf));
  assert(!buf || buf.length === size);

  // Short form.
  if (size <= 0x7f) {
    bw.writeU8(type);
    bw.writeU8(size);

    if (buf)
      bw.writeBytes(buf);

    return bw;
  }

  // Long form (1 byte).
  if (size <= 0xff) {
    bw.writeU8(type);
    bw.writeU8(0x80 | 1);
    bw.writeU8(size);

    if (buf)
      bw.writeBytes(buf);

    return bw;
  }

  assert(size <= 0xffff);

  // Long form (2 bytes).
  bw.writeU8(type);
  bw.writeU8(0x80 | 2);
  bw.writeU16BE(size);

  if (buf)
    bw.writeBytes(buf);

  return bw;
}

function sizeHeader(size) {
  return sizeRaw(size, 0);
}

function sizeField(size) {
  return sizeRaw(size, size);
}

function writeHeader(bw, type, size) {
  return writeRaw(bw, type, size, null);
}

function writeField(bw, type, buf) {
  return writeRaw(bw, type, buf.length, buf);
}

function sizeSeq(size) {
  return sizeHeader(size);
}

function writeSeq(bw, size) {
  return writeHeader(bw, 0x20 | SEQ, size);
}

function sizeInt(buf) {
  return sizeField(sizeInteger(buf));
}

function writeInt(bw, buf) {
  return writeField(bw, INT, encodeInteger(buf));
}

/*
 * Integer Encoding
 */

function sizeInteger(val) {
  assert(Buffer.isBuffer(val));

  if (val.length === 0)
    return 1;

  let i = 0;

  for (; i < val.length; i++) {
    if (val[i] !== 0x00)
      break;
  }

  if (i === val.length)
    i -= 1;

  let len = val.length - i;

  if (val[i] & 0x80)
    len += 1;

  return len;
}

function encodeInteger(val) {
  assert(Buffer.isBuffer(val));

  if (val.length === 0)
    return ZERO;

  let i = 0;

  for (; i < val.length; i++) {
    if (val[i] !== 0x00)
      break;
  }

  if (i === val.length)
    i -= 1;

  if (val[i] & 0x80) {
    if (i === 0)
      return bio.concat(ZERO, val);
    return val.slice(i - 1);
  }

  return val.slice(i);
}

function decodeInteger(val, strict = false) {
  assert(Buffer.isBuffer(val));
  assert(typeof strict === 'boolean');

  if (val.length === 0) {
    if (strict)
      throw new Error('No integer.');
    return ZERO;
  }

  let i = 0;

  for (; i < val.length; i++) {
    if (val[i] !== 0x00)
      break;
  }

  if (i === val.length)
    i -= 1;

  if (strict) {
    if (i === 0 && (val[i] & 0x80))
      throw new Error('Integer is negative.');
  }

  if (i === 0)
    return val;

  if (strict) {
    if (i > 1)
      throw new Error('Unexpected zero byte.');

    if (!(val[i] & 0x80))
      throw new Error('Padded integer does not have hi bit.');
  }

  return val.slice(i);
}

/*
 * Expose
 */

exports.readSeq = readSeq;
exports.readInt = readInt;
exports.sizeSeq = sizeSeq;
exports.writeSeq = writeSeq;
exports.sizeInt = sizeInt;
exports.writeInt = writeInt;
