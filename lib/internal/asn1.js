'use strict';

const assert = require('assert');
const BN = require('../bn');

/*
 * ASN1
 */

function readSize(data, pos) {
  assert(Buffer.isBuffer(data));
  assert((pos >>> 0) === pos);

  if (pos >= data.length)
    throw new Error('Invalid size.');

  const field = data[pos];
  const bytes = field & 0x7f;

  pos += 1;

  // Definite form
  if ((field & 0x80) === 0) {
    // Short form
    return [bytes, pos];
  }

  // Indefinite form.
  if (bytes === 0)
    throw new Error('Indefinite length.');

  let size = 0;

  for (let i = 0; i < bytes; i++) {
    assert(pos < data.length);

    const ch = data[pos];

    pos += 1;

    if (size >= (1 << 23))
      throw new Error('Length too large.');

    size *= 0x100;
    size += ch;

    if (size === 0)
      throw new Error('Unexpected leading zeroes.');
  }

  if (size < 0x80)
    throw new Error('Non-minimal length.');

  return [size, pos];
}

function readSeq(data, pos) {
  assert(Buffer.isBuffer(data));
  assert((pos >>> 0) === pos);

  if (pos >= data.length || data[pos] !== 0x30)
    throw new Error('Invalid sequence tag.');

  pos += 1;

  let size;
  [size, pos] = readSize(data, pos);

  if (pos + size !== data.length)
    throw new Error('Trailing bytes.');

  return pos;
}

function readInt(data, pos) {
  assert(Buffer.isBuffer(data));
  assert((pos >>> 0) === pos);

  if (pos >= data.length || data[pos] !== 0x02)
    throw new Error('Invalid integer tag.');

  pos += 1;

  let size;
  [size, pos] = readSize(data, pos);

  if (pos + size > data.length)
    throw new Error('Integer body out of bounds.');

  // No reason to have an integer larger than this.
  if (size === 0 || size > 1 + 2048)
    throw new Error('Invalid integer size.');

  // No negatives.
  if (data[pos] & 0x80)
    throw new Error('Integers must be positive.');

  // Allow zero only if it prefixes a high bit.
  if (size > 1) {
    if (data[pos] === 0x00 && (data[pos + 1] & 0x80) === 0x00)
      throw new Error('Unexpected leading zeroes.');
  }

  const num = BN.decode(data.slice(pos, pos + size));

  pos += size;

  return [num, pos];
}

function sizeSize(size) {
  assert((size >>> 0) === size);

  if (size <= 0x7f) // [size]
    return 1;

  if (size <= 0xff) // 0x81 [size]
    return 2;

  return 3; // 0x82 [size-hi] [size-lo]
}

function sizeInt(num) {
  assert(num instanceof BN);

  // 0x02 [size] [0x00?] [int]
  const bits = num.bitLength();

  let size = (bits + 7) >>> 3;

  if (bits > 0 && (bits & 7) === 0)
    size += num.testn(bits - 1);

  if (bits === 0)
    size = 1;

  return 1 + sizeSize(size) + size;
}

function writeSize(data, pos, size) {
  assert(Buffer.isBuffer(data));
  assert((pos >>> 0) === pos);
  assert((size >>> 0) === size);

  if (size <= 0x7f)  {
    // [size]
    data[pos++] = size;
  } else if (size <= 0xff) {
    // 0x81 [size]
    data[pos++] = 0x81;
    data[pos++] = size;
  } else {
    // 0x82 [size-hi] [size-lo]
    assert(size <= 0xffff);
    data[pos++] = 0x82;
    data[pos++] = size >> 8;
    data[pos++] = size & 0xff;
  }

  assert(pos <= data.length);

  return pos;
}

function writeInt(data, pos, num) {
  assert(Buffer.isBuffer(data));
  assert((pos >>> 0) === pos);
  assert(num instanceof BN);

  // 0x02 [size] [0x00?] [int]
  const bits = num.bitLength();

  let size = (bits + 7) >>> 3;
  let pad = 0;

  if (bits > 0 && (bits & 7) === 0)
    pad = num.testn(bits - 1);

  if (bits === 0)
    size = 1;

  data[pos++] = 0x02;

  pos = writeSize(data, pos, pad + size);

  if (pad)
    data[pos++] = 0x00;

  if (bits !== 0)
    num.encode().copy(data, pos);
  else
    data[pos] = 0x00;

  pos += size;

  assert(pos <= data.length);

  return pos;
}

/*
 * Expose
 */

exports.readSize = readSize;
exports.readSeq = readSeq;
exports.readInt = readInt;
exports.sizeSize = sizeSize;
exports.sizeInt = sizeInt;
exports.writeSize = writeSize;
exports.writeInt = writeInt;
