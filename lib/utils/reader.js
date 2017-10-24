/*!
 * reader.js - buffer reader for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');

const EMPTY = Buffer.alloc(0);

class BufferReader {
  /**
   * An object that allows reading of buffers in a sane manner.
   * @alias module:utils.BufferReader
   * @constructor
   * @param {Buffer} data
   * @param {Boolean?} zeroCopy - Do not reallocate buffers when
   * slicing. Note that this can lead to memory leaks if not used
   * carefully.
   */

  constructor(data, zeroCopy) {
    assert(Buffer.isBuffer(data), 'Must pass a Buffer.');

    this.data = data;
    this.offset = 0;
    this.zeroCopy = zeroCopy || false;
    this.stack = [];
  }

  /**
   * Assertion.
   * @param {Boolean} value
   */

  assert(value) {
    if (!value)
      throw new Error('Out of bounds read');
  }

  /**
   * Assertion.
   * @param {Boolean} value
   * @param {String} reason
   */

  enforce(value, reason) {
    if (!value)
      throw new Error(reason);
  }

  /**
   * Get total size of passed-in Buffer.
   * @returns {Buffer}
   */

  getSize() {
    return this.data.length;
  }

  /**
   * Calculate number of bytes left to read.
   * @returns {Number}
   */

  left() {
    this.assert(this.offset <= this.data.length);
    return this.data.length - this.offset;
  }

  /**
   * Seek to a position to read from by offset.
   * @param {Number} off - Offset (positive or negative).
   */

  seek(off) {
    this.assert(this.offset + off >= 0);
    this.assert(this.offset + off <= this.data.length);
    this.offset += off;
    return off;
  }

  /**
   * Mark the current starting position.
   */

  start() {
    this.stack.push(this.offset);
    return this.offset;
  }

  /**
   * Stop reading. Pop the start position off the stack
   * and calculate the size of the data read.
   * @returns {Number} Size.
   * @throws on empty stack.
   */

  end() {
    assert(this.stack.length > 0);

    const start = this.stack.pop();

    return this.offset - start;
  }

  /**
   * Stop reading. Pop the start position off the stack
   * and return the data read.
   * @param {Bolean?} zeroCopy - Do a fast buffer
   * slice instead of allocating a new buffer (warning:
   * may cause memory leaks if not used with care).
   * @returns {Buffer} Data read.
   * @throws on empty stack.
   */

  endData(zeroCopy) {
    assert(this.stack.length > 0);

    const start = this.stack.pop();
    const end = this.offset;
    const size = end - start;
    const data = this.data;

    if (size === data.length)
      return data;

    if (this.zeroCopy || zeroCopy)
      return data.slice(start, end);

    const ret = Buffer.allocUnsafe(size);
    data.copy(ret, 0, start, end);

    return ret;
  }

  /**
   * Destroy the reader. Remove references to the data.
   */

  destroy() {
    this.data = EMPTY;
    this.offset = 0;
    this.stack.length = 0;
  }

  /**
   * Read uint8.
   * @returns {Number}
   */

  readU8() {
    this.assert(this.offset + 1 <= this.data.length);
    const ret = this.data[this.offset];
    this.offset += 1;
    return ret;
  }

  /**
   * Read uint16le.
   * @returns {Number}
   */

  readU16() {
    this.assert(this.offset + 2 <= this.data.length);
    const ret = this.data.readUInt16LE(this.offset, true);
    this.offset += 2;
    return ret;
  }

  /**
   * Read uint16be.
   * @returns {Number}
   */

  readU16BE() {
    this.assert(this.offset + 2 <= this.data.length);
    const ret = this.data.readUInt16BE(this.offset, true);
    this.offset += 2;
    return ret;
  }

  /**
   * Read uint32le.
   * @returns {Number}
   */

  readU32() {
    this.assert(this.offset + 4 <= this.data.length);
    const ret = this.data.readUInt32LE(this.offset, true);
    this.offset += 4;
    return ret;
  }

  /**
   * Read uint32be.
   * @returns {Number}
   */

  readU32BE() {
    this.assert(this.offset + 4 <= this.data.length);
    const ret = this.data.readUInt32BE(this.offset, true);
    this.offset += 4;
    return ret;
  }

  /**
   * Read int8.
   * @returns {Number}
   */

  readI8() {
    this.assert(this.offset + 1 <= this.data.length);
    const ret = this.data.readInt8(this.offset, true);
    this.offset += 1;
    return ret;
  }

  /**
   * Read int16le.
   * @returns {Number}
   */

  readI16() {
    this.assert(this.offset + 2 <= this.data.length);
    const ret = this.data.readInt16LE(this.offset, true);
    this.offset += 2;
    return ret;
  }

  /**
   * Read int16be.
   * @returns {Number}
   */

  readI16BE() {
    this.assert(this.offset + 2 <= this.data.length);
    const ret = this.data.readInt16BE(this.offset, true);
    this.offset += 2;
    return ret;
  }

  /**
   * Read int32le.
   * @returns {Number}
   */

  readI32() {
    this.assert(this.offset + 4 <= this.data.length);
    const ret = this.data.readInt32LE(this.offset, true);
    this.offset += 4;
    return ret;
  }

  /**
   * Read int32be.
   * @returns {Number}
   */

  readI32BE() {
    this.assert(this.offset + 4 <= this.data.length);
    const ret = this.data.readInt32BE(this.offset, true);
    this.offset += 4;
    return ret;
  }

  /**
   * Read float le.
   * @returns {Number}
   */

  readFloat() {
    this.assert(this.offset + 4 <= this.data.length);
    const ret = this.data.readFloatLE(this.offset, true);
    this.offset += 4;
    return ret;
  }

  /**
   * Read float be.
   * @returns {Number}
   */

  readFloatBE() {
    this.assert(this.offset + 4 <= this.data.length);
    const ret = this.data.readFloatBE(this.offset, true);
    this.offset += 4;
    return ret;
  }

  /**
   * Read double float le.
   * @returns {Number}
   */

  readDouble() {
    this.assert(this.offset + 8 <= this.data.length);
    const ret = this.data.readDoubleLE(this.offset, true);
    this.offset += 8;
    return ret;
  }

  /**
   * Read double float be.
   * @returns {Number}
   */

  readDoubleBE() {
    this.assert(this.offset + 8 <= this.data.length);
    const ret = this.data.readDoubleBE(this.offset, true);
    this.offset += 8;
    return ret;
  }

  /**
   * Read N bytes (will do a fast slice if zero copy).
   * @param {Number} size
   * @param {Bolean?} zeroCopy - Do a fast buffer
   * slice instead of allocating a new buffer (warning:
   * may cause memory leaks if not used with care).
   * @returns {Buffer}
   */

  readBytes(size, zeroCopy) {
    assert(size >= 0);
    this.assert(this.offset + size <= this.data.length);

    let ret;
    if (this.zeroCopy || zeroCopy) {
      ret = this.data.slice(this.offset, this.offset + size);
    } else {
      ret = Buffer.allocUnsafe(size);
      this.data.copy(ret, 0, this.offset, this.offset + size);
    }

    this.offset += size;

    return ret;
  }

  /**
   * Read a string.
   * @param {String} enc - Any buffer-supported encoding.
   * @param {Number} size
   * @returns {String}
   */

  readString(enc, size) {
    assert(size >= 0);
    this.assert(this.offset + size <= this.data.length);
    const ret = this.data.toString(enc, this.offset, this.offset + size);
    this.offset += size;
    return ret;
  }
}

/*
 * Expose
 */

module.exports = BufferReader;
