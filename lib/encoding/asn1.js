/*!
 * asn1.js - ASN1 encoding for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Parts of this software are based on indutny/asn1.js:
 *   Copyright Fedor Indutny, 2013.
 *   https://github.com/indutny/asn1.js
 *
 * Resources:
 *   https://github.com/indutny/asn1.js/blob/master/rfc/2560/index.js
 *   https://github.com/indutny/asn1.js/blob/master/rfc/5280/index.js
 *   https://github.com/indutny/asn1.js/blob/master/lib/asn1/base/node.js
 *   https://github.com/indutny/asn1.js/blob/master/lib/asn1/encoders/der.js
 *   https://github.com/indutny/asn1.js/blob/master/lib/asn1/decoders/der.js
 *   https://github.com/openssl/openssl/blob/master/include/openssl/asn1.h
 */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const objects = require('../internal/objects');

/*
 * Constants
 */

const EMPTY = Buffer.alloc(0);
const ZERO = Buffer.alloc(1, 0x00);
const EMPTY_OID = new Uint32Array(2);

const types = {
  EOC: 0,
  BOOLEAN: 1,
  INTEGER: 2,
  BITSTRING: 3,
  OCTSTRING: 4,
  NULL: 5,
  OID: 6,
  OBJDESC: 7,
  EXTERNAL: 8,
  REAL: 9,
  ENUM: 10,
  // EMBED: 11,
  UTF8STRING: 12,
  // ROID: 13,
  SEQUENCE: 16,
  SET: 17,
  NUMSTRING: 18,
  PRINTSTRING: 19,
  T61STRING: 20,
  VIDEOSTRING: 21,
  IA5STRING: 22,
  UTCTIME: 23,
  GENTIME: 24,
  GRAPHSTRING: 25,
  ISO64STRING: 26,
  GENSTRING: 27,
  UNISTRING: 28,
  // CHARSTRING: 29,
  BMPSTRING: 30
};

const typesByVal = {
  0: 'EOC',
  1: 'BOOLEAN',
  2: 'INTEGER',
  3: 'BITSTRING',
  4: 'OCTSTRING',
  5: 'NULL',
  6: 'OID',
  7: 'OBJDESC',
  8: 'EXTERNAL',
  9: 'REAL',
  10: 'ENUM',
  // 11: 'EMBED',
  12: 'UTF8STRING',
  // 13: 'ROID',
  16: 'SEQUENCE',
  17: 'SET',
  18: 'NUMSTRING',
  19: 'PRINTSTRING',
  20: 'T61STRING',
  21: 'VIDEOSTRING',
  22: 'IA5STRING',
  23: 'UTCTIME',
  24: 'GENTIME',
  25: 'GRAPHSTRING',
  26: 'ISO64STRING',
  27: 'GENSTRING',
  28: 'UNISTRING',
  // 29: 'CHARSTRING',
  30: 'BMPSTRING'
};

const classes = {
  UNIVERSAL: 0,
  APPLICATION: 1,
  CONTEXT: 2,
  PRIVATE: 3
};

const classesByVal = {
  0: 'UNIVERSAL',
  1: 'APPLICATION',
  2: 'CONTEXT',
  3: 'PRIVATE'
};

const NORMAL = 0;
const EXPLICIT = 1;
const IMPLICIT = 2;

/**
 * Node
 */

class Node extends bio.Struct {
  constructor() {
    super();

    this._flags = 0;
    this._def = null;
  }

  get _mode() {
    return (this._flags >>> 9) & 0xff;
  }

  set _mode(value) {
    this._flags &= ~(0xff << 9);
    this._flags |= value << 9;
  }

  get _optional() {
    return (this._flags >>> 8) & 1;
  }

  set _optional(value) {
    const bit = value ? 1 : 0;
    this._flags &= ~(1 << 8);
    this._flags |= bit << 8;
  }

  get _target() {
    return this._flags & 0xff;
  }

  set _target(value) {
    this._flags &= ~0xff;
    this._flags |= value;
  }

  get any() {
    return false;
  }

  explicit(target) {
    assert((target >>> 0) === target);
    this._mode = 1;
    this._target = target;
    return this;
  }

  implicit(target) {
    assert((target >>> 0) === target);
    this._mode = 2;
    this._target = target;
    return this;
  }

  optional() {
    this._optional = true;
    return this;
  }

  instance(value) {
    const Element = typeToClass(this.type);
    return new Element(value);
  }

  clean() {
    return false;
  }

  isNull() {
    if (this._def)
      return this.equals(this._def);
    return this.clean();
  }

  equals(el) {
    assert(el instanceof Node);

    if (this.type !== el.type)
      return false;

    return this.encodeBody().equals(el.encodeBody());
  }

  def(value) {
    this._def = this.instance(value);
    this._optional = true;
    return this;
  }

  getBodySize() {
    return 0;
  }

  writeBody(bw) {
    return bw;
  }

  readBody(br) {
    return this;
  }

  encodeBody() {
    const size = this.getBodySize();
    const bw = bio.write(size);
    this.writeBody(bw);
    return bw.render();
  }

  decodeBody(data) {
    const br = bio.read(data);
    return this.readBody(br);
  }

  set() {
    return this;
  }

  from(options, ...extra) {
    if (options == null)
      return this;

    return this.set(options, ...extra);
  }

  error(str) {
    if (this._optional) {
      if (this._def)
        return this._def.clone();
      return this;
    }

    const err = new Error(str);

    if (Error.captureStackTrace)
      Error.captureStackTrace(err, this.error);

    throw err;
  }

  getSize() {
    if (this._optional && this.isNull())
      return 0;

    const body = this.getBodySize();

    let size = 0;

    size += sizeHeader(body);
    size += body;

    if (this._mode === EXPLICIT)
      size += sizeHeader(size);

    return size;
  }

  write(bw) {
    if (this._optional && this.isNull())
      return bw;

    const body = this.getBodySize();

    switch (this._mode) {
      case EXPLICIT: {
        const size = sizeHeader(body) + body;
        writeHeader(bw, this._target, classes.CONTEXT, false, size);
        // fall through
      }
      case NORMAL: {
        const primitive = this.type !== types.SEQUENCE
                       && this.type !== types.SET;
        writeHeader(bw, this.type, classes.UNIVERSAL, primitive, body);
        break;
      }
      case IMPLICIT: {
        const primitive = this.type !== types.SEQUENCE
                       && this.type !== types.SET;
        writeHeader(bw, this._target, classes.CONTEXT, primitive, body);
        break;
      }
      default: {
        throw new assert.AssertionError('Invalid mode.');
      }
    }

    return this.writeBody(bw);
  }

  read(br) {
    switch (this._mode) {
      case EXPLICIT: {
        if (this.any)
          throw new Error('Cannot read any for explicit field.');

        const hdr = peekHeader(br, this._optional);

        if (!hdr)
          return this;

        if (hdr.cls !== classes.CONTEXT)
          return this.error(`Unexpected class: ${hdr.cls}.`);

        if (hdr.primitive)
          return this.error('Unexpected primitive flag.');

        if (hdr.type !== this._target)
          return this.error(`Unexpected type: ${hdr.type}.`);

        br.seek(hdr.len);
        br = br.readChild(hdr.size);

        // Fall through.
      }

      case NORMAL: {
        const hdr = peekHeader(br, this._optional);

        if (!hdr)
          return this;

        if (hdr.cls !== classes.UNIVERSAL)
          return this.error(`Unexpected class: ${hdr.cls}.`);

        if (this.any)
          this.type = hdr.type;

        const primitive = this.type !== types.SEQUENCE
                       && this.type !== types.SET;

        if (hdr.primitive !== primitive)
          return this.error('Unexpected primitive flag.');

        if (hdr.type !== this.type)
          return this.error(`Unexpected type: ${hdr.type}.`);

        br.seek(hdr.len);

        const child = br.readChild(hdr.size);

        return this.readBody(child);
      }

      case IMPLICIT: {
        if (this.any)
          return this.error('Cannot read any for implicit field.');

        const hdr = peekHeader(br, this._optional);

        if (!hdr)
          return this;

        if (hdr.cls !== classes.CONTEXT)
          return this.error(`Unexpected class: ${hdr.cls}.`);

        const primitive = this.type !== types.SEQUENCE
                       && this.type !== types.SET;

        if (hdr.primitive !== primitive)
          return this.error('Unexpected primitive flag.');

        if (hdr.type !== this._target)
          return this.error(`Unexpected type: ${hdr.type}.`);

        br.seek(hdr.len);

        const child = br.readChild(hdr.size);

        return this.readBody(child);
      }

      default: {
        throw new assert.AssertionError('Invalid mode.');
      }
    }
  }

  typeName() {
    return typesByVal[this.type] || 'UNKNOWN';
  }

  fromArray(value) {
    return this;
  }

  fromNumber(num) {
    return this;
  }

  fromPEM(num) {
    return this;
  }

  static fromArray(value) {
    return new this().fromArray(value);
  }

  static fromNumber(num) {
    return new this().fromNumber(num);
  }

  static fromPEM(str) {
    return new this().fromPEM(str);
  }
}

/**
 * Sequence
 */

class Sequence extends Node {
  constructor(...options) {
    super();
    this.from(...options);
  }

  get type() {
    return types.SEQUENCE;
  }
};

/**
 * Set
 */

class Set extends Node {
  constructor(...options) {
    super();
    this.from(...options);
  }

  get type() {
    return types.SET;
  }
};

/**
 * Choice
 */

class Choice extends Node {
  constructor(node, ...options) {
    super();
    assert(node instanceof Node);
    this.node = node;
    this.from(...options);
  }

  get type() {
    return this.node.type;
  }

  choose() {
    throw new Error('Unimplemented.');
  }

  getSize() {
    return this.node.getSize();
  }

  write(bw) {
    assert(bw);
    assert(this.node instanceof Node);
    this.node._flags = this._flags;
    this.node.write(bw);
    return bw;
  }

  read(br) {
    assert(br);

    const types = this.choose();

    assert(Array.isArray(types));
    assert(types.length >= 1);

    const hdr = peekHeader(br, this._optional);

    if (!hdr)
      return this;

    const {type} = hdr;

    for (const target of types) {
      assert((target >>> 0) === target);

      if (type !== target)
        continue;

      const Element = typeToClass(type);
      const el = new Element();
      el._flags = this._flags;
      this.node = el.read(br);
      return this;
    }

    throw new Error(`Could not satisfy choice for: ${type}.`);
  }

  getBodySize() {
    return this.node.getBodySize();
  }

  writeBody(bw) {
    return this.node.writeBody(bw);
  }

  readBody(br) {
    this.node.readBody(br);
    return this;
  }

  set(...options) {
    return this.node.set(...options);
  }

  isNull() {
    return this.node.isNull();
  }

  clean() {
    return this.node.clean();
  }

  format() {
    return this.node;
  }
}

/**
 * Element
 */

class Element extends Node {
  constructor(...options) {
    super();
    this.from(...options);
  }

  getBodySize() {
    return this.value.length;
  }

  writeBody(bw) {
    bw.writeBytes(this.value);
    return bw;
  }

  readBody(br) {
    this.value = br.readBytes(br.left());
    return this;
  }

  set(value) {
    assert(Buffer.isBuffer(value));
    this.value = value;
    return this;
  }

  clean() {
    return this.value.length === 0;
  }

  format() {
    let value = this.value;

    if (value.length > 32)
      value = value.slice(0, 32);

    return `<${this.constructor.name}: ${value.toString('hex')}>`;
  }
}

/**
 * Unknown
 */

class Unknown extends Element {
  constructor(...options) {
    super(...options);
    this.type = types.NULL;
  }

  get any() {
    return true;
  }
}

/**
 * Any
 */

class Any extends Element {
  constructor() {
    super();
    this.type = types.NULL;
  }

  explicit(target) {
    throw new Error('Cannot set explicit on any.');
  }

  implicit(target) {
    throw new Error('Cannot set implicit on any.');
  }

  decode(data) {
    const br = bio.read(data);
    return this.read(br);
  }

  read(br) {
    assert(this._mode === 0);
    const el = maybeReadAny(br, this._optional);
    el._flags = this._flags;
    return el;
  }

  set(el) {
    assert(el instanceof Node);
    el._flags = this._flags;
    return el;
  }
}

/**
 * String
 */

const Str = class String extends Node {
  constructor(...options) {
    super();
    this.value = '';
    this.from(...options);
  }

  get encoding() {
    return 'binary';
  }

  getBodySize() {
    return Buffer.byteLength(this.value, this.encoding);
  }

  writeBody(bw) {
    bw.writeString(this.value, this.encoding);
    return bw;
  }

  readBody(br) {
    const str = br.readString(br.left(), this.encoding);

    switch (this.type) {
      case types.NUMSTRING: {
        if (!isNumString(str))
          throw new Error('Invalid num string.');
        break;
      }

      case types.PRINTSTRING: {
        if (!isPrintString(str))
          throw new Error('Invalid print string.');
        break;
      }
    }

    this.value = str;

    return this;
  }

  set(value) {
    assert(typeof value === 'string');
    this.value = value;
    return this;
  }

  clean() {
    return this.value === '';
  }

  format() {
    return `<${this.constructor.name}: ${this.value}>`;
  }
};

/**
 * EOC
 */

class EOC extends Node {
  constructor() {
    super();
  }

  get type() {
    return types.EOC;
  }

  getBodySize() {
    return 0;
  }

  writeBody(bw) {
    return bw;
  }

  readBody(br) {
    assert(br.left() === 0);
    return this;
  }

  set(...options) {
    return this;
  }

  clean() {
    return true;
  }

  format() {
    return `<${this.constructor.name}>`;
  }
}

/**
 * Boolean
 */

const Bool = class Boolean extends Node {
  constructor(...options) {
    super();
    this.value = false;
    this.from(...options);
  }

  get type() {
    return types.BOOLEAN;
  }

  getBodySize() {
    return 1;
  }

  writeBody(bw) {
    bw.writeU8(this.value ? 0xff : 0x00);
    return bw;
  }

  readBody(br) {
    const value = br.readU8();

    if (value !== 0x00 && value !== 0xff)
      throw new Error('Invalid boolean.');

    this.value = value === 0xff;

    return this;
  }

  set(value) {
    assert(typeof value === 'boolean');
    this.value = value;
    return this;
  }

  clean() {
    return this.value === false;
  }

  format() {
    return this.value;
  }
};

/**
 * Integer
 */

class Integer extends Node {
  constructor(...options) {
    super();
    this.value = ZERO;
    this.negative = false;
    this.from(...options);
  }

  get type() {
    return types.INTEGER;
  }

  getBodySize() {
    const b = this.value;

    if (b.length === 0)
      return 1;

    let pad = 0;
    let size = 0;

    if (!this.negative && b[0] > 127) {
      pad = 1;
    } else if (this.negative) {
      if (b[0] > 128) {
        pad = 1;
      } else if (b[0] === 128) {
        pad = 0;
        for (let i = 1; i < b.length; i++)
          pad |= b[i];
        pad = pad ? 1 : 0;
      }
    }

    size += pad;
    size += b.length;

    return size;
  }

  writeBody(bw) {
    const b = this.value;

    if (b.length === 0) {
      bw.writeU8(0x00);
      return bw;
    }

    let pad = 0;
    let pb = 0;

    if (!this.negative && b[0] > 127) {
      pad = 1;
      pb = 0;
    } else if (this.negative) {
      pb = 0xff;
      if (b[0] > 128) {
        pad = 1;
      } else if (b[0] === 128) {
        pad = 0;
        for (let i = 1; i < b.length; i++)
          pad |= b[i];
        pb = pad !== 0 ? 0xff : 0;
        pad = pb & 1;
      }
    }

    if (pad)
      bw.writeU8(pb);

    const start = bw.offset;

    bw.writeBytes(b);

    if (pb)
      twosComplement(bw.data, start, bw.offset);

    return this;
  }

  readBody(br) {
    let p = br.readBytes(br.left());

    if (p.length === 0)
      throw new Error('Zero-length integer.');

    const neg = p[0] & 0x80;

    if (p.length === 1) {
      if (neg)
        p[0] = (p[0] ^ 0xff) + 1;

      this.negative = neg !== 0;
      this.value = p;

      return this;
    }

    let pad = 0;

    if (p[0] === 0x00) {
      pad = 1;
    } else if (p[0] === 0xff) {
      for (let i = 1; i < p.length; i++)
        pad |= p[i];
      pad = pad !== 0 ? 1 : 0;
    }

    if (pad && neg === (p[1] & 0x80))
      throw new Error('Invalid integer padding.');

    if (pad)
      p = p.slice(1);

    if (neg)
      twosComplement(p, 0, p.length);

    this.negative = neg !== 0;
    this.value = p;

    return this;
  }

  set(value, negative) {
    if (typeof value === 'number')
      return this.fromNumber(value);

    assert(Buffer.isBuffer(value));

    this.value = value;

    if (negative != null) {
      assert(typeof negative === 'boolean');
      this.negative = negative;
    }

    return this;
  }

  clean() {
    return !this.negative && this.value.equals(ZERO);
  }

  formatValue() {
    return this.value.toString('hex');
  }

  toNumber() {
    let num = bio.readUBE(this.value, 0, this.value.length);

    if (this.negative)
      num = -num;

    return num;
  }

  fromNumber(num) {
    assert(Number.isSafeInteger(num));

    const buf = Buffer.allocUnsafe(8);

    if (num < 0) {
      this.negative = true;
      num = -num;
    }

    bio.writeU64BE(buf, num, 0);

    this.value = trimZeroes(buf);

    return this;
  }

  format() {
    const name = this.constructor.name;

    if (this.value.length <= 6)
      return `<${name}: ${this.toNumber()}>`;

    const sign = this.negative ? '-' : '';
    const hex = this.value.toString('hex');

    return `<${name}: ${sign}0x${hex}>`;
  }
}

/**
 * BitString
 */

class BitString extends Node {
  constructor(...options) {
    super();
    this.value = EMPTY;
    this.from(...options);
  }

  get type() {
    return types.BITSTRING;
  }

  getBodySize() {
    return 1 + this.value.length;
  }

  writeBody(bw) {
    bw.writeU8(0);
    bw.writeBytes(this.value);
    return bw;
  }

  readBody(br) {
    const padding = br.readU8();
    const data = br.readBytes(br.left(), true);
    const bits = data.length * 8 - padding;
    const shift = 8 - (bits % 8);

    if (shift === 8 || data.length === 0) {
      this.value = Buffer.from(data);
      return this;
    }

    const out = Buffer.allocUnsafe(data.length);
    out[0] = data[0] >>> shift;

    for (let i = 1; i < data.length; i++) {
      out[i] = data[i - 1] << (8 - shift);
      out[i] |= data[i] >>> shift;
    }

    this.value = out;

    return this;
  }

  set(value) {
    assert(Buffer.isBuffer(value));
    this.value = value;
    return this;
  }

  clean() {
    return this.value.length === 0;
  }

  format() {
    let value = this.value;

    if (value.length > 32)
      value = value.slice(0, 32);

    return `<${this.constructor.name}: ${value.toString('hex')}>`;
  }
}

/**
 * OctString
 */

class OctString extends Element {
  constructor(...options) {
    super(...options);
  }

  get type() {
    return types.OCTSTRING;
  }
}

/**
 * Null
 */

class Null extends Node {
  constructor(...options) {
    super();
    this.from(...options);
  }

  get type() {
    return types.NULL;
  }

  getBodySize() {
    return 0;
  }

  writeBody(bw) {
    return bw;
  }

  readBody(br) {
    assert(br.left() === 0);
    return this;
  }

  set(...options) {
    return this;
  }

  clean() {
    return true;
  }

  format() {
    return `<${this.constructor.name}>`;
  }
}

/**
 * OID
 */

class OID extends Node {
  constructor(...options) {
    super();
    this.value = EMPTY_OID;
    this.from(...options);
  }

  get type() {
    return types.OID;
  }

  getBodySize() {
    const id = this.value;

    let size = 0;

    for (let i = 0; i < id.length; i++) {
      let ident = id[i];

      if (this.type === types.OID && i === 0) {
        if (id[1] >= 40)
          throw new Error('Second objid identifier OOB');

        ident = id[0] * 40 + id[1];
        i = 1;
      }

      size += 1;

      while (ident >= 0x80) {
        size += 1;
        ident >>>= 7;
      }
    }

    return size;
  }

  writeBody(bw) {
    const id = this.value;
    const size = this.getBodySize();

    let offset = bw.offset + size - 1;

    assert(offset >= 0);
    assert(offset < bw.data.length);

    for (let i = id.length - 1; i >= 0; i--) {
      let ident = id[i];

      if (this.type === types.OID && i === 1) {
        ident = id[0] * 40 + id[1];
        i = 0;
      }

      bw.data[offset] = ident & 0x7f;
      offset -= 1;

      while ((ident >>>= 7) > 0) {
        bw.data[offset] = 0x80 | (ident & 0x7f);
        offset -= 1;
      }
    }

    assert(offset === bw.offset - 1);
    bw.offset += size;

    return bw;
  }

  readBody(br) {
    const data = br.readBytes(br.left(), true);
    const ids = [];

    let ident = 0;
    let subident = 0;

    for (let i = 0; i < data.length; i++) {
      subident = data[i];
      ident <<= 7;
      ident |= subident & 0x7f;

      if ((subident & 0x80) === 0) {
        ids.push(ident);
        ident = 0;
      }
    }

    if (subident & 0x80)
      ids.push(ident);

    let result = null;

    if (this.type === types.OID) {
      if (ids.length < 1)
        throw new Error('Invalid OID.');

      result = new Uint32Array(2 + ids.length - 1);
      result[0] = (ids[0] / 40) >>> 0;
      result[1] = ids[0] % 40;

      for (let i = 1, j = 2; i < ids.length; i++, j++)
        result[j] = ids[i];
    } else {
      result = new Uint32Array(ids.length);

      for (let i = 0; i < ids.length; i++)
        result[i] = ids[i];
    }

    this.value = result;

    return this;
  }

  set(value) {
    if (typeof value === 'string')
      return this.fromString(value);

    if (Array.isArray(value))
      return this.fromArray(value);

    assert(value instanceof Uint32Array);
    this.value = value;

    return this;
  }

  clean() {
    return isEqual(this.value, EMPTY_OID);
  }

  toArray() {
    const arr = [];

    for (let i = 0; i < this.value.length; i++)
      arr.push(this.value[i]);

    return arr;
  }

  fromArray(arr) {
    assert(Array.isArray(arr));

    const out = new Uint32Array(arr.length);

    for (let i = 0; i < arr.length; i++) {
      const val = arr[i];
      assert((val >>> 0) === val);
      out[i] = val;
    }

    this.value = out;

    return this;
  }

  toString() {
    return this.toArray().join('.');
  }

  fromString(str) {
    assert(typeof str === 'string');

    str = str.toLowerCase();

    if (objects.keyOid.hasOwnProperty(str))
      str = objects.keyOid[str];
    else if (objects.curveOid.hasOwnProperty(str))
      str = objects.curveOid[str];

    const parts = str.split('.');
    const out = new Uint32Array(parts.length);

    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      out[i] = parseU32(part);
    }

    this.value = out;

    return this;
  }

  getSignature() {
    return objects.oidToSig[this.toString()] || null;
  }

  getKey() {
    return objects.oidToKey[this.toString()] || null;
  }

  getHash() {
    return objects.oidToHash[this.toString()] || null;
  }

  getCurve() {
    return objects.oidToCurve[this.toString()] || null;
  }

  format() {
    let str = this.toString();
    let name = objects.oidToSig[str]
            || objects.oidToKey[str]
            || objects.oidToHash[str]
            || objects.oidToCurve[str];

    if (name) {
      if (typeof name === 'object') {
        const obj = name;
        name = obj.key;
        if (obj.hash)
          name += `-${obj.hash}`;
      }

      str += ` (${name.toUpperCase()})`;
    }

    return `<${this.constructor.name}: ${str}>`;
  }
}

/**
 * ObjDesc
 */

class ObjDesc extends Element {
  constructor(...options) {
    super(...options);
  }

  get type() {
    return types.OBJDESC;
  }
}

/**
 * External
 */

class External extends Element {
  constructor(...options) {
    super(...options);
  }

  get type() {
    return types.EXTERNAL;
  }
}

/**
 * Real
 */

class Real extends Element {
  constructor(...options) {
    super(...options);
  }

  get type() {
    return types.REAL;
  }
}

/**
 * Enum
 */

class Enum extends Integer {
  constructor(...options) {
    super(...options);
  }

  get type() {
    return types.ENUM;
  }
}

/**
 * Utf8String
 */

class Utf8String extends Str {
  constructor(...options) {
    super(...options);
  }

  get type() {
    return types.UTF8STRING;
  }

  get encoding() {
    return 'utf8';
  }
}

/**
 * RawSequence
 */

class RawSequence extends Element {
  constructor(...options) {
    super(...options);
  }

  get type() {
    return types.SEQUENCE;
  }

  *children() {
    const br = bio.read(this.value);

    while (br.left())
      yield readAny(br);
  }

  set(value) {
    if (Array.isArray(value))
      return this.fromArray(value);

    assert(Buffer.isBuffer(value));

    this.value = value;

    return this;
  }

  toArray() {
    const out = [];

    for (const el of this.children())
      out.push(el);

    return out;
  }

  fromArray(value) {
    assert(Array.isArray(value));

    let size = 0;

    for (const el of value) {
      assert(el instanceof Node);
      size += el.getSize();
    }

    const bw = bio.write(size);

    for (const el of value)
      el.write(bw);

    this.value = bw.render();

    return this;
  }

  format() {
    return this.toArray();
  }
}

/**
 * RawSet
 */

class RawSet extends RawSequence {
  constructor(...options) {
    super(...options);
  }

  get type() {
    return types.SET;
  }
}

/**
 * NumString
 */

class NumString extends Str {
  constructor(...options) {
    super(...options);
  }

  get type() {
    return types.NUMSTRING;
  }
}

/**
 * PrintString
 */

class PrintString extends Str {
  constructor(...options) {
    super(...options);
  }

  get type() {
    return types.PRINTSTRING;
  }
}

/**
 * T61String
 */

class T61String extends Str {
  constructor(...options) {
    super(...options);
  }

  get type() {
    return types.T61STRING;
  }
}

/**
 * VideoString
 */

class VideoString extends Str {
  constructor(...options) {
    super(...options);
  }

  get type() {
    return types.VIDEOSTRING;
  }
}

/**
 * IA5String
 */

class IA5String extends Str {
  constructor(...options) {
    super(...options);
  }

  get type() {
    return types.IA5STRING;
  }
}

/**
 * UTCTime
 */

class UTCTime extends Node {
  constructor(...options) {
    super();
    this.value = 0;
    this.from(...options);
  }

  get type() {
    return types.UTCTIME;
  }

  getBodySize() {
    return 13;
  }

  writeBody(bw) {
    const date = new Date(this.value * 1000);

    const str = [
      two(date.getUTCFullYear() % 100),
      two(date.getUTCMonth() + 1),
      two(date.getUTCDate()),
      two(date.getUTCHours()),
      two(date.getUTCMinutes()),
      two(date.getUTCSeconds()),
      'Z'
    ].join('');

    bw.writeString(str, 'binary');

    return bw;
  }

  readBody(br) {
    const str = br.readString(br.left(), 'binary');
    assert(str.length >= 12);

    const yr = parseU32(str.substring(0, 2));
    const mon = parseU32(str.substring(2, 4));
    const day = parseU32(str.substring(4, 6));
    const hour = parseU32(str.substring(6, 8));
    const min = parseU32(str.substring(8, 10));
    const sec = parseU32(str.substring(10, 12));

    let year = yr;

    if (year < 70)
      year = 2000 + year;
    else
      year = 1900 + year;

    this.value = Date.UTC(year, mon - 1, day, hour, min, sec, 0) / 1000;

    assert(Number.isSafeInteger(this.value));

    return this;
  }

  set(value) {
    assert(Number.isSafeInteger(value) && value >= 0);
    this.value = value;
    return this;
  }

  clean() {
    return this.value === 0;
  }

  format() {
    return `<${this.constructor.name}: ${this.value}>`;
  }
}

/**
 * GenTime
 */

class GenTime extends Node {
  constructor(...options) {
    super();
    this.value = 0;
    this.from(...options);
  }

  get type() {
    return types.GENTIME;
  }

  getBodySize() {
    return 15;
  }

  writeBody(bw) {
    const date = new Date(this.value * 1000);

    const str = [
      date.getUTCFullYear().toString(10),
      two(date.getUTCMonth() + 1),
      two(date.getUTCDate()),
      two(date.getUTCHours()),
      two(date.getUTCMinutes()),
      two(date.getUTCSeconds()),
      'Z'
    ].join('');

    bw.writeString(str, 'binary');

    return bw;
  }

  readBody(br) {
    const str = br.readString(br.left(), 'binary');

    assert(str.length >= 14);

    const year = parseU32(str.substring(0, 4));
    const mon = parseU32(str.substring(4, 6));
    const day = parseU32(str.substring(6, 8));
    const hour = parseU32(str.substring(8, 10));
    const min = parseU32(str.substring(10, 12));
    const sec = parseU32(str.substring(12, 14));

    this.value = Date.UTC(year, mon - 1, day, hour, min, sec, 0) / 1000;

    assert(Number.isSafeInteger(this.value));

    return this;
  }

  set(value) {
    assert(Number.isSafeInteger(value) && value >= 0);
    this.value = value;
    return this;
  }

  clean() {
    return this.value === 0;
  }

  format() {
    return `<${this.constructor.name}: ${this.value}>`;
  }
}

/**
 * GraphString
 */

class GraphString extends Str {
  constructor(...options) {
    super(...options);
  }

  get type() {
    return types.GRAPHSTRING;
  }
}

/**
 * ISO64String
 */

class ISO64String extends Str {
  constructor(...options) {
    super(...options);
  }

  get type() {
    return types.ISO64STRING;
  }
}

/**
 * GenString
 */

class GenString extends Str {
  constructor(...options) {
    super(...options);
  }

  get type() {
    return types.GENSTRING;
  }
}

/**
 * UniString
 */

class UniString extends Str {
  constructor(...options) {
    super(...options);
  }

  get type() {
    return types.UNISTRING;
  }
}

/**
 * BMPString
 */

class BMPString extends Str {
  constructor(...options) {
    super(...options);
  }

  get type() {
    return types.BMPSTRING;
  }

  get encoding() {
    return 'ucs2';
  }
}

/**
 * API
 */

function typeToClass(type) {
  assert((type >>> 0) === type);

  switch (type) {
    case types.EOC:
      return EOC;
    case types.BOOLEAN:
      return Bool;
    case types.INTEGER:
      return Integer;
    case types.BITSTRING:
      return BitString;
    case types.OCTSTRING:
      return OctString;
    case types.NULL:
      return Null;
    case types.OID:
      return OID;
    case types.OBJDESC:
      return ObjDesc;
    case types.EXTERNAL:
      return External;
    case types.REAL:
      return Real;
    case types.ENUM:
      return Enum;
    // case types.EMBED:
    //   return Embed;
    case types.UTF8STRING:
      return Utf8String;
    // case types.ROID:
    //   return ROID;
    case types.SEQUENCE:
      return RawSequence;
    case types.SET:
      return RawSet;
    case types.NUMSTRING:
      return NumString;
    case types.PRINTSTRING:
      return PrintString;
    case types.T61STRING:
      return T61String;
    case types.VIDEOSTRING:
      return VideoString;
    case types.IA5STRING:
      return IA5String;
    case types.UTCTIME:
      return UTCTime;
    case types.GENTIME:
      return GenTime;
    case types.GRAPHSTRING:
      return GraphString;
    case types.ISO64STRING:
      return ISO64String;
    case types.GENSTRING:
      return GenString;
    case types.UNISTRING:
      return UniString;
    // case types.CHARSTRING:
    //   return CharString;
    case types.BMPSTRING:
      return BMPString;
    default:
      return Unknown;
  }
}

function readAny(br) {
  assert(br && typeof br.readU8 === 'function');

  const {type, cls} = peekHeader(br, false);

  if (cls !== classes.UNIVERSAL)
    throw new Error('Invalid class.');

  const Element = typeToClass(type);
  return Element.read(br);
}

function maybeReadAny(br, optional) {
  const offset = br.offset;

  let el = null;
  let err = null;

  try {
    el = readAny(br);
  } catch (e) {
    err = e;
  }

  if (!el) {
    if (!optional)
      throw err;

    br.offset = offset;

    return new Null();
  }

  return el;
}

function decodeAny(data) {
  const br = bio.read(data);
  return readAny(br);
}

/*
 * Helpers
 */

function sizeHeader(size) {
  assert((size >>> 0) === size);

  if (size <= 0x7f)
    return 1 + 1;

  if (size <= 0xff)
    return 1 + 1 + 1;

  if (size <= 0xffff)
    return 1 + 1 + 2;

  assert(size <= 0xffffff);

  return 1 + 1 + 3;
}

function writeHeader(bw, type, cls, primitive, size) {
  assert(bw);
  assert((type >>> 0) === type);
  assert((cls >>> 0) === cls);
  assert(typeof primitive === 'boolean');
  assert((size >>> 0) === size);

  if (!primitive)
    type |= 0x20;

  type |= cls << 6;

  // Short form.
  if (size <= 0x7f) {
    bw.writeU8(type);
    bw.writeU8(size);

    return bw;
  }

  // Long form (1 byte).
  if (size <= 0xff) {
    bw.writeU8(type);
    bw.writeU8(0x80 | 1);
    bw.writeU8(size);

    return bw;
  }

  // Long form (2 bytes).
  if (size <= 0xffff) {
    bw.writeU8(type);
    bw.writeU8(0x80 | 2);
    bw.writeU16BE(size);

    return bw;
  }

  assert(size <= 0xffffff);

  // Long form (3 bytes).
  bw.writeU8(type);
  bw.writeU8(0x80 | 3);
  bw.writeU24BE(size);

  return bw;
}

function readHeader(br) {
  const start = br.offset;
  const field = br.readU8();
  const cls = field >>> 6;
  const primitive = (field & 0x20) === 0;

  let type = 0;

  if ((field & 0x1f) === 0x1f) {
    let oct = field;

    while (oct & 0x80) {
      oct = br.readU8();
      type <<= 7;
      type |= oct & 0x7f;
    }
  } else {
    type = field & 0x1f;
  }

  switch (cls) {
    case classes.UNIVERSAL:
    case classes.CONTEXT:
      break;
    default:
      throw new Error('Unknown class.');
  }

  const size = readSize(br, primitive);
  const len = br.offset - start;

  return {
    type,
    cls,
    primitive,
    size,
    len
  };
}

function peekHeader(br, optional) {
  const offset = br.offset;

  let hdr = null;
  let err = null;

  try {
    hdr = readHeader(br);
  } catch (e) {
    err = e;
  }

  br.offset = offset;

  if (!optional && !hdr)
    throw err;

  return hdr;
}

function readSize(br, primitive) {
  const size = br.readU8();

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

  switch (bytes) {
    case 0:
      return 0;
    case 1:
      return br.readU8();
    case 2:
      return br.readU16BE();
    case 3:
      return br.readU24BE();
    case 4:
      return br.readU32BE();
    default:
      throw new Error('Length octet is too long.');
  }
}

function two(num) {
  if (num < 10)
    return '0' + num.toString(10);
  return num.toString(10);
}

function isNumString(str) {
  assert(typeof str === 'string');

  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    if (ch >= 0x30 && ch <= 0x39)
      continue;

    if (ch === 0x20)
      continue;

    return false;
  }

  return true;
}

function isPrintString(str) {
  assert(typeof str === 'string');

  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    // 0 - 9
    if (ch >= 0x30 && ch <= 0x39)
      continue;

    // A - Z
    if (ch >= 0x41 && ch <= 0x5a)
      continue;

    // a - z
    if (ch >= 0x61 && ch <= 0x7a)
      continue;

    switch (ch) {
      case 0x20: // ' '
      case 0x27: // '
      case 0x28: // (
      case 0x29: // )
      case 0x2b: // +
      case 0x2c: // ,
      case 0x2d: // -
      case 0x2e: // .
      case 0x2f: // /
      case 0x3a: // :
      case 0x3d: // =
      case 0x3f: // ?
        continue;
    }

    return false;
  }

  return true;
}

function parseU32(str) {
  assert(typeof str === 'string');

  let word = 0;

  if (str.length === 0 || str.length > 10)
    throw new Error('Invalid integer.');

  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i) - 0x30;

    if (ch < 0 || ch > 9)
      throw new Error('Invalid integer.');

    word *= 10;
    word += ch;

    if (word > 0xffffffff)
      throw new Error('Invalid integer.');
  }

  return word;
}

function isEqual(a, b) {
  assert(a instanceof Uint32Array);
  assert(b instanceof Uint32Array);

  if (a.length !== b.length)
    return false;

  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i])
      return false;
  }

  return true;
}

function trimZeroes(buf) {
  assert(Buffer.isBuffer(buf));

  if (buf.length === 0)
    return Buffer.from([0x00]);

  if (buf[0] !== 0x00)
    return buf;

  for (let i = 1; i < buf.length; i++) {
    if (buf[i] !== 0x00)
      return buf.slice(i);
  }

  return buf.slice(-1);
}

function twosComplement(num, start, end) {
  assert(Buffer.isBuffer(num));
  assert((start >>> 0) === start);
  assert((end >>> 0) === end);
  assert(start <= end);

  let carry = 1;

  for (let i = end - 1; i >= start; i--) {
    carry += num[i] ^ 0xff;
    num[i] = carry & 0xff;
    carry >>>= 8;
  }

  return num;
}

/*
 * Expose
 */

exports.EMPTY = EMPTY;
exports.ZERO = ZERO;
exports.EMPTY_OID = EMPTY_OID;

exports.types = types;
exports.typesByVal = typesByVal;
exports.classes = classes;
exports.classesByVal = classesByVal;

exports.NORMAL = NORMAL;
exports.EXPLICIT = EXPLICIT;
exports.IMPLICIT = IMPLICIT;

exports.Node = Node;
exports.Sequence = Sequence;
exports.Set = Set;
exports.Choice = Choice;
exports.Element = Element;
exports.Unknown = Unknown;
exports.Any = Any;
exports.Str = Str;
exports.String = Str;
exports.EOC = EOC;
exports.Bool = Bool;
exports.Boolean = Bool;
exports.Integer = Integer;
exports.BitString = BitString;
exports.OctString = OctString;
exports.Null = Null;
exports.OID = OID;
exports.ObjDesc = ObjDesc;
exports.External = External;
exports.Real = Real;
exports.Enum = Enum;
exports.Utf8String = Utf8String;
exports.RawSequence = RawSequence;
exports.RawSet = RawSet;
exports.NumString = NumString;
exports.PrintString = PrintString;
exports.T61String = T61String;
exports.VideoString = VideoString;
exports.IA5String = IA5String;
exports.UTCTime = UTCTime;
exports.GenTime = GenTime;
exports.GraphString = GraphString;
exports.ISO64String = ISO64String;
exports.GenString = GenString;
exports.UniString = UniString;
exports.BMPString = BMPString;

exports.typeToClass = typeToClass;

exports.readAny = readAny;
exports.decodeAny = decodeAny;
