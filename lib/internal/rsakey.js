/*!
 * rsa.js - RSA for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Resources:
 *   https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem
 *   https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41
 */

'use strict';

const assert = require('assert');
const bio = require('bufio');

/*
 * Constants
 */

const DUMMY = Buffer.from([0x00]);
const VERSION = Buffer.from([0x01]);

/**
 * RSAKey
 */

class RSAKey extends bio.Struct {
  constructor() {
    super();
    this.n = DUMMY; // modulus
    this.e = DUMMY; // public exponent
  }

  bits() {
    return this.n.length << 3;
  }
}

/**
 * RSAPublicKey
 */

class RSAPublicKey extends RSAKey {
  constructor() {
    super();
    this.n = DUMMY; // modulus
    this.e = DUMMY; // public exponent
  }

  bodySize() {
    let size = 0;
    size += sizeInt(this.n);
    size += sizeInt(this.e);
    return size;
  }

  getSize() {
    let size = this.bodySize();
    size += sizeSeq(size);
    return size;
  }

  write(bw) {
    const size = this.bodySize();

    writeSeq(bw, size);
    writeInt(bw, this.n);
    writeInt(bw, this.e);

    return bw;
  }

  read(br) {
    const sr = readSeq(br);

    this.n = readInt(sr);
    this.e = readInt(sr);

    return this;
  }

  getJSON() {
    return {
      kty: 'RSA',
      n: toBase64URL(this.n),
      e: toBase64URL(this.e)
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(json.kty === 'RSA');

    this.n = fromBase64URL(json.n);
    this.e = fromBase64URL(json.e);

    return this;
  }

  toPEM() {
    return toPEM(this.encode(), 'RSA PUBLIC KEY');
  }

  fromPEM(pem) {
    const data = fromPEM(pem, 'RSA PUBLIC KEY');
    return this.decode(data);
  }

  format() {
    return {
      type: 'RSAPublicKey',
      n: this.n.toString('hex'),
      e: this.e.toString('hex')
    };
  }

  static fromPEM(pem) {
    return new this().fromPEM(pem);
  }
}

/**
 * RSAPrivateKey
 */

class RSAPrivateKey extends RSAKey {
  constructor() {
    super();
    this.n = DUMMY; // modulus
    this.e = DUMMY; // public exponent
    this.d = DUMMY; // private exponent
    this.p = DUMMY; // prime1
    this.q = DUMMY; // prime2
    this.dp = DUMMY; // exponent1
    this.dq = DUMMY; // exponent2
    this.qi = DUMMY; // coefficient
  }

  toPublic() {
    const pub = new RSAPublicKey();
    pub.n = this.n;
    pub.e = this.e;
    return pub;
  }

  bodySize() {
    let size = 0;
    size += sizeInt(VERSION);
    size += sizeInt(this.n);
    size += sizeInt(this.e);
    size += sizeInt(this.d);
    size += sizeInt(this.p);
    size += sizeInt(this.q);
    size += sizeInt(this.dp);
    size += sizeInt(this.dq);
    size += sizeInt(this.qi);
    return size;
  }

  getSize() {
    let size = this.bodySize();
    size += sizeSeq(size);
    return size;
  }

  write(bw) {
    const size = this.bodySize();

    writeSeq(bw, size);
    writeInt(bw, VERSION);
    writeInt(bw, this.n);
    writeInt(bw, this.e);
    writeInt(bw, this.d);
    writeInt(bw, this.p);
    writeInt(bw, this.q);
    writeInt(bw, this.dp);
    writeInt(bw, this.dq);
    writeInt(bw, this.qi);

    return bw;
  }

  read(br) {
    const sr = readSeq(br);

    readInt(sr);

    this.n = readInt(sr);
    this.e = readInt(sr);
    this.d = readInt(sr);
    this.p = readInt(sr);
    this.q = readInt(sr);
    this.dp = readInt(sr);
    this.dq = readInt(sr);
    this.qi = readInt(sr);

    return this;
  }

  getJSON() {
    return {
      kty: 'RSA',
      n: toBase64URL(this.n),
      e: toBase64URL(this.e),
      d: toBase64URL(this.d),
      p: toBase64URL(this.p),
      q: toBase64URL(this.q),
      dp: toBase64URL(this.dp),
      dq: toBase64URL(this.dq),
      qi: toBase64URL(this.qi)
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(json.kty === 'RSA');

    this.n = fromBase64URL(json.n);
    this.e = fromBase64URL(json.e);
    this.d = fromBase64URL(json.d);
    this.p = fromBase64URL(json.p);
    this.q = fromBase64URL(json.q);
    this.dp = fromBase64URL(json.dp);
    this.dq = fromBase64URL(json.dq);
    this.qi = fromBase64URL(json.qi);

    return this;
  }

  toPEM() {
    return toPEM(this.encode(), 'RSA PRIVATE KEY');
  }

  fromPEM(pem) {
    const data = fromPEM(pem, 'RSA PRIVATE KEY');
    return this.decode(data);
  }

  format() {
    return {
      type: 'RSAPrivateKey',
      n: this.n.toString('hex'),
      e: this.e.toString('hex'),
      d: this.d.toString('hex'),
      p: this.p.toString('hex'),
      q: this.q.toString('hex'),
      dp: this.dp.toString('hex'),
      dq: this.dq.toString('hex'),
      qi: this.qi.toString('hex')
    };
  }

  static fromPEM(pem) {
    return new this().fromPEM(pem);
  }
}

/*
 * ASN1
 */

function readTag(br) {
  let type = br.readU8();

  const primitive = (type & 0x20) === 0;

  if ((type & 0x1f) === 0x1f) {
    let oct = type;
    type = 0;
    while ((oct & 0x80) === 0x80) {
      oct = br.readU8();
      type <<= 7;
      type |= oct & 0x7f;
    }
  } else {
    type &= 0x1f;
  }

  const size = readSize(br, primitive);

  return {
    type,
    primitive,
    size
  };
}

function readSize(br, primitive) {
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

  if (bytes > 3)
    throw new Error('Length octet is too long.');

  size = 0;
  for (let i = 0; i < bytes; i++) {
    size <<= 8;
    size |= br.readU8();
  }

  return size;
}

function readSeq(br) {
  const tag = readTag(br);

  if (tag.primitive || tag.type !== 0x10)
    throw new Error(`Unexpected tag: ${tag.type}.`);

  return br.readChild(tag.size);
}

function readInt(br) {
  const tag = readTag(br);

  if (!tag.primitive || tag.type !== 0x02)
    throw new Error(`Unexpected tag: ${tag.type}.`);

  return br.readBytes(tag.size);
}

function sizeSeq(size) {
  if (size <= 0x7f)
    return 1 + 1;

  if (size <= 0xff)
    return 1 + 1 + 1;

  assert(size <= 0xffff);

  return 1 + 1 + 2;
}

function writeSeq(bw, size) {
  if (size <= 0x7f) {
    bw.writeU8(0x10 | 0x20); // seq
    bw.writeU8(size); // short form
    return bw;
  }

  if (size <= 0xff) {
    bw.writeU8(0x10 | 0x20); // seq
    bw.writeU8(0x80 | 1); // long form
    bw.writeU8(size);
    return bw;
  }

  assert(size <= 0xffff);

  bw.writeU8(0x10 | 0x20); // seq
  bw.writeU8(0x80 | 2); // long form
  bw.writeU16BE(size);
  return bw;
}

function sizeInt(buf) {
  if (buf.length <= 0x7f)
    return 1 + 1 + buf.length;

  if (buf.length <= 0xff)
    return 1 + 1 + 1 + buf.length;

  assert(buf.length <= 0xffff);

  return 1 + 1 + 2 + buf.length;
}

function writeInt(bw, buf) {
  if (buf.length <= 0x7f) {
    bw.writeU8(0x02); // int
    bw.writeU8(buf.length); // short form
    bw.writeBytes(buf);
    return bw;
  }

  if (buf.length <= 0xff) {
    bw.writeU8(0x02); // int
    bw.writeU8(0x80 | 1); // long form
    bw.writeU8(buf.length);
    bw.writeBytes(buf);
    return bw;
  }

  assert(buf.length <= 0xffff);

  bw.writeU8(0x02); // int
  bw.writeU8(0x80 | 2); // long form
  bw.writeU16BE(buf.length);
  bw.writeBytes(buf);
  return bw;
}

/*
 * PEM
 */

function parsePEM(pem) {
  const chunks = [];

  let chunk = '';
  let tag = null;

  while (pem.length) {
    let m;

    m = /^-----BEGIN ([^\-]+)-----/.exec(pem);
    if (m) {
      pem = pem.substring(m[0].length);
      tag = m[1];
      continue;
    }

    m = /^-----END ([^\-]+)-----/.exec(pem);
    if (m) {
      pem = pem.substring(m[0].length);

      assert(tag === m[1], 'Tag mismatch.');

      const data = Buffer.from(chunk, 'base64');

      chunks.push({
        tag: tag,
        data: data
      });

      chunk = '';
      tag = null;

      continue;
    }

    m = /^[a-zA-Z0-9\+=\/]+/.exec(pem);
    if (m) {
      pem = pem.substring(m[0].length);
      chunk += m[0];
      continue;
    }

    m = /^\s+/.exec(pem);
    if (m) {
      pem = pem.substring(m[0].length);
      continue;
    }

    throw new Error('PEM parse error.');
  }

  assert(chunks.length !== 0, 'PEM parse error.');
  assert(!tag, 'Un-ended tag.');
  assert(chunk.length === 0, 'Trailing data.');

  return chunks;
}

function fromPEM(pem, tag) {
  assert(typeof pem === 'string');
  assert(typeof tag === 'string');

  const chunk = parsePEM(pem)[0];

  assert.strictEqual(chunk.tag, tag);

  return chunk.data;
}

function toPEM(buf, tag) {
  assert(Buffer.isBuffer(buf));
  assert(typeof tag === 'string');

  const str = buf.toString('base64');

  let pem = '';

  for (let i = 0; i < str.length; i += 64)
    pem += str.slice(i, i + 64) + '\n';

  return ''
    + `-----BEGIN ${tag}-----\n`
    + pem
    + `-----END ${tag}-----\n`;
}

/*
 * Base64 URL
 */

function toBase64URL(buf) {
  assert(Buffer.isBuffer(buf));

  const b64 = buf.toString('base64');
  const str = b64
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  return str;
}

function fromBase64URL(str) {
  assert(typeof str === 'string');

  const b64 = pad64(str)
    .replace(/\-/g, '+')
    .replace(/_/g, '/');

  const buf = Buffer.from(b64, 'base64');

  return buf;
}

function pad64(str) {
  assert(typeof str === 'string');

  const pad = 4 - (str.length % 4);

  if (pad === 4)
    return str;

  for (let i = 0; i < pad; i++)
    str += '=';

  return str;
}

/*
 * Expose
 */

exports.RSAKey = RSAKey;
exports.RSAPublicKey = RSAPublicKey;
exports.RSAPrivateKey = RSAPrivateKey;
