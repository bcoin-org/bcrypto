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
const der = require('./der');

/*
 * Constants
 */

const DUMMY = Buffer.from([0x00]);
const VERSION = Buffer.from([0x00]);

/**
 * RSAKey
 */

class RSAKey extends bio.Struct {
  constructor() {
    super();
    this.n = DUMMY; // modulus
    this.e = DUMMY; // public exponent
  }

  setN(n) {
    this.n = trimZeroes(n);
    return this;
  }

  setE(e) {
    this.e = trimZeroes(e);
    return this;
  }

  bits() {
    return countBits(this.n);
  }

  verify() {
    // https://github.com/golang/go/blob/aadaec5/src/crypto/rsa/rsa.go#L74
    // https://github.com/openssl/openssl/blob/0396401/include/openssl/rsa.h
    // https://github.com/openssl/openssl/blob/0396401/crypto/rsa/rsa_locl.h
    // https://github.com/openssl/openssl/blob/0396401/crypto/rsa/rsa_ossl.c#L74
    const n = trimZeroes(this.n);
    const e = trimZeroes(this.e);
    const nb = countBits(n);
    const eb = countBits(e);

    if (e.length === 1 && e[0] < 2) // e < 2
      return false;

    // https://www.imperialviolet.org/2012/03/16/rsae.html
    // Note: Lots of people use 0x0100000001 for DNSSEC (??).
    if (eb > 31) // e > (1 << 31) - 1
      return false;

    if ((e[e.length - 1] & 1) === 0) // !is_odd(e)
      return false;

    if (nb < eb) // n < e
      return false;

    if (nb === eb && n.compare(e) <= 0) // n <= e
      return false;

    // https://www.imperialviolet.org/2012/03/17/rsados.html
    if (nb > 3072) { // OPENSSL_RSA_SMALL_MODULUS_BITS
      if (eb > 64) // OPENSSL_RSA_MAX_PUBEXP_BITS
        return false;
    }

    if (nb < 512) // RSA_MIN_MODULUS_BITS
      return false;

    if (nb > 16384) // OPENSSL_RSA_MAX_MODULUS_BITS
      return false;

    return true;
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
    size += der.sizeInt(this.n);
    size += der.sizeInt(this.e);
    return size;
  }

  getSize() {
    let size = this.bodySize();
    size += der.sizeSeq(size);
    return size;
  }

  write(bw) {
    const size = this.bodySize();

    der.writeSeq(bw, size);
    der.writeInt(bw, this.n);
    der.writeInt(bw, this.e);

    return bw;
  }

  read(br, strict = false) {
    const sr = der.readSeq(br, strict);

    this.n = der.readInt(sr, strict);
    this.e = der.readInt(sr, strict);

    if (strict) {
      if (br.left() !== 0 || sr.left() !== 0)
        throw new Error('Unexpected trailing bytes.');
    }

    return this;
  }

  toDNS() {
    const n = trimZeroes(this.n);
    const e = trimZeroes(this.e);

    let size = 1 + e.length + n.length;

    if (e.length > 255)
      size += 2;

    const bw = bio.write(size);

    if (e.length > 255) {
      bw.writeU8(0);
      bw.writeU16BE(e.length);
    } else {
      bw.writeU8(e.length);
    }

    bw.writeBytes(e);
    bw.writeBytes(n);

    return bw.render();
  }

  fromDNS(data) {
    assert(Buffer.isBuffer(data));

    const br = bio.read(data);

    let len = br.readU8();

    if (len === 0)
      len = br.readU16BE();

    const e = br.readBytes(len);
    const n = br.readBytes(br.left());

    this.n = trimZeroes(n);
    this.e = trimZeroes(e);

    return this;
  }

  getJSON() {
    return {
      kty: 'RSA',
      n: toBase64URL(this.n),
      e: toBase64URL(this.e),
      ext: true
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

  fromPEM(pem, strict) {
    const data = fromPEM(pem, 'RSA PUBLIC KEY');
    return this.decode(data, strict);
  }

  format() {
    return {
      type: 'RSAPublicKey',
      n: this.n.toString('hex'),
      e: this.e.toString('hex')
    };
  }

  static fromDNS(data) {
    return new this().fromDNS(data);
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

  setD(d) {
    this.d = trimZeroes(d);
    return this;
  }

  setP(p) {
    this.p = trimZeroes(p);
    return this;
  }

  setQ(q) {
    this.q = trimZeroes(q);
    return this;
  }

  setDP(dp) {
    this.dp = trimZeroes(dp);
    return this;
  }

  setDQ(dq) {
    this.dq = trimZeroes(dq);
    return this;
  }

  setQI(qi) {
    this.qi = trimZeroes(qi);
    return this;
  }

  toPublic() {
    const pub = new RSAPublicKey();
    pub.n = this.n;
    pub.e = this.e;
    return pub;
  }

  bodySize() {
    let size = 0;
    size += der.sizeInt(VERSION);
    size += der.sizeInt(this.n);
    size += der.sizeInt(this.e);
    size += der.sizeInt(this.d);
    size += der.sizeInt(this.p);
    size += der.sizeInt(this.q);
    size += der.sizeInt(this.dp);
    size += der.sizeInt(this.dq);
    size += der.sizeInt(this.qi);
    return size;
  }

  getSize() {
    let size = this.bodySize();
    size += der.sizeSeq(size);
    return size;
  }

  write(bw) {
    const size = this.bodySize();

    der.writeSeq(bw, size);
    der.writeInt(bw, VERSION);
    der.writeInt(bw, this.n);
    der.writeInt(bw, this.e);
    der.writeInt(bw, this.d);
    der.writeInt(bw, this.p);
    der.writeInt(bw, this.q);
    der.writeInt(bw, this.dp);
    der.writeInt(bw, this.dq);
    der.writeInt(bw, this.qi);

    return bw;
  }

  read(br, strict = true) {
    const sr = der.readSeq(br, strict);

    der.readInt(sr, strict);

    this.n = der.readInt(sr, strict);
    this.e = der.readInt(sr, strict);
    this.d = der.readInt(sr, strict);
    this.p = der.readInt(sr, strict);
    this.q = der.readInt(sr, strict);
    this.dp = der.readInt(sr, strict);
    this.dq = der.readInt(sr, strict);
    this.qi = der.readInt(sr, strict);

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
      qi: toBase64URL(this.qi),
      ext: true
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
 * PEM
 */

function parsePEM(pem) {
  const chunks = [];

  let chunk = '';
  let tag = null;

  while (pem.length) {
    let m;

    // Begin chunk.
    m = /^-----BEGIN ([^\-]+)-----/.exec(pem);
    if (m) {
      pem = pem.substring(m[0].length);
      tag = m[1];
      continue;
    }

    // End chunk.
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

    // Base64 line.
    m = /^[a-zA-Z0-9\+=\/]+/.exec(pem);
    if (m) {
      pem = pem.substring(m[0].length);
      chunk += m[0];
      continue;
    }

    // Eat whitespace.
    m = /^\s+/.exec(pem);
    if (m) {
      pem = pem.substring(m[0].length);
      continue;
    }

    // Ignore line (possibly some extra header info).
    m = /^[^\r\n]+(\r\n|\r|\n)/.exec(pem);
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

function countBits(buf) {
  assert(Buffer.isBuffer(buf));

  let i = 0;

  for (; i < buf.length; i++) {
    if (buf[i] !== 0x00)
      break;
  }

  let bits = (buf.length - i) * 8;

  if (bits === 0)
    return 0;

  bits -= 8;

  let oct = buf[i];

  while (oct) {
    bits += 1;
    oct >>>= 1;
  }

  return bits;
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

/*
 * Expose
 */

exports.RSAKey = RSAKey;
exports.RSAPublicKey = RSAPublicKey;
exports.RSAPrivateKey = RSAPrivateKey;
