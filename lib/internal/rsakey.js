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

const assert = require('bsert');
const bio = require('bufio');
const base64 = require('./base64');
const pkcs1 = require('./pkcs1');

/*
 * Constants
 */

const DUMMY = Buffer.from([0x00]);

const DEFAULT_BITS = 2048;
const DEFAULT_EXP = 65537;
const MIN_BITS = 512;
const MAX_BITS = 16384;
const MIN_EXP = 3;
const MAX_EXP = (2 ** 33) - 1;
const MAX_EXP_BITS = 33;

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
    // https://www.imperialviolet.org/2012/03/16/rsae.html
    // https://www.imperialviolet.org/2012/03/17/rsados.html
    const n = trimZeroes(this.n);
    const e = trimZeroes(this.e);
    const nb = countBits(n);
    const eb = countBits(e);

    // https://github.com/golang/go/blob/aadaec5/src/crypto/rsa/rsa.go#L74
    // https://github.com/openssl/openssl/blob/0396401/crypto/rsa/rsa_ossl.c#L85
    // Note: Lots of people use 0x0100000001 for DNSSEC.
    // - Use a 31 bit limit to match golang and older impls.
    // - Use a 33 bit limit to be compatible with dnssec-keygen.
    if (eb > MAX_EXP_BITS) // e > (1 << 33) - 1
      return false;

    // https://github.com/golang/go/blob/aadaec5/src/crypto/rsa/rsa.go#L74
    // https://github.com/openssl/openssl/blob/0396401/crypto/rsa/rsa_chk.c#L55
    if (e.length === 1 && e[0] === 1) // e == 1
      return false;

    // https://github.com/openssl/openssl/blob/0396401/crypto/rsa/rsa_chk.c#L59
    if ((e[e.length - 1] & 1) === 0) // !is_odd(e)
      return false;

    // https://github.com/openssl/openssl/blob/0396401/crypto/rsa/rsa_ossl.c#L80
    if (nb < eb || (nb === eb && n.compare(e) <= 0)) // n <= e
      return false;

    // https://github.com/openssl/openssl/blob/0396401/crypto/rsa/rsa_locl.h#L14
    if (nb < MIN_BITS) // RSA_MIN_MODULUS_BITS
      return false;

    // https://github.com/openssl/openssl/blob/0396401/crypto/rsa/rsa_ossl.c#L74
    if (nb > MAX_BITS) // OPENSSL_RSA_MAX_MODULUS_BITS
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

  toPKCS1() {
    return new pkcs1.RSAPublicKey(this.n, this.e);
  }

  fromPKCS1(key) {
    assert(key instanceof pkcs1.RSAPublicKey);

    this.n = key.n.value;
    this.e = key.e.value;

    return this;
  }

  encode() {
    const key = this.toPKCS1();
    return key.encode();
  }

  decode(data) {
    const key = pkcs1.RSAPublicKey.decode(data);
    return this.fromPKCS1(key);
  }

  toPEM() {
    const key = this.toPKCS1();
    return key.toPEM();
  }

  fromPEM(str) {
    const key = pkcs1.RSAPublicKey.fromPEM(str);
    return this.fromPKCS1(key);
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
      n: base64.encodeURL(this.n),
      e: base64.encodeURL(this.e),
      ext: true
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(json.kty === 'RSA');

    this.n = base64.decodeURL(json.n);
    this.e = base64.decodeURL(json.e);

    return this;
  }

  format() {
    return {
      type: 'RSAPublicKey',
      n: this.n.toString('hex'),
      e: this.e.toString('hex')
    };
  }

  static fromPEM(str) {
    return new this().fromPEM(str);
  }

  static fromDNS(data) {
    return new this().fromDNS(data);
  }

  static fromSSH(data) {
    return new this().fromSSH(data);
  }

  static fromSSHString(str) {
    return new this().fromSSHString(str);
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

  toPKCS1() {
    return new pkcs1.RSAPrivateKey(
      0,
      this.n,
      this.e,
      this.d,
      this.p,
      this.q,
      this.dp,
      this.dq,
      this.qi
    );
  }

  fromPKCS1(key) {
    assert(key instanceof pkcs1.RSAPrivateKey);

    this.n = key.n.value;
    this.e = key.e.value;
    this.d = key.d.value;
    this.p = key.p.value;
    this.q = key.q.value;
    this.dp = key.dp.value;
    this.dq = key.dq.value;
    this.qi = key.qi.value;

    return this;
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

  encode() {
    const key = this.toPKCS1();
    return key.encode();
  }

  decode(data) {
    const key = pkcs1.RSAPrivateKey.decode(data);
    return this.fromPKCS1(key);
  }

  toPEM() {
    const key = this.toPKCS1();
    return key.toPEM();
  }

  fromPEM(str) {
    const key = pkcs1.RSAPrivateKey.fromPEM(str);
    return this.fromPKCS1(key);
  }

  toPublic() {
    const pub = new RSAPublicKey();
    pub.n = this.n;
    pub.e = this.e;
    return pub;
  }

  getJSON() {
    return {
      kty: 'RSA',
      n: base64.encodeURL(this.n),
      e: base64.encodeURL(this.e),
      d: base64.encodeURL(this.d),
      p: base64.encodeURL(this.p),
      q: base64.encodeURL(this.q),
      dp: base64.encodeURL(this.dp),
      dq: base64.encodeURL(this.dq),
      qi: base64.encodeURL(this.qi),
      ext: true
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(json.kty === 'RSA');

    this.n = base64.decodeURL(json.n);
    this.e = base64.decodeURL(json.e);
    this.d = base64.decodeURL(json.d);
    this.p = base64.decodeURL(json.p);
    this.q = base64.decodeURL(json.q);
    this.dp = base64.decodeURL(json.dp);
    this.dq = base64.decodeURL(json.dq);
    this.qi = base64.decodeURL(json.qi);

    return this;
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

  static fromPEM(str) {
    return new this().fromPEM(str);
  }
}

/*
 * Helpers
 */

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

exports.DEFAULT_BITS = DEFAULT_BITS;
exports.DEFAULT_EXP = DEFAULT_EXP;
exports.MIN_BITS = MIN_BITS;
exports.MAX_BITS = MAX_BITS;
exports.MIN_EXP = MIN_EXP;
exports.MAX_EXP = MAX_EXP;

exports.RSAKey = RSAKey;
exports.RSAPublicKey = RSAPublicKey;
exports.RSAPrivateKey = RSAPrivateKey;
