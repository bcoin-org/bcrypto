/*!
 * rsakey.js - RSA keys for javascript
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
const BN = require('../../vendor/bn.js');
const base64 = require('./base64');
const pkcs1 = require('../encoding/pkcs1');
const {countBits, trimZeroes} = require('./util');

/*
 * Constants
 */

const ZERO = Buffer.from([0x00]);

const DEFAULT_BITS = 2048;
const DEFAULT_EXP = 65537;
const MIN_BITS = 512;
const MAX_BITS = 16384;
const MIN_EXP = 3;
const MAX_EXP = (2 ** 33) - 1;
const MIN_EXP_BITS = 2;
const MAX_EXP_BITS = 33;

/**
 * RSAKey
 */

class RSAKey extends bio.Struct {
  constructor() {
    super();
    this.n = ZERO; // modulus
    this.e = ZERO; // public exponent
  }

  get rsa() {
    return this.constructor.rsa;
  }

  get type() {
    return 'rsa';
  }

  get curve() {
    return null;
  }

  setN(n) {
    this.n = trimZeroes(n);
    return this;
  }

  setE(e) {
    if (typeof e === 'number')
      e = toU64(e);

    this.e = trimZeroes(e);

    return this;
  }

  bits() {
    return countBits(this.n);
  }

  validate() {
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
  constructor(n, e) {
    super();
    this.n = trimZeroes(n); // modulus
    this.e = trimZeroes(e); // public exponent
  }

  toPKCS1() {
    return new pkcs1.RSAPublicKey(this.n, this.e);
  }

  fromPKCS1(key) {
    assert(key instanceof pkcs1.RSAPublicKey);

    this.n = trimZeroes(key.n.value);
    this.e = trimZeroes(key.e.value);

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
      type: this.type,
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
}

/**
 * RSAPrivateKey
 */

class RSAPrivateKey extends RSAKey {
  constructor(n, e, d, p, q, dp, dq, qi) {
    super();
    this.n = trimZeroes(n); // modulus
    this.e = trimZeroes(e); // public exponent
    this.d = trimZeroes(d); // private exponent
    this.p = trimZeroes(p); // prime1
    this.q = trimZeroes(q); // prime2
    this.dp = trimZeroes(dp); // exponent1
    this.dq = trimZeroes(dq); // exponent2
    this.qi = trimZeroes(qi); // coefficient
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

    this.n = trimZeroes(key.n.value);
    this.e = trimZeroes(key.e.value);
    this.d = trimZeroes(key.d.value);
    this.p = trimZeroes(key.p.value);
    this.q = trimZeroes(key.q.value);
    this.dp = trimZeroes(key.dp.value);
    this.dq = trimZeroes(key.dq.value);
    this.qi = trimZeroes(key.qi.value);

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

  needsCompute() {
    return countBits(this.n) === 0
        || countBits(this.d) === 0
        || countBits(this.dp) === 0
        || countBits(this.dq) === 0
        || countBits(this.qi) === 0;
  }

  compute() {
    if (!this.needsCompute())
      return this;

    const eb = countBits(this.e);
    const nb = countBits(this.p) + countBits(this.q);

    if (eb < MIN_EXP_BITS || eb > MAX_EXP_BITS)
      throw new Error('Invalid exponent.');

    if (nb < eb || nb < MIN_BITS || nb > MAX_BITS)
      throw new Error('Invalid primes.');

    const e = new BN(this.e);
    const p = new BN(this.p);
    const q = new BN(this.q);

    if (e.cmpn(3) < 0 || e.isEven())
      throw new Error('Invalid exponent.');

    let n = new BN(this.n);
    let d = new BN(this.d);
    let dp = new BN(this.dp);
    let dq = new BN(this.dq);
    let qi = new BN(this.qi);

    if (n.bitLength() === 0)
      n = p.mul(q);

    if (d.bitLength() === 0) {
      const t = p.subn(1).imul(q.subn(1));
      d = e.invm(t);
    }

    if (dp.bitLength() === 0)
      dp = d.mod(p.subn(1));

    if (dq.bitLength() === 0)
      dq = d.mod(q.subn(1));

    if (qi.bitLength() === 0)
      qi = q.invm(p);

    this.n = toBuffer(n);
    this.d = toBuffer(d);
    this.dp = toBuffer(dp);
    this.dq = toBuffer(dq);
    this.qi = toBuffer(qi);

    return this;
  }

  validate() {
    return this.rsa.privateKeyVerify(this);
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
    const rsa = this.rsa;
    const pub = new rsa.RSAPublicKey();

    this.compute();

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
      type: this.type,
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

  static generate(bits) {
    return this.rsa.privateKeyGenerate(bits);
  }

  static async generateAsync(bits) {
    return this.rsa.privateKeyGenerateAsync(bits);
  }
}

/*
 * Helpers
 */

function toBuffer(n) {
  return n.toArrayLike(Buffer, 'be');
}

function toU64(n) {
  const b = Buffer.alloc(8);
  bio.writeU64BE(b, n, 0);
  return b;
}

/*
 * Expose
 */

module.exports = function create(backend) {
  assert(backend);

  return {
    DEFAULT_BITS,
    DEFAULT_EXP,
    MIN_BITS,
    MAX_BITS,
    MIN_EXP,
    MAX_EXP,
    RSAKey,
    RSAPublicKey: class RSAPublicKey_ extends RSAPublicKey {
      constructor(n, e) {
        super(n, e);
      }

      static get rsa() {
        return backend;
      }
    },
    RSAPrivateKey: class RSAPrivateKey_ extends RSAPrivateKey {
      constructor(n, e, d, p, q, dp, dq, qi) {
        super(n, e, d, p, q, dp, dq, qi);
      }

      static get rsa() {
        return backend;
      }
    }
  };
};
