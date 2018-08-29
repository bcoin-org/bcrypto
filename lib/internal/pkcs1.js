/*!
 * pkcs1.js - PKCS1 encoding for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   https://github.com/golang/go/blob/master/src/crypto/x509/pkcs1.go
 *   https://www.ietf.org/rfc/rfc3279.txt
 */

'use strict';

const asn1 = require('./asn1');
const pem = require('./pem');

/**
 * RSAPublicKey
 */

// RSAPublicKey ::= SEQUENCE {
//     modulus           INTEGER,  -- n
//     publicExponent    INTEGER   -- e
// }

class RSAPublicKey extends asn1.Sequence {
  constructor(n, e) {
    super();
    this.n = new asn1.Integer(n);
    this.e = new asn1.Integer(e);
  }

  getBodySize() {
    let size = 0;
    size += this.n.getSize();
    size += this.e.getSize();
    return size;
  }

  writeBody(bw) {
    this.n.write(bw);
    this.e.write(bw);
    return bw;
  }

  readBody(br) {
    this.n.read(br);
    this.e.read(br);
    return this;
  }

  clean() {
    return this.n.isNull() && this.e.isNull();
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'RSA PUBLIC KEY');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'RSA PUBLIC KEY');
    return this.decode(data);
  }

  format() {
    return {
      n: this.n,
      e: this.e
    };
  }
}

/**
 * RSAPrivateKey
 */

// RSAPrivateKey ::= SEQUENCE {
//   version           Version,
//   modulus           INTEGER,  -- n
//   publicExponent    INTEGER,  -- e
//   privateExponent   INTEGER,  -- d
//   prime1            INTEGER,  -- p
//   prime2            INTEGER,  -- q
//   exponent1         INTEGER,  -- d mod (p-1)
//   exponent2         INTEGER,  -- d mod (q-1)
//   coefficient       INTEGER,  -- (inverse of q) mod p
//   otherPrimeInfos   OtherPrimeInfos OPTIONAL
// }

class RSAPrivateKey extends asn1.Sequence {
  constructor(version, n, e, d, p, q, dp, dq, qi) {
    super();
    this.version = new asn1.Integer(version);
    this.n = new asn1.Integer(n);
    this.e = new asn1.Integer(e);
    this.d = new asn1.Integer(d);
    this.p = new asn1.Integer(p);
    this.q = new asn1.Integer(q);
    this.dp = new asn1.Integer(dp);
    this.dq = new asn1.Integer(dq);
    this.qi = new asn1.Integer(qi);
  }

  getBodySize() {
    let size = 0;
    size += this.version.getSize();
    size += this.n.getSize();
    size += this.e.getSize();
    size += this.d.getSize();
    size += this.p.getSize();
    size += this.q.getSize();
    size += this.dp.getSize();
    size += this.dq.getSize();
    size += this.qi.getSize();
    return size;
  }

  writeBody(bw) {
    this.version.write(bw);
    this.n.write(bw);
    this.e.write(bw);
    this.d.write(bw);
    this.p.write(bw);
    this.q.write(bw);
    this.dp.write(bw);
    this.dq.write(bw);
    this.qi.write(bw);
    return bw;
  }

  readBody(br) {
    this.version.read(br);
    this.n.read(br);
    this.e.read(br);
    this.d.read(br);
    this.p.read(br);
    this.q.read(br);
    this.dp.read(br);
    this.dq.read(br);
    this.qi.read(br);
    return this;
  }

  clean() {
    return this.n.isNull()
        && this.e.isNull()
        && this.d.isNull()
        && this.p.isNull()
        && this.q.isNull()
        && this.dp.isNull()
        && this.dq.isNull()
        && this.qi.isNull();
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'RSA PRIVATE KEY');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'RSA PRIVATE KEY');
    return this.decode(data);
  }

  format() {
    return {
      version: this.version,
      n: this.n,
      e: this.e,
      d: this.d,
      p: this.p,
      q: this.q,
      dp: this.dp,
      dq: this.dq,
      qi: this.qi
    };
  }
}

/**
 * DSA Public Key
 * @see https://www.ietf.org/rfc/rfc3279.txt
 */

// DSAPublicKey ::= INTEGER -- public key, Y

class DSAPublicKey extends asn1.Integer {
  constructor(y) {
    super(y);
  }

  get y() {
    return this.value;
  }

  set y(value) {
    this.value = value;
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'DSA PUBLIC KEY');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'DSA PUBLIC KEY');
    return this.decode(data);
  }

  static fromPEM(str) {
    return new this().fromPEM(str);
  }
}

/**
 * DSA Parms
 * @see https://www.ietf.org/rfc/rfc3279.txt
 */

// Dss-Parms  ::=  SEQUENCE  {
//     p             INTEGER,
//     q             INTEGER,
//     g             INTEGER  }

class DSAParameters extends asn1.Sequence {
  constructor(p, q, g) {
    super();
    this.p = new asn1.Integer(p);
    this.q = new asn1.Integer(q);
    this.g = new asn1.Integer(g);
  }

  getBodySize() {
    let size = 0;
    size += this.p.getSize();
    size += this.q.getSize();
    size += this.g.getSize();
    return size;
  }

  writeBody(bw) {
    this.p.write(bw);
    this.q.write(bw);
    this.g.write(bw);
    return bw;
  }

  readBody(br) {
    this.p.read(br);
    this.q.read(br);
    this.g.read(br);
    return this;
  }

  clean() {
    return this.p.isNull() && this.q.isNull() && this.g.isNull();
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'DSA PARAMETERS');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'DSA PARAMETERS');
    return this.decode(data);
  }

  format() {
    return {
      y: this.y
    };
  }
}

/**
 * DSAPrivateKey
 */

// OpenSSL's custom format. See:
// https://www.openssl.org/docs/man1.1.0/apps/dsa.html
// https://superuser.com/questions/478966/dsa-private-key-format
// https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/PublicKey/DSA.py
//
// DSSPrivatKey_OpenSSL ::= SEQUENCE {
//   version INTEGER,
//   p INTEGER,
//   q INTEGER,
//   g INTEGER,
//   y INTEGER,
//   x INTEGER
// }

class DSAPrivateKey extends asn1.Sequence {
  constructor(version, p, q, g, y, x) {
    super();
    this.version = new asn1.Integer(version);
    this.p = new asn1.Integer(p);
    this.q = new asn1.Integer(q);
    this.g = new asn1.Integer(g);
    this.y = new asn1.Integer(y);
    this.x = new asn1.Integer(x);
  }

  getBodySize() {
    let size = 0;
    size += this.version.getSize();
    size += this.p.getSize();
    size += this.q.getSize();
    size += this.g.getSize();
    size += this.y.getSize();
    size += this.x.getSize();
    return size;
  }

  writeBody(bw) {
    this.version.write(bw);
    this.p.write(bw);
    this.q.write(bw);
    this.g.write(bw);
    this.y.write(bw);
    this.x.write(bw);
    return bw;
  }

  readBody(br) {
    this.version.read(br);
    this.p.read(br);
    this.q.read(br);
    this.g.read(br);
    this.y.read(br);
    this.x.read(br);
    return this;
  }

  clean() {
    return this.p.isNull()
        && this.q.isNull()
        && this.g.isNull()
        && this.y.isNull()
        && this.x.isNull();
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'DSA PRIVATE KEY');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'DSA PRIVATE KEY');
    return this.decode(data);
  }

  format() {
    return {
      version: this.version,
      p: this.p,
      q: this.q,
      g: this.g,
      y: this.y,
      x: this.x
    };
  }
}

/**
 * DSA Full Public Key
 */

class DSAFullPublicKey extends asn1.Sequence {
  constructor(p, q, g, y) {
    super();
    this.params = new DSAParameters(p, q, g);
    this.y = new DSAPublicKey(y);
  }

  getBodySize() {
    let size = 0;
    size += this.params.getSize();
    size += this.y.getSize();
    return size;
  }

  writeBody(bw) {
    this.params.write(bw);
    this.y.write(bw);
    return bw;
  }

  readBody(br) {
    this.params.read(br);
    this.y.read(br);
    return this;
  }

  clean() {
    return this.params.isNull() && this.y.isNull();
  }

  toPEM() {
    return [this.params.toPEM(), this.y.toPEM()].join('\n');
  }

  fromPEM(str) {
    const blocks = [];

    for (const block of pem.decode(str)) {
      blocks.push(block);

      if (blocks.length === 2)
        break;
    }

    if (blocks.length !== 2)
      throw new Error('PEM type mismatch.');

    let [params, key] = blocks;

    if (params.type === 'DSA PUBLIC KEY')
      [params, key] = [key, params];

    if (params.type !== 'DSA PARAMETERS'
        || params.type !== 'DSA PUBLIC KEY') {
      throw new Error('PEM type mismatch.');
    }

    this.params.decode(params.block);
    this.y.decode(key.block);

    return this;
  }

  format() {
    return {
      params: this.params,
      y: this.y
    };
  }
}

/**
 * DSA Signature
 * @see https://www.ietf.org/rfc/rfc3279.txt
 */

class DSASignature extends asn1.Sequence {
  constructor(r, s) {
    super();
    this.r = new asn1.Integer(r);
    this.s = new asn1.Integer(s);
  }

  getBodySize() {
    let size = 0;
    size += this.r.getSize();
    size += this.s.getSize();
    return size;
  }

  writeBody(bw) {
    this.r.write(bw);
    this.s.write(bw);
    return bw;
  }

  readBody(br) {
    this.r.read(br);
    this.s.read(br);
    return this;
  }

  clean() {
    return this.r.isNull() && this.s.isNull();
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'DSA SIGNATURE');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'DSA SIGNATURE');
    return this.decode(data);
  }

  format() {
    return {
      r: this.r,
      s: this.s
    };
  }
}

/*
 * Expose
 */

exports.RSAPublicKey = RSAPublicKey;
exports.RSAPrivateKey = RSAPrivateKey;
exports.DSAPublicKey = DSAPublicKey;
exports.DSAPublicKey = DSAPublicKey;
exports.DSAParameters = DSAParameters;
exports.DSAPrivateKey = DSAPrivateKey;
exports.DSAFullPublicKey = DSAFullPublicKey;
exports.DSASignature = DSASignature;
