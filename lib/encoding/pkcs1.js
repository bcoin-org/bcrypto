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
 *   https://tools.ietf.org/html/rfc8017#appendix-A.1.1
 *   https://tools.ietf.org/html/rfc8017#appendix-A.1.2
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

/*
 * Expose
 */

exports.RSAPublicKey = RSAPublicKey;
exports.RSAPrivateKey = RSAPrivateKey;
