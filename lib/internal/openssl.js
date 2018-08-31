/*!
 * openssl.js - openssl-specific encoding for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Resources:
 *   https://www.openssl.org/docs/man1.1.0/apps/dsa.html
 *   https://superuser.com/questions/478966/dsa-private-key-format
 *   https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/PublicKey/DSA.py
 */

'use strict';

const asn1 = require('./asn1');
const pem = require('./pem');

/**
 * DSAPrivateKey
 */

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

/*
 * Expose
 */

exports.DSAPrivateKey = DSAPrivateKey;
