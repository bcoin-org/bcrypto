/*!
 * rfc2792.js - rfc2792 encoding for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc2792
 */

'use strict';

const asn1 = require('./asn1');
const pem = require('./pem');

/**
 * DSAPublicKey
 * https://tools.ietf.org/html/rfc2792#section-3.1
 */

// DSAPublicKey ::= SEQUENCE {
//   y INTEGER,
//   p INTEGER,
//   q INTEGER,
//   g INTEGER
// }

class DSAPublicKey extends asn1.Sequence {
  constructor(version, p, q, g, y, x) {
    super();
    this.y = new asn1.Integer(y);
    this.p = new asn1.Integer(p);
    this.q = new asn1.Integer(q);
    this.g = new asn1.Integer(g);
  }

  getBodySize() {
    let size = 0;
    size += this.y.getSize();
    size += this.p.getSize();
    size += this.q.getSize();
    size += this.g.getSize();
    return size;
  }

  writeBody(bw) {
    this.y.write(bw);
    this.p.write(bw);
    this.q.write(bw);
    this.g.write(bw);
    return bw;
  }

  readBody(br) {
    this.y.read(br);
    this.p.read(br);
    this.q.read(br);
    this.g.read(br);
    return this;
  }

  clean() {
    return this.y.isNull()
        && this.p.isNull()
        && this.q.isNull()
        && this.g.isNull();
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'DSA PUBLIC KEY');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'DSA PUBLIC KEY');
    return this.decode(data);
  }

  format() {
    return {
      y: this.y,
      p: this.p,
      q: this.q,
      g: this.g
    };
  }
}

/*
 * Expose
 */

exports.DSAPublicKey = DSAPublicKey;
