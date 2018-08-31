/*!
 * rfc3279.js - rfc3279 encoding for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Resources:
 *   https://www.ietf.org/rfc/rfc3279.txt
 *   https://tools.ietf.org/html/rfc5912
 */

'use strict';

const asn1 = require('./asn1');
const pem = require('./pem');

/**
 * DSA Parms
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
 * DSA Public Key
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

exports.DSAParameters = DSAParameters;
exports.DSAPublicKey = DSAPublicKey;
exports.DSAFullPublicKey = DSAFullPublicKey;
exports.DSASignature = DSASignature;
