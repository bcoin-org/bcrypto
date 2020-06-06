/*!
 * x509-extensions.js - X509 v3 Extensions for javascript
 * Copyright (c) 2020, Matthew Zipkin (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://www.itu.int/rec/T-REC-X.509-201910-I
 *   https://www.openssl.org/docs/manmaster/man5/x509v3_config.html
 *   https://tools.ietf.org/html/rfc8017#appendix-A
 */

'use strict';

const assert = require('../internal/assert');
const asn1 = require('./asn1');

// basicConstraints EXTENSION ::= {
//   SYNTAX         BasicConstraintsSyntax
//   IDENTIFIED BY  id-ce-basicConstraints }
// BasicConstraintsSyntax ::= SEQUENCE {
//   cA                 BOOLEAN DEFAULT FALSE,
//   pathLenConstraint  INTEGER(0..MAX) OPTIONAL,
//   ... }

class BasicConstraints extends asn1.Sequence {
  constructor() {
    super();
    this.cA = new asn1.Bool().optional();
    this.pathLenConstraint = new asn1.Integer().optional();
  }

  getBodySize() {
    let size = 0;
    size += this.cA.getSize();
    size += this.pathLenConstraint.getSize();
    return size;
  }

  writeBody(bw) {
    this.cA.write(bw);
    this.pathLenConstraint.write(bw);
    return bw;
  }

  readBody(br) {
    this.cA.read(br);
    this.pathLenConstraint.read(br);
    return this;
  }

  clean() {
    return this.cA.clean()
        && this.pathLenConstraint.clean();
  }

  format() {
    return {
      cA: this.cA,
      pathLenConstraint: this.pathLenConstraint
    };
  }

  getJSON() {
    return {
      cA: this.cA.getJSON(),
      pathLenConstraint: this.pathLenConstraint.toNumber()
    };
  }

  fromJSON(json) {
    this.cA.fromJSON(json.cA);
    this.pathLenConstraint.fromNumber(json.pathLenConstraint);

    return this;
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }
}

// RSAPublicKey ::= SEQUENCE {
//    modulus           INTEGER,  -- n
//    publicExponent    INTEGER   -- e
// }

class RSAPublicKey extends asn1.Sequence {
  constructor() {
    super();
    this.modulus = new asn1.Integer();
    this.publicExponent = new asn1.Integer();
  }

  getBodySize() {
    let size = 0;
    size += this.modulus.getSize();
    size += this.publicExponent.getSize();
    return size;
  }

  writeBody(bw) {
    this.modulus.write(bw);
    this.publicExponent.write(bw);
    return bw;
  }

  readBody(br) {
    this.modulus.read(br);
    this.publicExponent.read(br);
    return this;
  }

  clean() {
    return this.modulus.clean()
        && this.publicExponent.clean();
  }

  format() {
    return {
      modulus: this.modulus,
      publicExponent: this.publicExponent
    };
  }

  getJSON() {
    return {
      modulus: this.modulus.getJSON().value,
      publicExponent: this.publicExponent.getJSON().value
    };
  }

  fromJSON(json) {
    this.modulus.fromJSON({value: json.modulus, negative: false});
    this.publicExponent.fromJSON({value: json.publicExponent, negative: false});

    return this;
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }
}

/**
 * API
 */

function identifierToClass(oid) {
  assert(typeof oid === 'string');

  switch (oid) {
    case 'BasicConstraints':
      return BasicConstraints;
    case 'RSAPublicKey':
      return RSAPublicKey;
    default:
      return null;
  }
}

/*
 * Expose
 */

exports.BasicConstraints = BasicConstraints;
exports.RSAPublicKey = RSAPublicKey;

exports.identifierToClass = identifierToClass;

