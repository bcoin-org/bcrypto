/*!
 * sec1.js - SEC1 encoding for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   https://github.com/golang/go/blob/master/src/crypto/x509/sec1.go
 */

'use strict';

const asn1 = require('./asn1');
const pem = require('./pem');

/**
 * ECPrivateKey
 */

// ECPrivateKey ::= SEQUENCE {
//   version       INTEGER { ecPrivkeyVer1(1) },
//   privateKey    OCTET STRING,
//   parameters    [0] EXPLICIT ECDomainParameters OPTIONAL,
//   publicKey     [1] EXPLICIT BIT STRING OPTIONAL
// }

class ECPrivateKey extends asn1.Sequence {
  constructor(version, privateKey, namedCurveOID, publicKey) {
    super();
    this.version = new asn1.Integer(version);
    this.privateKey = new asn1.OctString(privateKey);
    this.namedCurveOID = new asn1.OID(namedCurveOID).explicit(0).optional();
    this.publicKey = new asn1.BitString(publicKey).explicit(1).optional();
  }

  getBodySize() {
    let size = 0;
    size += this.version.getSize();
    size += this.privateKey.getSize();
    size += this.namedCurveOID.getSize();
    size += this.publicKey.getSize();
    return size;
  }

  writeBody(bw) {
    this.version.write(bw);
    this.privateKey.write(bw);
    this.namedCurveOID.write(bw);
    this.publicKey.write(bw);
    return bw;
  }

  readBody(br) {
    this.version.read(br);
    this.privateKey.read(br);
    this.namedCurveOID.read(br);
    this.publicKey.read(br);
    return this;
  }

  clean() {
    return this.version.isNull()
        && this.privateKey.isNull()
        && this.namedCurveOID.isNull()
        && this.publicKey.isNull();
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'EC PRIVATE KEY');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'EC PRIVATE KEY');
    return this.decode(data);
  }

  format() {
    return {
      version: this.version,
      privateKey: this.privateKey,
      namedCurveOID: this.namedCurveOID,
      publicKey: this.publicKey
    };
  }
}

/*
 * Expose
 */

exports.ECPrivateKey = ECPrivateKey;
