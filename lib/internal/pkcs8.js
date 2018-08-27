/*!
 * pkcs8.js - PKCS8 encoding for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   https://github.com/golang/go/blob/master/src/crypto/x509/pkcs8.go
 */

'use strict';

const asn1 = require('./asn1');
const pem = require('./pem');
const pkcs1 = require('./pkcs1');
const x509 = require('./x509');

/**
 * PublicKeyInfo
 */

// PublicKeyInfo ::= SEQUENCE {
//   algorithm       AlgorithmIdentifier,
//   PublicKey       BIT STRING
// }

class PublicKeyInfo extends asn1.Sequence {
  constructor(algorithm, identifier, publicKey) {
    super();
    this.algorithm = new x509.AlgorithmIdentifier(algorithm, identifier);
    this.publicKey = new asn1.OctString(publicKey);
  }

  getBodySize() {
    let size = 0;
    size += this.algorithm.getSize();
    size += this.publicKey.getSize();
    return size;
  }

  writeBody(bw) {
    this.version.write(bw);
    this.algorithm.write(bw);
    this.publicKey.write(bw);
    return bw;
  }

  readBody(br) {
    this.version.read(br);
    this.algorithm.read(br);
    this.publicKey.read(br);
    return this;
  }

  clean() {
    return this.algorithm.isNull()
        && this.publicKey.isNull();
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'PUBLIC KEY');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'PUBLIC KEY');
    return this.decode(data);
  }

  getKey() {
    const {algorithm, parameters} = this.algorithm;
    const pub = this.publicKey.value;
    const type = algorithm.getKey();

    if (!type)
      throw new Error(`Unknown key OID: ${algorithm.toString()}.`);

    switch (type) {
      case 'dsa': {
        // Parameters in params? DSAParms?
        const key = pkcs1.DSAPublicKey.decode(pub);
        return key.getKey();
      }

      case 'rsa': {
        const key = pkcs1.RSAPublicKey.decode(pub);
        return key.getKey();
      }

      case 'ecdsa':
      case 'eddsa': {
        if (parameters.type !== asn1.types.OID)
          throw new Error('Unexpected parameters.');

        const curve = parameters.getCurve();

        if (!curve)
          throw new Error(`Unknown curve OID: ${parameters.toString()}`);

        return {
          type,
          curve,
          point: pub
        };
      }

      default: {
        throw new Error(`Unknown key algorithm: ${type}.`);
      }
    }
  }

  format() {
    return {
      version: this.version,
      algorithm: this.algorithm,
      publicKey: this.publicKey
    };
  }
}

/**
 * PrivateKeyInfo
 */

// PrivateKeyInfo ::= SEQUENCE {
//   version         Version,
//   algorithm       AlgorithmIdentifier,
//   PrivateKey      OCTET STRING
// }
//
// PrivateKeyInfo ::= SEQUENCE {
//    version Version,
//    privateKeyAlgorithm AlgorithmIdentifier {{PrivateKeyAlgorithms}},
//    privateKey PrivateKey,
//    attributes [0] Attributes OPTIONAL
// }
//
// Version ::= INTEGER {v1(0)} (v1,...)
//
// PrivateKey ::= OCTET STRING

class PrivateKeyInfo extends asn1.Sequence {
  constructor(version, algorithm, identifier, privateKey) {
    super();
    this.version = new asn1.Integer(version);
    this.algorithm = new x509.AlgorithmIdentifier(algorithm, identifier);
    this.privateKey = new asn1.OctString(privateKey);
    // this.attributes = new Attributes().optional();
  }

  getBodySize() {
    let size = 0;
    size += this.version.getSize();
    size += this.algorithm.getSize();
    size += this.privateKey.getSize();
    // size += this.attributes.getSize();
    return size;
  }

  writeBody(bw) {
    this.version.write(bw);
    this.algorithm.write(bw);
    this.privateKey.write(bw);
    // this.attributes.write(bw);
    return bw;
  }

  readBody(br) {
    this.version.read(br);
    this.algorithm.read(br);
    this.privateKey.read(br);
    // this.attributes.read(br);
    return this;
  }

  clean() {
    return this.version.isNull()
        && this.algorithm.isNull()
        && this.privateKey.isNull();
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'PRIVATE KEY');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'PRIVATE KEY');
    return this.decode(data);
  }

  getKey() {
    const {algorithm, parameters} = this.algorithm;
    const priv = this.privateKey.value;
    const type = algorithm.getKey();

    if (!type)
      throw new Error(`Unknown key OID: ${algorithm.toString()}.`);

    switch (type) {
      case 'dsa': {
        // Correct? Or just an X value?
        const key = pkcs1.DSAPrivateKey.decode(priv);
        return key.getKey();
      }

      case 'rsa': {
        const key = pkcs1.RSAPrivateKey.decode(priv);
        return key.getKey();
      }

      case 'ecdsa':
      case 'eddsa': {
        if (parameters.type !== asn1.types.OID)
          throw new Error('Unexpected parameters.');

        const curve = parameters.getCurve();

        if (!curve)
          throw new Error(`Unknown curve OID: ${parameters.toString()}`);

        return {
          type,
          curve,
          key: priv
        };
      }

      default: {
        throw new Error(`Unknown key algorithm: ${type}.`);
      }
    }
  }

  format() {
    return {
      version: this.version,
      algorithm: this.algorithm,
      privateKey: this.privateKey
      // attributes: this.attributes
    };
  }
}

/**
 * EncryptedPrivateKeyInfo
 */

// EncryptedPrivateKeyInfo ::= SEQUENCE {
//   encryptionAlgorithm  EncryptionAlgorithmIdentifier,
//   encryptedData        EncryptedData
// }
//
// EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
//
// EncryptedData ::= OCTET STRING

class EncryptedPrivateKeyInfo extends asn1.Sequence {
  constructor(algorithm, identifier, encryptedData) {
    super();
    this.encryptionAlgorithm =
      new x509.AlgorithmIdentifier(algorithm, identifier);
    this.encryptedData = new asn1.OctString(encryptedData);
  }

  getBodySize() {
    let size = 0;
    size += this.encryptionAlgorithm.getSize();
    size += this.encryptedData.getSize();
    return size;
  }

  writeBody(bw) {
    this.encryptionAlgorithm.write(bw);
    this.encryptedData.write(bw);
    return bw;
  }

  readBody(br) {
    this.encryptionAlgorithm.read(br);
    this.encryptedData.read(br);
    return this;
  }

  clean() {
    return this.encryptionAlgorithm.isNull()
        && this.encryptedData.isNull();
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'ENCRYPTED PRIVATE KEY');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'ENCRYPTED PRIVATE KEY');
    return this.decode(data);
  }

  getKey() {
    throw new Error('Unimplemented.');
  }

  format() {
    return {
      encryptionAlgorithm: this.encryptionAlgorithm,
      encryptedData: this.encryptedData
    };
  }
}

/*
 * Expose
 */

exports.PublicKeyInfo = PublicKeyInfo;
exports.PrivateKeyInfo = PrivateKeyInfo;
exports.EncryptedPrivateKeyInfo = EncryptedPrivateKeyInfo;
