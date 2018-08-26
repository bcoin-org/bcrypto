/*!
 * keys.js - Crypto keys for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const pkcs1 = require('./pkcs1');
const pkcs8 = require('./pkcs8');
const sec1 = require('./sec1');
const x509 = require('./x509');
const pem = require('./pem');

/*
 * Keys
 */

function parsePublicKey(str) {
  const [type, data] = pem.readPublicKey(str);

  switch (type) {
    case 'DSA PUBLIC KEY': { // RFC3279
      // Should maybe grab params?
      const key = pkcs1.DSAPublicKey.decode(data);
      return key.getKey();
    }

    case 'RSA PUBLIC KEY': { // PKCS1
      const key = pkcs1.RSAPublicKey.decode(data);
      return key.getKey();
    }

    case 'ECDSA PUBLIC KEY': { // SPKI?
      // Should maybe grab params?
      const key = x509.SubjectPublicKeyInfo.decode(data);
      return key.getKey();
    }

    case 'PUBLIC KEY': { // PKCS8
      const key = pkcs8.PrivateKeyInfo.decode(data);
      return key.getKey();
    }

    default: {
      throw new Error(`Unknown private key type: ${type}.`);
    }
  }
}

function serializePublicKey(key) {
  assert(key);
}

function parsePrivateKey(str, passphrase) {
  const [type, data] = pem.readPrivateKey(str, passphrase);

  switch (type) {
    case 'DSA PRIVATE KEY': { // OpenSSL PKCS1-like format
      const key = pkcs1.DSAPrivateKey.decode(data);
      return key.getKey();
    }

    case 'RSA PRIVATE KEY': { // PKCS1
      const key = pkcs1.RSAPrivateKey.decode(data);
      return key.getKey();
    }

    case 'EC PRIVATE KEY': { // SEC1
      const key = sec1.ECPrivateKey.decode(data);
      return key.getKey();
    }

    case 'PRIVATE KEY': { // PKCS8
      const key = pkcs8.PrivateKeyInfo.decode(data);
      return key.getKey();
    }

    case 'ENCRYPTED PRIVATE KEY': { // PKCS8
      const key = pkcs8.EncryptedPrivateKeyInfo.decode(data);
      return key.getKey();
    }

    default: {
      throw new Error(`Unknown private key type: ${type}.`);
    }
  }
}

function serializePrivateKey(key) {
  assert(key);
}

/*
 * Expose
 */

exports.parsePublicKey = parsePublicKey;
exports.serializePublicKey = serializePublicKey;
exports.parsePrivateKey = parsePrivateKey;
exports.serializePrivateKey = serializePrivateKey;
