/*!
 * dsa.js - DSA for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const bio = require('bufio');
const asn1 = require('../encoding/asn1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');
const dsa = require('../js/dsa');

/*
 * Constants
 */

const DEFAULT_BITS = 2048;
const MIN_BITS = 512;
const MAX_BITS = 10000;

/**
 * Generate params.
 * @param {Number} [bits=2048]
 * @returns {Buffer}
 */

function paramsGenerate(bits) {
  if (!crypto.generateKeyPairSync)
    return dsa.paramsGenerate(bits);

  const options = createOptions(bits);
  const {publicKey} = crypto.generateKeyPairSync('dsa', options);

  return parseParams(publicKey);
}

/**
 * Generate params.
 * @param {Number} [bits=2048]
 * @returns {Buffer}
 */

async function paramsGenerateAsync(bits) {
  if (!crypto.generateKeyPair)
    return dsa.paramsGenerateAsync(bits);

  const options = createOptions(bits);

  return new Promise((resolve, reject) => {
    const cb = (err, publicKey, privateKey) => {
      if (err) {
        reject(err);
        return;
      }

      let params;
      try {
        params = parseParams(publicKey);
      } catch (e) {
        reject(e);
        return;
      }

      resolve(params);
    };

    try {
      crypto.generateKeyPair('dsa', options, cb);
    } catch (e) {
      reject(e);
    }
  });
}

/**
 * Generate private key.
 * @param {Number} [bits=2048]
 * @returns {Buffer}
 */

function privateKeyGenerate(bits) {
  if (!crypto.generateKeyPairSync)
    return dsa.privateKeyGenerate(bits);

  const options = createOptions(bits);
  const {publicKey, privateKey} = crypto.generateKeyPairSync('dsa', options);

  return parsePrivateKey(publicKey, privateKey);
}

/**
 * Generate private key.
 * @param {Number} [bits=2048]
 * @returns {Buffer}
 */

async function privateKeyGenerateAsync(bits) {
  if (!crypto.generateKeyPair)
    return dsa.privateKeyGenerateAsync(bits);

  const options = createOptions(bits);

  return new Promise((resolve, reject) => {
    const cb = (err, publicKey, privateKey) => {
      if (err) {
        reject(err);
        return;
      }

      let key;
      try {
        key = parsePrivateKey(publicKey, privateKey);
      } catch (e) {
        reject(e);
        return;
      }

      resolve(key);
    };

    try {
      crypto.generateKeyPair('dsa', options, cb);
    } catch (e) {
      reject(e);
    }
  });
}

/*
 * Helpers
 */

function createOptions(bits) {
  if (bits == null)
    bits = DEFAULT_BITS;

  assert((bits >>> 0) === bits);

  if (bits < MIN_BITS || bits > MAX_BITS)
    throw new RangeError(`"bits" ranges from ${MIN_BITS} to ${MAX_BITS}.`);

  // OpenSSL behavior.
  const L = bits;
  const N = bits < 2048 ? 160 : 256;

  return {
    modulusLength: L,
    divisorLength: N,
    publicKeyEncoding: {
      type: 'spki',
      format: 'der'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'der'
    }
  };
}

function parseParams(publicKey) {
  const spki = x509.SubjectPublicKeyInfo.decode(publicKey);
  const br = bio.read(spki.algorithm.parameters.node.value);
  const p = asn1.Unsigned.read(br);
  const q = asn1.Unsigned.read(br);
  const g = asn1.Unsigned.read(br);

  return dsa.paramsImport({
    p: p.value,
    q: q.value,
    g: g.value
  });
}

function parsePrivateKey(publicKey, privateKey) {
  const spki = x509.SubjectPublicKeyInfo.decode(publicKey);
  const br = bio.read(spki.algorithm.parameters.node.value);
  const p = asn1.Unsigned.read(br);
  const q = asn1.Unsigned.read(br);
  const g = asn1.Unsigned.read(br);
  const y = asn1.Unsigned.decode(spki.publicKey.rightAlign());
  const pki = pkcs8.PrivateKeyInfo.decode(privateKey);
  const x = asn1.Unsigned.decode(pki.privateKey.value);

  return dsa.privateKeyImport({
    p: p.value,
    q: q.value,
    g: g.value,
    y: y.value,
    x: x.value
  });
}

/*
 * Expose
 */

exports.native = 1;
exports.paramsCreate = dsa.paramsCreate;
exports.paramsGenerate = paramsGenerate;
exports.paramsGenerateAsync = paramsGenerateAsync;
exports.paramsBits = dsa.paramsBits;
exports.paramsVerify = dsa.paramsVerify;
exports.paramsImport = dsa.paramsImport;
exports.paramsExport = dsa.paramsExport;
exports.privateKeyCreate = dsa.privateKeyCreate;
exports.privateKeyGenerate = privateKeyGenerate;
exports.privateKeyGenerateAsync = privateKeyGenerateAsync;
exports.privateKeyBits = dsa.privateKeyBits;
exports.privateKeyVerify = dsa.privateKeyVerify;
exports.privateKeyImport = dsa.privateKeyImport;
exports.privateKeyExport = dsa.privateKeyExport;
exports.publicKeyCreate = dsa.publicKeyCreate;
exports.publicKeyBits = dsa.publicKeyBits;
exports.publicKeyVerify = dsa.publicKeyVerify;
exports.publicKeyImport = dsa.publicKeyImport;
exports.publicKeyExport = dsa.publicKeyExport;
exports.signatureImport = dsa.signatureImport;
exports.signatureExport = dsa.signatureExport;
exports.sign = dsa.sign;
exports.signDER = dsa.signDER;
exports.verify = dsa.verify;
exports.verifyDER = dsa.verifyDER;
exports.derive = dsa.derive;
