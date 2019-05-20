/*!
 * dsa.js - DSA for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const backend = require('./binding');
const binding = backend.dsa;

if (!binding)
  throw new Error('DSA native support not available.');

const dsakey = require('../internal/dsakey');
const asn1 = require('../encoding/asn1');
const openssl = require('../encoding/openssl');
const pkcs8 = require('../encoding/pkcs8');
const rfc3279 = require('../encoding/rfc3279');
const x509 = require('../encoding/x509');

const {
  DSAKey,
  DSAParams,
  DSAPublicKey,
  DSAPrivateKey
} = dsakey;

/**
 * Generate params.
 * @param {Number} [bits=2048]
 * @returns {DSAParams}
 */

function paramsGenerate(bits) {
  if (bits == null)
    bits = 2048;

  assert((bits >>> 0) === bits);

  if (bits < 1024 || bits > 3072)
    throw new RangeError('`bits` must range between 1024 and 3072.');

  backend.reseed();

  const items = binding.paramsGenerate(bits);
  const params = new DSAParams();

  [
    params.p,
    params.q,
    params.g
  ] = items;

  return params;
}

/**
 * Generate params.
 * @param {Number} [bits=2048]
 * @returns {DSAParams}
 */

async function paramsGenerateAsync(bits) {
  if (bits == null)
    bits = 2048;

  assert((bits >>> 0) === bits);

  if (bits < 1024 || bits > 3072)
    throw new RangeError('`bits` must range between 1024 and 3072.');

  backend.reseed();

  return new Promise((resolve, reject) => {
    const cb = (err, items) => {
      if (err) {
        reject(err);
        return;
      }

      const params = new DSAParams();

      [
        params.p,
        params.q,
        params.g
      ] = items;

      resolve(params);
    };

    try {
      binding.paramsGenerateAsync(bits, cb);
    } catch (e) {
      reject(e);
    }
  });
}

/**
 * Verify params.
 * @param {DSAParams} params
 * @returns {Boolean}
 */

function paramsVerify(params) {
  assert(params instanceof DSAParams);

  return binding.paramsVerify(
    params.p,
    params.q,
    params.g
  );
}

/**
 * Export params in OpenSSL ASN.1 format.
 * @param {DSAParams} params
 * @returns {Buffer}
 */

function paramsExport(params) {
  assert(params instanceof DSAParams);

  // if (!isSaneParams(params))
  //   throw new Error('Invalid DSA parameters.');

  return new openssl.DSAParams(
    params.p,
    params.q,
    params.g
  ).encode();
}

/**
 * Import params in OpenSSL ASN.1 format.
 * @param {Buffer} raw
 * @returns {DSAParams}
 */

function paramsImport(raw) {
  const params = openssl.DSAParams.decode(raw);

  return new DSAPrivateKey(
    params.p.value,
    params.q.value,
    params.g.value
  );
}

/**
 * Export a public key to JWK JSON format.
 * @param {DSAParams} key
 * @returns {Object}
 */

function paramsExportJWK(key) {
  assert(key instanceof DSAParams);
  return key.toParams().toJSON();
}

/**
 * Import a public key from JWK JSON format.
 * @param {Object} json
 * @returns {DSAPublicKey}
 */

function paramsImportJWK(json) {
  return DSAParams.fromJSON(json);
}

/**
 * Generate private key from params.
 * @param {DSAParams} params
 * @returns {DSAPrivateKey}
 */

function privateKeyCreate(params) {
  assert(params instanceof DSAParams);

  backend.reseed();

  const items = binding.privateKeyCreate(
    params.p,
    params.q,
    params.g
  );

  const key = new DSAPrivateKey();

  [
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  ] = items;

  return key;
}

/**
 * Generate private key.
 * @param {Number} [bits=2048]
 * @returns {DSAPrivateKey}
 */

function privateKeyGenerate(bits) {
  const params = paramsGenerate(bits);
  return privateKeyCreate(params);
}

/**
 * Generate private key.
 * @param {Number} [bits=2048]
 * @returns {DSAPrivateKey}
 */

async function privateKeyGenerateAsync(bits) {
  const params = await paramsGenerateAsync(bits);
  return privateKeyCreate(params);
}

/**
 * Pre-compute a private key.
 * @param {DSAPrivateKey}
 * @returns {DSAPrivateKey}
 */

function privateKeyCompute(key) {
  assert(key instanceof DSAPrivateKey);

  backend.reseed();

  const y = binding.privateKeyCompute(
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  );

  if (y)
    key.y = y;

  return key;
}

/**
 * Verify a private key.
 * @param {DSAPrivateKey} key
 * @returns {Boolean}
 */

function privateKeyVerify(key) {
  assert(key instanceof DSAPrivateKey);

  backend.reseed();

  return binding.privateKeyVerify(
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  );
}

/**
 * Export a private key in OpenSSL ASN.1 format.
 * @param {DSAPrivateKey} key
 * @returns {Buffer}
 */

function privateKeyExport(key) {
  assert(key instanceof DSAPrivateKey);

  // if (!isSanePrivateKey(key))
  //   throw new Error('Invalid DSA private key.');

  return new openssl.DSAPrivateKey(
    0,
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  ).encode();
}

/**
 * Import a private key in OpenSSL ASN.1 format.
 * @param {Buffer} raw
 * @returns {DSAPrivateKey}
 */

function privateKeyImport(raw) {
  const key = openssl.DSAPrivateKey.decode(raw);

  assert(key.version.toNumber() === 0);

  return new DSAPrivateKey(
    key.p.value,
    key.q.value,
    key.g.value,
    key.y.value,
    key.x.value
  );
}

/**
 * Export a private key in PKCS8 ASN.1 format.
 * @param {DSAPrivateKey} key
 * @returns {Buffer}
 */

function privateKeyExportPKCS8(key) {
  assert(key instanceof DSAPrivateKey);

  // if (!isSanePrivateKey(key))
  //   throw new Error('Invalid DSA private key.');

  return new pkcs8.PrivateKeyInfo(
    0,
    asn1.objects.keyAlgs.DSA,
    new rfc3279.DSAParams(key.p, key.q, key.g),
    new asn1.Unsigned(key.x).encode()
  ).encode();
}

/**
 * Import a private key in PKCS8 ASN.1 format.
 * @param {Buffer} key
 * @returns {DSAPrivateKey}
 */

function privateKeyImportPKCS8(raw) {
  const pki = pkcs8.PrivateKeyInfo.decode(raw);
  const {algorithm, parameters} = pki.algorithm;

  assert(pki.version.toNumber() === 0);
  assert(algorithm.toString() === asn1.objects.keyAlgs.DSA);
  assert(parameters.node.type === asn1.types.SEQUENCE);

  const {p, q, g} = rfc3279.DSAParams.decodeBody(parameters.node.value);
  const x = asn1.Unsigned.decode(pki.privateKey.value);

  const key = new DSAPrivateKey(
    p.value,
    q.value,
    g.value,
    null,
    x.value
  );

  privateKeyCompute(key);

  return key;
}

/**
 * Export a private key to JWK JSON format.
 * @param {DSAPrivateKey} key
 * @returns {Object}
 */

function privateKeyExportJWK(key) {
  assert(key instanceof DSAPrivateKey);
  return key.toJSON();
}

/**
 * Import a private key from JWK JSON format.
 * @param {Object} json
 * @returns {DSAPrivateKey}
 */

function privateKeyImportJWK(json) {
  const key = DSAPrivateKey.fromJSON(json);

  privateKeyCompute(key);

  return key;
}

/**
 * Create a public key from a private key.
 * @param {DSAPrivateKey} key
 * @returns {DSAPublicKey}
 */

function publicKeyCreate(key) {
  assert(key instanceof DSAPrivateKey);

  const pub = new DSAPublicKey();

  pub.p = key.p;
  pub.q = key.q;
  pub.g = key.g;
  pub.y = key.y;

  return pub;
}

/**
 * Verify a public key.
 * @param {DSAKey} key
 * @returns {Boolean}
 */

function publicKeyVerify(key) {
  assert(key instanceof DSAKey);

  return binding.publicKeyVerify(
    key.p,
    key.q,
    key.g,
    key.y
  );
}

/**
 * Export a public key to OpenSSL ASN.1 format.
 * @param {DSAKey} key
 * @returns {Buffer}
 */

function publicKeyExport(key) {
  assert(key instanceof DSAKey);

  // if (!isSanePublicKey(key))
  //   throw new Error('Invalid DSA public key.');

  return new openssl.DSAPublicKey(
    key.y,
    key.p,
    key.q,
    key.g
  ).encode();
}

/**
 * Import a public key from OpenSSL ASN.1 format.
 * @param {Buffer} raw
 * @returns {DSAPublicKey}
 */

function publicKeyImport(raw) {
  const key = openssl.DSAPublicKey.decode(raw);

  return new DSAPublicKey(
    key.p.value,
    key.q.value,
    key.g.value,
    key.y.value
  );
}

/**
 * Export a public key to SubjectPublicKeyInfo ASN.1 format.
 * @param {DSAKey} key
 * @returns {Buffer}
 */

function publicKeyExportSPKI(key) {
  assert(key instanceof DSAKey);

  // if (!isSanePublicKey(key))
  //   throw new Error('Invalid DSA public key.');

  // https://tools.ietf.org/html/rfc3279#section-2.3.2
  return new x509.SubjectPublicKeyInfo(
    asn1.objects.keyAlgs.DSA,
    new rfc3279.DSAParams(key.p, key.q, key.g),
    new asn1.Unsigned(key.y).encode()
  ).encode();
}

/**
 * Import a public key from SubjectPublicKeyInfo ASN.1 format.
 * @param {Buffer} raw
 * @returns {DSAPublicKey}
 */

function publicKeyImportSPKI(raw) {
  const spki = x509.SubjectPublicKeyInfo.decode(raw);
  const {algorithm, parameters} = spki.algorithm;

  assert(algorithm.toString() === asn1.objects.keyAlgs.DSA);
  assert(parameters.node.type === asn1.types.SEQUENCE);

  const {p, q, g} = rfc3279.DSAParams.decodeBody(parameters.node.value);
  const y = asn1.Unsigned.decode(spki.publicKey.rightAlign());

  return new DSAPublicKey(
    p.value,
    q.value,
    g.value,
    y.value
  );
}

/**
 * Export a public key to JWK JSON format.
 * @param {DSAKey} key
 * @returns {Object}
 */

function publicKeyExportJWK(key) {
  assert(key instanceof DSAKey);
  return key.toPublic().toJSON();
}

/**
 * Import a public key from JWK JSON format.
 * @param {Object} json
 * @returns {DSAPublicKey}
 */

function publicKeyImportJWK(json) {
  return DSAPublicKey.fromJSON(json);
}

/**
 * Convert R/S signature to DER.
 * @param {Buffer} sig
 * @param {Number} size
 * @returns {Buffer} DER-formatted signature.
 */

function signatureExport(sig, size) {
  return binding.signatureExport(sig, size);
}

/**
 * Convert DER signature to R/S.
 * @param {Buffer} sig
 * @param {Number} size
 * @returns {Buffer} R/S-formatted signature.
 */

function signatureImport(sig, size) {
  return binding.signatureImport(sig, size);
}

/**
 * Sign a message (R/S).
 * @param {Buffer} msg
 * @param {DSAPrivateKey} key - Private key.
 * @returns {Buffer} R/S-formatted signature.
 */

function sign(msg, key) {
  assert(key instanceof DSAPrivateKey);

  backend.reseed();

  return binding.sign(
    msg,
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  );
}

/**
 * Sign a message (DER).
 * @param {Buffer} msg
 * @param {DSAPrivateKey} key - Private key.
 * @returns {Buffer} DER-formatted signature.
 */

function signDER(msg, key) {
  assert(key instanceof DSAPrivateKey);

  backend.reseed();

  return binding.signDER(
    msg,
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  );
}

/**
 * Verify a signature (R/S).
 * @param {Buffer} msg
 * @param {Buffer} sig - R/S-formatted.
 * @param {DSAKey} key
 * @returns {Boolean}
 */

function verify(msg, sig, key) {
  assert(key instanceof DSAKey);

  return binding.verify(
    msg,
    sig,
    key.p,
    key.q,
    key.g,
    key.y
  );
}

/**
 * Verify a signature (DER).
 * @param {Buffer} msg
 * @param {Buffer} sig - DER-formatted.
 * @param {DSAKey} key
 * @returns {Boolean}
 */

function verifyDER(msg, sig, key) {
  assert(key instanceof DSAKey);

  return binding.verifyDER(
    msg,
    sig,
    key.p,
    key.q,
    key.g,
    key.y
  );
}

/**
 * Perform a diffie-hellman.
 * @param {DSAKey} pub
 * @param {DSAPrivateKey} priv
 * @returns {Buffer}
 */

function derive(pub, priv) {
  assert(pub instanceof DSAKey);
  assert(priv instanceof DSAPrivateKey);

  backend.reseed();

  return binding.derive(
    pub.p,
    pub.q,
    pub.g,
    pub.y,
    priv.p,
    priv.q,
    priv.g,
    priv.y,
    priv.x
  );
}

/*
 * Expose
 */

exports.native = 2;
exports.DSAParams = DSAParams;
exports.DSAKey = DSAKey;
exports.DSAPublicKey = DSAPublicKey;
exports.DSAPrivateKey = DSAPrivateKey;
exports.paramsGenerate = paramsGenerate;
exports.paramsGenerateAsync = paramsGenerateAsync;
exports.paramsVerify = paramsVerify;
exports.paramsExport = paramsExport;
exports.paramsImport = paramsImport;
exports.paramsExportJWK = paramsExportJWK;
exports.paramsImportJWK = paramsImportJWK;
exports.privateKeyCreate = privateKeyCreate;
exports.privateKeyGenerate = privateKeyGenerate;
exports.privateKeyGenerateAsync = privateKeyGenerateAsync;
exports.privateKeyCompute = privateKeyCompute;
exports.privateKeyVerify = privateKeyVerify;
exports.privateKeyExport = privateKeyExport;
exports.privateKeyImport = privateKeyImport;
exports.privateKeyExportPKCS8 = privateKeyExportPKCS8;
exports.privateKeyImportPKCS8 = privateKeyImportPKCS8;
exports.privateKeyExportJWK = privateKeyExportJWK;
exports.privateKeyImportJWK = privateKeyImportJWK;
exports.publicKeyCreate = publicKeyCreate;
exports.publicKeyVerify = publicKeyVerify;
exports.publicKeyExport = publicKeyExport;
exports.publicKeyImport = publicKeyImport;
exports.publicKeyExportSPKI = publicKeyExportSPKI;
exports.publicKeyImportSPKI = publicKeyImportSPKI;
exports.publicKeyExportJWK = publicKeyExportJWK;
exports.publicKeyImportJWK = publicKeyImportJWK;
exports.signatureExport = signatureExport;
exports.signatureImport = signatureImport;
exports.sign = sign;
exports.signDER = signDER;
exports.verify = verify;
exports.verifyDER = verifyDER;
exports.derive = derive;
