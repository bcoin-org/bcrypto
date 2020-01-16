/*!
 * rsa.js - RSA for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const binding = require('./binding');
const asn1 = require('../encoding/asn1');
const pkcs1 = require('../encoding/pkcs1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');
const rsakey = require('../internal/rsakey');
const backend = binding.rsa;

const {
  RSAKey,
  RSAPrivateKey,
  RSAPublicKey,
  DEFAULT_BITS,
  DEFAULT_EXP,
  MIN_BITS,
  MAX_BITS,
  MIN_EXP,
  MAX_EXP
} = rsakey;

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @param {Number} [exponent=65537]
 * @returns {RSAPrivateKey} Private key.
 */

function privateKeyGenerate(bits, exponent) {
  if (bits == null)
    bits = DEFAULT_BITS;

  if (exponent == null)
    exponent = DEFAULT_EXP;

  assert((bits >>> 0) === bits);
  assert(Number.isSafeInteger(exponent) && exponent >= 0);

  if (bits < MIN_BITS || bits > MAX_BITS)
    throw new RangeError(`"bits" ranges from ${MIN_BITS} to ${MAX_BITS}.`);

  if (exponent < MIN_EXP || exponent > MAX_EXP)
    throw new RangeError(`"exponent" ranges from ${MIN_EXP} to ${MAX_EXP}.`);

  if (exponent === 1 || (exponent & 1) === 0)
    throw new RangeError('"exponent" must be odd.');

  const raw = backend.privateKeyGenerate(bits, exponent, binding.entropy());

  return _privateKeyImport(raw);
}

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @param {Number} [exponent=65537]
 * @returns {RSAPrivateKey} Private key.
 */

async function privateKeyGenerateAsync(bits, exponent) {
  if (bits == null)
    bits = DEFAULT_BITS;

  if (exponent == null)
    exponent = DEFAULT_EXP;

  assert((bits >>> 0) === bits);
  assert(Number.isSafeInteger(exponent) && exponent >= 0);

  if (bits < MIN_BITS || bits > MAX_BITS)
    throw new RangeError(`"bits" ranges from ${MIN_BITS} to ${MAX_BITS}.`);

  if (exponent < MIN_EXP || exponent > MAX_EXP)
    throw new RangeError(`"exponent" ranges from ${MIN_EXP} to ${MAX_EXP}.`);

  if (exponent === 1 || (exponent & 1) === 0)
    throw new RangeError('"exponent" must be odd.');

  return new Promise(function(resolve, reject) {
    const cb = function(err, raw) {
      if (err) {
        reject(err);
        return;
      }

      resolve(_privateKeyImport(raw));
    };

    try {
      backend.privateKeyGenerateAsync(bits, exponent, binding.entropy(), cb);
    } catch (e) {
      reject(e);
    }
  });
}

/**
 * Pre-compute a private key.
 * @param {RSAPrivateKey}
 * @returns {RSAPrivateKey}
 */

function privateKeyCompute(key) {
  const raw = backend.privateKeyRecover(_privateKeyExport(key),
                                        binding.entropy());
  const ret = _privateKeyImport(raw);

  [
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  ] = [
    ret.n,
    ret.e,
    ret.d,
    ret.p,
    ret.q,
    ret.dp,
    ret.dq,
    ret.qi
  ];
}

/**
 * Verify a private key.
 * @param {RSAPrivateKey} key
 * @returns {Boolean}
 */

function privateKeyVerify(key) {
  return backend.privateKeyVerify(_privateKeyExport(key));
}

/**
 * Export a private key to PKCS1 ASN.1 format.
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

function privateKeyExport(key) {
  // [RFC8017] Page 55, Section A.1.2.
  assert(key instanceof RSAPrivateKey);

  // if (!isSanePrivateKey(key))
  //   throw new Error('Invalid RSA private key.');

  return new pkcs1.RSAPrivateKey(
    0,
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  ).encode();
}

/**
 * Import a private key from PKCS1 ASN.1 format.
 * @param {Buffer} raw
 * @returns {RSAPrivateKey}
 */

function privateKeyImport(raw) {
  // [RFC8017] Page 55, Section A.1.2.
  const key = pkcs1.RSAPrivateKey.decode(raw);

  assert(key.version.toNumber() === 0);

  return new RSAPrivateKey(
    key.n.value,
    key.e.value,
    key.d.value,
    key.p.value,
    key.q.value,
    key.dp.value,
    key.dq.value,
    key.qi.value
  );
}

/**
 * Export a private key to PKCS8 ASN.1 format.
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

function privateKeyExportPKCS8(key) {
  assert(key instanceof RSAPrivateKey);

  return new pkcs8.PrivateKeyInfo(
    0,
    asn1.objects.keyAlgs.RSA,
    new asn1.Null(),
    privateKeyExport(key)
  ).encode();
}

/**
 * Import a private key from PKCS8 ASN.1 format.
 * @param {Buffer} raw
 * @returns {RSAPrivateKey}
 */

function privateKeyImportPKCS8(raw) {
  const pki = pkcs8.PrivateKeyInfo.decode(raw);
  const {algorithm, parameters} = pki.algorithm;

  assert(pki.version.toNumber() === 0);
  assert(algorithm.toString() === asn1.objects.keyAlgs.RSA);
  assert(parameters.node.type === asn1.types.NULL);

  return privateKeyImport(pki.privateKey.value);
}

/**
 * Export a private key to JWK JSON format.
 * @param {RSAPrivateKey} key
 * @returns {Object}
 */

function privateKeyExportJWK(key) {
  assert(key instanceof RSAPrivateKey);
  return key.toJSON();
}

/**
 * Import a private key from JWK JSON format.
 * @param {Object} json
 * @returns {RSAPrivateKey}
 */

function privateKeyImportJWK(json) {
  const key = RSAPrivateKey.fromJSON(json);

  privateKeyCompute(key);

  return key;
}

/**
 * Create a public key from a private key.
 * @param {RSAPrivateKey} key
 * @returns {RSAPublicKey}
 */

function publicKeyCreate(key) {
  assert(key instanceof RSAPrivateKey);

  const pub = new RSAPublicKey();

  pub.n = key.n;
  pub.e = key.e;

  return pub;
}

/**
 * Verify a public key.
 * @param {RSAKey} key
 * @returns {Boolean}
 */

function publicKeyVerify(key) {
  return backend.publicKeyVerify(_publicKeyExport(key));
}

/**
 * Export a public key to PKCS1 ASN.1 format.
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function publicKeyExport(key) {
  // [RFC8017] Page 54, Section A.1.1.
  assert(key instanceof RSAKey);

  // if (!isSanePublicKey(key))
  //   throw new Error('Invalid RSA public key.');

  return new pkcs1.RSAPublicKey(key.n, key.e).encode();
}

/**
 * Import a public key from PKCS1 ASN.1 format.
 * @param {Buffer} raw
 * @returns {RSAPublicKey}
 */

function publicKeyImport(raw) {
  // [RFC8017] Page 54, Section A.1.1.
  const key = pkcs1.RSAPublicKey.decode(raw);
  return new RSAPublicKey(key.n.value, key.e.value);
}

/**
 * Export a public key to SubjectPublicKeyInfo ASN.1 format.
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function publicKeyExportSPKI(key) {
  return new x509.SubjectPublicKeyInfo(
    asn1.objects.keyAlgs.RSA,
    new asn1.Null(),
    publicKeyExport(key)
  ).encode();
}

/**
 * Import a public key from SubjectPublicKeyInfo ASN.1 format.
 * @param {Buffer} raw
 * @returns {RSAPublicKey}
 */

function publicKeyImportSPKI(raw) {
  const spki = x509.SubjectPublicKeyInfo.decode(raw);
  const {algorithm, parameters} = spki.algorithm;

  assert(algorithm.toString() === asn1.objects.keyAlgs.RSA);
  assert(parameters.node.type === asn1.types.NULL);

  return publicKeyImport(spki.publicKey.rightAlign());
}

/**
 * Export a public key to JWK JSON format.
 * @param {RSAKey} key
 * @returns {Object}
 */

function publicKeyExportJWK(key) {
  assert(key instanceof RSAKey);
  return key.toPublic().toJSON();
}

/**
 * Import a public key from JWK JSON format.
 * @param {Object} json
 * @returns {RSAPublicKey}
 */

function publicKeyImportJWK(json) {
  return RSAPublicKey.fromJSON(json);
}

/**
 * Sign a message (PKCS1v1.5).
 * @param {Object|String|null} hash
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key - Private key.
 * @returns {Buffer} PKCS#1v1.5-formatted signature.
 */

function sign(hash, msg, key) {
  if (hash && typeof hash.id === 'string')
    hash = hash.id;

  if (hash == null)
    hash = -1;
  else
    hash = binding.hashes[hash];

  return backend.sign(hash, msg, _privateKeyExport(key), binding.entropy());
}

/**
 * Verify a signature (PKCS1v1.5).
 * @param {Object|String|null} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PKCS#1v1.5-formatted.
 * @param {RSAKey} key
 * @returns {Boolean}
 */

function verify(hash, msg, sig, key) {
  if (hash && typeof hash.id === 'string')
    hash = hash.id;

  if (hash == null)
    hash = -1;
  else
    hash = binding.hashes[hash];

  return backend.verify(hash, msg, sig, _publicKeyExport(key));
}

/**
 * Verify a signature (PKCS1v1.5).
 * @param {Object|String|null} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PKCS#1v1.5-formatted.
 * @param {RSAKey} key
 * @returns {Boolean}
 */

function verifyLax(hash, msg, sig, key) {
  assert(key instanceof RSAKey);
  return verify(hash, msg, key.pad(sig), key);
}

/**
 * Encrypt a message with public key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function encrypt(msg, key) {
  return backend.encrypt(msg, _publicKeyExport(key), binding.entropy());
}

/**
 * Decrypt a message with private key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

function decrypt(msg, key) {
  return backend.decrypt(msg, _privateKeyExport(key), binding.entropy());
}

/**
 * Decrypt a message with private key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

function decryptLax(msg, key) {
  assert(key instanceof RSAKey);
  return decrypt(key.pad(msg), key);
}

/**
 * Encrypt a message with public key (OAEP).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {RSAKey} key
 * @param {Buffer?} label
 * @returns {Buffer}
 */

function encryptOAEP(hash, msg, key, label) {
  return backend.encryptOAEP(binding.hash(hash),
                             msg,
                             _publicKeyExport(key),
                             binding.entropy(),
                             label);
}

/**
 * Decrypt a message with private key (OAEP).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @param {Buffer?} label
 * @returns {Buffer}
 */

function decryptOAEP(hash, msg, key, label) {
  return backend.decryptOAEP(binding.hash(hash),
                             msg,
                             _privateKeyExport(key),
                             binding.entropy(),
                             label);
}

/**
 * Decrypt a message with private key (OAEP).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @param {Buffer?} label
 * @returns {Buffer}
 */

function decryptOAEPLax(hash, msg, key, label) {
  assert(key instanceof RSAKey);
  return decryptOAEP(hash, key.pad(msg), key, label);
}

/**
 * Sign a message (PSS).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key - Private key.
 * @param {Number} [saltLen=SALT_LENGTH_HASH]
 * @returns {Buffer} PSS-formatted signature.
 */

function signPSS(hash, msg, key, saltLen) {
  return backend.signPSS(binding.hash(hash),
                         msg,
                         _privateKeyExport(key),
                         binding.entropy(),
                         saltLen);
}

/**
 * Verify a signature (PSS).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PSS-formatted.
 * @param {RSAKey} key
 * @param {Number} [saltLen=SALT_LENGTH_HASH]
 * @returns {Boolean}
 */

function verifyPSS(hash, msg, sig, key, saltLen) {
  return backend.verifyPSS(binding.hash(hash),
                           msg,
                           sig,
                           _publicKeyExport(key),
                           saltLen);
}

/**
 * Verify a signature (PSS).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PSS-formatted.
 * @param {RSAKey} key
 * @param {Number} [saltLen=SALT_LENGTH_HASH]
 * @returns {Boolean}
 */

function verifyPSSLax(hash, msg, sig, key, saltLen) {
  assert(key instanceof RSAKey);
  return verifyPSS(hash, msg, key.pad(sig), key, saltLen);
}

/**
 * Raw encryption.
 * @private
 * @param {Buffer} msg
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function encryptRaw(msg, key) {
  return backend.encryptRaw(msg, _publicKeyExport(key));
}

/**
 * Raw decryption.
 * @private
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

function decryptRaw(msg, key) {
  return backend.decryptRaw(msg, _privateKeyExport(key), binding.entropy());
}

/**
 * "Veil" an RSA ciphertext to hide the key size.
 * @param {Buffer} msg
 * @param {Number} bits
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function veil(msg, bits, key) {
  return backend.veil(msg, bits, _publicKeyExport(key), binding.entropy());
}

/**
 * "Veil" an RSA ciphertext to hide the key size.
 * @param {Buffer} msg
 * @param {Number} bits
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function veilLax(msg, bits, key) {
  assert(key instanceof RSAKey);
  return veil(key.pad(msg), bits, key);
}

/**
 * "Unveil" a veiled RSA ciphertext.
 * @param {Buffer} msg
 * @param {Number} bits
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function unveil(msg, bits, key) {
  return backend.unveil(msg, bits, _publicKeyExport(key));
}

/**
 * "Unveil" a veiled RSA ciphertext.
 * @param {Buffer} msg
 * @param {Number} bits
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function unveilLax(msg, bits, key) {
  assert(key instanceof RSAKey);
  return unveil(key.pad(msg), bits, key);
}

/*
 * Helpers
 */

function _privateKeyExport(key) {
  assert(key instanceof RSAPrivateKey);

  return new pkcs1.RSAPrivateKey(
    0,
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  ).encode();
}

function _privateKeyImport(raw) {
  const key = pkcs1.RSAPrivateKey.decode(raw);

  assert(key.version.toNumber() === 0);

  return new RSAPrivateKey(
    key.n.value,
    key.e.value,
    key.d.value,
    key.p.value,
    key.q.value,
    key.dp.value,
    key.dq.value,
    key.qi.value
  );
}

function _publicKeyExport(key) {
  assert(key instanceof RSAKey);
  return new pkcs1.RSAPublicKey(key.n, key.e).encode();
}

function _publicKeyImport(raw) {
  const key = pkcs1.RSAPublicKey.decode(raw);
  return new RSAPublicKey(key.n.value, key.e.value);
}

/*
 * Expose
 */

exports.native = 2;
exports.RSAKey = RSAKey;
exports.RSAPublicKey = RSAPublicKey;
exports.RSAPrivateKey = RSAPrivateKey;
exports.SALT_LENGTH_AUTO = 0;
exports.SALT_LENGTH_HASH = -1;
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
exports.sign = sign;
exports.verify = verify;
exports.verifyLax = verifyLax;
exports.encrypt = encrypt;
exports.decrypt = decrypt;
exports.decryptLax = decryptLax;
exports.encryptOAEP = encryptOAEP;
exports.decryptOAEP = decryptOAEP;
exports.decryptOAEPLax = decryptOAEPLax;
exports.signPSS = signPSS;
exports.verifyPSS = verifyPSS;
exports.verifyPSSLax = verifyPSSLax;
exports.encryptRaw = encryptRaw;
exports.decryptRaw = decryptRaw;
exports.veil = veil;
exports.veilLax = veilLax;
exports.unveil = unveil;
exports.unveilLax = unveilLax;
