/*!
 * rsa.js - RSA for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const pem = require('../encoding/pem');
const rsa = require('../js/rsa');
const {constants} = crypto;

/*
 * Constants
 */

const DEFAULT_BITS = 2048;
const DEFAULT_EXP = 65537;
const MIN_BITS = 512;
const MAX_BITS = 16384;
const MIN_EXP = 3;
const MAX_EXP = (2 ** 33) - 1;

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @param {Number} [exponent=65537]
 * @returns {Buffer} Private key.
 */

function privateKeyGenerate(bits, exponent) {
  if (!crypto.generateKeyPairSync || (exponent && exponent > 0xffffffff))
    return rsa.privateKeyGenerate(bits, exponent);

  const options = createOptions(bits, exponent);
  const {privateKey} = crypto.generateKeyPairSync('rsa', options);

  return importKey(privateKey);
}

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @param {Number} [exponent=65537]
 * @returns {Buffer} Private key.
 */

async function privateKeyGenerateAsync(bits, exponent) {
  if (!crypto.generateKeyPair || (exponent && exponent > 0xffffffff))
    return rsa.privateKeyGenerateAsync(bits, exponent);

  const options = createOptions(bits, exponent);

  return new Promise((resolve, reject) => {
    const cb = (err, publicKey, privateKey) => {
      if (err) {
        reject(err);
        return;
      }

      resolve(importKey(privateKey));
    };

    try {
      crypto.generateKeyPair('rsa', options, cb);
    } catch (e) {
      reject(e);
    }
  });
}

/**
 * Sign a message (PKCS1v1.5).
 * @param {Object|String|null} hash
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} PKCS#1v1.5-formatted signature.
 */

function sign(hash, msg, key) {
  return rsa.sign(hash, msg, key, decryptRaw);
}

/**
 * Verify a signature (PKCS1v1.5).
 * @param {Object|String|null} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PKCS#1v1.5-formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function verify(hash, msg, sig, key) {
  return rsa.verify(hash, msg, sig, key, encryptRaw);
}

/**
 * Encrypt a message with public key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {Buffer} key
 * @returns {Buffer}
 */

function encrypt(msg, key) {
  return rsa.encrypt(msg, key, encryptRaw);
}

/**
 * Decrypt a message with private key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {Buffer} key
 * @returns {Buffer}
 */

function decrypt(msg, key) {
  return rsa.decrypt(msg, key, decryptRaw);
}

/**
 * Sign a message (PSS).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @param {Number} [saltLen=SALT_LENGTH_HASH]
 * @returns {Buffer} PSS-formatted signature.
 */

function signPSS(hash, msg, key, saltLen) {
  return rsa.signPSS(hash, msg, key, saltLen, decryptRaw);
}

/**
 * Verify a signature (PSS).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PSS-formatted.
 * @param {Buffer} key
 * @param {Number} [saltLen=SALT_LENGTH_HASH]
 * @returns {Boolean}
 */

function verifyPSS(hash, msg, sig, key, saltLen) {
  return rsa.verifyPSS(hash, msg, sig, key, saltLen, encryptRaw);
}

/**
 * Encrypt a message with public key (OAEP).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} key
 * @param {Buffer?} label
 * @returns {Buffer}
 */

function encryptOAEP(hash, msg, key, label) {
  return rsa.encryptOAEP(hash, msg, key, label, encryptRaw);
}

/**
 * Decrypt a message with private key (OAEP).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} key
 * @param {Buffer?} label
 * @returns {Buffer}
 */

function decryptOAEP(hash, msg, key, label) {
  return rsa.decryptOAEP(hash, msg, key, label, decryptRaw);
}

/**
 * Raw encryption.
 * @private
 * @param {Buffer} msg
 * @param {Buffer} key
 * @returns {Buffer}
 */

function encryptRaw(msg, key) {
  assert(Buffer.isBuffer(msg));

  return crypto.publicEncrypt({
    key: pem.toPEM(key.encode(), 'RSA PUBLIC KEY'),
    padding: constants.RSA_NO_PADDING
  }, msg);
}

/**
 * Raw decryption.
 * @private
 * @param {Buffer} msg
 * @param {Buffer} key
 * @returns {Buffer}
 */

function decryptRaw(msg, key) {
  assert(Buffer.isBuffer(msg));

  return crypto.privateDecrypt({
    key: pem.toPEM(key.encode(), 'RSA PRIVATE KEY'),
    padding: constants.RSA_NO_PADDING
  }, msg);
}

/*
 * Helpers
 */

function createOptions(bits, exponent) {
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

  return {
    modulusLength: bits,
    publicExponent: exponent,
    publicKeyEncoding: {
      type: 'pkcs1',
      format: 'der'
    },
    privateKeyEncoding: {
      type: 'pkcs1',
      format: 'der'
    }
  };
}

function importKey(key) {
  const {p, q, e} = rsa.privateKeyExport(key);
  return rsa.privateKeyImport({ p, q, e });
}

/*
 * Expose
 */

exports.native = 1;
exports.SALT_LENGTH_AUTO = rsa.SALT_LENGTH_AUTO;
exports.SALT_LENGTH_HASH = rsa.SALT_LENGTH_HASH;
exports.privateKeyGenerate = privateKeyGenerate;
exports.privateKeyGenerateAsync = privateKeyGenerateAsync;
exports.privateKeyBits = rsa.privateKeyBits;
exports.privateKeyVerify = rsa.privateKeyVerify;
exports.privateKeyImport = rsa.privateKeyImport;
exports.privateKeyExport = rsa.privateKeyExport;
exports.publicKeyCreate = rsa.publicKeyCreate;
exports.publicKeyBits = rsa.publicKeyBits;
exports.publicKeyVerify = rsa.publicKeyVerify;
exports.publicKeyImport = rsa.publicKeyImport;
exports.publicKeyExport = rsa.publicKeyExport;
exports.sign = sign;
exports.verify = verify;
exports.encrypt = encrypt;
exports.decrypt = decrypt;
exports.signPSS = signPSS;
exports.verifyPSS = verifyPSS;
exports.encryptOAEP = encryptOAEP;
exports.decryptOAEP = decryptOAEP;
exports.veil = rsa.veil;
exports.unveil = rsa.unveil;
