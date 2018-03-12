/*!
 * secp256k1.js - wrapper for secp256k1-node
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const secp256k1 = require('./secp256k1-backend');
const random = require('./random');
const ec = exports;

/*
 * Constants
 */

const ZERO_S = Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex'
);

const HALF_ORDER = Buffer.from(
  '7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0',
  'hex');

/**
 * Generate a private key.
 * @returns {Buffer} Private key.
 */

ec.generatePrivateKey = function generatePrivateKey() {
  let key;

  do {
    key = random.randomBytes(32);
  } while (!secp256k1.privateKeyVerify(key));

  return key;
};

/**
 * Create a public key from a private key.
 * @param {Buffer} key
 * @param {Boolean?} compress
 * @returns {Buffer}
 */

ec.publicKeyCreate = function publicKeyCreate(key, compress) {
  return secp256k1.publicKeyCreate(key, compress);
};

/**
 * Compress or decompress public key.
 * @param {Buffer} pub
 * @returns {Buffer}
 */

ec.publicKeyConvert = function publicKeyConvert(key, compress) {
  return secp256k1.publicKeyConvert(key, compress);
};

/**
 * ((tweak + key) % n)
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer} key
 */

ec.privateKeyTweakAdd = function privateKeyTweakAdd(key, tweak) {
  assert(Buffer.isBuffer(key));
  return secp256k1.privateKeyTweakAdd(key, tweak);
};

/**
 * ((g * tweak) + key)
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer} key
 */

ec.publicKeyTweakAdd = function publicKeyTweakAdd(key, tweak, compress) {
  return secp256k1.publicKeyTweakAdd(key, tweak, compress);
};

/**
 * Create an ecdh.
 * @param {Buffer} pub
 * @param {Buffer} priv
 * @returns {Buffer}
 */

ec.ecdh = function ecdh(pub, priv) {
  return secp256k1.ecdhUnsafe(pub, priv, true);
};

/**
 * Validate a public key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid public key.
 */

ec.publicKeyVerify = function publicKeyVerify(key) {
  return secp256k1.publicKeyVerify(key);
};

/**
 * Validate a private key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid private key.
 */

ec.privateKeyVerify = function privateKeyVerify(key) {
  return secp256k1.privateKeyVerify(key);
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} R/S-formatted signature.
 */

ec.sign = function sign(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));

  // Sign message
  const {signature} = secp256k1.sign(msg, key);

  // Ensure low S value
  return secp256k1.signatureNormalize(signature);
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} DER-formatted signature.
 */

ec.signDER = function signDER(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));

  // Sign message
  const sig = ec.sign(msg, key);

  // Convert to DER
  return secp256k1.signatureExport(sig);
};

/**
 * Verify a signature.
 * @param {Buffer} msg
 * @param {Buffer} sig - R/S formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

ec.verify = function verify(msg, sig, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));

  if (sig.length === 0)
    return false;

  if (key.length === 0)
    return false;

  try {
    sig = secp256k1.signatureNormalize(sig);
    return secp256k1.verify(msg, sig, key);
  } catch (e) {
    return false;
  }
};

/**
 * Verify a signature.
 * @param {Buffer} msg
 * @param {Buffer} sig - DER formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

ec.verifyDER = function verifyDER(msg, sig, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));

  if (sig.length === 0)
    return false;

  if (key.length === 0)
    return false;

  try {
    sig = secp256k1.signatureImportLax(sig);
  } catch (e) {
    return false;
  }

  return ec.verify(msg, sig, key);
};

/**
 * Recover a public key.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Number?} param
 * @param {Boolean?} compress
 * @returns {Buffer[]|Buffer|null}
 */

ec.recover = function recover(msg, sig, param, compress) {
  if (param == null)
    param = 0;

  try {
    return secp256k1.recover(msg, sig, param, compress);
  } catch (e) {
    return null;
  }
};

/**
 * Recover a public key.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Number?} param
 * @param {Boolean?} compress
 * @returns {Buffer[]|Buffer|null}
 */

ec.recoverDER = function recoverDER(msg, sig, param, compress) {
  try {
    sig = secp256k1.signatureImport(sig);
  } catch (e) {
    return null;
  }
  return ec.recover(msg, sig, param, compress);
};

/**
 * Convert DER signature to R/S.
 * @param {Buffer} sig
 * @returns {Buffer} R/S-formatted signature.
 */

ec.fromDER = function fromDER(sig) {
  assert(Buffer.isBuffer(sig));
  return secp256k1.signatureImport(sig);
};

/**
 * Convert R/S signature to DER.
 * @param {Buffer} sig
 * @returns {Buffer} DER-formatted signature.
 */

ec.toDER = function toDER(sig) {
  assert(Buffer.isBuffer(sig));
  return secp256k1.signatureExport(sig);
};

/**
 * Test whether a signature has a low S value.
 * @param {Buffer} sig
 * @returns {Boolean}
 */

ec.isLowS = function isLowS(sig) {
  assert(Buffer.isBuffer(sig));

  if (sig.length !== 64)
    return false;

  sig = sig.slice(32, 64);

  if (sig.equals(ZERO_S))
    return false;

  if (sig.compare(HALF_ORDER) > 0)
    return false;

  return true;
};

/**
 * Test whether a signature has a low S value.
 * @param {Buffer} sig
 * @returns {Boolean}
 */

ec.isLowDER = function isLowDER(sig) {
  assert(Buffer.isBuffer(sig));
  try {
    sig = secp256k1.signatureImport(sig);
  } catch (e) {
    return false;
  }
  return ec.isLowS(sig);
};
