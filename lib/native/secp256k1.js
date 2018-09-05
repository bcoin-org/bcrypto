/*!
 * secp256k1.js - secp256k1 for bcrypto
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

if (process.env.NODE_BACKEND && process.env.NODE_BACKEND !== 'native')
  throw new Error('Non-native backend selected.');

const assert = require('bsert');
const binding = require('bindings')('secp256k1');
const random = require('./random');
const secp256k1 = exports;

/*
 * Constants
 */

const ZERO = Buffer.alloc(32, 0x00);

const ORDER = Buffer.from(
  'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
  'hex');

const HALF_ORDER = Buffer.from(
  '7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0',
  'hex');

/**
 * Name of the curve.
 * @const {String}
 */

secp256k1.id = 'secp256k1';

/**
 * Size of the curve in bits.
 * @const {Number}
 */

secp256k1.bits = 256;

/**
 * Size of the curve in bytes.
 * @const {Buffer}
 */

secp256k1.size = 32;

/**
 * Zero value of the curve.
 * @const {Buffer}
 */

secp256k1.zero = ZERO;

/**
 * Order of the curve.
 * @const {Buffer}
 */

secp256k1.order = ORDER;

/**
 * Half-order of the curve.
 * @const {Buffer}
 */

secp256k1.half = HALF_ORDER;

/**
 * Whether the backend is a binding.
 * @const {Number}
 */

secp256k1.native = 2;

/**
 * Generate a private key.
 * @returns {Buffer} Private key.
 */

secp256k1.privateKeyGenerate = function privateKeyGenerate() {
  const key = Buffer.allocUnsafe(32);

  do {
    random.randomFill(key, 0, 32);
  } while (!binding.privateKeyVerify(key));

  return key;
};

/**
 * Validate a private key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid private key.
 */

secp256k1.privateKeyVerify = function privateKeyVerify(key) {
  assert(Buffer.isBuffer(key));

  if (key.length !== 32)
    return false;

  return binding.privateKeyVerify(key);
};

/**
 * Export a private key to SEC1 ASN.1 format.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

secp256k1.privateKeyExport = function privateKeyExport(key, compress) {
  if (compress == null)
    compress = true;

  assert(Buffer.isBuffer(key));
  assert(typeof compress === 'boolean');

  return binding.privateKeyExport(key, compress);
};

/**
 * Import a private key from SEC1 ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

secp256k1.privateKeyImport = function privateKeyImport(raw) {
  assert(Buffer.isBuffer(raw));
  return binding.privateKeyImport(raw);
};

/**
 * Compute ((tweak + key) % n).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer} key
 */

secp256k1.privateKeyTweakAdd = function privateKeyTweakAdd(key, tweak) {
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(tweak));
  assert(key.length === 32);
  return binding.privateKeyTweakAdd(key, tweak);
};

/**
 * Create a public key from a private key.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

secp256k1.publicKeyCreate = function publicKeyCreate(key, compress) {
  if (compress == null)
    compress = true;

  assert(Buffer.isBuffer(key));
  assert(typeof compress === 'boolean');

  return binding.publicKeyCreate(key, compress);
};

/**
 * Compress or decompress public key.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

secp256k1.publicKeyConvert = function publicKeyConvert(key, compress) {
  if (compress == null)
    compress = true;

  assert(Buffer.isBuffer(key));
  assert(typeof compress === 'boolean');

  return binding.publicKeyConvert(key, compress);
};

/**
 * Validate a public key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid public key.
 */

secp256k1.publicKeyVerify = function publicKeyVerify(key) {
  assert(Buffer.isBuffer(key));
  return binding.publicKeyVerify(key);
};

/**
 * Export a public key to X/Y format.
 * @param {Buffer} key
 * @returns {Buffer}
 */

secp256k1.publicKeyExport = function publicKeyExport(key) {
  return secp256k1.publicKeyConvert(key, false).slice(1);
};

/**
 * Import a public key from X/Y format.
 * @param {Buffer} raw
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

secp256k1.publicKeyImport = function publicKeyImport(raw, compress) {
  assert(Buffer.isBuffer(raw));
  assert(raw.length === 64);

  const key = Buffer.allocUnsafe(1 + raw.length);
  key[0] = 0x04;
  raw.copy(key, 1);

  return secp256k1.publicKeyConvert(key, compress);
};

/**
 * Compute ((g * tweak) + key).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @param {Boolean} [compress=true]
 * @returns {Buffer} key
 */

secp256k1.publicKeyTweakAdd = function publicKeyTweakAdd(key, tweak, compress) {
  if (compress == null)
    compress = true;

  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(tweak));
  assert(typeof compress === 'boolean');

  return binding.publicKeyTweakAdd(key, tweak, compress);
};

/**
 * Convert R/S signature to DER.
 * @param {Buffer} sig
 * @returns {Buffer} DER-formatted signature.
 */

secp256k1.signatureExport = function signatureExport(sig) {
  assert(Buffer.isBuffer(sig));
  assert(sig.length === 64);
  return binding.signatureExport(sig);
};

/**
 * Convert DER signature to R/S.
 * @param {Buffer} sig
 * @returns {Buffer} R/S-formatted signature.
 */

secp256k1.signatureImport = function signatureImport(sig) {
  assert(Buffer.isBuffer(sig));
  return binding.signatureImportLax(sig);
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} R/S-formatted signature.
 */

secp256k1.sign = function sign(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));
  assert(key.length === 32);

  // Sign message.
  const {signature} = binding.sign(msg, key);

  // Ensure low S value.
  return binding.signatureNormalize(signature);
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} DER-formatted signature.
 */

secp256k1.signDER = function signDER(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));
  assert(key.length === 32);

  // Sign message.
  const sig = secp256k1.sign(msg, key);

  // Convert to DER.
  return binding.signatureExport(sig);
};

/**
 * Verify a signature.
 * @param {Buffer} msg
 * @param {Buffer} sig - R/S formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

secp256k1.verify = function verify(msg, sig, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));

  if (sig.length !== 64)
    return false;

  if (key.length === 0)
    return false;

  try {
    const s = binding.signatureNormalize(sig);
    return binding.verify(msg, s, key);
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

secp256k1.verifyDER = function verifyDER(msg, sig, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));

  if (sig.length === 0)
    return false;

  if (key.length === 0)
    return false;

  let s;
  try {
    s = binding.signatureImportLax(sig);
  } catch (e) {
    return false;
  }

  return secp256k1.verify(msg, s, key);
};

/**
 * Recover a public key.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Number} [param=0]
 * @param {Boolean} [compress=true]
 * @returns {Buffer|null}
 */

secp256k1.recover = function recover(msg, sig, param, compress) {
  if (param == null)
    param = 0;

  if (compress == null)
    compress = true;

  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert((param >>> 0) === param);
  assert(typeof compress === 'boolean');

  if (sig.length !== 64)
    return null;

  try {
    return binding.recover(msg, sig, param, compress);
  } catch (e) {
    return null;
  }
};

/**
 * Recover a public key.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Number} [param=0]
 * @param {Boolean} [compress=true]
 * @returns {Buffer|null}
 */

secp256k1.recoverDER = function recoverDER(msg, sig, param, compress) {
  assert(Buffer.isBuffer(sig));

  let s;
  try {
    s = binding.signatureImportLax(sig);
  } catch (e) {
    return null;
  }

  return secp256k1.recover(msg, s, param, compress);
};

/**
 * Create an ecdh.
 * @param {Buffer} pub
 * @param {Buffer} priv
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

secp256k1.ecdh = function ecdh(pub, priv, compress) {
  if (compress == null)
    compress = true;

  assert(Buffer.isBuffer(pub));
  assert(Buffer.isBuffer(priv));
  assert(typeof compress === 'boolean');

  return binding.ecdhUnsafe(pub, priv, compress);
};

/**
 * Test whether a signature has a low S value.
 * @param {Buffer} sig
 * @returns {Boolean}
 */

secp256k1.isLowS = function isLowS(raw) {
  assert(Buffer.isBuffer(raw));

  if (raw.length !== 64)
    return false;

  const sig = raw.slice(32, 64);

  if (sig.equals(ZERO))
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

secp256k1.isLowDER = function isLowDER(raw) {
  assert(Buffer.isBuffer(raw));

  let sig;

  try {
    sig = binding.signatureImportLax(raw);
  } catch (e) {
    return false;
  }

  return secp256k1.isLowS(sig);
};

/*
 * Compat
 */

secp256k1.generatePrivateKey = secp256k1.privateKeyGenerate;
secp256k1.toDER = secp256k1.signatureExport;
secp256k1.fromDER = secp256k1.signatureImport;
