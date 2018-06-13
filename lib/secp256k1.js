/*!
 * secp256k1.js - wrapper for secp256k1-node
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const backend = require('./internal/secp256k1');
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

secp256k1.native = backend._bcryptoBinding ? 2 : 0;

/**
 * Generate a private key.
 * @returns {Buffer} Private key.
 */

secp256k1.privateKeyGenerate = function privateKeyGenerate() {
  const key = Buffer.allocUnsafe(32);

  do {
    random.randomFill(key, 0, 32);
  } while (!backend.privateKeyVerify(key));

  return key;
};

/**
 * Generate a private key.
 * @returns {Buffer} Private key.
 */

secp256k1.generatePrivateKey = secp256k1.privateKeyGenerate;

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

  return backend.publicKeyCreate(key, compress);
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

  return backend.publicKeyConvert(key, compress);
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
  return backend.privateKeyTweakAdd(key, tweak);
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

  return backend.publicKeyTweakAdd(key, tweak, compress);
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

  return backend.ecdhUnsafe(pub, priv, compress);
};

/**
 * Validate a public key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid public key.
 */

secp256k1.publicKeyVerify = function publicKeyVerify(key) {
  assert(Buffer.isBuffer(key));
  return backend.publicKeyVerify(key);
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

  return backend.privateKeyVerify(key);
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
  const {signature} = backend.sign(msg, key);

  // Ensure low S value.
  return backend.signatureNormalize(signature);
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
  return backend.signatureExport(sig);
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
    const s = backend.signatureNormalize(sig);
    return backend.verify(msg, s, key);
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
    s = backend.signatureImportLax(sig);
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
    return backend.recover(msg, sig, param, compress);
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
    s = backend.signatureImport(sig);
  } catch (e) {
    return null;
  }

  return secp256k1.recover(msg, s, param, compress);
};

/**
 * Convert DER signature to R/S.
 * @param {Buffer} sig
 * @returns {Buffer} R/S-formatted signature.
 */

secp256k1.fromDER = function fromDER(sig) {
  assert(Buffer.isBuffer(sig));
  return backend.signatureImport(sig);
};

/**
 * Convert DER signature to R/S.
 * @param {Buffer} sig
 * @returns {Buffer} R/S-formatted signature.
 */

secp256k1.fromLax = function fromLax(sig) {
  assert(Buffer.isBuffer(sig));
  return backend.signatureImportLax(sig);
};

/**
 * Convert R/S signature to DER.
 * @param {Buffer} sig
 * @returns {Buffer} DER-formatted signature.
 */

secp256k1.toDER = function toDER(sig) {
  assert(Buffer.isBuffer(sig));
  assert(sig.length === 64);
  return backend.signatureExport(sig);
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
    sig = backend.signatureImport(raw);
  } catch (e) {
    return false;
  }

  return secp256k1.isLowS(sig);
};
