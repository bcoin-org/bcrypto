/*!
 * secp256k1.js - wrapper for secp256k1-node
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const binding = require('./secp256k1-backend');
const random = require('./random');
const secp256k1 = exports;

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

secp256k1.privateKeyGenerate = function privateKeyGenerate() {
  let key;

  do {
    key = random.randomBytes(32);
  } while (!binding.privateKeyVerify(key));

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
 * Compute ((tweak + key) % n).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer} key
 */

secp256k1.privateKeyTweakAdd = function privateKeyTweakAdd(key, tweak) {
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(tweak));
  return binding.privateKeyTweakAdd(key, tweak);
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
 * Validate a public key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid public key.
 */

secp256k1.publicKeyVerify = function publicKeyVerify(key) {
  assert(Buffer.isBuffer(key));
  return binding.publicKeyVerify(key);
};

/**
 * Validate a private key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid private key.
 */

secp256k1.privateKeyVerify = function privateKeyVerify(key) {
  assert(Buffer.isBuffer(key));
  return binding.privateKeyVerify(key);
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

  // Sign message
  const sig = secp256k1.sign(msg, key);

  // Convert to DER
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
    s = binding.signatureImport(sig);
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
  return binding.signatureImport(sig);
};

/**
 * Convert R/S signature to DER.
 * @param {Buffer} sig
 * @returns {Buffer} DER-formatted signature.
 */

secp256k1.toDER = function toDER(sig) {
  assert(Buffer.isBuffer(sig));
  assert(sig.length === 64);
  return binding.signatureExport(sig);
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

secp256k1.isLowDER = function isLowDER(raw) {
  assert(Buffer.isBuffer(raw));

  let sig;

  try {
    sig = binding.signatureImport(raw);
  } catch (e) {
    return false;
  }

  return secp256k1.isLowS(sig);
};
