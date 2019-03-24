/*!
 * ed25519.js - ed25519 for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const binding = require('./binding').ed25519;
const random = require('./random');
const asn1 = require('../internal/asn1-mini');
const ed25519 = exports;

/*
 * Constants
 */

const ZERO = Buffer.alloc(32, 0x00);

const ORDER = Buffer.from(
  '1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed',
  'hex');

const CURVE_OID = Buffer.from('2b6570', 'hex');

/**
 * Name of the curve.
 * @const {String}
 */

ed25519.id = 'ED25519';

/**
 * Edwards flag.
 * @const {Boolean}
 */

ed25519.edwards = true;

/**
 * Montgomery flag.
 * @const {Boolean}
 */

ed25519.mont = false;

/**
 * Size of the curve in bits.
 * @const {Number}
 */

ed25519.bits = 253;

/**
 * Size of the curve in bytes.
 * @const {Buffer}
 */

ed25519.size = 32;

/**
 * Zero value of the curve.
 * @const {Buffer}
 */

ed25519.zero = ZERO;

/**
 * Order of the curve.
 * @const {Buffer}
 */

ed25519.order = ORDER;

/**
 * Whether the backend is a binding.
 * @const {Number}
 */

ed25519.native = 2;

/**
 * Generate a secret.
 * @returns {Buffer}
 */

ed25519.privateKeyGenerate = function privateKeyGenerate() {
  return random.randomBytes(32);
};

/**
 * Generate a clamped scalar.
 * @returns {Buffer}
 */

ed25519.scalarGenerate = function scalarGenerate() {
  const scalar = random.randomBytes(32);

  scalar[0] &= 248;
  scalar[31] &= 127;
  scalar[31] |= 64;

  return scalar;
};

/**
 * Create a private key from a secret.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed25519.privateKeyConvert = function privateKeyConvert(secret) {
  return binding.privateKeyConvert(secret);
};

/**
 * Validate a secret.
 * @param {Buffer} secret
 * @returns {Boolean}
 */

ed25519.privateKeyVerify = function privateKeyVerify(secret) {
  assert(Buffer.isBuffer(secret));
  return secret.length === 32;
};

/**
 * Validate a scalar.
 * @param {Buffer} secret
 * @returns {Boolean}
 */

ed25519.scalarVerify = function scalarVerify(scalar) {
  assert(Buffer.isBuffer(scalar));

  if (scalar.length !== 32)
    return false;

  if (scalar[0] & ~248)
    return false;

  if (scalar[31] & ~127)
    return false;

  if (!(scalar[31] & 64))
    return false;

  return true;
};

/**
 * Export a private key to ASN.1 format.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed25519.privateKeyExport = function privateKeyExport(secret) {
  assert(Buffer.isBuffer(secret));
  assert(secret.length === 32);
  return asn1.encodeOct(secret);
};

/**
 * Import a private key from ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

ed25519.privateKeyImport = function privateKeyImport(raw) {
  const key = asn1.decodeOct(raw);
  assert(key.length === 32);
  return Buffer.from(key);
};

/**
 * Export a private key to PKCS8 ASN.1 format.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed25519.privateKeyExportPKCS8 = function privateKeyExportPKCS8(secret) {
  assert(Buffer.isBuffer(secret));
  assert(secret.length === 32);

  return asn1.encodePKCS8({
    version: 0,
    algorithm: {
      oid: CURVE_OID,
      type: asn1.NULL,
      params: null
    },
    key: ed25519.privateKeyExport(secret)
  });
};

/**
 * Import a private key from PKCS8 ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

ed25519.privateKeyImportPKCS8 = function privateKeyImportPKCS8(raw) {
  const pki = asn1.decodePKCS8(raw);

  assert(pki.version === 0 || pki.version === 1);
  assert(pki.algorithm.oid.equals(CURVE_OID));
  assert(pki.algorithm.type === asn1.NULL);

  return ed25519.privateKeyImport(pki.key);
};

/**
 * Add tweak value to scalar.
 * @param {Buffer} scalar
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

ed25519.scalarTweakAdd = function scalarTweakAdd(scalar, tweak) {
  return binding.scalarTweakAdd(scalar, tweak);
};

/**
 * Multiply scalar by tweak value.
 * @param {Buffer} scalar
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

ed25519.scalarTweakMul = function scalarTweakMul(scalar, tweak) {
  return binding.scalarTweakMul(scalar, tweak);
};

/**
 * Create a public key from a secret.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed25519.publicKeyCreate = function publicKeyCreate(secret) {
  return binding.publicKeyCreate(secret);
};

/**
 * Create a public key from a scalar.
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

ed25519.publicKeyFromScalar = function publicKeyFromScalar(scalar) {
  return binding.publicKeyFromScalar(scalar);
};

/**
 * Convert key to an X25519 key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

ed25519.publicKeyConvert = function publicKeyConvert(key) {
  return binding.publicKeyConvert(key);
};

/**
 * Convert key from an X25519 key.
 * @param {Buffer} key
 * @param {Boolean} [sign=false]
 * @returns {Buffer}
 */

ed25519.publicKeyDeconvert = function publicKeyDeconvert(key, sign) {
  return binding.publicKeyDeconvert(key, sign);
};

/**
 * Validate a public key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

ed25519.publicKeyVerify = function publicKeyVerify(key) {
  return binding.publicKeyVerify(key);
};

/**
 * Export a public key to PKCS1 ASN.1 format.
 * @param {Buffer} key
 * @returns {Buffer}
 */

ed25519.publicKeyExport = function publicKeyExport(key) {
  assert(Buffer.isBuffer(key));
  assert(key.length === 32);
  return key;
};

/**
 * Import a public key from PKCS1 ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

ed25519.publicKeyImport = function publicKeyImport(raw) {
  assert(Buffer.isBuffer(raw));
  assert(raw.length === 32);

  if (!ed25519.publicKeyVerify(raw))
    throw new Error('Invalid public key.');

  return raw;
};

/**
 * Export a public key to SubjectPublicKeyInfo ASN.1 format.
 * @param {Buffer} key
 * @returns {Buffer}
 */

ed25519.publicKeyExportSPKI = function publicKeyExportSPKI(key) {
  assert(Buffer.isBuffer(key));
  assert(key.length === 32);

  return asn1.encodeSPKI({
    algorithm: {
      oid: CURVE_OID,
      type: asn1.NULL,
      params: null
    },
    key
  });
};

/**
 * Import a public key from SubjectPublicKeyInfo ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

ed25519.publicKeyImportSPKI = function publicKeyImportSPKI(raw) {
  const spki = asn1.decodeSPKI(raw);

  assert(spki.algorithm.oid.equals(CURVE_OID));
  assert(spki.algorithm.type === asn1.NULL);
  assert(spki.key.length === 32);

  return Buffer.from(spki.key);
};

/**
 * Compute ((tweak + key) % n).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

ed25519.publicKeyTweakAdd = function publicKeyTweakAdd(key, tweak) {
  return binding.publicKeyTweakAdd(key, tweak);
};

/**
 * Compute ((tweak * key) % n).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

ed25519.publicKeyTweakMul = function publicKeyTweakMul(key, tweak) {
  return binding.publicKeyTweakMul(key, tweak);
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} secret
 * @param {Boolean|null} ph
 * @param {Buffer|null} ctx
 * @returns {Buffer}
 */

ed25519.sign = function sign(msg, secret, ph, ctx) {
  return binding.sign(msg, secret, ph, ctx);
};

/**
 * Sign a message with a scalar and raw prefix.
 * @param {Buffer} msg
 * @param {Buffer} scalar
 * @param {Buffer} prefix
 * @param {Boolean|null} ph
 * @param {Buffer|null} ctx
 * @returns {Buffer}
 */

ed25519.signWithScalar = function signWithScalar(msg, scalar, prefix, ph, ctx) {
  return binding.signWithScalar(msg, scalar, prefix, ph, ctx);
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} secret
 * @param {Buffer} tweak
 * @param {Boolean|null} ph
 * @param {Buffer|null} ctx
 * @returns {Buffer}
 */

ed25519.signTweakAdd = function signTweakAdd(msg, secret, tweak, ph, ctx) {
  return binding.signTweakAdd(msg, secret, tweak, ph, ctx);
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} secret
 * @param {Buffer} tweak
 * @param {Boolean|null} ph
 * @param {Buffer|null} ctx
 * @returns {Buffer}
 */

ed25519.signTweakMul = function signTweakMul(msg, secret, tweak, ph, ctx) {
  return binding.signTweakMul(msg, secret, tweak, ph, ctx);
};

/**
 * Verify a signature.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Buffer} key
 * @param {Boolean|null} ph
 * @param {Buffer|null} ctx
 * @returns {Boolean}
 */

ed25519.verify = function verify(msg, sig, key, ph, ctx) {
  return binding.verify(msg, sig, key, ph, ctx);
};

/**
 * Perform an ECDH.
 * @param {Buffer} pub - ED25519 key.
 * @param {Buffer} secret - ED25519 secret.
 * @returns {Buffer}
 */

ed25519.derive = function derive(pub, secret) {
  return binding.derive(pub, secret);
};

/**
 * Perform an ECDH with a raw scalar.
 * @param {Buffer} pub - ED25519 key.
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

ed25519.deriveWithScalar = function deriveWithScalar(pub, scalar) {
  return binding.deriveWithScalar(pub, scalar);
};

/**
 * Perform an ECDH (X25519).
 * @param {Buffer} xpub - X25519 key (little endian).
 * @param {Buffer} secret - ED25519 secret.
 * @returns {Buffer}
 */

ed25519.exchange = function exchange(xpub, secret) {
  return binding.exchange(xpub, secret);
};

/**
 * Perform an ECDH (X25519) with a raw scalar.
 * @param {Buffer} xpub - X25519 key (little endian).
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

ed25519.exchangeWithScalar = function exchangeWithScalar(xpub, scalar) {
  return binding.exchangeWithScalar(xpub, scalar);
};

/*
 * Compat
 */

ed25519.ecdh = ed25519.derive;
