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
 * Create a public key from a secret.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed25519.publicKeyCreate = function publicKeyCreate(secret) {
  return binding.publicKeyCreate(secret);
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
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed25519.sign = function sign(msg, secret) {
  return binding.sign(msg, secret);
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} secret
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

ed25519.signTweak = function signTweak(msg, secret, tweak) {
  return binding.signTweak(msg, secret, tweak);
};

/**
 * Verify a signature.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Buffer} key
 * @returns {Boolean}
 */

ed25519.verify = function verify(msg, sig, key) {
  return binding.verify(msg, sig, key);
};

/**
 * Perform an ECDH.
 * @param {Buffer} edpub - ED25519 key.
 * @param {Buffer} secret - ED25519 secret.
 * @returns {Buffer}
 */

ed25519.derive = function derive(edpub, secret) {
  return binding.derive(edpub, secret);
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

/*
 * Compat
 */

ed25519.ecdh = ed25519.derive;
