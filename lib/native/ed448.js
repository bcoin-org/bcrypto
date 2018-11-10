/*!
 * ed448.js - ed448 for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const binding = require('./binding').ed448;
const random = require('./random');
const asn1 = require('../internal/asn1-mini');
const ed448 = exports;

/*
 * Constants
 */

const ZERO = Buffer.alloc(57, 0x00);

const ORDER = Buffer.from(''
  + '3fffffffffffffffffffffffffff'
  + 'ffffffffffffffffffffffffffff'
  + '7cca23e9c44edb49aed63690216c'
  + 'c2728dc58f552378c292ab5844f3',
  'hex');

const CURVE_OID = Buffer.from('2b6571', 'hex');

/**
 * Name of the curve.
 * @const {String}
 */

ed448.id = 'ED448';

/**
 * Edwards flag.
 * @const {Boolean}
 */

ed448.edwards = true;

/**
 * Size of the curve in bits.
 * @const {Number}
 */

ed448.bits = 456;

/**
 * Size of the curve in bytes.
 * @const {Buffer}
 */

ed448.size = 57;

/**
 * Zero value of the curve.
 * @const {Buffer}
 */

ed448.zero = ZERO;

/**
 * Order of the curve.
 * @const {Buffer}
 */

ed448.order = ORDER;

/**
 * Whether the backend is a binding.
 * @const {Number}
 */

ed448.native = 2;

/**
 * Generate a secret.
 * @returns {Buffer}
 */

ed448.privateKeyGenerate = function privateKeyGenerate() {
  return random.randomBytes(57);
};

/**
 * Create a private key from a secret.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed448.privateKeyConvert = function privateKeyConvert(secret) {
  return binding.privateKeyConvert(secret);
};

/**
 * Validate a secret.
 * @param {Buffer} secret
 * @returns {Boolean}
 */

ed448.privateKeyVerify = function privateKeyVerify(secret) {
  assert(Buffer.isBuffer(secret));
  return secret.length === 57;
};

/**
 * Export a private key to ASN.1 format.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed448.privateKeyExport = function privateKeyExport(secret) {
  assert(Buffer.isBuffer(secret));
  assert(secret.length === 57);
  return asn1.encodeOct(secret);
};

/**
 * Import a private key from ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

ed448.privateKeyImport = function privateKeyImport(raw) {
  const key = asn1.decodeOct(raw);
  assert(key.length === 57);
  return Buffer.from(key);
};

/**
 * Export a private key to PKCS8 ASN.1 format.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed448.privateKeyExportPKCS8 = function privateKeyExportPKCS8(secret) {
  assert(Buffer.isBuffer(secret));
  assert(secret.length === 57);

  return asn1.encodePKCS8({
    version: 0,
    algorithm: {
      oid: CURVE_OID,
      type: asn1.NULL,
      params: null
    },
    key: ed448.privateKeyExport(secret)
  });
};

/**
 * Import a private key from PKCS8 ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

ed448.privateKeyImportPKCS8 = function privateKeyImportPKCS8(raw) {
  const pki = asn1.decodePKCS8(raw);

  assert(pki.version === 0 || pki.version === 1);
  assert(pki.algorithm.oid.equals(CURVE_OID));
  assert(pki.algorithm.type === asn1.NULL);

  return ed448.privateKeyImport(pki.key);
};

/**
 * Create a public key from a secret.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed448.publicKeyCreate = function publicKeyCreate(secret) {
  return binding.publicKeyCreate(secret);
};

/**
 * Convert key to an X448 key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

ed448.publicKeyConvert = function publicKeyConvert(key) {
  return binding.publicKeyConvert(key);
};

/**
 * Convert key from an X448 key.
 * @param {Buffer} key
 * @param {Boolean} [sign=false]
 * @returns {Buffer}
 */

ed448.publicKeyDeconvert = function publicKeyDeconvert(key, sign) {
  return binding.publicKeyDeconvert(key, sign);
};

/**
 * Validate a public key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

ed448.publicKeyVerify = function publicKeyVerify(key) {
  return binding.publicKeyVerify(key);
};

/**
 * Export a public key to PKCS1 ASN.1 format.
 * @param {Buffer} key
 * @returns {Buffer}
 */

ed448.publicKeyExport = function publicKeyExport(key) {
  assert(Buffer.isBuffer(key));
  assert(key.length === 57);
  return key;
};

/**
 * Import a public key from PKCS1 ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

ed448.publicKeyImport = function publicKeyImport(raw) {
  assert(Buffer.isBuffer(raw));
  assert(raw.length === 57);

  if (!ed448.publicKeyVerify(raw))
    throw new Error('Invalid public key.');

  return raw;
};

/**
 * Export a public key to SubjectPublicKeyInfo ASN.1 format.
 * @param {Buffer} key
 * @returns {Buffer}
 */

ed448.publicKeyExportSPKI = function publicKeyExportSPKI(key) {
  assert(Buffer.isBuffer(key));
  assert(key.length === 57);

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

ed448.publicKeyImportSPKI = function publicKeyImportSPKI(raw) {
  const spki = asn1.decodeSPKI(raw);

  assert(spki.algorithm.oid.equals(CURVE_OID));
  assert(spki.algorithm.type === asn1.NULL);
  assert(spki.key.length === 57);

  return Buffer.from(spki.key);
};

/**
 * Compute ((tweak + key) % n).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

ed448.publicKeyTweakAdd = function publicKeyTweakAdd(key, tweak) {
  throw new Error('Unimplemented.');
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed448.sign = function sign(msg, secret) {
  return binding.sign(msg, secret);
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} secret
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

ed448.signTweak = function signTweak(msg, secret, tweak) {
  throw new Error('Unimplemented.');
};

/**
 * Verify a signature.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Buffer} key
 * @returns {Boolean}
 */

ed448.verify = function verify(msg, sig, key) {
  return binding.verify(msg, sig, key);
};

/**
 * Perform an ECDH.
 * @param {Buffer} edpub - ED448 key.
 * @param {Buffer} secret - ED448 secret.
 * @returns {Buffer}
 */

ed448.derive = function derive(edpub, secret) {
  return binding.derive(edpub, secret);
};

/**
 * Perform an ECDH (X448).
 * @param {Buffer} xpub - X448 key (little endian).
 * @param {Buffer} secret - ED448 secret.
 * @returns {Buffer}
 */

ed448.exchange = function exchange(xpub, secret) {
  return binding.exchange(xpub, secret);
};

/*
 * Compat
 */

ed448.ecdh = ed448.derive;
