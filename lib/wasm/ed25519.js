/*!
 * ed25519.js - ed25519 for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const wasm = require('./binding');
const random = require('./random');
const asn1 = require('../internal/asn1-mini');
const eckey = require('../internal/eckey');
const ed25519 = exports;

/*
 * Constants
 */

const CURVE_OID = Buffer.from('2b6570', 'hex');

/**
 * Name of the curve.
 * @const {String}
 */

ed25519.id = 'ED25519';

/**
 * Curve type.
 * @const {String}
 */

ed25519.type = 'edwards';

/**
 * Curve encoding length in bytes.
 * @const {Buffer}
 */

ed25519.size = 32;

/**
 * Size of the curve's prime in bits.
 * @const {Number}
 */

ed25519.bits = 255;

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

  scalar[0] &= -8;
  scalar[31] &= 0x7f;
  scalar[31] |= 0x40;

  return scalar;
};

/**
 * Expand secret.
 * @param {Buffer} secret
 * @returns {Buffer[]}
 */

ed25519.privateKeyExpand = function privateKeyExpand(secret) {
  assert(Buffer.isBuffer(secret));
  assert(secret.length === 32);

  const save = wasm.save();
  const out = wasm.alloc(64);

  try {
    wasm.call('bcrypto_ed25519_privkey_expand', out, secret);
    return [wasm.read(out, 32), wasm.read(out + 32, 32)];
  } finally {
    wasm.restore(save);
  }
};

/**
 * Create a private key from a secret.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed25519.privateKeyConvert = function privateKeyConvert(secret) {
  assert(Buffer.isBuffer(secret));
  assert(secret.length === 32);

  const save = wasm.save();
  const out = wasm.alloc(32);

  try {
    assert(wasm.call('bcrypto_ed25519_privkey_convert', out, secret) !== -1);
    return wasm.read(out, 32);
  } finally {
    wasm.restore(save);
  }
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

  if (scalar[0] & ~-8)
    return false;

  if (scalar[31] & ~0x7f)
    return false;

  if (!(scalar[31] & 0x40))
    return false;

  return true;
};

/**
 * Clamp a scalar.
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

ed25519.scalarClamp = function scalarClamp(scalar) {
  assert(Buffer.isBuffer(scalar));
  assert(scalar.length === 32);

  if (!ed25519.scalarVerify(scalar)) {
    scalar = Buffer.from(scalar);
    scalar[0] &= -8;
    scalar[31] &= 0x7f;
    scalar[31] |= 0x40;
  }

  return scalar;
};

/**
 * Export a private key to ASN.1 format.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed25519.privateKeyExport = function privateKeyExport(secret) {
  if (!ed25519.privateKeyVerify(secret))
    throw new Error('Invalid private key.');

  return asn1.encodeOct(secret);
};

/**
 * Import a private key from ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

ed25519.privateKeyImport = function privateKeyImport(raw) {
  const secret = asn1.decodeOct(raw);

  if (!ed25519.privateKeyVerify(secret))
    throw new Error('Invalid private key.');

  return secret;
};

/**
 * Export a private key to PKCS8 ASN.1 format.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed25519.privateKeyExportPKCS8 = function privateKeyExportPKCS8(secret) {
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
 * Export a private key to JWK JSON format.
 * @param {Buffer} secret
 * @returns {Object}
 */

ed25519.privateKeyExportJWK = function privateKeyExportJWK(secret) {
  return eckey.privateKeyExportJWK(ed25519, secret);
};

/**
 * Import a private key from JWK JSON format.
 * @param {Object} json
 * @returns {Buffer}
 */

ed25519.privateKeyImportJWK = function privateKeyImportJWK(json) {
  return eckey.privateKeyImportJWK(ed25519, json);
};

/**
 * Add tweak value to scalar.
 * @param {Buffer} scalar
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

ed25519.scalarTweakAdd = function scalarTweakAdd(scalar, tweak) {
  assert(Buffer.isBuffer(scalar));
  assert(Buffer.isBuffer(tweak));
  assert(scalar.length === 32);
  assert(tweak.length === 32);

  const save = wasm.save();
  const out = wasm.alloc(32);

  try {
    assert(wasm.call('bcrypto_ed25519_scalar_tweak_add', out, scalar, tweak) !== -1);
    return wasm.read(out, 32);
  } finally {
    wasm.restore(save);
  }
};

/**
 * Multiply scalar by tweak value.
 * @param {Buffer} scalar
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

ed25519.scalarTweakMul = function scalarTweakMul(scalar, tweak) {
  assert(Buffer.isBuffer(scalar));
  assert(Buffer.isBuffer(tweak));
  assert(scalar.length === 32);
  assert(tweak.length === 32);

  const save = wasm.save();
  const out = wasm.alloc(32);

  try {
    assert(wasm.call('bcrypto_ed25519_scalar_tweak_mul', out, scalar, tweak) !== -1);
    return wasm.read(out, 32);
  } finally {
    wasm.restore(save);
  }
};

/**
 * Compute (scalar mod n).
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

ed25519.scalarReduce = function scalarReduce(scalar) {
  assert(Buffer.isBuffer(scalar));

  if (scalar.length < 32) {
    const buf = Buffer.alloc(32, 0x00);
    scalar.copy(buf, 0);
    scalar = buf;
  } else if (scalar.length > 32) {
    scalar = scalar.slice(0, 32);
  }

  const save = wasm.save();
  const out = wasm.alloc(32);

  try {
    wasm.call('bcrypto_ed25519_scalar_reduce', out, scalar);
    return wasm.read(out, 32);
  } finally {
    wasm.restore(save);
  }
};

/**
 * Compute (-scalar mod n).
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

ed25519.scalarNegate = function scalarNegate(scalar) {
  assert(Buffer.isBuffer(scalar));
  assert(scalar.length === 32);

  const save = wasm.save();
  const out = wasm.alloc(32);

  try {
    assert(wasm.call('bcrypto_ed25519_scalar_negate', out, scalar) !== -1);
    return wasm.read(out, 32);
  } finally {
    wasm.restore(save);
  }
};

/**
 * Compute (scalar^-1 mod n).
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

ed25519.scalarInvert = function scalarInvert(scalar) {
  assert(Buffer.isBuffer(scalar));
  assert(scalar.length === 32);

  const save = wasm.save();
  const out = wasm.alloc(32);

  try {
    assert(wasm.call('bcrypto_ed25519_scalar_inverse', out, scalar) !== -1);
    return wasm.read(out, 32);
  } finally {
    wasm.restore(save);
  }
};

/**
 * Create a public key from a secret.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed25519.publicKeyCreate = function publicKeyCreate(secret) {
  assert(Buffer.isBuffer(secret));
  assert(secret.length === 32);

  const save = wasm.save();
  const out = wasm.alloc(32);

  try {
    assert(wasm.call('bcrypto_ed25519_publickey', out, secret) !== -1);
    return wasm.read(out, 32);
  } finally {
    wasm.restore(save);
  }
};

/**
 * Create a public key from a scalar.
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

ed25519.publicKeyFromScalar = function publicKeyFromScalar(scalar) {
  assert(Buffer.isBuffer(scalar));
  assert(scalar.length === 32);

  const save = wasm.save();
  const out = wasm.alloc(32);

  try {
    assert(wasm.call('bcrypto_ed25519_publickey_from_scalar', out, scalar) !== -1);
    return wasm.read(out, 32);
  } finally {
    wasm.restore(save);
  }
};

/**
 * Convert key to an X25519 key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

ed25519.publicKeyConvert = function publicKeyConvert(key) {
  assert(Buffer.isBuffer(key));
  assert(key.length === 32);

  const save = wasm.save();
  const out = wasm.alloc(32);

  try {
    assert(wasm.call('bcrypto_ed25519_pubkey_convert', out, key) !== -1);
    return wasm.read(out, 32);
  } finally {
    wasm.restore(save);
  }
};

/**
 * Convert key from an X25519 key.
 * @param {Buffer} key
 * @param {Boolean} [sign=false]
 * @returns {Buffer}
 */

ed25519.publicKeyDeconvert = function publicKeyDeconvert(key, sign) {
  assert(Buffer.isBuffer(key));
  assert(key.length === 32);
  assert(typeof sign === 'boolean');

  const save = wasm.save();
  const out = wasm.alloc(32);

  try {
    assert(wasm.call('bcrypto_ed25519_pubkey_deconvert', out, key, sign) !== -1);
    return wasm.read(out, 32);
  } finally {
    wasm.restore(save);
  }
};

/**
 * Validate a public key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

ed25519.publicKeyVerify = function publicKeyVerify(key) {
  assert(Buffer.isBuffer(key));

  if (key.length !== 32)
    return false;

  return wasm.call('bcrypto_ed25519_verify_key', key) !== -1;
};

/**
 * Export a public key to PKCS1 ASN.1 format.
 * @param {Buffer} key
 * @returns {Buffer}
 */

ed25519.publicKeyExport = function publicKeyExport(key) {
  if (!ed25519.publicKeyVerify(key))
    throw new Error('Invalid public key.');

  return Buffer.from(key);
};

/**
 * Import a public key from PKCS1 ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

ed25519.publicKeyImport = function publicKeyImport(raw) {
  if (!ed25519.publicKeyVerify(raw))
    throw new Error('Invalid public key.');

  return Buffer.from(raw);
};

/**
 * Export a public key to SubjectPublicKeyInfo ASN.1 format.
 * @param {Buffer} key
 * @returns {Buffer}
 */

ed25519.publicKeyExportSPKI = function publicKeyExportSPKI(key) {
  return asn1.encodeSPKI({
    algorithm: {
      oid: CURVE_OID,
      type: asn1.NULL,
      params: null
    },
    key: ed25519.publicKeyExport(key)
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

  return ed25519.publicKeyImport(spki.key);
};

/**
 * Export a public key to JWK JSON format.
 * @param {Buffer} key
 * @returns {Object}
 */

ed25519.publicKeyExportJWK = function publicKeyExportJWK(key) {
  return eckey.publicKeyExportJWK(ed25519, key);
};

/**
 * Import a public key from JWK JSON format.
 * @param {Object} json
 * @returns {Buffer}
 */

ed25519.publicKeyImportJWK = function publicKeyImportJWK(json) {
  return eckey.publicKeyImportJWK(ed25519, json);
};

/**
 * Compute ((tweak + key) mod n).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

ed25519.publicKeyTweakAdd = function publicKeyTweakAdd(key, tweak) {
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(tweak));
  assert(key.length === 32);
  assert(tweak.length === 32);

  const save = wasm.save();
  const out = wasm.alloc(32);

  try {
    assert(wasm.call('bcrypto_ed25519_pubkey_tweak_add', out, key, tweak) !== -1);
    return wasm.read(out, 32);
  } finally {
    wasm.restore(save);
  }
};

/**
 * Compute ((tweak * key) mod n).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

ed25519.publicKeyTweakMul = function publicKeyTweakMul(key, tweak) {
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(tweak));
  assert(key.length === 32);
  assert(tweak.length === 32);

  const save = wasm.save();
  const out = wasm.alloc(32);

  try {
    assert(wasm.call('bcrypto_ed25519_pubkey_tweak_mul', out, key, tweak) !== -1);
    return wasm.read(out, 32);
  } finally {
    wasm.restore(save);
  }
};

/**
 * Add two public keys.
 * @param {Buffer} key1
 * @param {Buffer} key2
 * @returns {Buffer}
 */

ed25519.publicKeyAdd = function publicKeyAdd(key1, key2) {
  assert(Buffer.isBuffer(key1));
  assert(Buffer.isBuffer(key2));
  assert(key1.length === 32);
  assert(key2.length === 32);

  const save = wasm.save();
  const out = wasm.alloc(32);

  try {
    assert(wasm.call('bcrypto_ed25519_pubkey_add', out, key1, key2) !== -1);
    return wasm.read(out, 32);
  } finally {
    wasm.restore(save);
  }
};

/**
 * Negate public key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

ed25519.publicKeyNegate = function publicKeyNegate(key) {
  assert(Buffer.isBuffer(key));
  assert(key.length === 32);

  const save = wasm.save();
  const out = wasm.alloc(32);

  try {
    assert(wasm.call('bcrypto_ed25519_pubkey_negate', out, key) !== -1);
    return wasm.read(out, 32);
  } finally {
    wasm.restore(save);
  }
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
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(secret));
  assert(secret.length === 32);
  assert(ph == null || typeof ph === 'boolean');
  assert(ctx == null || Buffer.isBuffer(ctx));

  if (ph == null)
    ph = -1;

  if (ctx == null || ctx.length === 0)
    ctx = 0;

  const save = wasm.save();
  const out = wasm.alloc(64);

  try {
    assert(wasm.call('bcrypto_ed25519_sign', out, msg, msg.length, secret, ph, ctx) !== -1);
    return wasm.read(out, 64);
  } finally {
    wasm.restore(save);
  }
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
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(secret));
  assert(secret.length === 32);
  assert(ph == null || typeof ph === 'boolean');
  assert(ctx == null || Buffer.isBuffer(ctx));

  if (ph == null)
    ph = -1;

  if (ctx == null || ctx.length === 0)
    ctx = 0;

  const save = wasm.save();
  const out = wasm.alloc(64);

  try {
    assert(wasm.call('bcrypto_ed25519_sign_with_scalar', out, msg, secret, ph, ctx) !== -1);
    return wasm.read(out, 64);
  } finally {
    wasm.restore(save);
  }
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
 * Batch verify signatures.
 * @param {Object[]} batch
 * @returns {Boolean}
 */

ed25519.batchVerify = function batchVerify(batch, ph, ctx) {
  backend.reseed();
  return binding.batchVerify(batch, ph, ctx);
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
 * @param {Buffer} pub - X25519 key (little endian).
 * @param {Buffer} secret - ED25519 secret.
 * @returns {Buffer}
 */

ed25519.exchange = function exchange(pub, secret) {
  return binding.exchange(pub, secret);
};

/**
 * Perform an ECDH (X25519) with a raw scalar.
 * @param {Buffer} pub - X25519 key (little endian).
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

ed25519.exchangeWithScalar = function exchangeWithScalar(pub, scalar) {
  return binding.exchangeWithScalar(pub, scalar);
};

/*
 * Compat
 */

ed25519.ecdh = ed25519.derive;
