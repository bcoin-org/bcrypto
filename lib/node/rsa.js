/*!
 * rsa.js - RSA for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const crypto = require('crypto');
const PEM = require('../utils/pem');

/**
 * Verify RSA signature.
 * @param {Object} alg - Hash algorithm.
 * @param {Buffer} msg - Signed message.
 * @param {Buffer} sig - Signature.
 * @param {Buffer} key - ASN1 serialized RSA key.
 * @returns {Boolean}
 */

exports.verify = function verify(alg, msg, sig, key) {
  assert(alg && typeof alg.name === 'string', 'No algorithm selected.');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));

  const name = normalizeAlg('rsa', alg);
  const pem = PEM.encode(key, 'rsa', 'public key');
  const ctx = crypto.createVerify(name);

  try {
    ctx.update(msg);
    return ctx.verify(pem, sig);
  } catch (e) {
    return false;
  }
};

/**
 * Sign message with RSA key.
 * @param {Object} alg - Hash algorithm.
 * @param {Buffer} msg - Signed message.
 * @param {Buffer} key - ASN1 serialized RSA key.
 * @returns {Buffer} Signature (DER)
 */

exports.sign = function sign(alg, msg, key) {
  assert(alg && typeof alg.name === 'string', 'No algorithm selected.');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));

  const name = normalizeAlg('rsa', alg);
  const pem = PEM.encode(key, 'rsa', 'private key');
  const ctx = crypto.createSign(name);

  ctx.update(msg);

  return ctx.sign(pem);
};

/*
 * Helpers
 */

function normalizeAlg(pk, alg) {
  return `${pk.toUpperCase()}-${alg.name.toUpperCase()}`;
}
