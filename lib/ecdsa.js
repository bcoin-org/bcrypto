/*!
 * ecdsa.js - ecdsa for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module crypto/ecdsa
 */

const assert = require('assert');
const elliptic = require('elliptic');

/**
 * Verify ECDSA signature.
 * @param {String} curve - Curve name.
 * @param {Object} alg - Hash algorithm.
 * @param {Buffer} msg - Signed message.
 * @param {Buffer} sig - Signature.
 * @param {Buffer} key - ASN1 serialized ECDSA key.
 * @returns {Boolean}
 */

exports.verify = function verify(curve, alg, msg, sig, key) {
  assert(typeof curve === 'string', 'No curve selected.');
  assert(alg && typeof alg.name === 'string', 'No algorithm selected.');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));

  const ec = elliptic.ec(curve);
  const hash = alg.digest(msg);

  try {
    return ec.verify(hash, sig, key);
  } catch (e) {
    return false;
  }
};

/**
 * Sign message with ECDSA key.
 * @memberof module:crypto/pk.ecdsa
 * @param {String} curve - Curve name.
 * @param {Object} alg - Hash algorithm.
 * @param {Buffer} msg - Signed message.
 * @param {Buffer} key - ASN1 serialized ECDSA key.
 * @returns {Buffer} Signature (DER)
 */

exports.sign = function sign(curve, alg, msg, key) {
  assert(typeof curve === 'string', 'No curve selected.');
  assert(alg && typeof alg.name === 'string', 'No algorithm selected.');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));

  const ec = elliptic.ec(curve);
  const hash = alg.digest(msg);
  const sig = ec.sign(hash, key, { canonical: true });

  return Buffer.from(sig.toDER());
};
