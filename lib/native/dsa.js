/*!
 * dsa.js - DSA generation for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   https://github.com/golang/go/blob/master/src/crypto/dsa/dsa.go
 *   https://github.com/golang/go/blob/master/src/math/big/int.go
 */

'use strict';

const assert = require('bsert');
const binding = require('./binding').dsa;

if (!binding)
  throw new Error('DSA native support not available.');

const dsakey = require('../internal/dsakey')(exports);
const DSASignature = require('../internal/dsasig');

const {
  DSAKey,
  DSAParams,
  DSAPublicKey,
  DSAPrivateKey
} = dsakey;

/*
 * DSA
 */

function generate(bits) {
  if (bits == null)
    bits = 2048;

  assert((bits >>> 0) === bits);

  if (bits < 1024 || bits > 3072)
    throw new RangeError('`bits` must range between 1024 and 3072.');

  const items = binding.generate(bits);
  const params = new DSAParams();

  [
    params.p,
    params.q,
    params.g
  ] = items;

  return params;
}

async function generateAsync(bits) {
  if (bits == null)
    bits = 2048;

  assert((bits >>> 0) === bits);

  if (bits < 1024 || bits > 3072)
    throw new RangeError('`bits` must range between 1024 and 3072.');

  return new Promise((resolve, reject) => {
    const cb = (err, items) => {
      if (err) {
        reject(err);
        return;
      }

      const params = new DSAParams();

      [
        params.p,
        params.q,
        params.g
      ] = items;

      resolve(params);
    };

    try {
      binding.generateAsync(bits, cb);
    } catch (e) {
      reject(e);
    }
  });
}

function create(params) {
  assert(params instanceof DSAParams);

  const items = binding.create(
    params.p,
    params.q,
    params.g
  );

  const key = new DSAPrivateKey();

  [
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  ] = items;

  return key;
}

function computeY(key) {
  assert(key instanceof DSAPrivateKey);
  return binding.computeY(key.p, key.g, key.x);
}

function sign(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(key instanceof DSAPrivateKey);

  const [r, s] = binding.sign(
    msg,
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  );

  return new DSASignature(key.size(), r, s);
}

function verify(msg, sig, key) {
  assert(Buffer.isBuffer(msg));
  assert(sig instanceof DSASignature);
  assert(key instanceof DSAKey);

  return binding.verify(
    msg,
    sig.r,
    sig.s,
    key.p,
    key.q,
    key.g,
    key.y
  );
}

/*
 * Expose
 */

exports.native = 2;
exports.DSAKey = DSAKey;
exports.DSAParams = DSAParams;
exports.DSAPublicKey = DSAPublicKey;
exports.DSAPrivateKey = DSAPrivateKey;
exports.DSASignature = DSASignature;

exports.generate = generate;
exports.generateAsync = generateAsync;
exports.create = create;
exports.computeY = computeY;
exports.sign = sign;
exports.verify = verify;
