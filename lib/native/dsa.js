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

function paramsGenerate(bits) {
  if (bits == null)
    bits = 2048;

  assert((bits >>> 0) === bits);

  if (bits < 1024 || bits > 3072)
    throw new RangeError('`bits` must range between 1024 and 3072.');

  const items = binding.paramsGenerate(bits);
  const params = new DSAParams();

  [
    params.p,
    params.q,
    params.g
  ] = items;

  return params;
}

async function paramsGenerateAsync(bits) {
  if (bits == null)
    bits = 2048;

  assert((bits >>> 0) === bits);

  if (bits < 1024 || bits > 3072)
    throw new RangeError('`bits` must range between 1024 and 3072.');

  const items = await binding.paramsGenerateAsync(bits);
  const params = new DSAParams();

  [
    params.p,
    params.q,
    params.g
  ] = items;

  return params;
}

function privateKeyCreate(params) {
  assert(params instanceof DSAParams);

  const items = binding.privateKeyCreate(
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

function privateKeyGenerate(bits) {
  const params = paramsGenerate(bits);
  return privateKeyCreate(params);
}

async function privateKeyGenerateAsync(bits) {
  const params = await paramsGenerateAsync(bits);
  return privateKeyCreate(params);
}

function computeY(key) {
  assert(key instanceof DSAPrivateKey);
  return binding.computeY(key.p, key.g, key.x);
}

function publicKeyCreate(key) {
  assert(key instanceof DSAPrivateKey);
  return key.toPublic();
}

function publicKeyVerify(key) {
  assert(key instanceof DSAPublicKey);
  return key.validate();
}

function privateKeyVerify(key) {
  assert(key instanceof DSAPrivateKey);

  if (!key.toPublic().validate())
    return false;

  return key.validate();
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

exports.paramsGenerate = paramsGenerate;
exports.paramsGenerateAsync = paramsGenerateAsync;
exports.privateKeyCreate = privateKeyCreate;
exports.privateKeyGenerate = privateKeyGenerate;
exports.privateKeyGenerateAsync = privateKeyGenerateAsync;
exports.computeY = computeY;
exports.publicKeyCreate = publicKeyCreate;
exports.publicKeyVerify = publicKeyVerify;
exports.privateKeyVerify = privateKeyVerify;
exports.sign = sign;
exports.verify = verify;
