/*!
 * secretbox.js - nacl secretbox for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   https://nacl.cr.yp.to/secretbox.html
 *   https://github.com/golang/crypto/tree/master/nacl
 *   https://github.com/golang/crypto/blob/master/nacl/secretbox/secretbox.go
 *   https://github.com/golang/crypto/blob/master/nacl/secretbox/secretbox_test.go
 *   https://github.com/golang/crypto/blob/master/nacl/secretbox/example_test.go
 *   https://github.com/golang/crypto/blob/master/nacl/box/box.go
 *   https://github.com/golang/crypto/blob/master/nacl/box/box_test.go
 *   https://github.com/golang/crypto/blob/master/nacl/box/example_test.go
 */

'use strict';

const assert = require('bsert');
const Salsa20 = require('./salsa20');
const Poly1305 = require('./poly1305');

/*
 * Constants
 */

const ZERO16 = Buffer.alloc(16, 0x00);

/*
 * Secret Box
 */

function seal(msg, key, nonce) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(nonce));
  assert(key.length === 32);
  assert(nonce.length === 24);

  const box = Buffer.alloc(16 + msg.length, 0x00);
  const first = box.slice(16, 16 + 32);
  const ct = box.slice(16 + 32);
  const subKey = Salsa20.derive(key, nonce.slice(0, 16));
  const counter = padRight(nonce.slice(16, 24), 16);
  const salsa = new Salsa20();
  const poly = new Poly1305();
  const block = Buffer.alloc(64, 0x00);
  const polyKey = block.slice(0, 32);
  const rightSide = block.slice(32);

  salsa.init(subKey, counter);
  salsa.encrypt(block);

  poly.init(polyKey);

  // box = tag || (first-block/msg[:32] || msg[32:])
  nonce.copy(box, 0);
  msg.copy(box, 16);

  // We don't encrypt the first 32 byte block,
  // we XOR it the right side of the right half
  // of the first salsa block.
  for (let i = 0; i < first.length; i++)
    first[i] ^= rightSide[i];

  counter[8] = 1;
  salsa.init(subKey, counter);
  salsa.encrypt(ct);

  // We do, however, MAC it with poly1305.
  poly.update(first);
  poly.update(ct);
  poly.final().copy(box, 0);

  return box;
}

function open(box, key, nonce) {
  assert(Buffer.isBuffer(box));
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(nonce));
  assert(key.length === 32);
  assert(nonce.length === 24);

  if (box.length < 16)
    throw new Error('Invalid box size.');

  const input = Buffer.from(box);
  const tag = input.slice(0, 16);
  const first = input.slice(16, 16 + 32);
  const ct = input.slice(16 + 32);
  const msg = input.slice(16);
  const subKey = Salsa20.derive(key, nonce.slice(0, 16));
  const counter = padRight(nonce.slice(16, 24), 16);
  const salsa = new Salsa20();
  const poly = new Poly1305();
  const block = Buffer.alloc(64, 0x00);
  const polyKey = block.slice(0, 32);
  const rightSide = block.slice(32, 64);

  salsa.init(subKey, counter);
  salsa.encrypt(block);

  poly.init(polyKey);
  poly.update(first);
  poly.update(ct);

  const valid = Poly1305.verify(poly.final(), tag);

  if (!valid)
    throw new Error('Invalid box tag.');

  for (let i = 0; i < first.length; i++)
    first[i] ^= rightSide[i];

  counter[8] = 1;
  salsa.init(subKey, counter);
  salsa.encrypt(ct);

  return msg;
}

function derive(secret, kdf) {
  const key = deriveSecret(secret, kdf);
  return Salsa20.derive(key, ZERO16);
}

/*
 * Helpers
 */

function padRight(data, size) {
  const out = Buffer.alloc(size, 0x00);
  data.copy(out, 0);
  return out;
}

function deriveSecret(secret, kdf) {
  assert(Buffer.isBuffer(secret));

  if (kdf == null) {
    if (secret.length !== 32)
      throw new Error('Invalid secret size for secret box.');

    return secret;
  }

  if (typeof kdf.digest === 'function') {
    if (kdf.size < 32)
      throw new Error('Hash is too small for secret box.');

    return kdf.digest(secret).slice(0, 32);
  }

  assert(typeof kdf === 'function');

  const key = kdf(secret);

  assert(Buffer.isBuffer(key));

  if (key.length < 32)
    throw new Error('Key is too small for secret box.');

  return key.slice(0, 32);
}

/*
 * Expose
 */

exports.seal = seal;
exports.open = open;
exports.derive = derive;
exports.native = 0;
