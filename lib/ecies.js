/*!
 * ecies.js - ecies for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const AEAD = require('./aead');
const random = require('./random');

/*
 * ECIES
 */

const ECIES = {
  encrypt(curve, hash, msg, pub, priv = null) {
    assert(curve && typeof curve.id === 'string');
    assert(hash && typeof hash.id === 'string');
    assert(hash.size === 32);
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(pub));
    assert(priv == null || Buffer.isBuffer(priv));

    if (priv == null)
      priv = curve.privateKeyGenerate();

    const ourPriv = priv;
    const ourPub = curve.publicKeyCreate(ourPriv);
    const secret = curve.derive(pub, ourPriv);
    const key = hash.digest(secret);
    const iv = random.randomBytes(16);
    const ct = padPKCS5(msg);
    const tag = AEAD.encrypt(key, iv, ct, ourPub);

    return Buffer.concat([ourPub, iv, tag, ct]);
  },

  decrypt(curve, hash, msg, priv) {
    assert(curve && typeof curve.id === 'string');
    assert(hash && typeof hash.id === 'string');
    assert(hash.size === 32);
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(priv));

    const klen = curve.edwards
      ? curve.size
      : 1 + curve.size;

    if (msg.length < klen + 16 + 16)
      throw new Error('Invalid ciphertext.');

    const theirPub = msg.slice(0, klen);
    const iv = msg.slice(klen, klen + 16);
    const tag = msg.slice(klen + 16, klen + 16 + 16);
    const pt = Buffer.from(msg.slice(klen + 16 + 16));
    const secret = curve.derive(theirPub, priv);
    const key = hash.digest(secret);
    const result = AEAD.decrypt(key, iv, pt, tag, theirPub);

    if (!result)
      throw new Error('Invalid ciphertext.');

    return unpadPKCS5(pt);
  }
};

/*
 * PKCS5 Padding (for concealing length)
 */

function padPKCS5(pt) {
  assert(Buffer.isBuffer(pt));

  const left = 64 - (pt.length & 63);
  const out = Buffer.allocUnsafe(pt.length + left);
  pt.copy(out, 0);

  for (let i = pt.length; i < out.length; i++)
    out[i] = left;

  return out;
}

function unpadPKCS5(pt) {
  assert(Buffer.isBuffer(pt));

  if (pt.length < 64 || (pt.length & 63) !== 0)
    throw new Error('Invalid padding.');

  const left = pt[pt.length - 1];

  if (left === 0 || left > 64)
    throw new Error('Invalid padding.');

  for (let i = pt.length - left; i < pt.length; i++) {
    if (pt[i] !== left)
      throw new Error('Invalid padding.');
  }

  return pt.slice(0, -left);
}

/*
 * Expose
 */

module.exports = ECIES;
