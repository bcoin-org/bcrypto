/*!
 * dsaies.js - dsaies for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const AEAD = require('./aead');
const dsa = require('./dsa');
const random = require('./random');
const {leftPad} = require('./internal/util');

/*
 * DSAIES
 */

const DSAIES = {
  encrypt(hash, msg, pub, priv = null) {
    assert(hash && typeof hash.id === 'string');
    assert(hash.size === 32);
    assert(Buffer.isBuffer(msg));
    assert(pub instanceof dsa.DSAKey);
    assert(priv == null || (priv instanceof dsa.DSAPrivateKey));

    if (priv == null)
      priv = dsa.privateKeyCreate(pub);

    const klen = (pub.bits() + 7) >>> 3;

    const ourPriv = priv;
    const ourPub = dsa.publicKeyCreate(ourPriv);
    const secret = dsa.derive(pub, ourPriv);
    const key = hash.digest(secret);
    const iv = random.randomBytes(16);
    const ct = pad(msg);
    const ourY = leftPad(ourPub.y, klen);
    const tag = AEAD.encrypt(key, iv, ct, ourY);

    return Buffer.concat([ourY, iv, tag, ct]);
  },

  decrypt(hash, msg, priv) {
    assert(hash && typeof hash.id === 'string');
    assert(hash.size === 32);
    assert(Buffer.isBuffer(msg));
    assert(priv instanceof dsa.DSAPrivateKey);

    const klen = (priv.bits() + 7) >>> 3;

    if (msg.length < klen + 16 + 16)
      throw new Error('Invalid ciphertext.');

    const theirY = msg.slice(0, klen);

    const theirPub = new dsa.DSAPublicKey(
      priv.p,
      priv.q,
      priv.g,
      theirY
    );

    const iv = msg.slice(klen, klen + 16);
    const tag = msg.slice(klen + 16, klen + 16 + 16);
    const pt = Buffer.from(msg.slice(klen + 16 + 16));
    const secret = dsa.derive(theirPub, priv);
    const key = hash.digest(secret);
    const result = AEAD.decrypt(key, iv, pt, tag, theirY);

    if (!result)
      throw new Error('Invalid ciphertext.');

    return unpad(pt);
  }
};

/*
 * CBC-like Padding
 */

function pad(pt) {
  assert(Buffer.isBuffer(pt));

  const left = 16 - (pt.length & 15);
  const out = Buffer.allocUnsafe(pt.length + left);
  pt.copy(out, 0);

  for (let i = pt.length; i < out.length; i++)
    out[i] = left;

  return out;
}

function unpad(pt) {
  assert(Buffer.isBuffer(pt));

  if (pt.length < 16)
    throw new Error('Invalid padding.');

  const left = pt[pt.length - 1];

  if (left === 0 || left > 16)
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

module.exports = DSAIES;
