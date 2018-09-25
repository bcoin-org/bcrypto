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
 * Constants
 */

// Pad all Y values to 3072 bits to
// conceal the size of the recipient's key.
const KEY_PADDING = 3072 / 8;

/*
 * DSAIES
 */

const DSAIES = {
  _generate(priv, pub) {
    if (priv == null)
      return dsa.privateKeyCreate(pub);

    assert(priv instanceof dsa.DSAPrivateKey);

    return priv;
  },

  encrypt(hash, msg, pub, priv = null) {
    assert(hash && typeof hash.id === 'string');
    assert(hash.size === 32);
    assert(Buffer.isBuffer(msg));
    assert(pub instanceof dsa.DSAKey);
    assert(priv == null || (priv instanceof dsa.DSAPrivateKey));

    const klen = (pub.bits() + 7) >>> 3;

    const ourPriv = this._generate(priv, pub);
    const ourPub = dsa.publicKeyCreate(ourPriv);
    const secret = dsa.dh(pub, ourPriv);
    const key = hash.digest(secret);
    const iv = random.randomBytes(16);
    const ct = pad(msg);
    const ourY = leftPad(ourPub.y, klen);
    const paddedY = padKey(ourY, KEY_PADDING);
    const tag = AEAD.encrypt(key, iv, ct, paddedY);

    return Buffer.concat([paddedY, iv, tag, ct]);
  },

  decrypt(hash, msg, priv) {
    assert(hash && typeof hash.id === 'string');
    assert(hash.size === 32);
    assert(Buffer.isBuffer(msg));
    assert(priv instanceof dsa.DSAPrivateKey);

    const klen = (priv.bits() + 7) >>> 3;

    if (msg.length < klen + 16 + 16)
      throw new Error('Invalid ciphertext.');

    const pos = unpadKey(msg, priv.bits(), KEY_PADDING);
    const paddedY = msg.slice(0, pos);
    const theirY = msg.slice(pos - klen, pos);

    const theirPub = new dsa.DSAPublicKey(
      priv.p,
      priv.q,
      priv.g,
      theirY
    );

    const iv = msg.slice(pos, pos + 16);
    const tag = msg.slice(pos + 16, pos + 16 + 16);
    const pt = Buffer.from(msg.slice(pos + 16 + 16));
    const secret = dsa.dh(theirPub, priv);
    const key = hash.digest(secret);
    const result = AEAD.decrypt(key, iv, pt, tag, paddedY);

    if (!result)
      throw new Error('Invalid ciphertext.');

    return unpad(pt);
  }
};

/*
 * Padding
 */

function padKey(key, size) {
  assert(Buffer.isBuffer(key));
  assert((size >>> 0) === size);

  if (key.length >= size)
    return key;

  // We pad the Y value with random bytes
  // to hopefully disguise the fact that
  // this may be a smaller (i.e. older) key.
  const out = Buffer.allocUnsafe(size);
  const pos = size - key.length;

  random.randomFill(out, 0, pos);
  key.copy(out, pos);

  return out;
}

function unpadKey(msg, bits, size) {
  assert(Buffer.isBuffer(msg));
  assert((bits >>> 0) === bits);
  assert((size >>> 0) === size);

  const klen = (bits + 7) >>> 3;

  if (klen >= size) {
    if (msg.length < klen)
      throw new Error('Invalid ciphertext.');

    return klen;
  }

  if (msg.length < size)
    throw new Error('Invalid ciphertext.');

  return size;
}

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
