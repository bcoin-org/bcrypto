'use strict';

const assert = require('bsert');
const AEAD = require('./aead');
const random = require('./random');

/*
 * ECIES
 */

class ECIES {
  constructor(curve, hash) {
    assert(curve && typeof curve.id === 'string');
    assert(hash && typeof hash.id === 'string');
    assert(hash.size === 32);

    this.curve = curve;
    this.hash = hash;
    this.edwards = curve.id === 'ED25519' || curve.id === 'ED448';
    this.size = this.edwards ? curve.size : 1 + curve.size;
  }

  _generate(priv) {
    if (priv == null) {
      if (this.edwards)
        return this.curve.secretGenerate();
      return this.curve.privateKeyGenerate();
    }

    assert(Buffer.isBuffer(priv));

    return priv;
  }

  encrypt(msg, pub, priv = null) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(pub));
    assert(priv == null || Buffer.isBuffer(priv));

    const ourPriv = this._generate(priv);
    const ourPub = this.curve.publicKeyCreate(ourPriv);
    const secret = this.curve.ecdh(pub, ourPriv);
    const key = this.hash.digest(secret);
    const iv = random.randomBytes(16);
    const ct = pad(msg);
    const tag = AEAD.encrypt(key, iv, ct, ourPub);

    return Buffer.concat([ourPub, iv, tag, ct]);
  }

  decrypt(msg, priv) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(priv));

    const klen = this.size;

    if (msg.length < klen + 16 + 16)
      throw new Error('Invalid ciphertext.');

    const theirPub = msg.slice(0, klen);
    const iv = msg.slice(klen, klen + 16);
    const tag = msg.slice(klen + 16, klen + 16 + 16);
    const pt = Buffer.from(msg.slice(klen + 16 + 16));
    const secret = this.curve.ecdh(theirPub, priv);
    const key = this.hash.digest(secret);
    const result = AEAD.decrypt(key, iv, pt, tag, theirPub);

    if (!result)
      throw new Error('Invalid ciphertext.');

    return unpad(pt);
  }
}

/*
 * CBC-like padding
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

module.exports = ECIES;
