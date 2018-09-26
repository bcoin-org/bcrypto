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
    const ct = Buffer.from(msg);
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

    return pt;
  }
};

/*
 * Expose
 */

module.exports = ECIES;
