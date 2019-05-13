/*!
 * eddsa.js - ed25519 for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const crypto = require('crypto');
const JS = require('../js/eddsa');

/*
 * EDDSA
 */

class EDDSA extends JS {
  constructor(id, xid, hash, pre) {
    super(id, xid, hash, pre);
    this.native = 1;
  }

  publicKeyCreate(secret) {
    if (!crypto.createPrivateKey)
      return super.publicKeyCreate(secret);

    // KeyObject was exported in 11.13.0.
    // Check for this before trying to import
    // a private key as public (might be better
    // to check for crypto.sign() though).
    if (!crypto.KeyObject)
      return super.publicKeyCreate(secret);

    // Added in 11.6.0.
    // `key` allowed to be private in 11.7.0.
    const pub = crypto.createPublicKey({
      key: this.privateKeyExportPKCS8(secret),
      format: 'der',
      type: 'pkcs8'
    });

    const raw = pub.export({
      format: 'der',
      type: 'spki'
    });

    return this.publicKeyImportSPKI(raw);
  }

  _sign(msg, secret, ph, ctx) {
    if (this.curve.context && ph === false)
      ph = null;

    if (!crypto.sign || ph != null || (ctx && ctx.length > 0))
      return super._sign(msg, secret, ph, ctx);

    // Added in 11.6.0.
    const priv = crypto.createPrivateKey({
      key: this.privateKeyExportPKCS8(secret),
      format: 'der',
      type: 'pkcs8'
    });

    // Added in 12.0.0.
    return crypto.sign(null, msg, priv);
  }

  _verify(msg, sig, key, ph, ctx) {
    if (this.curve.context && ph === false)
      ph = null;

    if (!crypto.verify || ph != null || (ctx && ctx.length > 0))
      return super._verify(msg, sig, key, ph, ctx);

    // Added in 11.6.0.
    const pub = crypto.createPublicKey({
      key: this.publicKeyExportSPKI(key),
      format: 'der',
      type: 'spki'
    });

    // Added in 12.0.0.
    return crypto.verify(null, msg, pub, sig);
  }

  _batchVerify(batch, ph, ctx) {
    if (this.curve.context && ph === false)
      ph = null;

    if (!crypto.verify || ph != null || (ctx && ctx.length > 0))
      return super._batchVerify(batch, ph, ctx);

    for (const [msg, sig, key] of batch) {
      if (!this._verify(msg, sig, key, ph, ctx))
        return false;
    }

    return true;
  }
}

/*
 * Expose
 */

module.exports = EDDSA;

