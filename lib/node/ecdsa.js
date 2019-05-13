/*!
 * ecdsa.js - ecdsa for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const JS = require('../js/ecdsa');
const Signature = require('../internal/signature');
const {ECDH} = crypto;

/*
 * Constants
 */

const NO_CONVERT = {};

/**
 * ECDSA
 */

class ECDSA extends JS {
  constructor(name, hash, pre) {
    super(name, hash, pre);
    this.native = 1;
  }

  publicKeyCreate(key, compress) {
    if (!crypto.createECDH)
      return super.publicKeyCreate(key, compress);

    if (compress == null)
      compress = true;

    if (compress === NO_CONVERT)
      return null;

    assert(typeof compress === 'boolean');

    // Added in 0.11.4.
    const ecdh = crypto.createECDH(this.curve.ossl);
    const format = compress ? 'compressed' : 'uncompressed';

    ecdh.setPrivateKey(key);

    return ecdh.getPublicKey(null, format);
  }

  publicKeyConvert(key, compress) {
    if (!ECDH || !ECDH.convertKey)
      return super.publicKeyConvert(key, compress);

    if (compress == null)
      compress = true;

    if (compress === NO_CONVERT)
      return key;

    assert(typeof compress === 'boolean');

    const format = compress ? 'compressed' : 'uncompressed';

    // Added in 10.0.0.
    return ECDH.convertKey(key, this.curve.ossl, null, null, format);
  }

  _sign(msg, key) {
    // Added in 11.6.0.
    const priv = crypto.createPrivateKey({
      key: this.privateKeyExport(key, NO_CONVERT),
      format: 'der',
      type: 'sec1'
    });

    // Added in 12.0.0.
    const raw = crypto.sign(null, msg, priv);
    const sig = this.signatureImport(raw);
    const norm = this.signatureNormalize(sig);

    return Signature.decode(norm, this.size);
  }

  signRecoverable(msg, key) {
    const sig = super._sign(msg, key);
    return {
      signature: sig.encode(this.size),
      recovery: sig.param
    };
  }

  signRecoverableDER(msg, key) {
    const sig = super._sign(msg, key);
    return {
      signature: sig.toDER(this.size),
      recovery: sig.param
    };
  }

  _verify(msg, sig, key) {
    const raw = sig.toDER(this.size);

    // Added in 11.6.0.
    const pub = crypto.createPublicKey({
      key: this.publicKeyExportSPKI(key, NO_CONVERT),
      format: 'der',
      type: 'spki'
    });

    // Added in 12.0.0.
    return crypto.verify(null, msg, pub, raw);
  }

  // This only gives us the x coordinate.
  // derive(pub, priv, compress) {
  //   // Added in 0.11.4.
  //   const ecdh = crypto.createECDH(this.curve.ossl);
  //
  //   ecdh.setPrivateKey(priv);
  //
  //   const x = ecdh.computeSecret(pub);
  //
  //   return x;
  // }
}

/*
 * Expose
 */

module.exports = ECDSA;
