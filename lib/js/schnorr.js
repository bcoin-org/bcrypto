/*!
 * schnorr.js - bip-schnorr for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on sipa/bip-schnorr:
 *   https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr/reference.py
 *
 * Parts of this software are based on ElementsProject/secp256k1-zkp:
 *   https://github.com/ElementsProject/secp256k1-zkp/tree/secp256k1-zkp/src/modules/schnorrsig
 *
 * Resources:
 *   https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki
 *   https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr/reference.py
 *   https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr/test-vectors.csv
 *   https://github.com/ElementsProject/secp256k1-zkp
 *   https://github.com/ElementsProject/secp256k1-zkp/tree/secp256k1-zkp/src/modules/musig
 *   https://github.com/ElementsProject/secp256k1-zkp/tree/secp256k1-zkp/src/modules/schnorrsig
 */

'use strict';

const assert = require('bsert');
const {jacobi} = require('../internal/primes');

/**
 * Schnorr
 */

class Schnorr {
  constructor(curve) {
    this.curve = curve;
  }

  sign(msg, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(key));
    assert(key.length === this.curve.size);

    const N = this.curve.n;
    const P = this.curve.p;
    const G = this.curve.g;

    let k = this.curve.hashInt(key, msg);

    if (k.isZero())
      throw new Error('`k` cannot be zero.');

    const Rp = G.mul(k);

    if (jacobi(Rp.getY(), P) !== 1)
      k = N.sub(k);

    const a = this.curve.decodeInt(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const Araw = this.curve.encodePoint(G.mul(a));
    const Rraw = this.curve.encodeInt(Rp.getX());
    const e = this.curve.hashInt(Rraw, Araw, msg);
    const S = k.add(e.mul(a)).umod(N);

    return Buffer.concat([Rraw, this.curve.encodeInt(S)]);
  }

  verify(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    try {
      return this._verify(msg, sig, key);
    } catch (e) {
      return false;
    }
  }

  _verify(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    if (sig.length !== this.curve.size * 2)
      return false;

    const N = this.curve.n;
    const P = this.curve.p;
    const G = this.curve.g;

    const Rraw = sig.slice(0, this.curve.size);
    const Sraw = sig.slice(this.curve.size);

    const A = this.curve.decodePoint(key);
    const R = this.curve.decodeInt(Rraw);
    const S = this.curve.decodeInt(Sraw);

    if (R.cmp(P) >= 0 || S.cmp(N) >= 0)
      return false;

    const e = this.curve.hashInt(Rraw, key, msg);
    const Rp = G.mul(S).add(A.mul(N.sub(e)));

    if (Rp.isInfinity())
      return false;

    if (jacobi(Rp.getY(), P) !== 1)
      return false;

    if (!Rp.getX().eq(R))
      return false;

    return true;
  }
}

/*
 * Expose
 */

module.exports = Schnorr;
