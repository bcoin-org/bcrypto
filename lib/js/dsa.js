/*!
 * dsa.js - DSA generation for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
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
const BN = require('../../vendor/bn.js');
const random = require('../random');
const {trimZeroes, countBits} = require('../internal/util');
const {probablyPrime} = require('../internal/primes');
const dsakey = require('../internal/dsakey');
const Signature = require('../internal/signature');
const openssl = require('../encoding/openssl');
const dsa = exports;

const {
  DSAKey,
  DSAParams,
  DSAPublicKey,
  DSAPrivateKey
} = dsakey;

/**
 * Whether the backend is a binding.
 * @const {Number}
 */

dsa.native = 0;

/**
 * DSAParams
 */

dsa.DSAParams = DSAParams;

/**
 * DSAKey
 */

dsa.DSAKey = DSAKey;

/**
 * DSAPublicKey
 */

dsa.DSAPublicKey = DSAPublicKey;

/**
 * DSAPrivateKey
 */

dsa.DSAPrivateKey = DSAPrivateKey;

/**
 * Generate params.
 * @param {Number} [bits=2048]
 * @returns {DSAParams}
 */

dsa.paramsGenerate = function paramsGenerate(bits) {
  if (bits == null)
    bits = 2048;

  assert((bits >>> 0) === bits);

  if (bits < 1024 || bits > 3072)
    throw new RangeError('`bits` must range between 1024 and 3072.');

  // OpenSSL behavior.
  const L = bits;
  const N = bits < 2048 ? 160 : 256;

  return generateParams(L, N);
};

/**
 * Generate params.
 * @param {Number} [bits=2048]
 * @returns {DSAParams}
 */

dsa.paramsGenerateAsync = async function paramsGenerateAsync(bits) {
  return dsa.paramsGenerate(bits);
};

/**
 * Verify params.
 * @param {DSAParams} params
 * @returns {Boolean}
 */

dsa.paramsVerify = function paramsVerify(params) {
  assert(params instanceof DSAParams);

  const pb = countBits(params.p);
  const qb = countBits(params.q);
  const gb = countBits(params.g);

  if (pb < 1024 || pb > 3072)
    return false;

  if (qb !== 160 && qb !== 224 && qb !== 256)
    return false;

  if (gb === 0 || gb > pb)
    return false;

  const p = new BN(params.p);
  const q = new BN(params.q);
  const g = new BN(params.g);
  const pm1 = p.subn(1);
  const {div, mod} = pm1.divmod(q);

  if (!mod.isZero())
    return false;

  const x = modPow(g, div, p);

  if (x.cmpn(1) === 0)
    return false;

  return true;
};

/**
 * Generate private key from params.
 * @param {DSAParams} params
 * @returns {DSAPrivateKey}
 */

dsa.privateKeyCreate = function privateKeyCreate(params) {
  assert(params instanceof DSAParams);

  const qn = new BN(params.q);
  const xb = Buffer.alloc(qn.bitLength() >>> 3);

  let xn = null;

  for (;;) {
    random.randomFill(xb, 0, xb.length);

    xn = new BN(xb);

    if (!xn.isZero() && xn.cmp(qn) < 0)
      break;
  }

  const pn = new BN(params.p);
  const gn = new BN(params.g);
  const yn = modPow(gn, xn, pn);

  const key = new DSAPrivateKey();
  key.setParams(params);
  key.x = toBuffer(xn);
  key.y = toBuffer(yn);
  return key;
};

/**
 * Generate private key.
 * @param {Number} [bits=2048]
 * @returns {DSAPrivateKey}
 */

dsa.privateKeyGenerate = function privateKeyGenerate(bits) {
  const params = dsa.paramsGenerate(bits);
  return dsa.privateKeyCreate(params);
};

/**
 * Generate private key.
 * @param {Number} [bits=2048]
 * @returns {DSAPrivateKey}
 */

dsa.privateKeyGenerateAsync = async function privateKeyGenerateAsync(bits) {
  const params = await dsa.paramsGenerateAsync(bits);
  return dsa.privateKeyCreate(params);
};

/**
 * Pre-compute a private key.
 * @param {DSAPrivateKey}
 */

dsa.privateKeyCompute = function privateKeyCompute(key) {
  assert(key instanceof DSAPrivateKey);

  if (countBits(key.y) === 0)
    key.y = dsa._computeY(key);
};

/**
 * Re-compute Y value.
 * @private
 * @param {DSAPrivateKey}
 * @returns {Buffer}
 */

dsa._computeY = function _computeY(key) {
  assert(key instanceof DSAPrivateKey);

  if (!dsa.publicKeyVerify(key))
    throw new Error('Invalid params.');

  const qb = countBits(key.q);
  const xb = countBits(key.x);

  if (xb === 0 || xb > qb)
    throw new Error('Invalid key.');

  const p = new BN(key.p);
  const g = new BN(key.g);
  const x = new BN(key.x);
  const y = modPow(g, x, p);

  return toBuffer(y);
};

/**
 * Verify a private key.
 * @param {DSAPrivateKey} key
 * @returns {Boolean}
 */

dsa.privateKeyVerify = function privateKeyVerify(key) {
  assert(key instanceof DSAPrivateKey);

  if (!dsa.publicKeyVerify(key))
    return false;

  if (countBits(key.x) > countBits(key.q))
    return false;

  const q = new BN(key.q);
  const x = new BN(key.x);

  if (x.isZero() || x.cmp(q) >= 0)
    return false;

  dsa.privateKeyCompute(key);

  const y = trimZeroes(key.y);

  return y.equals(dsa._computeY(key));
};

/**
 * Export a private key in OpenSSL ASN.1 format.
 * @param {DSAPrivateKey} key
 * @returns {Buffer}
 */

dsa.privateKeyExport = function privateKeyExport(key) {
  assert(key instanceof DSAPrivateKey);

  dsa.privateKeyCompute(key);

  return new openssl.DSAPrivateKey(
    0,
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  ).encode();
};

/**
 * Import a private key in OpenSSL ASN.1 format.
 * @param {Buffer} key
 * @returns {DSAPrivateKey}
 */

dsa.privateKeyImport = function privateKeyImport(raw) {
  const key = openssl.DSAPrivateKey.decode(raw);

  assert(key.version.toNumber() === 0);

  return new DSAPrivateKey(
    key.p.value,
    key.q.value,
    key.g.value,
    key.y.value,
    key.x.value
  );
};

/**
 * Create a public key from a private key.
 * @param {DSAPrivateKey} key
 * @returns {DSAPublicKey}
 */

dsa.publicKeyCreate = function publicKeyCreate(key) {
  assert(key instanceof DSAPrivateKey);

  dsa.privateKeyCompute(key);

  const pub = new DSAPublicKey();

  pub.p = key.p;
  pub.q = key.q;
  pub.g = key.g;
  pub.y = key.y;

  return pub;
};

/**
 * Verify a public key.
 * @param {DSAKey} key
 * @returns {Boolean}
 */

dsa.publicKeyVerify = function publicKeyVerify(key) {
  assert(key instanceof DSAKey);

  if (!dsa.paramsVerify(key))
    return false;

  const pb = countBits(key.p);
  const yb = countBits(key.y);

  if (yb === 0 || yb > pb)
    return false;

  return true;
};

/**
 * Export a public key to SubjectPublicKeyInfo ASN.1 format.
 * @param {DSAKey} key
 * @returns {Buffer}
 */

dsa.publicKeyExport = function publicKeyExport(key) {
  assert(key instanceof DSAKey);

  return new openssl.DSAPublicKey(
    key.y,
    key.p,
    key.q,
    key.g
  ).encode();
};

/**
 * Import a public key from SubjectPublicKeyInfo ASN.1 format.
 * @param {Buffer} raw
 * @returns {DSAPublicKey}
 */

dsa.publicKeyImport = function publicKeyImport(raw) {
  const key = openssl.DSAPublicKey.decode(raw);
  return new DSAPublicKey(
    key.p.value,
    key.q.value,
    key.g.value,
    key.y.value
  );
};

/**
 * Convert R/S signature to DER.
 * @param {Buffer} sig
 * @param {Number} size
 * @returns {Buffer} DER-formatted signature.
 */

dsa.signatureExport = function signatureExport(sig, size) {
  if (size == null) {
    assert(Buffer.isBuffer(sig));
    assert((sig.length & 1) === 0);
    size = sig.length >>> 1;
  }

  return Signature.toDER(sig, size);
};

/**
 * Convert DER signature to R/S.
 * @param {Buffer} sig
 * @param {Number} size
 * @returns {Buffer} R/S-formatted signature.
 */

dsa.signatureImport = function signatureImport(sig, size) {
  return Signature.toRS(sig, size);
};

/**
 * Sign a message.
 * @private
 * @param {Buffer} msg
 * @param {DSAPrivateKey} key
 * @returns {Signature}
 */

dsa._sign = function _sign(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(key instanceof DSAPrivateKey);

  dsa.privateKeyCompute(key);

  const pn = new BN(key.p);
  const qn = new BN(key.q);
  const gn = new BN(key.g);
  const xn = new BN(key.x);

  let n = qn.bitLength();

  if (qn.cmpn(0) <= 0
      || pn.cmpn(0) <= 0
      || gn.cmpn(0) <= 0
      || xn.cmpn(0) <= 0
      || (n & 7) !== 0) {
    throw new Error('Invalid key.');
  }

  n >>>= 3;

  let attempts = 10;
  let r, s;

  for (; attempts > 0; attempts--) {
    let k = new BN(0);

    const buf = Buffer.allocUnsafe(n);

    for (;;) {
      random.randomFill(buf, 0, n);
      k = new BN(buf);

      if (!k.isZero() && k.cmp(qn) < 0)
        break;
    }

    const ki = fermatInverse(k, qn);

    r = modPow(gn, k, pn);
    r = r.mod(qn);

    if (r.isZero())
      continue;

    const z = new BN(msg);

    s = xn.mul(r);
    s.iadd(z);
    s = s.mod(qn);
    s.imul(ki);
    s = s.mod(qn);

    if (!s.isZero())
      break;
  }

  if (attempts === 0)
    throw new Error('Could not sign.');

  const sig = new Signature();
  const size = key.size();

  sig.setR(toBuffer(r), size);
  sig.setS(toBuffer(s), size);

  return sig;
};

/**
 * Sign a message (R/S).
 * @param {Buffer} msg
 * @param {DSAPrivateKey} key - Private key.
 * @returns {Buffer} R/S-formatted signature.
 */

dsa.sign = function sign(msg, key) {
  const sig = dsa._sign(msg, key);
  return sig.encode(key.size());
};

/**
 * Sign a message (DER).
 * @param {Buffer} msg
 * @param {DSAPrivateKey} key - Private key.
 * @returns {Buffer} DER-formatted signature.
 */

dsa.signDER = function signDER(msg, key) {
  const sig = dsa._sign(msg, key);
  return sig.toDER(key.size());
};

/**
 * Verify a signature.
 * @private
 * @param {Buffer} msg
 * @param {Signature} sig
 * @param {DSAKey} key
 * @returns {Boolean}
 */

dsa._verify = function _verify(msg, sig, key) {
  assert(Buffer.isBuffer(msg));
  assert(sig instanceof Signature);
  assert(key instanceof DSAKey);

  if (!dsa.publicKeyVerify(key))
    return false;

  const pn = new BN(key.p);
  const qn = new BN(key.q);
  const gn = new BN(key.g);
  const yn = new BN(key.y);

  const rn = new BN(sig.r);
  const sn = new BN(sig.s);

  if (pn.isZero())
    return false;

  if (rn.isZero() || rn.cmp(qn) >= 0)
    return false;

  if (sn.isZero() || sn.cmp(qn) >= 0)
    return false;

  let w = sn.invm(qn);

  const n = qn.bitLength();

  if ((n & 7) !== 0)
    return false;

  const z = new BN(msg);

  let u1 = z.mul(w);
  u1 = u1.mod(qn);
  w = rn.mul(w);

  let u2 = w;
  u2 = u2.mod(qn);

  u1 = modPow(gn, u1, pn);
  let v = u1;

  u2 = modPow(yn, u2, pn);

  v.imul(u2);
  v = v.mod(pn);
  v = v.mod(qn);

  return v.cmp(rn) === 0;
};

/**
 * Verify a signature (R/S).
 * @param {Buffer} msg
 * @param {Buffer} sig - R/S-formatted.
 * @param {DSAKey} key
 * @returns {Boolean}
 */

dsa.verify = function verify(msg, sig, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(key instanceof DSAKey);

  if (sig.length !== key.size() * 2)
    return false;

  const s = Signature.decode(sig, key.size());

  return dsa._verify(msg, s, key);
};

/**
 * Verify a signature (DER).
 * @param {Buffer} msg
 * @param {Buffer} sig - DER-formatted.
 * @param {DSAKey} key
 * @returns {Boolean}
 */

dsa.verifyDER = function verifyDER(msg, sig, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(key instanceof DSAKey);

  if (sig.length === 0)
    return false;

  let s;
  try {
    s = Signature.fromDER(sig, key.size());
  } catch (e) {
    return false;
  }

  return dsa._verify(msg, s, key);
};

/*
 * Generation
 */

function generateParams(L, N) {
  assert((L >>> 0) === L);
  assert((N >>> 0) === N);

  if (!(L === 1024 && N === 160)
      && !(L === 2048 && N === 224)
      && !(L === 2048 && N === 256)
      && !(L === 3072 && N === 256)) {
    throw new Error('Invalid parameter sizes.');
  }

  const qb = Buffer.alloc(N >>> 3);
  const pb = Buffer.alloc(L >>> 3);

  let qn = new BN(0);
  let pn = new BN(0);
  let rem = new BN(0);

generate:
  for (;;) {
    random.randomFill(qb, 0, N >>> 3);

    qb[qb.length - 1] |= 1;
    qb[0] |= 0x80;

    qn = new BN(qb);

    if (!probablyPrime(qn, 64))
      continue;

    for (let i = 0; i < 4 * L; i++) {
      random.randomFill(pb, 0, L >>> 3);

      pb[pb.length - 1] |= 1;
      pb[0] |= 0x80;

      pn = new BN(pb);

      rem = pn.mod(qn);
      rem.isubn(1);
      pn.isub(rem);

      if (pn.bitLength() < L)
        continue;

      if (!probablyPrime(pn, 64))
        continue;

      break generate;
    }
  }

  const h = new BN(2);
  const pm1 = pn.subn(1);
  const e = pm1.div(qn);

  for (;;) {
    const gn = modPow(h, e, pn);

    if (gn.cmpn(1) === 0) {
      h.iaddn(1);
      continue;
    }

    const params = new DSAParams();
    params.p = toBuffer(pn);
    params.q = toBuffer(qn);
    params.g = toBuffer(gn);
    return params;
  }
}

function modPow(x, y, m) {
  return x.toRed(BN.red(m)).redPow(y).fromRed();
}

function fermatInverse(k, p) {
  return modPow(k, p.subn(2), p);
}

/*
 * Helpers
 */

function toBuffer(n) {
  return n.toArrayLike(Buffer, 'be');
}
