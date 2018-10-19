/*!
 * dsa.js - DSA for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   https://github.com/openssl/openssl/blob/master/crypto/dsa/dsa_ossl.c
 *   https://github.com/golang/go/blob/master/src/crypto/dsa/dsa.go
 *   https://github.com/golang/go/blob/master/src/math/big/int.go
 */

/* eslint func-name-matching: "off" */

'use strict';

const assert = require('bsert');
const BN = require('../../vendor/bn.js');
const random = require('../random');
const DRBG = require('../drbg');
const SHA256 = require('../sha256');
const {countBits, leftPad} = require('../internal/util');
const {probablyPrime, randomInt} = require('../internal/primes');
const dsakey = require('../internal/dsakey');
const Signature = require('../internal/signature');
const openssl = require('../encoding/openssl');
const dsa = exports;

const {
  DEFAULT_BITS,
  MIN_BITS,
  MAX_BITS,
  MIN_HASH_SIZE,
  MAX_HASH_SIZE,
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
    bits = DEFAULT_BITS;

  assert((bits >>> 0) === bits);

  if (bits < MIN_BITS || bits > MAX_BITS)
    throw new RangeError(`"bits" ranges from ${MIN_BITS} to ${MAX_BITS}.`);

  // OpenSSL behavior.
  const L = bits;
  const N = bits < 2048 ? 160 : 256;

  return this.generateParams(L, N);
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

  if (!isSaneParams(params))
    return false;

  const p = new BN(params.p);
  const q = new BN(params.q);
  const g = new BN(params.g);
  const pm1 = p.subn(1);
  const {div, mod} = pm1.divmod(q);

  if (!mod.isZero())
    return false;

  const x = this.modPow(g, div, p);

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

  if (!isSaneParams(params))
    throw new Error('Invalid DSA parameters.');

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
  const yn = this.modPow(gn, xn, pn);

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

  if (!isSaneCompute(key))
    throw new Error('Invalid DSA private key.');

  if (!needsCompute(key))
    return;

  const p = new BN(key.p);
  const g = new BN(key.g);
  const x = new BN(key.x);
  const y = this.modPow(g, x, p);

  key.y = toBuffer(y);
};

/**
 * Verify a private key.
 * @param {DSAPrivateKey} key
 * @returns {Boolean}
 */

dsa.privateKeyVerify = function privateKeyVerify(key) {
  assert(key instanceof DSAPrivateKey);

  if (!isSanePrivateKey(key))
    return false;

  if (!dsa.publicKeyVerify(key))
    return false;

  const q = new BN(key.q);
  const x = new BN(key.x);

  if (x.isZero() || x.cmp(q) >= 0)
    return false;

  const p = new BN(key.p);
  const g = new BN(key.g);
  const y = this.modPow(g, x, p);

  return new BN(key.y).eq(y);
};

/**
 * Export a private key in OpenSSL ASN.1 format.
 * @param {DSAPrivateKey} key
 * @returns {Buffer}
 */

dsa.privateKeyExport = function privateKeyExport(key) {
  assert(key instanceof DSAPrivateKey);

  if (!isSanePrivateKey(key))
    throw new Error('Invalid DSA private key.');

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
 * Add tweak integer to private key.
 * @param {DSAPrivateKey} key
 * @param {Buffer} tweak
 * @returns {DSAPrivateKey}
 */

dsa.privateKeyTweakAdd = function privateKeyTweakAdd(key, tweak) {
  assert(key instanceof DSAPrivateKey);
  assert(Buffer.isBuffer(tweak));

  if (!isSanePrivateKey(key))
    throw new Error('Invalid DSA private key.');

  if (tweak.length < MIN_HASH_SIZE || tweak.length > MAX_HASH_SIZE)
    throw new Error('Invalid DSA tweak integer.');

  const size = key.size();

  if (tweak.length > size)
    tweak = tweak.slice(0, size);

  const q = new BN(key.q);
  const t = new BN(tweak).umod(q);

  if (t.isZero())
    throw new Error('Invalid DSA tweak integer.');

  const p = new BN(key.p);
  const g = new BN(key.g);

  // priv = (x + (t % q)) % q
  // where `t` is the tweak integer
  let newX = new BN(key.x);
  newX.iadd(t);
  newX = newX.umod(q);

  if (newX.isZero())
    throw new Error('Invalid DSA tweak integer.');

  const newY = this.modPow(g, newX, p);
  const priv = new DSAPrivateKey();

  priv.p = key.p;
  priv.q = key.q;
  priv.g = key.g;
  priv.y = toBuffer(newY);
  priv.x = toBuffer(newX);

  return priv;
};

/**
 * Create a public key from a private key.
 * @param {DSAPrivateKey} key
 * @returns {DSAPublicKey}
 */

dsa.publicKeyCreate = function publicKeyCreate(key) {
  assert(key instanceof DSAPrivateKey);

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

  return isSanePublicKey(key);
};

/**
 * Export a public key to SubjectPublicKeyInfo ASN.1 format.
 * @param {DSAKey} key
 * @returns {Buffer}
 */

dsa.publicKeyExport = function publicKeyExport(key) {
  assert(key instanceof DSAKey);

  if (!isSanePublicKey(key))
    throw new Error('Invalid DSA public key.');

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
 * Add tweak integer to public key.
 * @param {DSAKey} key
 * @param {Buffer} tweak
 * @returns {DSAPublicKey}
 */

dsa.publicKeyTweakAdd = function publicKeyTweakAdd(key, tweak) {
  assert(key instanceof DSAKey);
  assert(Buffer.isBuffer(tweak));

  if (!isSanePublicKey(key))
    throw new Error('Invalid DSA public key.');

  if (tweak.length < MIN_HASH_SIZE || tweak.length > MAX_HASH_SIZE)
    throw new Error('Invalid DSA tweak integer.');

  const size = key.size();

  if (tweak.length > size)
    tweak = tweak.slice(0, size);

  const q = new BN(key.q);
  const t = new BN(tweak).umod(q);

  if (t.isZero())
    throw new Error('Invalid DSA tweak integer.');

  const p = new BN(key.p);
  const g = new BN(key.g);
  const y = new BN(key.y);

  // pub = ((g^(t % q) % p) * y) % p
  // where `t` is the tweak integer
  let newY = this.modPow(g, t, p);
  newY.imul(y);
  newY = newY.umod(p);

  const pub = new DSAPublicKey();

  pub.p = key.p;
  pub.q = key.q;
  pub.g = key.g;
  pub.y = toBuffer(newY);

  if (!dsa.publicKeyVerify(pub))
    throw new Error('Invalid DSA tweak integer.');

  return pub;
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
 * Sign a message.
 * @private
 * @param {Buffer} msg
 * @param {DSAPrivateKey} key
 * @returns {Signature}
 */

dsa._sign = function _sign(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(key instanceof DSAPrivateKey);

  if (msg.length < MIN_HASH_SIZE || msg.length > MAX_HASH_SIZE)
    throw new Error('Invalid DSA message size.');

  if (!isSanePrivateKey(key))
    throw new Error('Invalid DSA private key.');

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
    throw new Error('Invalid DSA private key.');
  }

  n >>>= 3;

  if (msg.length > n)
    msg = msg.slice(0, n);

  let attempts = 10;
  let r, s, b, t, bm;

  // https://tools.ietf.org/html/rfc6979#section-3.2
  const entropy = leftPad(key.x, n < 24 ? 24 : n);
  const drbg = new DRBG(SHA256, entropy, msg);

  for (; attempts > 0; attempts--) {
    let k = null;

    for (;;) {
      k = new BN(drbg.generate(n));

      if (!k.isZero() && k.cmp(qn) < 0)
        break;
    }

    const ki = this.fermatInverse(k, qn);

    r = this.modPow(gn, k, pn);
    r = r.umod(qn);

    if (r.isZero())
      continue;

    const z = new BN(msg);

    // Without blinding factor.
    // s := k^-1 * (m + r * priv_key) mod q
    // s = xn.mul(r);
    // s.iadd(z);
    // s = s.umod(qn);
    // s.imul(ki);
    // s = s.umod(qn);

    // Blinding factor.
    do {
      b = randomInt(qn);
    } while (b.isZero());

    // tmp := blind * priv_key * r mod q
    t = b.mul(xn).umod(qn);
    t = t.mul(r).umod(qn);

    // blindm := blind * m mod q
    bm = b.mul(z).umod(qn);

    // s := (blind * priv_key * r) + (blind * m) mod q
    s = t.add(bm).umod(qn);

    // s := s * k^-1 mod q
    s = s.mul(ki).umod(qn);

    // s := s * blind^-1 mod q
    b = this.invm(b, qn).umod(qn);
    s = s.mul(b).umod(qn);

    if (s.isZero())
      continue;

    break;
  }

  if (attempts === 0)
    throw new Error('Could not sign.');

  const sig = new Signature();

  sig.r = toBuffer(r, n);
  sig.s = toBuffer(s, n);

  return sig;
};

/**
 * Verify a signature (R/S).
 * @private
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

  try {
    return dsa._verify(msg, s, key);
  } catch (e) {
    return false;
  }
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

  if (msg.length < MIN_HASH_SIZE || msg.length > MAX_HASH_SIZE)
    return false;

  const k = key.size();

  if (sig.r.length !== k)
    return false;

  if (sig.s.length !== k)
    return false;

  if (!isSanePublicKey(key))
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

  let n = qn.bitLength();

  if ((n & 7) !== 0)
    return false;

  n >>>= 3;

  if (msg.length > n)
    msg = msg.slice(0, n);

  const w = this.invm(sn, qn);
  const z = new BN(msg);

  let u1, u2, v;

  u1 = z.imul(w);
  u1 = u1.umod(qn);

  u2 = rn.mul(w);
  u2 = u2.umod(qn);

  v = this.modPow(gn, u1, pn);

  u2 = this.modPow(yn, u2, pn);

  v.imul(u2);
  v = v.umod(pn);
  v = v.umod(qn);

  return v.cmp(rn) === 0;
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

  let s;
  try {
    s = Signature.fromDER(sig, key.size());
  } catch (e) {
    return false;
  }

  return dsa._verify(msg, s, key);
};

/**
 * Perform a diffie-hellman.
 * @param {DSAKey} pub
 * @param {DSAPrivateKey} priv
 * @returns {Buffer}
 */

dsa.derive = function derive(pub, priv) {
  assert(pub instanceof DSAKey);
  assert(priv instanceof DSAPrivateKey);

  if (!isSanePublicKey(pub))
    throw new Error('Invalid DSA public key.');

  if (!isSanePrivateKey(priv))
    throw new Error('Invalid DSA private key.');

  const pubP = new BN(pub.p);
  const pubQ = new BN(pub.q);
  const pubG = new BN(pub.g);
  const p = new BN(priv.p);
  const q = new BN(priv.q);
  const g = new BN(priv.g);

  if (!pubP.eq(p) || !pubQ.eq(q) || !pubG.eq(g))
    throw new Error('Incompatible DSA parameters.');

  // secret = (theirY^ourX) % p
  const pubY = new BN(pub.y);
  const x = new BN(priv.x);
  const s = this.modPow(pubY, x, p);

  return toBuffer(s);
};

/**
 * Generate params from L and N.
 * @private
 * @param {Number} L
 * @param {Number} N
 * @returns {DSAParams}
 */

dsa.generateParams = function generateParams(L, N) {
  assert((L >>> 0) === L);
  assert((N >>> 0) === N);

  if (!(L === 1024 && N === 160)
      && !(L === 2048 && N === 224)
      && !(L === 2048 && N === 256)
      && !(L === 3072 && N === 256)) {
    throw new Error('Invalid parameter sizes.');
  }

  if (L < MIN_BITS || L > MAX_BITS || (N & 7) !== 0)
    throw new Error('Invalid parameter sizes.');

  const qb = Buffer.alloc(N >>> 3);
  const pb = Buffer.alloc((L + 7) >>> 3);

  let qn = null;
  let pn = null;

generate:
  for (;;) {
    random.randomFill(qb, 0, qb.length);

    qb[qb.length - 1] |= 1;
    qb[0] |= 0x80;

    qn = new BN(qb);

    if (!this.probablyPrime(qn, 64))
      continue;

    for (let i = 0; i < 4 * L; i++) {
      random.randomFill(pb, 0, pb.length);

      pb[pb.length - 1] |= 1;
      pb[0] |= 0x80;

      pn = new BN(pb);

      const rem = pn.umod(qn);
      rem.isubn(1);
      pn.isub(rem);

      const bits = pn.bitLength();

      if (bits < L || bits > MAX_BITS)
        continue;

      if (!this.probablyPrime(pn, 64))
        continue;

      break generate;
    }
  }

  const h = new BN(2);
  const pm1 = pn.subn(1);
  const e = pm1.div(qn);

  for (;;) {
    const gn = this.modPow(h, e, pn);

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
};

/**
 * Test primality for number.
 * @private
 * @param {BN} x
 * @param {Number} n
 * @returns {Boolean}
 */

dsa.probablyPrime = function _probablyPrime(x, n) {
  return probablyPrime(x, n);
};

/**
 * Compute modular exponentiation.
 * @private
 * @param {BN} x
 * @param {BN} y
 * @param {BN} m
 * @returns {BN}
 */

dsa.modPow = function modPow(x, y, m) {
  assert(x instanceof BN);
  assert(y instanceof BN);
  assert(m instanceof BN);
  return x.toRed(BN.red(m)).redPow(y).fromRed();
};

/**
 * Compute fermat inverse.
 * @private
 * @param {BN} k
 * @param {BN} p
 * @returns {BN}
 */

dsa.fermatInverse = function fermatInverse(k, p) {
  assert(k instanceof BN);
  assert(p instanceof BN);
  return this.modPow(k, p.subn(2), p);
};

/**
 * Compute modular inverse.
 * @private
 * @param {BN} k
 * @param {BN} p
 * @returns {BN}
 */

dsa.invm = function invm(k, p) {
  assert(k instanceof BN);
  assert(p instanceof BN);
  return k.invm(p);
};

/*
 * Compat
 */

dsa.dh = dsa.derive;

/*
 * Sanity Checking
 */

function isSaneParams(params) {
  assert(params instanceof DSAParams);

  const pb = countBits(params.p);
  const qb = countBits(params.q);
  const gb = countBits(params.g);

  if (pb < MIN_BITS || pb > MAX_BITS)
    return false;

  if (qb !== 160 && qb !== 224 && qb !== 256)
    return false;

  if (gb === 0 || gb > pb)
    return false;

  return true;
}

function isSanePublicKey(key) {
  assert(key instanceof DSAKey);

  if (!isSaneParams(key))
    return false;

  const pb = countBits(key.p);
  const yb = countBits(key.y);

  if (yb === 0 || yb > pb)
    return false;

  return true;
}

function isSanePrivateKey(key) {
  assert(key instanceof DSAPrivateKey);

  if (!isSanePublicKey(key))
    return false;

  const qb = countBits(key.q);
  const xb = countBits(key.x);

  if (xb === 0 || xb > qb)
    return false;

  return true;
}

function isSaneCompute(key) {
  assert(key instanceof DSAPrivateKey);

  const pb = countBits(key.p);
  const qb = countBits(key.q);
  const gb = countBits(key.g);
  const yb = countBits(key.y);
  const xb = countBits(key.x);

  if (pb < MIN_BITS || pb > MAX_BITS)
    return false;

  if (qb !== 160 && qb !== 224 && qb !== 256)
    return false;

  if (gb === 0 || gb > pb)
    return false;

  if (yb > pb)
    return false;

  if (xb === 0 || xb > qb)
    return false;

  return true;
}

function needsCompute(key) {
  assert(key instanceof DSAPrivateKey);
  return countBits(key.y) === 0;
}

/*
 * Helpers
 */

function toBuffer(n, size) {
  return n.toArrayLike(Buffer, 'be', size);
}
