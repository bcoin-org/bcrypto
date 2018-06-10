/*!
 * ecdsa-native.js - ecdsa wrapper for openssl
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const binding = require('../native/binding').ecdsa;
const curves = require('./curves');
const ecsig = require('./ecsig');
const random = require('../random');
const Signature = ecsig.ECSignature;

/*
 * ECDSA
 */

class ECDSA {
  constructor(name) {
    assert(typeof name === 'string');

    const ec = curves[name];
    assert(ec);

    this.name = name;
    this.size = ec.size;
    this.bits = ec.bits;
    this.zero = Buffer.alloc(this.size, 0x00);
    this.order = Buffer.from(ec.order, 'hex');
    this.half = Buffer.from(ec.half, 'hex');
  }

  privateKeyGenerate() {
    let key;

    // Note could also use:
    // binding.privateKeyGenerate(this.name);

    do {
      key = random.randomBytes(this.size);
    } while (!this.privateKeyVerify(key));

    return key;
  }

  generatePrivateKey() {
    return this.privateKeyGenerate();
  }

  publicKeyCreate(key, compress) {
    return binding.publicKeyCreate(this.name, key, compress);
  }

  publicKeyConvert(key, compress) {
    return binding.publicKeyConvert(this.name, key, compress);
  }

  privateKeyTweakAdd(key, tweak) {
    return binding.privateKeyTweakAdd(this.name, key, tweak);
  }

  publicKeyTweakAdd(key, tweak, compress) {
    return binding.publicKeyTweakAdd(this.name, key, tweak, compress);
  }

  ecdh(pub, priv, compress) {
    return binding.ecdh(this.name, pub, priv, compress);
  }

  publicKeyVerify(key) {
    return binding.publicKeyVerify(this.name, key);
  }

  privateKeyVerify(key) {
    // NOTE: Binding doesn't work and requires a point mult.
    assert(Buffer.isBuffer(key));

    if (key.length !== this.size)
      return false;

    if (key.equals(this.zero))
      return false;

    return key.compare(this.order) < 0;
  }

  _sign(msg, key) {
    const sig = new Signature();

    [sig.r, sig.s] = binding.sign(this.name, msg, key);

    return sig;
  }

  sign(msg, key) {
    const sig = this._sign(msg, key);
    return sig.encode(this.size);
  }

  signDER(msg, key) {
    const sig = this._sign(msg, key);
    return sig.toDER(this.size);
  }

  verify(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    if (key.length === 0)
      return false;

    if (sig.length !== this.size * 2)
      return false;

    const r = sig.slice(0, this.size);
    const s = sig.slice(this.size, this.size * 2);

    return binding.verify(this.name, msg, r, s, key);
  }

  verifyDER(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    if (key.length === 0)
      return false;

    // OpenSSL's DER parsing is known
    // to be buggy, so we do it ourselves.
    let s;
    try {
      s = Signature.fromDERLax(sig, this.size);
    } catch (e) {
      return false;
    }

    return binding.verify(this.name, msg, s.r, s.s, key);
  }

  recover(msg, sig, param, compress) {
    throw new Error('Not implemented.');
  }

  recoverDER(msg, sig, param, compress) {
    throw new Error('Not implemented.');
  }

  fromDER(raw) {
    return ecsig.fromDER(raw, this.size);
  }

  toDER(raw) {
    return ecsig.toDER(raw, this.size);
  }

  isLowS(raw) {
    return ecsig.isLowS(raw, this.size, this.half);
  }

  isLowDER(raw) {
    return ecsig.isLowDER(raw, this.size, this.half);
  }
}

/*
 * Expose
 */

module.exports = ECDSA;
