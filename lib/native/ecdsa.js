/*!
 * ecdsa.js - ecdsa wrapper for openssl
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const binding = require('./binding').ecdsa;

if (!binding)
  throw new Error('ECDSA native support not available.');

const curves = require('../internal/curves');
const ecsig = require('../internal/ecsig');
const Signature = ecsig.ECSignature;

/**
 * ECDSA
 */

class ECDSA {
  constructor(name) {
    assert(typeof name === 'string');

    const ec = curves[name];
    assert(ec);

    this.id = name;
    this.size = ec.size;
    this.bits = ec.bits;
    this.zero = Buffer.alloc(this.size, 0x00);
    this.order = Buffer.from(ec.order, 'hex');
    this.half = Buffer.from(ec.half, 'hex');
    this.native = 2;

    this._js = null;
  }

  get js() {
    if (!this._js) {
      const ECDSAJS = require('../js/ecdsa');
      this._js = new ECDSAJS(this.id);
    }
    return this._js;
  }

  privateKeyGenerate() {
    return binding.privateKeyGenerate(this.id);
  }

  generatePrivateKey() {
    return this.privateKeyGenerate();
  }

  publicKeyCreate(key, compress) {
    return binding.publicKeyCreate(this.id, key, compress);
  }

  publicKeyConvert(key, compress) {
    return binding.publicKeyConvert(this.id, key, compress);
  }

  privateKeyTweakAdd(key, tweak) {
    return binding.privateKeyTweakAdd(this.id, key, tweak);
  }

  publicKeyTweakAdd(key, tweak, compress) {
    return binding.publicKeyTweakAdd(this.id, key, tweak, compress);
  }

  ecdh(pub, priv, compress) {
    return binding.ecdh(this.id, pub, priv, compress);
  }

  publicKeyVerify(key) {
    return binding.publicKeyVerify(this.id, key);
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

    [sig.r, sig.s] = binding.sign(this.id, msg, key);

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

    return binding.verify(this.id, msg, r, s, key);
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
      s = Signature.fromLax(sig, this.size);
    } catch (e) {
      return false;
    }

    return binding.verify(this.id, msg, s.r, s.s, key);
  }

  recover(msg, sig, param, compress) {
    return this.js.recover(msg, sig, param, compress);
  }

  recoverDER(msg, sig, param, compress) {
    return this.js.recoverDER(msg, sig, param, compress);
  }

  fromDER(sig) {
    return ecsig.fromDER(sig, this.size);
  }

  fromLax(sig) {
    return ecsig.fromLax(sig, this.size);
  }

  toDER(sig) {
    return ecsig.toDER(sig, this.size);
  }

  isLowS(sig) {
    return ecsig.isLowS(sig, this.size, this.half);
  }

  isLowDER(sig) {
    return ecsig.isLowDER(sig, this.size, this.half);
  }
}

/*
 * Expose
 */

module.exports = ECDSA;
