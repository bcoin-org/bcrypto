/*!
 * dsakey.js - DSA keys for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const {countBits, trimZeroes} = require('./util');
const {custom} = require('./custom');

/*
 * Constants
 */

const DEFAULT_BITS = 2048;
const MIN_BITS = 512;
const MAX_BITS = 10000;
const MIN_HASH_SIZE = 20;
const MAX_HASH_SIZE = 128;

/**
 * DSA Params
 */

class DSAParams {
  constructor(p, q, g) {
    this.p = trimZeroes(p);
    this.q = trimZeroes(q);
    this.g = trimZeroes(g);
  }

  setP(p) {
    this.p = trimZeroes(p);
    return this;
  }

  setQ(q) {
    this.q = trimZeroes(q);
    return this;
  }

  setG(g) {
    this.g = trimZeroes(g);
    return this;
  }

  L() {
    return countBits(this.p);
  }

  N() {
    return countBits(this.q);
  }

  bits() {
    return this.L();
  }

  size() {
    return (this.N() + 7) >>> 3;
  }

  [custom]() {
    return this.format();
  }

  format() {
    return {
      bits: this.bits(),
      size: this.size(),
      pbits: countBits(this.p),
      qbits: countBits(this.q),
      gbits: countBits(this.g),
      p: this.p.toString('hex'),
      q: this.q.toString('hex'),
      g: this.g.toString('hex')
    };
  }
}

/**
 * DSA Key
 */

class DSAKey extends DSAParams {
  constructor(p, q, g, y) {
    super(p, q, g);
    this.y = trimZeroes(y);
  }

  toParams() {
    return new DSAParams(this.p, this.q, this.g);
  }

  fromParams(params) {
    assert(params instanceof DSAParams);
    this.p = params.p;
    this.q = params.q;
    this.g = params.g;
    return this;
  }

  setParams(params) {
    return this.fromParams(params);
  }

  setY(y) {
    this.y = trimZeroes(y);
    return this;
  }

  static fromParams(params) {
    return new this().fromParams(params);
  }
}

/**
 * DSA Public Key
 */

class DSAPublicKey extends DSAKey {
  constructor(p, q, g, y) {
    super(p, q, g, y);
  }

  format() {
    return {
      bits: this.bits(),
      size: this.size(),
      pbits: countBits(this.p),
      qbits: countBits(this.q),
      gbits: countBits(this.g),
      ybits: countBits(this.y),
      p: this.p.toString('hex'),
      q: this.q.toString('hex'),
      g: this.g.toString('hex'),
      y: this.y.toString('hex')
    };
  }
}

/**
 * DSA Public Key
 */

class DSAPrivateKey extends DSAKey {
  constructor(p, q, g, y, x) {
    super(p, q, g, y);
    this.x = trimZeroes(x);
  }

  setX(x) {
    this.x = trimZeroes(x);
    return this;
  }

  format() {
    return {
      bits: this.bits(),
      size: this.size(),
      pbits: countBits(this.p),
      qbits: countBits(this.q),
      gbits: countBits(this.g),
      ybits: countBits(this.y),
      xbits: countBits(this.x),
      p: this.p.toString('hex'),
      q: this.q.toString('hex'),
      g: this.g.toString('hex'),
      y: this.y.toString('hex'),
      x: this.x.toString('hex')
    };
  }
}

/*
 * Expose
 */

exports.DEFAULT_BITS = DEFAULT_BITS;
exports.MIN_BITS = MIN_BITS;
exports.MAX_BITS = MAX_BITS;
exports.MIN_HASH_SIZE = MIN_HASH_SIZE;
exports.MAX_HASH_SIZE = MAX_HASH_SIZE;

exports.DSAKey = DSAKey;
exports.DSAParams = DSAParams;
exports.DSAPublicKey = DSAPublicKey;
exports.DSAPrivateKey = DSAPrivateKey;
