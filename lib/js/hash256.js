/*!
 * hash256.js - Hash256 implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const SHA256 = require('./sha256');
const HMAC = require('../hmac');

let ctx = null;

/**
 * Hash256
 */

class Hash256 {
  constructor() {
    this.ctx = new SHA256();
  }

  init() {
    this.ctx.init();
    return this;
  }

  update(data) {
    this.ctx.update(data);
    return this;
  }

  final() {
    const out = Buffer.allocUnsafe(32);
    this.ctx._final(out);
    this.ctx.init();
    this.ctx.update(out);
    this.ctx._final(out);
    return out;
  }

  static hash() {
    return new Hash256();
  }

  static hmac() {
    return new HMAC(Hash256, 64);
  }

  static digest(data) {
    return ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 32);
    assert(Buffer.isBuffer(right) && right.length === 32);
    return ctx.init().update(left).update(right).final();
  }

  static mac(data, key) {
    return this.hmac().init(key).update(data).final();
  }
}

ctx = new Hash256();

/*
 * Expose
 */

module.exports = Hash256;
