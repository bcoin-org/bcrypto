/*!
 * hash160.js - Hash160 implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const SHA256 = require('./sha256');
const RIPEMD160 = require('./ripemd160');
const HMAC = require('../hmac');

const rmd = new RIPEMD160();

let ctx = null;

/**
 * Hash160
 */

class Hash160 {
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
    rmd.init();
    rmd.update(out);
    rmd._final(out);
    return out.slice(0, 20);
  }

  static hash() {
    return new Hash160();
  }

  static hmac() {
    return new HMAC(Hash160, 64);
  }

  static digest(data) {
    return ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 20);
    assert(Buffer.isBuffer(right) && right.length === 20);
    return ctx.init().update(left).update(right).final();
  }

  static mac(data, key) {
    return this.hmac().init(key).update(data).final();
  }
}

ctx = new Hash160();

/*
 * Expose
 */

module.exports = Hash160;
