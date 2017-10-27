/*!
 * ripemd160.js - RIPEMD160 implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const crypto = require('crypto');
const HMAC = require('../hmac');

/**
 * RIPEMD160
 */

class RIPEMD160 {
  constructor() {
    this.ctx = null;
  }

  init() {
    this.ctx = crypto.createHash('ripemd160');
    return this;
  }

  update(data) {
    assert(Buffer.isBuffer(data));
    assert(this.ctx, 'Context already finalized.');
    this.ctx.update(data);
    return this;
  }

  final() {
    assert(this.ctx, 'Context already finalized.');
    const hash = this.ctx.digest();
    this.ctx = null;
    return hash;
  }

  static hash() {
    return new RIPEMD160();
  }

  static hmac() {
    return new HMAC(RIPEMD160, 64);
  }

  static digest(data) {
    return new RIPEMD160().init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 20);
    assert(Buffer.isBuffer(right) && right.length === 20);
    return new RIPEMD160().init().update(left).update(right).final();
  }

  static mac(data, key) {
    return RIPEMD160.hmac().init(key).update(data).final();
  }
}

/*
 * Expose
 */

module.exports = RIPEMD160;
