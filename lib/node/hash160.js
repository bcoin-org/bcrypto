/*!
 * hash160.js - Hash160 implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const crypto = require('crypto');
const HMAC = require('../hmac');

/**
 * Hash160
 */

class Hash160 {
  constructor() {
    this.ctx = null;
  }

  init() {
    this.ctx = crypto.createHash('sha256');
    return this;
  }

  update(data) {
    assert(Buffer.isBuffer(data));
    this.ctx.update(data);
    return this;
  }

  final() {
    const rmd = crypto.createHash('ripemd160');
    rmd.update(this.ctx.digest());
    return rmd.digest();
  }

  static hash() {
    return new Hash160();
  }

  static hmac() {
    return new HMAC(Hash160, 64);
  }

  static digest(data) {
    return new Hash160().init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 20);
    assert(Buffer.isBuffer(right) && right.length === 20);
    return new Hash160().init().update(left).update(right).final();
  }

  static mac(data, key) {
    return this.hmac().init(key).update(data).final();
  }
}

/*
 * Expose
 */

module.exports = Hash160;
