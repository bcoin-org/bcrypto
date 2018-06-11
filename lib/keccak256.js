/*!
 * keccak256.js - Keccak-256 implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const Keccak = require('./keccak');

/**
 * Keccak256
 */

class Keccak256 extends Keccak {
  /**
   * Create a Keccak256 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init() {
    return super.init(256);
  }

  final() {
    return super.final(false);
  }

  static hash() {
    return new Keccak256();
  }

  static hmac() {
    throw new Error('Not implemented.');
  }

  static digest(data) {
    return super.digest(data, 256, false);
  }

  static root(left, right) {
    return super.root(left, right, 256, false);
  }

  static multi(one, two, three) {
    return super.multi(one, two, three, 256, false);
  }

  static mac(data) {
    throw new Error('Not implemented.');
  }
}

Keccak256.native = Keccak.native;
Keccak256.id = 'keccak256';
Keccak256.size = 32;
Keccak256.bits = 256;
Keccak256.blockSize = 128;
Keccak256.zero = Buffer.alloc(32, 0x00);
Keccak256.ctx = new Keccak256();

/*
 * Expose
 */

module.exports = Keccak256;
