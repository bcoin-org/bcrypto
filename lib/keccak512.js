/*!
 * keccak512.js - Keccak-512 implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const Keccak = require('./keccak');

/**
 * Keccak512
 */

class Keccak512 extends Keccak {
  /**
   * Create a Keccak512 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init() {
    return super.init(512);
  }

  final() {
    return super.final(false);
  }

  static hash() {
    return new Keccak512();
  }

  static hmac() {
    throw new Error('Not implemented.');
  }

  static digest(data) {
    return super.digest(data, 512, false);
  }

  static root(left, right) {
    return super.root(left, right, 512, false);
  }

  static multi(one, two, three) {
    return super.multi(one, two, three, 512, false);
  }

  static mac(data) {
    throw new Error('Not implemented.');
  }
}

Keccak512.native = Keccak.native;
Keccak512.id = 'keccak512';
Keccak512.size = 32;
Keccak512.bits = 512;
Keccak512.blockSize = 72;
Keccak512.zero = Buffer.alloc(32, 0x00);
Keccak512.ctx = new Keccak512();

/*
 * Expose
 */

module.exports = Keccak512;
