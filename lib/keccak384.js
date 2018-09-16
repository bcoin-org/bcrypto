/*!
 * keccak384.js - Keccak-384 implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const Keccak = require('./keccak');

/**
 * Keccak384
 */

class Keccak384 extends Keccak {
  /**
   * Create a Keccak384 context.
   * @constructor
   */

  constructor() {
    super();
  }

  init() {
    return super.init(384);
  }

  final() {
    return super.final(false);
  }

  static hash() {
    return new Keccak384();
  }

  static hmac() {
    throw new Error('Not implemented.');
  }

  static digest(data) {
    return super.digest(data, 384, false);
  }

  static root(left, right) {
    return super.root(left, right, 384, false);
  }

  static multi(one, two, three) {
    return super.multi(one, two, three, 384, false);
  }

  static mac(data) {
    throw new Error('Not implemented.');
  }
}

Keccak384.native = Keccak.native;
Keccak384.id = 'KECCAK384';
Keccak384.size = 48;
Keccak384.bits = 384;
Keccak384.blockSize = 104;
Keccak384.zero = Buffer.alloc(48, 0x00);
Keccak384.ctx = new Keccak384();

/*
 * Expose
 */

module.exports = Keccak384;
