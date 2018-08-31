/*!
 * ecsig.js - EC signatures for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const Signature = require('./signature');
const {leftPad} = require('./util');

/*
 * Expose
 */

module.exports = function create(curve) {
  assert(curve);

  return class ECSignature extends Signature {
    constructor(r, s) {
      super();
      this.r = leftPad(r, curve.size);
      this.s = leftPad(s, curve.size);
    }

    setR(r) {
      return super.setR(r, curve.size);
    }

    setS(s) {
      return super.setS(s, curve.size);
    }

    isLowS() {
      return super.isLowS(curve.size, curve.half);
    }

    encode() {
      return super.encode(curve.size);
    }

    decode(data) {
      return super.decode(data, curve.size);
    }

    toDER() {
      return super.toDER(curve.size);
    }

    fromDER(data) {
      return super.fromDER(data, curve.size);
    }

    static decode(data) {
      return new this().decode(data);
    }

    static fromDER(data) {
      return new this().fromDER(data);
    }

    static toRS(raw) {
      return super.toRS(raw, curve.size);
    }

    static toDER(raw) {
      return super.toDER(raw, curve.size);
    }

    static normalize(raw) {
      return super.normalize(raw, curve.size);
    }

    static isLowDER(raw) {
      return super.isLowDER(raw, curve.size, curve.half);
    }

    static isLowS(raw) {
      return super.isLowS(raw, curve.size, curve.half);
    }
  };
};
