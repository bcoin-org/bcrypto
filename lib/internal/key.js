/*!
 * pkcs1.js - PKCS1 encoding for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');

/*
 * Constants
 */

const EMPTY = Buffer.alloc(0);

/*
 * Key
 */

class Key {
  constructor(type, curve) {
    assert(!type || typeof type === 'string');
    assert(!curve || typeof curve === 'string');
    this.type = type || 'rsa';
    this.curve = curve || null;
    this.priv = false;
  }
}

/*
 * PublicKey
 */

class PublicKey extends Key {
  constructor(type, curve) {
    super(type, curve);

    // RSA
    this.n = EMPTY;
    this.e = EMPTY;

    // El Gamal
    this.p = EMPTY;
    this.g = EMPTY;
    this.y = EMPTY;

    // DSA
    // this.p = EMPTY;
    this.q = EMPTY;
    // this.g = EMPTY;
    // this.y = EMPTY;

    // ECDSA
    this.point = EMPTY;
  }
}

/*
 * PrivateKey
 */

class PrivateKey extends Key {
  constructor(type, curve) {
    super(type, curve);

    this.priv = true;

    // RSA
    this.d = EMPTY;
    this.p = EMPTY;
    this.q = EMPTY;
    this.qi = EMPTY;

    // DSA
    this.x = EMPTY;

    // El Gamal
    // this.x = EMPTY;

    // ECDSA
    // this.d = EMPTY;
  }
}

/*
 * Expose
 */

exports.Key = Key;
exports.PublicKey = PublicKey;
exports.PrivateKey = PrivateKey;
