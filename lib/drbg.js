/*!
 * drbg.js - hmac-drbg implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 * Parts of this software based on hmac-drbg.
 */

'use strict';

const assert = require('assert');

/*
 * Constants
 */

const RESEED_INTERVAL = 0x1000000000000;
const ZERO = Buffer.from([0x00]);
const ONE = Buffer.from([0x01]);

/**
 * DRBG
 */

class DRBG {
  /**
   * Create a DRBG context.
   * @constructor
   */

  constructor(alg, entropy, nonce, pers) {
    assert(alg && typeof alg.id === 'string');

    this.alg = alg;
    this.K = Buffer.allocUnsafe(alg.size);
    this.V = Buffer.allocUnsafe(alg.size);
    this.rounds = 0;
    this.last = null;

    if (entropy)
      this.init(entropy, nonce, pers);
  }

  mac(data) {
    return this.alg.mac(data, this.K);
  }

  hmac() {
    return this.alg.hmac().init(this.K);
  }

  init(entropy, nonce, pers = null) {
    assert(Buffer.isBuffer(entropy));
    assert(Buffer.isBuffer(nonce));
    assert(!pers || Buffer.isBuffer(pers));

    // if (entropy.length < this.alg.size)
    //   throw new Error('Not enough entropy.');

    for (let i = 0; i < this.V.length; i++) {
      this.K[i] = 0x00;
      this.V[i] = 0x01;
    }

    const seed = concat(entropy, nonce, pers);

    this.update(seed);
    this.rounds = 1;
    this.last = null;

    return this;
  }

  update(seed = null) {
    assert(!seed || Buffer.isBuffer(seed));

    const kmac = this.hmac();

    kmac.update(this.V);
    kmac.update(ZERO);

    if (seed)
      kmac.update(seed);

    this.K = kmac.final();
    this.V = this.mac(this.V);

    if (seed) {
      const kmac = this.hmac();

      kmac.update(this.V);
      kmac.update(ONE);
      kmac.update(seed);

      this.K = kmac.final();
      this.V = this.mac(this.V);
    }

    return this;
  }

  reseed(entropy, add = null) {
    assert(Buffer.isBuffer(entropy));
    assert(!add || Buffer.isBuffer(add));

    // if (entropy.length < this.alg.size)
    //  throw new Error('Not enough entropy.');

    // Apply deferred update.
    if (this.rounds > 1) {
      this.update(this.last);
      this.last = null;
    }

    if (add)
      entropy = concat(entropy, add);

    this.update(entropy);
    this.rounds = 1;

    return this;
  }

  generate(len, add = null) {
    assert((len >>> 0) === len);
    assert(!add || Buffer.isBuffer(add));

    // Apply deferred update.
    if (this.rounds > 1) {
      this.update(this.last);
      this.last = null;
    }

    if (this.rounds > RESEED_INTERVAL)
      throw new Error('Reseed is required.');

    if (add)
      this.update(add);

    const data = Buffer.allocUnsafe(len);

    let pos = 0;

    while (pos < len) {
      this.V = this.mac(this.V);
      this.V.copy(data, pos);
      pos += this.alg.size;
    }

    // Deferred update.
    this.last = add;
    this.rounds += 1;

    return data;
  }
}

DRBG.native = 0;

/*
 * Helpers
 */

function concat(a, b, c = null) {
  let s = a.length + b.length;
  let p = 0;

  if (c)
    s += c.length;

  const d = Buffer.allocUnsafe(s);

  p += a.copy(d, p);
  p += b.copy(d, p);

  if (c)
    c.copy(d, p);

  return d;
}

/*
 * Expose
 */

module.exports = DRBG;
