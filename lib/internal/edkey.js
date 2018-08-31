/*!
 * edkey.js - eddsa keys for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Resources:
 *   https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem
 *   https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41
 */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const base64 = require('./base64');
const sec1 = require('./sec1');
const {leftPad} = require('./util');

/*
 * Constants
 */

const EMPTY = Buffer.alloc(0);

/**
 * EDDSAKey
 */

class EDDSAKey extends bio.Struct {
  constructor() {
    super();
  }

  get ec() {
    return this.constructor.ec;
  }

  get type() {
    return 'eddsa';
  }

  get curve() {
    return this.ec.id;
  }

  get size() {
    return this.ec.size;
  }

  toPoint() {
    return EMPTY;
  }
}

/**
 * EDDSAPublicKey
 */

class EDDSAPublicKey extends EDDSAKey {
  constructor(x) {
    super();
    this.x = leftPad(x, this.size);
  }

  validate() {
    return this.ec.publicKeyVerify(this.toPoint(false));
  }

  verify(msg, sig) {
    return this.ec.verify(msg, sig.encode(), this.toPoint(false));
  }

  setPoint(point) {
    const size = this.size;

    if (!isValidPoint(point, size))
      throw new Error('Invalid point format.');

    if (point.length === 1 + size) {
      const buf = Buffer.allocUnsafe(size);

      for (let i = point.length - 1, j = 0; i >= 1; i--, j++)
        buf[j] = point[i];

      point = buf;
    }

    this.x = point;

    return this;
  }

  setX(x) {
    this.x = leftPad(x, this.size);
    return this;
  }

  toPoint(compress = false) {
    assert(typeof compress === 'boolean');

    const size = this.size;

    assert(this.x.length === size);

    if (compress) {
      const x = this.x;
      const raw = Buffer.allocUnsafe(1 + size);

      raw[0] = 0x40;

      for (let i = x.length - 1, j = 1; i >= 0; i--, j++)
        raw[j] = x[i];

      return raw;
    }

    return this.x;
  }

  fromPoint(point) {
    return this.setPoint(point);
  }

  encode(compress = false) {
    return this.toPoint(compress);
  }

  decode(data) {
    return this.fromPoint(data);
  }

  getJSON() {
    return {
      kty: 'EC',
      crv: toJWKCurve(this.curve),
      x: base64.encodeURL(this.x),
      ext: true
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(json.kty === 'EC');
    assert(fromJWKCurve(json.crv) === this.curve);

    this.x = base64.decodeURL(json.x);

    return this;
  }

  format() {
    return {
      type: this.type,
      curve: this.curve,
      x: this.x.toString('hex')
    };
  }

  static fromPoint(point) {
    return new this().fromPoint(point);
  }
}

/**
 * EDDSAPrivateKey
 */

class EDDSAPrivateKey extends EDDSAKey {
  constructor(d) {
    super();
    this.d = leftPad(d, this.size);
  }

  toSEC1() {
    const point = this.toPoint(true);
    return new sec1.ECPrivateKey(1, this.d, this.curve, point);
  }

  fromSEC1(key) {
    assert(key instanceof sec1.ECPrivateKey);
    assert(key.namedCurveOID.getCurve() === this.curve);

    this.d = leftPad(key.privateKey.value, this.size);

    return this;
  }

  validate() {
    return this.ec.privateKeyVerify(this.d);
  }

  sign(msg) {
    const raw = this.ec.sign(msg, this.d);
    const sig = new this.ec.Signature();
    return sig.decode(raw);
  }

  verify(msg, sig) {
    return this.ec.verify(msg, sig.encode(), this.toPoint(false));
  }

  setD(d) {
    this.d = leftPad(d, this.size);
    return this;
  }

  encode() {
    const key = this.toSEC1();
    return key.encode();
  }

  decode(data) {
    const key = sec1.ECPrivateKey.decode(data);
    return this.fromSEC1(key);
  }

  toPEM() {
    const key = this.toSEC1();
    return key.toPEM();
  }

  fromPEM(str) {
    const key = sec1.ECPrivateKey.fromPEM(str);
    return this.fromSEC1(key);
  }

  toPoint(compress = false) {
    return this.ec.publicKeyCreate(this.d, compress);
  }

  toPublic() {
    const pub = new this.ec.EDDSAPublicKey();
    const point = this.toPoint(false);
    return pub.fromPoint(point);
  }

  getJSON() {
    const pub = this.toPublic();

    return {
      kty: 'EC',
      crv: toJWKCurve(this.curve),
      x: base64.encodeURL(pub.x),
      d: base64.encodeURL(this.d),
      ext: true
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(json.kty === 'EC');
    assert(fromJWKCurve(json.crv) === this.curve);

    this.d = base64.decodeURL(json.d);

    return this;
  }

  format() {
    return {
      type: this.type,
      curve: this.curve,
      d: this.d.toString('hex')
    };
  }

  static fromPEM(str) {
    return new this().fromPEM(str);
  }

  static generate() {
    return this.ec.privateKeyGenerate();
  }
}

/*
 * Helpers
 */

function isValidPoint(point, size) {
  assert(Buffer.isBuffer(point));
  assert((size >>> 0) === size);

  if (point.length === 1 + size)
    return point[0] === 0x40;

  return point.length === size;
}

function toJWKCurve(name) {
  assert(typeof name === 'string');
  switch (name) {
    case 'ed25519':
      return 'ED25519';
    case 'ed448':
      return 'ED448';
    default:
      return name.toUpperCase();
  }
}

function fromJWKCurve(name) {
  assert(typeof name === 'string');
  switch (name) {
    case 'P-192':
      return 'p192';
    case 'P-256':
      return 'p256';
    case 'P-384':
      return 'p384';
    case 'P-521':
      return 'p521';
    default:
      return name.toLowerCase();
  }
}

/*
 * Expose
 */

module.exports = function create(backend) {
  assert(backend);

  return {
    EDDSAKey,
    EDDSAPublicKey: class EDDSAPublicKey_ extends EDDSAPublicKey {
      constructor(x, y) {
        super(x, y);
      }

      static get ec() {
        return backend;
      }
    },
    EDDSAPrivateKey: class EDDSAPrivateKey_ extends EDDSAPrivateKey {
      constructor(d) {
        super(d);
      }

      static get ec() {
        return backend;
      }
    }
  };
};
