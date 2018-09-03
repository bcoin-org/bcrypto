/*!
 * eckey.js - ecdsa keys for javascript
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
const sec1 = require('../encoding/sec1');
const {leftPad} = require('./util');

/*
 * Constants
 */

const EMPTY = Buffer.alloc(0);

/**
 * ECKey
 */

class ECKey extends bio.Struct {
  constructor() {
    super();
  }

  get ec() {
    return this.constructor.ec;
  }

  get type() {
    return 'ecdsa';
  }

  get curve() {
    return this.ec.id;
  }

  get size() {
    return this.ec.size;
  }
}

/**
 * ECPublicKey
 */

class ECPublicKey extends ECKey {
  constructor(x, y) {
    super();
    this.x = leftPad(x, this.size);
    this.y = leftPad(y, this.size);
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

    if (point[0] < 4)
      point = this.ec.publicKeyConvert(point, false);

    this.x = point.slice(1, 1 + size);
    this.y = point.slice(1 + size, 1 + size * 2);

    return this;
  }

  setX(x) {
    this.x = leftPad(x, this.size);
    return this;
  }

  setY(y) {
    this.y = leftPad(y, this.size);
    return this;
  }

  tweakAdd(tweak) {
    const point = this.toPoint(false);
    const p = this.ec.publicKeyTweakAdd(point, tweak, false);
    return this.ec.PublicKey.fromPoint(p);
  }

  toPoint(compress = true) {
    assert(typeof compress === 'boolean');

    const size = this.size;

    assert(this.x.length === size && this.y.length === size);

    if (compress) {
      const raw = Buffer.allocUnsafe(1 + size);

      raw[0] = 0x02 + (this.y[size - 1] & 1);

      this.x.copy(raw, 1, 0, size);

      return raw;
    }

    const raw = Buffer.allocUnsafe(1 + size * 2);

    raw[0] = 0x04;

    this.x.copy(raw, 1, 0, size);
    this.y.copy(raw, 1 + size, 0, size);

    return raw;
  }

  fromPoint(point) {
    return this.setPoint(point);
  }

  fromX(x, odd) {
    assert(Buffer.isBuffer(x));
    assert(typeof odd === 'boolean');

    const size = this.size;
    const raw = leftPad(x, 1 + size);

    assert(raw[0] === 0x00);

    raw[0] = 0x02 + (odd ? 1 : 0);

    const point = this.ec.publicKeyConvert(raw, false);

    this.x = point.slice(1, 1 + size);
    this.y = point.slice(1 + size, 1 + size * 2);

    return this;
  }

  encode(compress = true) {
    return this.toPoint(compress);
  }

  decode(data) {
    return this.fromPoint(data);
  }

  toXY() {
    return this.toPoint(false).slice(1);
  }

  fromXY(data) {
    const size = this.size;

    assert(Buffer.isBuffer(data));
    assert(data.length === size * 2);

    this.x = data.slice(0, size);
    this.y = data.slize(size, size * 2);

    return this;
  }

  toDNS() {
    return this.toXY();
  }

  fromDNS(data) {
    return this.fromXY(data);
  }

  getJSON() {
    return {
      kty: 'EC',
      crv: toJWKCurve(this.curve),
      x: base64.encodeURL(this.x),
      y: base64.encodeURL(this.y),
      ext: true
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(json.kty === 'EC');
    assert(fromJWKCurve(json.crv) === this.curve);

    this.x = base64.decodeURL(json.x);
    this.y = base64.decodeURL(json.y);

    return this;
  }

  format() {
    return {
      type: this.type,
      curve: this.curve,
      x: this.x.toString('hex'),
      y: this.y.toString('hex')
    };
  }

  static fromPoint(point) {
    return new this().fromPoint(point);
  }

  static fromX(data, odd) {
    return new this().fromX(data, odd);
  }

  static fromXY(data) {
    return new this().fromXY(data);
  }

  static fromDNS(data) {
    return new this().fromDNS(data);
  }

  static recover(msg, sig) {
    assert(sig instanceof this.ec.Signature);

    const point = this.ec.recover(msg, sig.encode(), sig.param, false);

    if (!point)
      throw new Error('Could not recover key.');

    return this.fromPoint(point);
  }
}

/**
 * ECPrivateKey
 */

class ECPrivateKey extends ECKey {
  constructor(key) {
    super();
    this.key = leftPad(key, this.size);
  }

  toSEC1() {
    const point = this.toPoint(true);
    return new sec1.ECPrivateKey(1, this.key, this.curve, point);
  }

  fromSEC1(key) {
    assert(key instanceof sec1.ECPrivateKey);
    assert(key.namedCurveOID.getCurve() === this.curve);

    this.key = leftPad(key.privateKey.value, this.size);

    return this;
  }

  validate() {
    return this.ec.privateKeyVerify(this.key);
  }

  sign(msg) {
    const {r, s, param} = this.ec._sign(msg, this.key);
    const sig = new this.ec.Signature();
    sig.r = r;
    sig.s = s;
    sig.param = param;
    return sig;
  }

  verify(msg, sig) {
    assert(sig instanceof this.ec.Signature);

    return this.ec.verify(msg, sig.encode(), this.toPoint(false));
  }

  setKey(key) {
    this.key = leftPad(key, this.size);
    return this;
  }

  tweakAdd(tweak) {
    const key = this.ec.privateKeyTweakAdd(this.key, tweak);
    return new this.ec.PrivateKey(key);
  }

  derive(pub) {
    assert(pub instanceof this.ec.PublicKey);

    const raw = this.ec.ecdh(
      pub.toPoint(false),
      this.key,
      false
    );

    return this.ec.PublicKey.fromPoint(raw);
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

  toPoint(compress = true) {
    return this.ec.publicKeyCreate(this.key, compress);
  }

  toPublic() {
    const pub = new this.ec.PublicKey();
    const point = this.toPoint(false);
    return pub.fromPoint(point);
  }

  getJSON() {
    const pub = this.toPublic();

    return {
      kty: 'EC',
      crv: toJWKCurve(this.curve),
      x: base64.encodeURL(pub.x),
      y: base64.encodeURL(pub.y),
      d: base64.encodeURL(this.key),
      ext: true
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(json.kty === 'EC');
    assert(fromJWKCurve(json.crv) === this.curve);

    this.key = base64.decodeURL(json.d);

    return this;
  }

  format() {
    return {
      type: this.type,
      curve: this.curve,
      key: this.key.toString('hex')
    };
  }

  static fromPEM(str) {
    return new this().fromPEM(str);
  }

  static generate() {
    const raw = this.ec.privateKeyGenerate();
    return new this.ec.PrivateKey(raw);
  }
}

/*
 * Helpers
 */

function isValidPoint(point, size) {
  assert(Buffer.isBuffer(point));
  assert((size >>> 0) === size);

  if (point.length < 2)
    return false;

  switch (point[0]) {
    case 0x02:
    case 0x03:
      return point.length === 1 + size;
    case 0x04:
      return point.length === 1 + size * 2;
    case 0x06:
    case 0x07:
      return point.length === 1 + size * 2
          && (point[0] & 1) === (point[point.length - 1] & 1);
    default:
      return false;
  }
}

function toJWKCurve(name) {
  assert(typeof name === 'string');
  switch (name) {
    case 'p192':
      return 'P-192';
    case 'p256':
      return 'P-256';
    case 'p384':
      return 'P-384';
    case 'p521':
      return 'P-521';
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
    ECKey,
    ECPublicKey: class ECPublicKey_ extends ECPublicKey {
      constructor(x, y) {
        super(x, y);
      }

      static get ec() {
        return backend;
      }
    },
    ECPrivateKey: class ECPrivateKey_ extends ECPrivateKey {
      constructor(key) {
        super(key);
      }

      static get ec() {
        return backend;
      }
    }
  };
};
