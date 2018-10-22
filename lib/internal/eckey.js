'use strict';

const assert = require('bsert');
const base64 = require('../internal/base64');

/*
 * JWK
 */

exports.privateKeyExportJWK = function privateKeyExportJWK(curve, key) {
  assert(curve && typeof curve.publicKeyCreate === 'function');

  const pub = curve.publicKeyCreate(key, false);
  const json = exports.publicKeyExportJWK(curve, pub);

  return {
    kty: 'EC',
    crv: json.crv,
    x: json.x,
    y: json.y,
    d: base64.encodeURL(key),
    ext: true
  };
};

exports.privateKeyImportJWK = function privateKeyImportJWK(curve, json) {
  assert(curve && typeof curve.privateKeyVerify === 'function');
  assert(json && typeof json === 'object');
  assert(json.kty === 'EC');
  assert(json.crv == null || fromCurve(json.crv) === curve.id);

  const key = base64.decodeURL(json.d);

  if (!curve.privateKeyVerify(key))
    throw new Error('Invalid private key.');

  return key;
};

exports.publicKeyExportJWK = function publicKeyExportJWK(curve, key) {
  assert(curve && typeof curve.publicKeyExport === 'function');

  const pub = curve.publicKeyExport(key);
  const x = pub.slice(0, curve.size);
  const y = pub.slice(curve.size, curve.size * 2);

  return {
    kty: 'EC',
    crv: toCurve(curve.id),
    x: base64.encodeURL(x),
    y: base64.encodeURL(y),
    ext: true
  };
};

exports.publicKeyImportJWK = function publicKeyImportJWK(curve, json, compress) {
  assert(curve && typeof curve.publicKeyImport === 'function');
  assert(json && typeof json === 'object');
  assert(json.kty === 'EC');
  assert(json.crv == null || fromCurve(json.crv) === curve.id);

  const x = base64.decodeURL(json.x);
  const y = base64.decodeURL(json.y);

  assert(x.length === curve.size);
  assert(y.length === curve.size);

  const pub = Buffer.concat([x, y]);

  return curve.publicKeyImport(pub, compress);
};

/*
 * Helpers
 */

function toCurve(id) {
  assert(typeof id === 'string');

  switch (id) {
    case 'P192':
      return 'P-192';
    case 'P224':
      return 'P-224';
    case 'P256':
      return 'P-256';
    case 'P384':
      return 'P-384';
    case 'P521':
      return 'P-521';
    default:
      return id;
  }
}

function fromCurve(crv, id) {
  assert(typeof crv === 'string');

  switch (crv) {
    case 'P-192':
      return 'P192';
    case 'P-224':
      return 'P224';
    case 'P-256':
      return 'P256';
    case 'P-384':
      return 'P384';
    case 'P-521':
      return 'P521';
    default:
      return crv;
  }
}
