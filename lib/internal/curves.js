/*!
 * curves.js - elliptic curve definitions
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const curves = {
  P192: {
    id: 'P192',
    ossl: 'prime192v1',
    oid: '2a8648ce3d030101',
    edwards: false,
    bits: 192,
    size: 24,
    order: 'ffffffffffffffffffffffff99def836146bc9b1b4d22831',
    half: '7fffffffffffffffffffffffccef7c1b0a35e4d8da691418'
  },
  P224: {
    id: 'P224',
    oid: '2b81040021',
    ossl: 'secp224r1',
    edwards: false,
    bits: 224,
    size: 28,
    order: 'ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d',
    half: '7fffffffffffffffffffffffffff8b51705c781f09ee94a2ae2e151e'
  },
  P256: {
    id: 'P256',
    ossl: 'prime256v1',
    oid: '2a8648ce3d030107',
    edwards: false,
    bits: 256,
    size: 32,
    order: 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
    half: '7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8'
  },
  P384: {
    id: 'P384',
    ossl: 'secp384r1',
    oid: '2b81040022',
    edwards: false,
    bits: 384,
    size: 48,
    order: ''
      + 'ffffffffffffffffffffffffffffffffffffffffffffffff'
      + 'c7634d81f4372ddf581a0db248b0a77aecec196accc52973',
    half: ''
      + '7fffffffffffffffffffffffffffffffffffffffffffffff'
      + 'e3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294b9'
  },
  P521: {
    id: 'P521',
    ossl: 'secp521r1',
    oid: '2b81040023',
    edwards: false,
    bits: 521,
    size: 66,
    order: ''
      + '01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
      + 'a51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409',
    half: ''
      + '00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
      + 'd28c343c1df97cb35bfe600a47b84d2e81ddae4dc44ce23d75db7db8f489c3204'
  },
  SECP256K1: {
    id: 'SECP256K1',
    ossl: 'secp256k1',
    oid: '2b8104000a',
    edwards: false,
    bits: 256,
    size: 32,
    order: 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
    half: '7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0'
  },
  CURVE25519: {
    id: 'CURVE25519',
    ossl: 'X25519',
    oid: '2b656e',
    edwards: false,
    bits: 253,
    size: 32,
    order: '1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed',
    half: '080000000000000000000000000000000a6f7cef517bce6b2c09318d2e7ae9f6'
  },
  CURVE448: {
    id: 'CURVE448',
    ossl: 'X448',
    oid: '2b656f',
    edwards: false,
    bits: 448,
    size: 56,
    order: ''
      + '3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9'
      + 'c44edb49aed63690216cc2728dc58f552378c292ab5844f3',
    half: ''
      + '1fffffffffffffffffffffffffffffffffffffffffffffffffffffffbe6511f4'
      + 'e2276da4d76b1b4810b6613946e2c7aa91bc614955ac2279'
  },
  ED25519: {
    id: 'ED25519',
    ossl: 'ED25519',
    oid: '2b6570',
    edwards: true,
    bits: 253,
    size: 32,
    order: '1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed',
    half: '080000000000000000000000000000000a6f7cef517bce6b2c09318d2e7ae9f6'
  },
  ED448: {
    id: 'ED448',
    ossl: 'ED448',
    oid: '2b6571',
    edwards: true,
    bits: 448,
    size: 56,
    order: ''
      + '3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9'
      + 'c44edb49aed63690216cc2728dc58f552378c292ab5844f3',
    half: ''
      + '1fffffffffffffffffffffffffffffffffffffffffffffffffffffffbe6511f4'
      + 'e2276da4d76b1b4810b6613946e2c7aa91bc614955ac2279'
  }
};

/*
 * Expose
 */

module.exports = curves;
