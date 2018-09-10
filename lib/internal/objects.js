/*!
 * objects.js - OIDs encoding for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://www.ietf.org/rfc/rfc2459.txt
 *   https://tools.ietf.org/html/rfc3279
 *   http://oid-info.com/get/1.2.840.10040.4
 *   http://oid-info.com/get/1.2.840.113549.1.1
 *   http://oid-info.com/get/1.2.840.10045.4.3
 *   https://tools.ietf.org/html/draft-jivsov-openpgp-sha3-01
 *   https://github.com/golang/go/blob/master/src/crypto/x509/x509.go
 *   https://tools.ietf.org/html/draft-josefsson-pkix-eddsa-01
 *   https://tools.ietf.org/html/rfc5480
 *   https://tools.ietf.org/html/draft-josefsson-pkix-newcurves-00
 *   https://tools.ietf.org/id/draft-ietf-curdle-pkix-06.html
 *   https://tools.ietf.org/html/rfc7693
 */

'use strict';

const oidToSig = {
  '1.2.840.10040.4.3'        : { key: 'dsa',    hash: 'sha1'     },
  '1.2.840.113549.1.1.2'     : { key: 'rsa',    hash: 'md2'      },
  '1.2.840.113549.1.1.3'     : { key: 'rsa',    hash: 'md4'      },
  '1.2.840.113549.1.1.4'     : { key: 'rsa',    hash: 'md5'      },
  '1.2.840.113549.1.1.5'     : { key: 'rsa',    hash: 'sha1'     },
  '1.2.840.113549.1.1.10'    : { key: 'rsapss', hash: 'mgf1'     },
  '1.2.840.113549.1.1.11'    : { key: 'rsa',    hash: 'sha256'   },
  '1.2.840.113549.1.1.12'    : { key: 'rsa',    hash: 'sha384'   },
  '1.2.840.113549.1.1.13'    : { key: 'rsa',    hash: 'sha512'   },
  '1.2.840.113549.1.1.14'    : { key: 'rsa',    hash: 'sha224'   },
  '2.16.840.1.101.3.4.2.8'   : { key: 'rsa',    hash: 'sha3-256' },
  '2.16.840.1.101.3.4.2.9'   : { key: 'rsa',    hash: 'sha3-384' },
  '2.16.840.1.101.3.4.2.10'  : { key: 'rsa',    hash: 'sha3-512' },
  '1.3.14.3.2.29'            : { key: 'rsa',    hash: 'sha1'     },
  '1.2.840.10045.4.1'        : { key: 'ecdsa',  hash: 'sha1'     },
  '1.2.840.10045.4.3.1'      : { key: 'ecdsa',  hash: 'sha224'   },
  '1.2.840.10045.4.3.2'      : { key: 'ecdsa',  hash: 'sha256'   },
  '1.2.840.10045.4.3.3'      : { key: 'ecdsa',  hash: 'sha384'   },
  '1.2.840.10045.4.3.4'      : { key: 'ecdsa',  hash: 'sha512'   },
  '1.3.6.1.4.1.11591.4.12.2' : { key: 'eddsa',  hash: null       }
};

const keyOid = {
  dsa: '1.2.840.10040.4.1',
  rsa: '1.2.840.113549.1.1.1',
  ecdsa: '1.2.840.10045.2.1',
  eddsa: '1.3.6.1.4.1.11591.4.12.1'
};

const oidToKey = {
  '1.2.840.10040.4.1': 'dsa',
  '1.2.840.10040.4.2': 'dsa',
  '1.2.840.113549.1.1.1': 'rsa',
  '1.2.840.10045.2.1': 'ecdsa',
  '1.3.6.1.4.1.11591.4.12.1': 'eddsa'
};

const hashOid = {
  md5: '1.2.840.113549.2.5',
  sha1: '1.3.14.3.2.26',
  ripemd160: '1.0.10118.3.0.49',
  mgf1: '1.2.840.113549.1.1.8',
  sha224: '2.16.840.1.101.3.4.2.4',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
  'sha3-224': '2.16.840.1.101.3.4.2.7',
  'sha3-256': '2.16.840.1.101.3.4.2.8',
  'sha3-384': '2.16.840.1.101.3.4.2.9',
  'sha3-512': '2.16.840.1.101.3.4.2.10',
  blake2b160: '1.3.6.1.4.1.1722.12.2.1.5',
  blake2b256: '1.3.6.1.4.1.1722.12.2.1.8',
  blake2b384: '1.3.6.1.4.1.1722.12.2.1.12',
  blake2b512: '1.3.6.1.4.1.1722.12.2.1.16',
  blake2s128: '1.3.6.1.4.1.1722.12.2.2.4',
  blake2s160: '1.3.6.1.4.1.1722.12.2.2.5',
  blake2s224: '1.3.6.1.4.1.1722.12.2.2.7',
  blake2s256: '1.3.6.1.4.1.1722.12.2.2.8'
};

const oidToHash = {
  '1.2.840.113549.2.5': 'md5',
  '1.3.14.3.2.26': 'sha1',
  '1.3.36.3.2.1': 'ripemd160',
  '1.0.10118.3.0.49': 'ripemd160',
  '1.2.840.113549.1.1.8': 'mgf1',
  '2.16.840.1.101.3.4.2.4': 'sha224',
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
  '2.16.840.1.101.3.4.2.7': 'sha3-224',
  '2.16.840.1.101.3.4.2.8': 'sha3-256',
  '2.16.840.1.101.3.4.2.9': 'sha3-384',
  '2.16.840.1.101.3.4.2.10': 'sha3-512',
  '1.3.6.1.4.1.1722.12.2.1.5': 'blake2b160',
  '1.3.6.1.4.1.1722.12.2.1.8': 'blake2b256',
  '1.3.6.1.4.1.1722.12.2.1.12': 'blake2b384',
  '1.3.6.1.4.1.1722.12.2.1.16': 'blake2b512',
  '1.3.6.1.4.1.1722.12.2.2.4': 'blake2s128',
  '1.3.6.1.4.1.1722.12.2.2.5': 'blake2s160',
  '1.3.6.1.4.1.1722.12.2.2.7': 'blake2s224',
  '1.3.6.1.4.1.1722.12.2.2.8': 'blake2s256'
};

const curveOid = {
  p192: '1.2.840.10045.3.1.1',
  p224: '1.3.132.0.33',
  p256: '1.2.840.10045.3.1.7',
  p384: '1.3.132.0.34',
  p521: '1.3.132.0.35',
  secp256k1: '1.3.132.0.10',
  curve25519: '1.3.101.110',
  curve448: '1.3.101.111',
  ed25519: '1.3.101.112',
  ed448: '1.3.101.113'
};

const oidToCurve = {
  '1.2.840.10045.3.1.1': 'p192',
  '1.3.132.0.33': 'p224',
  '1.2.840.10045.3.1.7': 'p256',
  '1.3.132.0.34': 'p384',
  '1.3.132.0.35': 'p521',
  '1.3.132.0.10': 'secp256k1',
  '1.3.6.1.4.1.11591.7': 'curve25519',
  '1.3.6.1.4.1.11591.8': 'curve448',
  '1.3.101.110': 'curve25519',
  '1.3.101.111': 'curve448',
  '1.3.101.112': 'ed25519',
  '1.3.101.113': 'ed448'
};

/*
 * Expose
 */

exports.oidToSig = oidToSig;
exports.keyOid = keyOid;
exports.oidToKey = oidToKey;
exports.hashOid = hashOid;
exports.oidToHash = oidToHash;
exports.curveOid = curveOid;
exports.oidToCurve = oidToCurve;
