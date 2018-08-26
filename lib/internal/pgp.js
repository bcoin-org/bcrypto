/*!
 * pgp.js - PGP for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Parts of this software are based on golang/crypto:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/crypto
 *
 * Resources:
 *   https://github.com/golang/crypto/tree/master/openpgp
 *   https://github.com/gpg/gnupg/blob/master/common/openpgpdefs.h
 *   https://github.com/gpg/gnupg/blob/master/g10/parse-packet.c
 */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const {PEMBlock} = require('./pem');
const {trimZeroes, countBits} = require('./util');
const MD5 = require('../md5');
const SHA1 = require('../sha1');
const RIPEMD160 = require('../ripemd160');
const SHA224 = require('../sha224');
const SHA256 = require('../sha256');
const SHA384 = require('../sha384');
const SHA512 = require('../sha512');

/*
 * Constants
 */

const packetTypes = {
  ENCRYPTED_KEY: 1,
  SIGNATURE: 2,
  SYMMETRIC_KEY_ENCRYPTED: 3,
  ONE_PASS_SIGNATURE: 4,
  PRIVATE_KEY: 5,
  PUBLIC_KEY: 6,
  PRIVATE_SUBKEY: 7,
  COMPRESSED: 8,
  SYMMETRICALLY_ENCRYPTED: 9,
  MARKER: 10,
  LITERAL_DATA: 11,
  RING_TRUST: 12,
  USER_ID: 13,
  PUBLIC_SUBKEY: 14,
  OLD_COMMENT: 16,
  USER_ATTRIBUTE: 17,
  SYMMETRICALLY_ENCRYPTED_MDC: 18,
  MDC: 19,
  ENCRYPTED_AEAD: 20
};

const packetTypesByVal = {
  1: 'ENCRYPTED_KEY',
  2: 'SIGNATURE',
  3: 'SYMMETRIC_KEY_ENCRYPTED',
  4: 'ONE_PASS_SIGNATURE',
  5: 'PRIVATE_KEY',
  6: 'PUBLIC_KEY',
  7: 'PRIVATE_SUBKEY',
  8: 'COMPRESSED',
  9: 'SYMMETRICALLY_ENCRYPTED',
  10: 'MARKER',
  11: 'LITERAL_DATA',
  12: 'RING_TRUST',
  13: 'USER_ID',
  14: 'PUBLIC_SUBKEY',
  16: 'OLD_COMMENT',
  17: 'USER_ATTRIBUTE',
  18: 'SYMMETRICALLY_ENCRYPTED_MDC',
  19: 'MDC',
  20: 'ENCRYPTED_AEAD'
};

const sigTypes = {
  BINARY: 0x00,
  TEXT: 0x01,
  GENERIC_CERT: 0x10,
  PERSONA_CERT: 0x11,
  CASUAL_CERT: 0x12,
  POSITIVE_CERT: 0x13,
  SUBKEY_BINDING: 0x18,
  PRIMARY_KEY_BINDING: 0x19,
  DIRECT_SIGNATURE: 0x1f,
  KEY_REVOCATION: 0x20,
  SUBKEY_REVOCATION: 0x28
};

const sigTypesByVal = {
  0x00: 'BINARY',
  0x01: 'TEXT',
  0x10: 'GENERIC_CERT',
  0x11: 'PERSONA_CERT',
  0x12: 'CASUAL_CERT',
  0x13: 'POSITIVE_CERT',
  0x18: 'SUBKEY_BINDING',
  0x19: 'PRIMARY_KEY_BINDING',
  0x1f: 'DIRECT_SIGNATURE',
  0x20: 'KEY_REVOCATION',
  0x28: 'SUBKEY_REVOCATION'
};

const keyTypes = {
  RSA: 1,
  RSA_ENCRYPT_ONLY: 2,
  RSA_SIGN_ONLY: 3,
  ELGAMAL: 16,
  DSA: 17,
  ECDH: 18,
  ECDSA: 19,
  ELGAMAL_LEGACY: 20,
  EDDSA: 22
};

const keyTypesByVal = {
  1: 'RSA',
  2: 'RSA_ENCRYPT_ONLY',
  3: 'RSA_SIGN_ONLY',
  16: 'ELGAMAL',
  17: 'DSA',
  18: 'ECDH',
  19: 'ECDSA',
  20: 'ELGAMAL_LEGACY',
  22: 'EDDSA'
};

const cipherTypes = {
  NONE: 0,
  IDEA: 1,
  DES3: 2,
  CAST5: 3,
  BLOWFISH: 4,
  AES128: 7,
  AES192: 8,
  AES256: 9,
  TWOFISH: 10,
  CAMELLIA128: 11,
  CAMELLIA192: 12,
  CAMELLIA256: 13
};

const cipherTypesByVal = {
  0: 'NONE',
  1: 'IDEA',
  2: 'DES3',
  3: 'CAST5',
  4: 'BLOWFISH',
  7: 'AES128',
  8: 'AES192',
  9: 'AES256',
  10: 'TWOFISH',
  11: 'CAMELLIA128',
  12: 'CAMELLIA192',
  13: 'CAMELLIA256'
};

const hashTypes = {
  MD5: 1,
  SHA1: 2,
  RIPEMD160: 3,
  SHA256: 8,
  SHA384: 9,
  SHA512: 10,
  SHA224: 11
};

const hashTypesByVal = {
  1: 'MD5',
  2: 'SHA1',
  3: 'RIPEMD160',
  8: 'SHA256',
  9: 'SHA384',
  10: 'SHA512',
  11: 'SHA224'
};

const hashToHash = {
  1: MD5,
  2: SHA1,
  3: RIPEMD160,
  8: SHA256,
  9: SHA384,
  10: SHA512,
  11: SHA224
};

const compressTypes = {
  NONE: 0,
  ZIP: 1,
  ZLIB: 2,
  BZIP2: 3
};

const compressTypesByVal = {
  0: 'NONE',
  1: 'ZIP',
  2: 'ZLIB',
  3: 'BZIP2'
};

const curveTypes = {
  NONE: 0,
  P256: 1,
  P384: 2,
  P521: 3,
  SECP256K1: 4,
  CURVE25519: 5,
  BRAINPOOLP256: 6,
  BRAINPOOLP384: 7,
  BRAINPOOLP521: 8,
  ED25519: 9
};

const curveTypesByVal = {
  0: 'NONE',
  1: 'P256',
  2: 'P384',
  3: 'P521',
  4: 'SECP256K1',
  5: 'CURVE25519',
  6: 'BRAINPOOLP256',
  7: 'BRAINPOOLP384',
  8: 'BRAINPOOLP521',
  9: 'ED25519'
};

const oids = {
  P256: Buffer.from('2a8648ce3d030107', 'hex'),
  P384: Buffer.from('2b81040022', 'hex'),
  P521: Buffer.from('2b81040023', 'hex'),
  SECP256K1: Buffer.from('2b8104000a', 'hex'),
  CURVE25519: Buffer.from('2b060104019755010501', 'hex'),
  BRAINPOOLP256: Buffer.from('2b2403030208010107', 'hex'),
  BRAINPOOLP384: Buffer.from('2b240303020801010b', 'hex'),
  BRAINPOOLP521: Buffer.from('2b240303020801010d', 'hex'),
  ED25519: Buffer.from('2b06010401da470f01', 'hex')
};

const DUMMY = Buffer.alloc(0);
const ZERO = Buffer.alloc(1);

/**
 * PGP Message
 */

class PGPMessage extends bio.Struct {
  constructor() {
    super();
    this.packets = [];
  }

  getSize() {
    let size = 0;

    for (const pkt of this.packets)
      size += pkt.getSize();

    return size;
  }

  write(bw) {
    for (const pkt of this.packets)
      pkt.write(bw);

    return bw;
  }

  read(br) {
    while (br.left()) {
      const pkt = PGPPacket.read(br);
      this.packets.push(pkt);
    }

    return this;
  }

  toString(type = 'PGP MESSAGE') {
    assert(typeof type === 'string');

    const block = new PEMBlock();

    block.type = type;
    block.data = this.encode();

    return block.toString(true);
  }

  fromString(str) {
    const block = PEMBlock.fromString(str, true);

    if (block.type.substring(0, 4) !== 'PGP ')
      throw new Error('PEM type mismatch.');

    return this.decode(block.data);
  }

  format() {
    return {
      packets: this.packets
    };
  }
}

/**
 * PGP Packet
 */

class PGPPacket extends bio.Struct {
  constructor() {
    super();
    this.type = 0;
    this.body = new PGPUnknown();
  }

  getSize() {
    const len = this.body.getSize();

    let size = 0;

    size += 1;

    if (len < 192) {
      size += 1;
    } else if (len < 8384) {
      size += 2;
    } else {
      size += 5;
    }

    size += len;

    return size;
  }

  write(bw) {
    let len = this.body.getSize();

    bw.writeU8(0x80 | 0x40 | this.type);

    if (len < 192) {
      bw.writeU8(len);
    } else if (len < 8384) {
      len -= 192;
      bw.writeU8(192 + (len >>> 8));
      bw.writeU8(len & 0xff);
    } else {
      bw.writeU8(255);
      bw.writeU32BE(len);
    }

    this.body.write(bw);

    return bw;
  }

  read(br) {
    const ch = br.readU8();

    if ((ch & 0x80) === 0)
      throw new Error('Hi bit unset in PGP packet header.');

    let type = 0;
    let child = null;

    if ((ch & 0x40) === 0) {
      const t = (ch & 0x3f) >>> 2;
      const s = 1 << (ch & 3);

      let size = 0;

      switch (s) {
        case 1:
          size = br.readU8();
          break;
        case 2:
          size = br.readU16BE();
          break;
        case 4:
          size = br.readU32BE();
          break;
        case 8:
          size = br.left();
          break;
      }

      type = t;
      child = br.readChild(size);
    } else {
      const t = ch & 0x3f;
      const s = br.readU8();

      let size = 0;

      if (s < 192) {
        size = s;
      } else if (s < 224) {
        size = (s - 192) * 0x100;
        size += br.readU8() + 192;
      } else if (s < 255) {
        throw new Error('Cannot handle PGP partial length.');
      } else {
        size = br.readU32BE();
      }

      type = t;
      child = br.readChild(size);
    }

    this.type = type;

    switch (this.type) {
      case packetTypes.ENCRYPTED_KEY:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.SIGNATURE:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.SYMMETRIC_KEY_ENCRYPTED:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.ONE_PASS_SIGNATURE:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.PRIVATE_KEY:
        this.body = PGPPrivateKey.read(child);
        break;
      case packetTypes.PUBLIC_KEY:
        this.body = PGPPublicKey.read(child);
        break;
      case packetTypes.PRIVATE_SUBKEY:
        this.body = PGPPrivateKey.read(child);
        break;
      case packetTypes.COMPRESSED:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.SYMMETRICALLY_ENCRYPTED:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.MARKER:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.LITERAL_DATA:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.RING_TRUST:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.USER_ID:
        this.body = PGPUserID.read(child);
        break;
      case packetTypes.PUBLIC_SUBKEY:
        this.body = PGPPublicKey.read(child);
        break;
      case packetTypes.OLD_COMMENT:
        this.body = PGPPublicKey.read(child);
        break;
      case packetTypes.USER_ATTRIBUTE:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.SYMMETRICALLY_ENCRYPTED_MDC:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.MDC:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.ENCRYPTED_AEAD:
        this.body = PGPUnknown.read(child);
        break;
      default:
        this.body = PGPUnknown.read(child);
        break;
    }

    return this;
  }

  format() {
    return {
      type: packetTypesByVal[this.type] || 'UNKNOWN',
      body: this.body
    };
  }
}

/**
 * PGP Body
 */

class PGPBody extends bio.Struct {
  constructor() {
    super();
  }
}

/**
 * PGP Unknown
 */

class PGPUnknown extends PGPBody {
  constructor() {
    super();
    this.data = DUMMY;
  }

  getSize() {
    return this.data.length;
  }

  write(bw) {
    bw.writeBytes(this.data);
    return bw;
  }

  read(br) {
    this.data = br.readBytes(br.left());
    return this;
  }

  format() {
    return {
      data: this.data.toString('hex')
    };
  }
}

/**
 * PGP Public Key
 */

class PGPPublicKey extends PGPBody {
  constructor() {
    super();

    this.algorithm = 0;
    this.timestamp = 0;

    // RSA
    this.n = DUMMY;
    this.e = DUMMY;

    // El Gamal
    this.p = DUMMY;
    this.g = DUMMY;
    this.y = DUMMY;

    // DSA
    // this.p = DUMMY;
    this.q = DUMMY;
    // this.g = DUMMY;
    // this.y = DUMMY;

    // ECDH
    this.oid = DUMMY;
    this.point = DUMMY;
    this.kdfHash = 0;
    this.kdfAlg = 0;

    // ECDSA
    // this.oid = DUMMY;
    // this.point = DUMMY;

    // Unknown
    this.data = DUMMY;
  }

  get curve() {
    if (this.oid.equals(oids.P256))
      return curveTypes.P256;

    if (this.oid.equals(oids.P384))
      return curveTypes.P384;

    if (this.oid.equals(oids.P521))
      return curveTypes.P521;

    if (this.oid.equals(oids.SECP256K1))
      return curveTypes.SECP256K1;

    if (this.oid.equals(oids.CURVE25519))
      return curveTypes.CURVE25519;

    if (this.oid.equals(oids.BRAINPOOLP256))
      return curveTypes.BRAINPOOLP256;

    if (this.oid.equals(oids.BRAINPOOLP384))
      return curveTypes.BRAINPOOLP384;

    if (this.oid.equals(oids.BRAINPOOLP521))
      return curveTypes.BRAINPOOLP521;

    if (this.oid.equals(oids.ED25519))
      return curveTypes.ED25519;

    return 0;
  }

  set curve(value) {
    switch (value) {
      case curveTypes.P256:
        this.oid = oids.P256;
        break;
      case curveTypes.P384:
        this.oid = oids.P384;
        break;
      case curveTypes.P521:
        this.oid = oids.P521;
        break;
      case curveTypes.SECP256K1:
        this.oid = oids.SECP256K1;
        break;
      case curveTypes.CURVE25519:
        this.oid = oids.CURVE25519;
        break;
      case curveTypes.BRAINPOOLP256:
        this.oid = oids.BRAINPOOLP256;
        break;
      case curveTypes.BRAINPOOLP384:
        this.oid = oids.BRAINPOOLP384;
        break;
      case curveTypes.BRAINPOOLP521:
        this.oid = oids.BRAINPOOLP521;
        break;
      case curveTypes.ED25519:
        this.oid = oids.ED25519;
        break;
    }
  }

  getSize() {
    let size = 0;

    size += 1;
    size += 4;
    size += 1;

    switch (this.algorithm) {
      case keyTypes.RSA:
      case keyTypes.RSA_ENCRYPT_ONLY:
      case keyTypes.RSA_SIGN_ONLY: {
        size += sizeMPI(this.n);
        size += sizeMPI(this.e);
        break;
      }

      case keyTypes.ELGAMAL: {
        size += sizeMPI(this.p);
        size += sizeMPI(this.g);
        size += sizeMPI(this.y);
        break;
      }

      case keyTypes.DSA: {
        size += sizeMPI(this.p);
        size += sizeMPI(this.q);
        size += sizeMPI(this.g);
        size += sizeMPI(this.y);
        break;
      }

      case keyTypes.ECDH: {
        size += 1;
        size += this.oid.length;
        size += sizeMPI(this.point);
        size += 4;
        break;
      }

      case keyTypes.ECDSA:
      case keyTypes.EDDSA: {
        size += 1;
        size += this.oid.length;
        size += sizeMPI(this.point);
        break;
      }

      default: {
        size += this.data.length;
        break;
      }
    }

    return size;
  }

  write(bw) {
    bw.writeU8(4);
    bw.writeU32BE(this.timestamp);
    bw.writeU8(this.algorithm);

    switch (this.algorithm) {
      case keyTypes.RSA:
      case keyTypes.RSA_ENCRYPT_ONLY:
      case keyTypes.RSA_SIGN_ONLY: {
        writeMPI(bw, this.n);
        writeMPI(bw, this.e);
        break;
      }

      case keyTypes.ELGAMAL: {
        writeMPI(bw, this.p);
        writeMPI(bw, this.g);
        writeMPI(bw, this.y);
        break;
      }

      case keyTypes.DSA: {
        writeMPI(bw, this.p);
        writeMPI(bw, this.q);
        writeMPI(bw, this.g);
        writeMPI(bw, this.y);
        break;
      }

      case keyTypes.ECDH: {
        bw.writeU8(this.oid.length);
        bw.writeBytes(this.oid);
        writeMPI(bw, this.point);
        bw.writeU8(3);
        bw.writeU8(0x01);
        bw.writeU8(this.kdfHash);
        bw.writeU8(this.kdfAlg);
        break;
      }

      case keyTypes.ECDSA:
      case keyTypes.EDDSA: {
        bw.writeU8(this.oid.length);
        bw.writeBytes(this.oid);
        writeMPI(bw, this.point);
        break;
      }

      default: {
        bw.writeBytes(this.data);
        break;
      }
    }

    return bw;
  }

  read(br) {
    const version = br.readU8();

    switch (version) {
      case 2:
      case 3: {
        this.timestamp = br.readU32BE();

        br.readU16BE();

        this.algorithm = br.readU8();

        if (this.algorithm < 1 || this.algorithm > 3)
          throw new Error('Unknown PGP key algorithm.');

        break;
      }

      case 4: {
        this.timestamp = br.readU32BE();
        this.algorithm = br.readU8();
        break;
      }

      default: {
        throw new Error('Unknown PGP key version.');
      }
    }

    switch (this.algorithm) {
      case keyTypes.RSA:
      case keyTypes.RSA_ENCRYPT_ONLY:
      case keyTypes.RSA_SIGN_ONLY: {
        this.n = readMPI(br);
        this.e = readMPI(br);
        break;
      }

      case keyTypes.ELGAMAL: {
        this.p = readMPI(br);
        this.g = readMPI(br);
        this.y = readMPI(br);
        break;
      }

      case keyTypes.DSA: {
        this.p = readMPI(br);
        this.q = readMPI(br);
        this.g = readMPI(br);
        this.y = readMPI(br);
        break;
      }

      case keyTypes.ECDH: {
        this.oid = br.readBytes(br.readU8());
        this.point = readMPI(br);

        const size = br.readU8();

        if (size < 3 || size > br.left())
          throw new Error('Invalid ECDH params.');

        // Reserved.
        if (br.readU8() !== 0x01)
          throw new Error('Invalid ECDH reserved byte.');

        this.kdfHash = br.readU8();
        this.kdfAlg = br.readU8();

        break;
      }

      case keyTypes.ECDSA:
      case keyTypes.EDDSA: {
        this.oid = br.readBytes(br.readU8());
        this.point = readMPI(br);
        break;
      }

      default: {
        this.data = br.readBytes(br.left());
        break;
      }
    }

    return this;
  }

  format() {
    const algorithm = keyTypesByVal[this.algorithm] || 'UNKNOWN';
    const timestamp = this.timestamp;

    switch (this.algorithm) {
      case keyTypes.RSA:
      case keyTypes.RSA_ENCRYPT_ONLY:
      case keyTypes.RSA_SIGN_ONLY: {
        return {
          algorithm,
          timestamp,
          n: this.n.toString('hex'),
          e: this.e.toString('hex')
        };
      }

      case keyTypes.ELGAMAL: {
        return {
          algorithm,
          timestamp,
          p: this.p.toString('hex'),
          g: this.g.toString('hex'),
          y: this.y.toString('hex')
        };
      }

      case keyTypes.DSA: {
        return {
          algorithm,
          timestamp,
          p: this.p.toString('hex'),
          q: this.q.toString('hex'),
          g: this.g.toString('hex'),
          y: this.y.toString('hex')
        };
      }

      case keyTypes.ECDH: {
        return {
          algorithm,
          timestamp,
          curve: curveTypesByVal[this.curve] || 'UNKNOWN',
          point: this.point.toString('hex'),
          kdfHash: this.kdfHash,
          kdfAlg: this.kdfAlg
        };
      }

      case keyTypes.ECDSA:
      case keyTypes.EDDSA: {
        return {
          algorithm,
          timestamp,
          curve: curveTypesByVal[this.curve] || 'UNKNOWN',
          point: this.point.toString('hex')
        };
      }

      default: {
        return {
          algorithm,
          timestamp,
          data: this.data.toString('hex')
        };
      }
    }
  }
}

/**
 * PGP Private Key
 */

class PGPPrivateKey extends PGPBody {
  constructor() {
    super();

    this.key = new PGPPublicKey();
    this.params = new CipherParams();
    this.data = DUMMY;
  }

  secret(passphrase) {
    let data = this.data;

    if (this.params.encrypted) {
      if (passphrase == null)
        throw new Error('Key requires a passphrase.');

      data = this.params.decrypt(data, passphrase);
    }

    return SecretKey.decode(data, this.key.algorithm);
  }

  getSize() {
    let size = 0;

    size += this.key.getSize();
    size += this.params.getSize();
    size += this.data.length;

    return size;
  }

  write(bw) {
    this.key.write(bw);
    this.params.write(bw);
    bw.writeBytes(this.data);
    return bw;
  }

  read(br) {
    this.key.read(br);
    this.params.read(br);
    this.data = br.readBytes(br.left());
    return this;
  }

  format() {
    let params = null;
    let data = null;

    if (this.params.encrypted) {
      params = this.params;
      data = this.data.toString('hex');
    } else {
      params = null;
      data = this.secret();
    }

    return {
      key: this.key,
      params,
      data
    };
  }
}

/**
 * Cipher Params
 */

class CipherParams extends bio.Struct {
  constructor() {
    super();
    this.encrypted = false;
    this.checksum = false;
    this.cipher = 0;
    this.s2k = new S2K();
    this.iv = DUMMY;
  }

  blockSize() {
    switch (this.cipher) {
      case cipherTypes.DES3:
        return 8;
      case cipherTypes.CAST5:
        return 8;
      case cipherTypes.AES128:
      case cipherTypes.AES192:
      case cipherTypes.AES256:
        return 16;
      default:
        throw new Error('Unknown cipher type.');
    }
  }

  keySize() {
    switch (this.cipher) {
      case cipherTypes.DES3:
        return 24; // ??
      case cipherTypes.CAST5:
        return 16;
      case cipherTypes.AES128:
        return 16;
      case cipherTypes.AES192:
        return 24;
      case cipherTypes.AES256:
        return 32;
      default:
        throw new Error('Unknown cipher type.');
    }
  }

  derive(passphrase) {
    if (!this.encrypted)
      throw new Error('Cannot derive passphrase.');

    return this.s2k.derive(passphrase, this.keySize());
  }

  encipher(data, key) {
    throw new Error('Unimplemented.');
  }

  decipher(data, key) {
    throw new Error('Unimplemented.');
  }

  encrypt(data, passphrase) {
    const key = this.derive(passphrase);
    return this.encipher(data, key);
  }

  decrypt(data, passphrase) {
    const key = this.derive(passphrase);
    return this.decipher(data, key);
  }

  getSize() {
    let size = 0;

    if (this.encrypted) {
      size += 1;
      size += 1;
      size += this.s2k.getSize();
      size += this.iv.length;
    } else {
      size += 1;
    }

    return size;
  }

  write(bw) {
    if (this.encrypted) {
      assert(this.iv.length === this.blockSize());

      bw.writeU8(this.checksum ? 0xfe : 0xff);
      bw.writeU8(this.cipher);
      this.s2k.write(bw);
      bw.writeBytes(this.iv);
    } else {
      bw.writeU8(0x00);
    }

    return bw;
  }

  read(br) {
    const type = br.readU8();

    switch (type) {
      case 0x00:
        break;
      case 0xfe:
      case 0xff:
        this.encrypted = true;
        this.checksum = type === 0xfe;
        this.cipher = br.readU8();
        this.s2k.read(br);
        this.iv = br.readBytes(this.blockSize());
        break;
      default:
        throw new Error('Unknown S2K type.');
    }

    return this;
  }

  format() {
    return {
      encrypted: this.encrypted,
      checksum: this.checksum,
      cipher: cipherTypesByVal[this.cipher] || 'UNKNOWN',
      s2k: this.s2k,
      iv: this.iv.toString('hex')
    };
  }
}

/**
 * S2K
 */

class S2K extends bio.Struct {
  constructor() {
    super();
    this.mode = 0;
    this.hash = 0;
    this.count = 0;
    this.salt = DUMMY;
  }

  derive(passphrase, size) {
    assert(typeof passphrase === 'string');
    assert((size >>> 0) === size);

    const input = Buffer.from(passphrase, 'binary');
    const hash = hashToHash[this.hash];

    if (!hash)
      throw new Error('Unknown hash.');

    switch (this.mode) {
      case 0:
        return this._simple(hash, input, size);
      case 1:
        return this._salted(hash, input, size);
      case 3:
        return this._iterated(hash, input, size);
      default:
        throw new Error('Unknown S2K mode.');
    }
  }

  _simple(hash, input, size) {
    return this._hash(hash, input, DUMMY, size);
  }

  _salted(hash, input, size) {
    return this._hash(hash, input, this.salt, size);
  }

  _hash(hash, input, salt, size) {
    assert(hash && typeof hash.id === 'string');
    assert(Buffer.isBuffer(input));
    assert(Buffer.isBuffer(salt));
    assert((size >>> 0) === size);

    const ctx = hash.ctx;
    const out = Buffer.alloc(size);

    let i = 0;
    let pos = 0;

    while (pos < size) {
      ctx.init();

      for (let j = 0; j < i; j++)
        ctx.update(ZERO);

      ctx.update(salt);
      ctx.update(input);

      pos += ctx.final().copy(out, pos);
      i += 1;
    }

    return out;
  }

  _iterated(hash, input, size) {
    assert(hash && typeof hash.id === 'string');
    assert(Buffer.isBuffer(input));
    assert((size >>> 0) === size);

    const salt = this.salt;
    const ctx = hash.ctx;
    const out = Buffer.alloc(size);
    const combined = bio.concat(salt, input);

    let count = this.count;

    if (count < combined.length)
      count = combined.length;

    let i = 0;
    let pos = 0;

    while (pos < size) {
      ctx.init();

      for (let j = 0; j < i; j++)
        ctx.update(ZERO);

      let w = 0;

      while (w < count) {
        if (w + combined.length > count) {
          const todo = count - w;
          ctx.update(combined.slice(0, todo));
          w = count;
        } else {
          ctx.update(combined);
          w += combined.length;
        }
      }

      pos += ctx.final().copy(out, pos);
      i += 1;
    }

    return out;
  }

  getSize() {
    let size = 2;

    switch (this.mode) {
      case 0:
        break;
      case 1:
        size += 8;
        break;
      case 3:
        size += 8;
        size += 1;
        break;
      default:
        throw new Error('Unknown S2K function.');
    }

    return size;
  }

  write(bw) {
    bw.writeU8(this.mode);
    bw.writeU8(this.hash);

    switch (this.mode) {
      case 0:
        break;
      case 1:
        bw.writeBytes(this.salt);
        break;
      case 3:
        bw.writeBytes(this.salt);
        bw.writeU8(encodeCount(this.count));
        break;
      default:
        throw new Error('Unknown S2K function.');
    }

    return bw;
  }

  read(br) {
    this.mode = br.readU8();
    this.hash = br.readU8();

    switch (this.mode) {
      case 0:
        break;
      case 1:
        this.salt = br.readBytes(8);
        break;
      case 3:
        this.salt = br.readBytes(8);
        this.count = decodeCount(br.readU8());
        break;
      default:
        throw new Error('Unknown S2K function.');
    }

    return this;
  }

  format() {
    return {
      mode: this.mode,
      hash: hashTypesByVal[this.hash] || 'UNKNOWN',
      count: this.count,
      salt: this.salt.toString('hex')
    };
  }
}

/**
 * Secret Key
 */

class SecretKey extends bio.Struct {
  constructor() {
    super();

    // RSA
    this.d = DUMMY;
    this.p = DUMMY;
    this.q = DUMMY;
    this.qi = DUMMY;

    // DSA
    this.x = DUMMY;

    // El Gamal
    // this.x = DUMMY;

    // ECDSA
    // this.d = DUMMY;
  }

  getSize(algorithm) {
    assert((algorithm & 0xff) === algorithm);

    let size = 0;

    switch (algorithm) {
      case keyTypes.RSA:
      case keyTypes.RSA_ENCRYPT_ONLY:
      case keyTypes.RSA_SIGN_ONLY: {
        size += sizeMPI(this.d);
        size += sizeMPI(this.p);
        size += sizeMPI(this.q);
        size += sizeMPI(this.qi);
        break;
      }

      case keyTypes.ELGAMAL: {
        size += sizeMPI(this.x);
        break;
      }

      case keyTypes.DSA: {
        size += sizeMPI(this.x);
        break;
      }

      case keyTypes.ECDSA:
      case keyTypes.EDDSA: {
        size += sizeMPI(this.d);
        break;
      }

      default: {
        throw new Error('Unknown key type.');
      }
    }

    return size;
  }

  write(bw, algorithm) {
    assert((algorithm & 0xff) === algorithm);

    switch (algorithm) {
      case keyTypes.RSA:
      case keyTypes.RSA_ENCRYPT_ONLY:
      case keyTypes.RSA_SIGN_ONLY: {
        writeMPI(bw, this.d);
        writeMPI(bw, this.p);
        writeMPI(bw, this.q);
        writeMPI(bw, this.qi);
        break;
      }

      case keyTypes.ELGAMAL: {
        writeMPI(bw, this.x);
        break;
      }

      case keyTypes.DSA: {
        writeMPI(bw, this.x);
        break;
      }

      case keyTypes.ECDSA:
      case keyTypes.EDDSA: {
        writeMPI(bw, this.d);
        break;
      }

      default: {
        throw new Error('Unknown key type.');
      }
    }

    return bw;
  }

  read(br, algorithm) {
    assert((algorithm & 0xff) === algorithm);

    switch (algorithm) {
      case keyTypes.RSA:
      case keyTypes.RSA_ENCRYPT_ONLY:
      case keyTypes.RSA_SIGN_ONLY: {
        this.d = readMPI(br);
        this.p = readMPI(br);
        this.q = readMPI(br);
        this.qi = readMPI(br);
        break;
      }

      case keyTypes.ELGAMAL: {
        this.x = readMPI(br);
        break;
      }

      case keyTypes.DSA: {
        this.x = readMPI(br);
        break;
      }

      case keyTypes.ECDSA:
      case keyTypes.EDDSA: {
        this.d = readMPI(br);
        break;
      }

      default: {
        throw new Error('Unknown key type.');
      }
    }

    return this;
  }

  format() {
    if (this.p.length > 0) {
      return {
        d: this.d.toString('hex'),
        p: this.p.toString('hex'),
        q: this.q.toString('hex'),
        qi: this.qi.toString('hex')
      };
    }

    if (this.x.length > 0) {
      return {
        x: this.x.toString('hex')
      };
    }

    if (this.d.length > 0) {
      return {
        d: this.d.toString('hex')
      };
    }

    return {
      d: this.d.toString('hex'),
      p: this.p.toString('hex'),
      q: this.q.toString('hex'),
      qi: this.qi.toString('hex'),
      x: this.x.toString('hex')
    };
  }
}

/**
 * PGP User ID
 */

class PGPUserID extends PGPBody {
  constructor() {
    super();
    this.id = '';
  }

  getSize() {
    return Buffer.byteLength(this.id, 'utf8');
  }

  write(bw) {
    bw.writeString(this.id, 'utf8');
    return bw;
  }

  read(br) {
    this.id = br.readString(br.left(), 'utf8');
    return this;
  }

  format() {
    return {
      id: this.id
    };
  }
}

/*
 * Helpers
 */

function sizeMPI(n) {
  assert(Buffer.isBuffer(n));
  return 2 + n.length;
}

function writeMPI(bw, n) {
  assert(Buffer.isBuffer(n));
  bw.writeU16BE(countBits(n));
  bw.writeBytes(n);
  return bw;
}

function readMPI(br) {
  const s = (br.readU16BE() + 7) >>> 3;
  const n = br.readBytes(s);
  return trimZeroes(n);
}

function encodeCount(i) {
  assert((i >>> 0) === i);

  if (i < 1024 || i > 65011712)
    throw RangeError('Invalid iteration count.');

  for (let j = 0; j < 256; j++) {
    const c = decodeCount(j);

    if (c >= i)
      return j;
  }

  return 255;
}

function decodeCount(c) {
  assert((c & 0xff) === c);
  return (16 + (c & 15)) << ((c >>> 4) + 6);
}

/*
 * Expose
 */

exports.packetTypes = packetTypes;
exports.packetTypesByVal = packetTypesByVal;
exports.sigTypes = sigTypes;
exports.sigTypesByVal = sigTypesByVal;
exports.keyTypes = keyTypes;
exports.keyTypesByVal = keyTypesByVal;
exports.cipherTypes = cipherTypes;
exports.cipherTypesByVal = cipherTypesByVal;
exports.hashTypes = hashTypes;
exports.hashTypesByVal = hashTypesByVal;
exports.compressTypes = compressTypes;
exports.compressTypesByVal = compressTypesByVal;
exports.curveTypes = curveTypes;
exports.curveTypesByVal = curveTypesByVal;
exports.oids = oids;

exports.PGPMessage = PGPMessage;
exports.PGPPacket = PGPPacket;
exports.PGPBody = PGPBody;
exports.PGPUnknown = PGPUnknown;
exports.PGPPublicKey = PGPPublicKey;
exports.PGPPrivateKey = PGPPrivateKey;
exports.CipherParams = CipherParams;
exports.S2K = S2K;
exports.SecretKey = SecretKey;
exports.PGPUserID = PGPUserID;
