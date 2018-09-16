/*!
 * ssh.js - SSH keys for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://github.com/openssh/openssh-portable/blob/master/cipher.c
 *   https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
 */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const base64 = require('./internal/base64');
const bcrypt = require('./bcrypt');
const cipher = require('./cipher');
const random = require('./random');
const openssl = require('./encoding/openssl');
const {PEMBlock} = require('./encoding/pem');
const pemcrypt = require('./encoding/pemcrypt');
const pkcs1 = require('./encoding/pkcs1');
const sec1 = require('./encoding/sec1');
const p256 = require('./p256');
const p384 = require('./p384');
const p521 = require('./p521');
const ed25519 = require('./ed25519');

/*
 * Constants
 */

const keyTypes = {
  DSA: 'ssh-dss',
  RSA: 'ssh-rsa',
  P256: 'ecdsa-sha2-nistp256',
  P384: 'ecdsa-sha2-nistp384',
  P521: 'ecdsa-sha2-nistp521',
  ED25519: 'ssh-ed25519'
};

const keyTypesByVal = {
  [keyTypes.DSA]: 'DSA',
  [keyTypes.RSA]: 'RSA',
  [keyTypes.P256]: 'P256',
  [keyTypes.P384]: 'P384',
  [keyTypes.P521]: 'P521',
  [keyTypes.ED25519]: 'ED25519'
};

const typeToCurve = {
  [keyTypes.P256]: 'nistp256',
  [keyTypes.P384]: 'nistp384',
  [keyTypes.P521]: 'nistp521'
};

const cipherToName = {
  '3des-cbc': 'DES-EDE3-CBC',
  'aes128-cbc': 'AES-128-CBC',
  'aes192-cbc': 'AES-192-CBC',
  'aes256-cbc': 'AES-256-CBC',
  'rijndael-cbc@lysator.liu.se': 'AES-256-CBC',
  'aes128-ctr': 'AES-128-CTR',
  'aes192-ctr': 'AES-192-CTR',
  'aes256-ctr': 'AES-256-CTR'
};

const AUTH_MAGIC = 'openssh-key-v1';

const EMPTY = Buffer.alloc(0);
const ZERO32 = Buffer.alloc(32, 0x00);

/**
 * SSHPublicKey
 */

class SSHPublicKey extends bio.Struct {
  constructor() {
    super();

    this.type = keyTypes.ED25519;

    // DSA
    this.p = EMPTY;
    this.q = EMPTY;
    this.g = EMPTY;
    this.y = EMPTY;

    // RSA
    this.n = EMPTY;
    this.e = EMPTY;

    // ECDSA / EDDSA
    this.point = ZERO32;

    // Comment
    this.comment = '';
  }

  getCurve() {
    if (!typeToCurve.hasOwnProperty(this.type))
      throw new Error('No curve available.');

    return typeToCurve[this.type];
  }

  getSize() {
    let size = 0;

    size += sizeString(this.type);

    switch (this.type) {
      case keyTypes.DSA: {
        size += sizeBytes(this.p);
        size += sizeBytes(this.q);
        size += sizeBytes(this.g);
        size += sizeBytes(this.y);
        break;
      }

      case keyTypes.RSA: {
        size += sizeBytes(this.e);
        size += sizeBytes(this.n);
        break;
      }

      case keyTypes.P256:
      case keyTypes.P384:
      case keyTypes.P521: {
        size += sizeBytes(this.getCurve());
        size += sizeBytes(this.point);
        break;
      }

      case keyTypes.ED25519: {
        size += sizeBytes(this.point);
        break;
      }

      default: {
        throw new assert.AssertionError('Invalid key.');
      }
    }

    return size;
  }

  write(bw) {
    writeString(bw, this.type);

    switch (this.type) {
      case keyTypes.DSA: {
        writeBytes(bw, this.p);
        writeBytes(bw, this.q);
        writeBytes(bw, this.g);
        writeBytes(bw, this.y);
        break;
      }

      case keyTypes.RSA: {
        writeBytes(bw, this.e);
        writeBytes(bw, this.n);
        break;
      }

      case keyTypes.P256:
      case keyTypes.P384:
      case keyTypes.P521: {
        writeString(bw, this.getCurve());
        writeBytes(bw, this.point);
        break;
      }

      case keyTypes.ED25519: {
        writeBytes(bw, this.point);
        break;
      }

      default: {
        throw new assert.AssertionError('Invalid key.');
      }
    }

    return bw;
  }

  read(br) {
    this.type = readString(br);

    switch (this.type) {
      case keyTypes.DSA: {
        this.p = readBytes(br);
        this.q = readBytes(br);
        this.g = readBytes(br);
        this.y = readBytes(br);
        break;
      }

      case keyTypes.RSA: {
        this.e = readBytes(br);
        this.n = readBytes(br);
        break;
      }

      case keyTypes.P256:
      case keyTypes.P384:
      case keyTypes.P521: {
        if (readString(br) !== this.getCurve())
          throw new Error('Invalid curve prefix.');

        this.point = readBytes(br);

        break;
      }

      case keyTypes.ED25519: {
        this.point = readBytes(br);
        break;
      }

      default: {
        throw new Error('Invalid key type.');
      }
    }

    return this;
  }

  toString() {
    const raw = this.encode();

    let comment = this.comment;

    if (comment.length > 0)
      comment = ' ' + comment;

    return `${this.type} ${base64.encode(raw)}${comment}`;
  }

  fromString(str) {
    assert(typeof str === 'string');

    const parts = str.split(' ', 3);

    if (parts.length < 2)
      throw new Error('Invalid SSH key text.');

    const [type, rest] = parts;

    if (!keyTypesByVal.hasOwnProperty(type))
      throw new Error(`Unknown SSH public key type: ${type}.`);

    const data = base64.decode(rest);

    this.decode(data);

    if (this.type !== type)
      throw new Error('Key type mismatch.');

    if (parts.length > 2)
      this.comment = parts[2].trim();

    return this;
  }

  format() {
    switch (this.type) {
      case keyTypes.DSA: {
        return {
          type: this.type,
          p: this.p.toString('hex'),
          q: this.q.toString('hex'),
          g: this.g.toString('hex'),
          y: this.y.toString('hex'),
          comment: this.comment
        };
      }

      case keyTypes.RSA: {
        return {
          type: this.type,
          n: this.n.toString('hex'),
          e: this.e.toString('hex'),
          comment: this.comment
        };
      }

      case keyTypes.P256:
      case keyTypes.P384:
      case keyTypes.P521:
      case keyTypes.ED25519: {
        return {
          type: this.type,
          point: this.point.toString('hex'),
          comment: this.comment
        };
      }

      default: {
        return this;
      }
    }
  }
}

/**
 * SSHPrivateKey
 */

class SSHPrivateKey extends bio.Struct {
  constructor() {
    super();

    this.type = keyTypes.ED25519;

    // DSA
    this.p = EMPTY;
    this.q = EMPTY;
    this.g = EMPTY;
    this.y = EMPTY;
    this.x = EMPTY;

    // RSA
    this.n = EMPTY;
    this.e = EMPTY;
    this.d = EMPTY;
    this.p = EMPTY;
    this.q = EMPTY;
    this.dp = EMPTY;
    this.dq = EMPTY;
    this.qi = EMPTY;

    // ECDSA / EDDSA
    this.key = ZERO32;

    // Comment
    this.comment = '';
  }

  getCurve() {
    if (!typeToCurve.hasOwnProperty(this.type))
      throw new Error('No curve available.');

    return typeToCurve[this.type];
  }

  encodeSSH(passwd) {
    assert(this.type === keyTypes.ED25519);
    assert(!passwd || typeof passwd === 'string');

    const kdf = new KDFOptions();
    const pub = new SSHPublicKey();
    const priv = new RawPrivateKey();

    const bw = bio.write(4096);

    bw.writeString(AUTH_MAGIC);
    bw.writeU8(0);

    if (passwd) {
      kdf.name = 'bcrypt';
      kdf.salt = random.randomBytes(16);
      kdf.rounds = 16;

      writeString(bw, 'aes256-ctr');
      kdf.write(bw);
    } else {
      writeString(bw, 'none');
      kdf.write(bw);
    }

    writeInt(bw, 1);

    pub.type = this.type;

    writeBytes(bw, pub.encode());

    priv.type = this.type;
    priv.privateKey = this.key;
    priv.publicKey = ed25519.publicKeyCreate(this.key);
    priv.comment = this.comment;

    let raw = priv.encode(passwd);

    if (passwd)
      raw = encrypt(raw, 'aes256-ctr', passwd, kdf.salt, kdf.rounds);

    writeBytes(bw, raw);

    return bw.slice();
  }

  decodeSSH(data, passwd) {
    const br = bio.read(data);
    const magic = br.readString(14, 'binary');

    if (magic !== AUTH_MAGIC || br.readU8() !== 0)
      throw new Error('Invalid magic prefix for SSH key.');

    const cipher = readString(br);
    const kdf = KDFOptions.read(br);

    if (readInt(br) !== 1)
      throw new Error('Too many SSH keys.');

    const pubRaw = readBytes(br);
    const publicKey = SSHPublicKey.decode(pubRaw);

    let privRaw = readBytes(br);

    if (cipher !== 'none') {
      if (passwd == null)
        throw new Error('Cannot decrypt without passphrase.');

      if (kdf.name !== 'bcrypt')
        throw new Error('Invalid KDF.');

      privRaw = decrypt(privRaw, cipher, passwd, kdf.salt, kdf.rounds);
    }

    const rawKey = RawPrivateKey.decode(privRaw);

    if (rawKey.type !== keyTypes.ED25519)
      throw new Error('Invalid key.');

    if (rawKey.type !== publicKey.type)
      throw new Error('Public/private mismatch.');

    this.type = publicKey.type;
    this.key = rawKey.privateKey;
    this.comment = rawKey.comment;

    return this;
  }

  encode(passwd) {
    switch (this.type) {
      case keyTypes.DSA: {
        const key = new openssl.DSAPrivateKey(0,
          this.p,
          this.q,
          this.g,
          this.y,
          this.x
        );
        return key.encode();
      }

      case keyTypes.RSA: {
        const key = new pkcs1.RSAPrivateKey(0,
          this.n,
          this.e,
          this.d,
          this.p,
          this.q,
          this.dp,
          this.dq,
          this.qi
        );
        return key.encode();
      }

      case keyTypes.P256:
      case keyTypes.P384:
      case keyTypes.P521: {
        let curve = null;
        let pub = null;

        switch (this.type) {
          case keyTypes.P256:
            curve = 'P256';
            pub = p256.publicKeyCreate(this.key, false);
            break;
          case keyTypes.P384:
            curve = 'P384';
            pub = p384.publicKeyCreate(this.key, false);
            break;
          case keyTypes.P521:
            curve = 'P521';
            pub = p521.publicKeyCreate(this.key, false);
            break;
        }

        const key = new sec1.ECPrivateKey(1, this.key, curve, pub);

        return key.encode();
      }

      case keyTypes.ED25519: {
        return this.encodeSSH(passwd);
      }

      default: {
        throw new assert.AssertionError('Invalid key.');
      }
    }
  }

  toString(passwd) {
    const block = new PEMBlock();

    switch (this.type) {
      case keyTypes.DSA: {
        block.type = 'DSA PRIVATE KEY';
        break;
      }

      case keyTypes.RSA: {
        block.type = 'RSA PRIVATE KEY';
        break;
      }

      case keyTypes.P256:
      case keyTypes.P384:
      case keyTypes.P521: {
        block.type = 'EC PRIVATE KEY';
        break;
      }

      case keyTypes.ED25519: {
        block.type = 'OPENSSH PRIVATE KEY';
        break;
      }

      default: {
        throw new assert.AssertionError('Invalid key.');
      }
    }

    block.data = this.encode(passwd);

    if (this.type !== keyTypes.ED25519 && passwd)
      pemcrypt.encrypt(block, 'AES-128-CBC', passwd);

    return block.toString();
  }

  fromString(str, passwd) {
    const block = PEMBlock.fromString(str);

    if (block.isEncrypted()) {
      if (passwd == null)
        throw new Error('Private key requires a passphrase.');

      pemcrypt.decrypt(block, passwd);
    }

    switch (block.type) {
      case 'DSA PRIVATE KEY': { // OpenSSL PKCS1-like format
        const key = openssl.DSAPrivateKey.decode(block.data);

        this.type = keyTypes.DSA;
        this.p = key.p.value;
        this.q = key.q.value;
        this.g = key.g.value;
        this.y = key.y.value;
        this.x = key.x.value;

        return this;
      }

      case 'RSA PRIVATE KEY': { // PKCS1
        const key = pkcs1.RSAPrivateKey.decode(block.data);

        this.type = keyTypes.RSA;
        this.n = key.n.value;
        this.e = key.e.value;
        this.d = key.d.value;
        this.p = key.p.value;
        this.q = key.q.value;
        this.dp = key.dp.value;
        this.dq = key.dq.value;
        this.qi = key.qi.value;

        return this;
      }

      case 'EC PRIVATE KEY': { // SEC1
        const key = sec1.ECPrivateKey.decode(block.data);
        const curve = key.namedCurveOID.getCurveName();

        if (!curve)
          throw new Error(`Unknown curve: ${key.namedCurveOID.toString()}.`);

        let type = null;

        switch (curve) {
          case 'P256':
            type = keyTypes.P256;
            break;
          case 'P384':
            type = keyTypes.P384;
            break;
          case 'P521':
            type = keyTypes.P521;
            break;
          case 'ED25519':
            type = keyTypes.ED25519;
            break;
          default:
            throw new Error(`Unsupported curve: ${curve}.`);
        }

        this.type = type;
        this.key = key.privateKey.value;

        return this;
      }

      case 'OPENSSH PRIVATE KEY': { // OpenSSH format
        return this.decodeSSH(block.data, passwd);
      }

      default: {
        throw new Error(`Unknown private key type: ${block.type}.`);
      }
    }
  }

  format() {
    switch (this.type) {
      case keyTypes.DSA: {
        return {
          type: this.type,
          p: this.p.toString('hex'),
          q: this.q.toString('hex'),
          g: this.g.toString('hex'),
          y: this.y.toString('hex'),
          x: this.x.toString('hex'),
          comment: this.comment
        };
      }

      case keyTypes.RSA: {
        return {
          type: this.type,
          n: this.n.toString('hex'),
          e: this.q.toString('hex'),
          d: this.d.toString('hex'),
          p: this.p.toString('hex'),
          q: this.q.toString('hex'),
          dp: this.dp.toString('hex'),
          dq: this.dq.toString('hex'),
          qi: this.qi.toString('hex'),
          comment: this.comment
        };
      }

      case keyTypes.P256:
      case keyTypes.P384:
      case keyTypes.P521:
      case keyTypes.ED25519: {
        return {
          type: this.type,
          key: this.key.toString('hex'),
          comment: this.comment
        };
      }

      default: {
        return this;
      }
    }
  }
}

/**
 * KDFOptions
 */

class KDFOptions extends bio.Struct {
  constructor() {
    super();
    this.name = 'none';
    this.salt = EMPTY;
    this.rounds = 0;
  }

  getBodySize() {
    let size = 0;

    switch (this.name) {
      case 'none':
        break;
      case 'bcrypt':
        size += sizeBytes(this.salt);
        size += sizeInt(this.rounds);
        break;
      default:
        throw new Error(`Unknown KDF: ${this.name}.`);
    }

    return size;
  }

  getSize() {
    let size = 0;
    size += sizeString(this.name);
    size += sizeInt(0);
    size += this.getBodySize();
    return size;
  }

  write(bw) {
    writeString(bw, this.name);
    writeInt(bw, this.getBodySize());

    switch (this.name) {
      case 'none':
        break;
      case 'bcrypt':
        writeBytes(bw, this.salt);
        writeInt(bw, this.rounds);
        break;
      default:
        throw new Error(`Unknown KDF: ${this.name}.`);
    }

    return bw;
  }

  read(br) {
    this.name = readString(br);

    const child = readChild(br);

    switch (this.name) {
      case 'none':
        break;
      case 'bcrypt':
        this.salt = readBytes(child);
        this.rounds = readInt(child);
        break;
      default:
        throw new Error(`Unknown KDF: ${this.name}.`);
    }

    return this;
  }
}

/**
 * RawPrivateKey
 */

class RawPrivateKey extends bio.Struct {
  constructor() {
    super();

    this.type = keyTypes.ED25519;
    this.publicKey = ZERO32;
    this.privateKey = ZERO32;
    this.comment = '';
  }

  getSize(passwd) {
    let size = 0;

    size += sizeInt(0);
    size += sizeInt(0);
    size += sizeString(this.type);
    size += sizeBytes(this.publicKey);
    size += sizeInt(0);
    size += this.privateKey.length;
    size += this.publicKey.length;
    size += sizeString(this.comment);
    size += 8 - (size & 7);

    return size;
  }

  write(bw, passwd) {
    const offset = bw.offset;

    let n = 0;

    if (passwd)
      n = (Math.random() * 0x100000000) >>> 0;

    writeInt(bw, n);
    writeInt(bw, n);
    writeString(bw, this.type);
    writeBytes(bw, this.publicKey);
    writeBytes(bw, bio.concat(this.privateKey, this.publicKey)); // wtf?
    writeString(bw, this.comment);

    let size = bw.offset - offset;
    let i = 1;

    while (size & 7) {
      bw.writeU8(i);
      size += 1;
      i += 1;
    }

    return bw;
  }

  read(br, passwd) {
    if ((br.left() & 7) !== 0)
      throw new Error('Invalid padding.');

    if (readInt(br) !== readInt(br))
      throw new Error('Decryption failed.');

    const type = readString(br);

    if (!keyTypesByVal.hasOwnProperty(type))
      throw new Error('Invalid type.');

    const publicKey = readBytes(br);

    const blob = readBytes(br);

    if (blob.length !== 64)
      throw new Error('Invalid key pair.');

    const privateKey = blob.slice(0, 32);
    const publicKey2 = blob.slice(32, 64);

    if (!publicKey.equals(publicKey2))
      throw new Error('Public key mismatch.');

    const comment = readString(br);
    const padding = br.readBytes(br.left(), true);

    for (let i = 0; i < padding.length; i++) {
      if (padding[i] !== i + 1)
        throw new Error('Invalid padding.');
    }

    this.type = type;
    this.publicKey = publicKey;
    this.privateKey = privateKey;
    this.comment = comment;

    return this;
  }
}

/*
 * Encryption
 */

function derive(sname, passwd, salt, rounds) {
  assert(typeof sname === 'string');
  assert(typeof passwd === 'string');
  assert(Buffer.isBuffer(salt));
  assert((rounds >>> 0) === rounds);

  if (!cipherToName.hasOwnProperty(sname))
    throw new Error(`Unknown cipher: ${sname}.`);

  const name = cipherToName[sname];
  const {keySize, ivSize} = cipher.get(name);

  const size = keySize + ivSize;
  const secret = bcrypt.pbkdf(passwd, salt, rounds, size);

  const key = secret.slice(0, keySize);
  const iv = secret.slice(keySize, keySize + ivSize);

  return [name, key, iv];
}

function encrypt(data, sname, passwd, salt, rounds) {
  const [name, key, iv] = derive(sname, passwd, salt, rounds);
  return cipher.encrypt(name, key, iv, data);
}

function decrypt(data, sname, passwd, salt, rounds) {
  const [name, key, iv] = derive(sname, passwd, salt, rounds);
  return cipher.decrypt(name, key, iv, data);
}

/*
 * Encoding
 */

function readString(br) {
  return br.readString(br.readU32BE(), 'binary');
}

function readBytes(br) {
  return br.readBytes(br.readU32BE());
}

function readChild(br) {
  return br.readChild(br.readU32BE());
}

function readInt(br) {
  return br.readU32BE();
}

function sizeString(str) {
  return 4 + str.length;
}

function writeString(bw, str) {
  bw.writeU32BE(str.length);
  bw.writeString(str, 'binary');
  return bw;
}

function sizeBytes(data) {
  return 4 + data.length;
}

function writeBytes(bw, data) {
  bw.writeU32BE(data.length);
  bw.writeBytes(data);
  return bw;
}

function sizeInt(num) {
  return 4;
}

function writeInt(bw, num) {
  bw.writeU32BE(num);
  return bw;
}

/*
 * Expose
 */

exports.keyTypes = keyTypes;
exports.keyTypesByVal = keyTypesByVal;
exports.SSHPublicKey = SSHPublicKey;
exports.SSHPrivateKey = SSHPrivateKey;
exports.KDFOptions = KDFOptions;
exports.RawPrivateKey = RawPrivateKey;
