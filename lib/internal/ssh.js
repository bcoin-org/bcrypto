/*!
 * ssh.js - SSH keys for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Resources:
 *   https://github.com/openssh/openssh-portable/blob/master/cipher.c
 *   https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
 */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const base64 = require('./base64');
const bcrypt = require('../bcrypt');
const crypto = require('./crypto');
const openssl = require('./openssl');
const pem = require('./pem');
const pkcs1 = require('./pkcs1');
const sec1 = require('./sec1');

/*
 * Constants
 */

const algs = {
  'ssh-dss': { type: 'dsa', curve: null },
  'ssh-rsa': { type: 'rsa', curve: null },
  'ecdsa-sha2-nistp256': { type: 'ecdsa', curve: 'p256' },
  'ecdsa-sha2-nistp384': { type: 'ecdsa', curve: 'p384' },
  'ecdsa-sha2-nistp521': { type: 'ecdsa', curve: 'p521' },
  'ssh-ed25519': { type: 'eddsa', curve: 'ed25519' }
};

const tags = {
  'dsa': { prefix: 'ssh-dss', curve: null },
  'rsa': { prefix: 'ssh-rsa', curve: null },
  'ecdsa-p256': { prefix: 'ecdsa-sha2-nistp256', curve: 'nistp256' },
  'ecdsa-p384': { prefix: 'ecdsa-sha2-nistp384', curve: 'nistp384' },
  'ecdsa-p521': { prefix: 'ecdsa-sha2-nistp521', curve: 'nistp521' },
  'eddsa-ed25519': { prefix: 'ssh-ed25519', curve: 'ed25519' }
};

const ciphers = {
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

/**
 * SSHPublicKey
 */

class SSHPublicKey extends bio.Struct {
  constructor() {
    super();

    this.type = 'rsa';
    this.curve = null;

    // DSA
    this.p = EMPTY;
    this.q = EMPTY;
    this.g = EMPTY;
    this.y = EMPTY;

    // RSA
    this.n = EMPTY;
    this.e = EMPTY;

    // ECDSA / EDDSA
    this.point = EMPTY;
  }

  getTag() {
    const tag = algToTag(this);

    if (!tag)
      throw new Error('Invalid key type.');

    return tag;
  }

  getPrefix() {
    return this.getTag().prefix;
  }

  getSize() {
    const tag = this.getTag();

    let size = 0;

    size += sizeString(tag.prefix);

    switch (this.type) {
      case 'dsa': {
        size += sizeBytes(this.p);
        size += sizeBytes(this.q);
        size += sizeBytes(this.g);
        size += sizeBytes(this.y);
        break;
      }

      case 'rsa': {
        size += sizeBytes(this.e);
        size += sizeBytes(this.n);
        break;
      }

      case 'ecdsa': {
        size += sizeBytes(tag.curve);
        size += sizeBytes(this.point);
        break;
      }

      case 'eddsa': {
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
    const tag = this.getTag();

    writeString(bw, tag.prefix);

    switch (this.type) {
      case 'dsa': {
        writeBytes(bw, this.p);
        writeBytes(bw, this.q);
        writeBytes(bw, this.g);
        writeBytes(bw, this.y);
        break;
      }

      case 'rsa': {
        writeBytes(bw, this.e);
        writeBytes(bw, this.n);
        break;
      }

      case 'ecdsa': {
        writeString(bw, tag.curve);
        writeBytes(bw, this.point);
        break;
      }

      case 'eddsa': {
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
    const prefix = readString(br);
    const alg = prefixToAlg(prefix);

    if (!alg)
      throw new Error(`Unknown SSH public key type: ${prefix}.`);

    switch (alg.type) {
      case 'dsa': {
        this.type = alg.type;
        this.p = readBytes(br);
        this.q = readBytes(br);
        this.g = readBytes(br);
        this.y = readBytes(br);
        return this;
      }

      case 'rsa': {
        this.type = alg.type;
        this.e = readBytes(br);
        this.n = readBytes(br);
        return this;
      }

      case 'ecdsa': {
        const tag = algToTag(alg);
        assert(tag);

        if (readString(br) !== tag.curve)
          throw new Error('Invalid curve prefix.');

        this.type = alg.type;
        this.curve = alg.curve;
        this.point = readBytes(br);

        return this;
      }

      case 'eddsa': {
        this.type = alg.type;
        this.curve = alg.curve;
        this.point = readBytes(br);
        return this;
      }

      default: {
        throw new assert.AssertionError('Invalid key type.');
      }
    }
  }

  toString(comment) {
    if (comment == null)
      comment = '';

    assert(typeof comment === 'string');

    const tag = this.getTag();
    const raw = this.encode();

    if (comment.length > 0)
      comment = ' ' + comment;

    return `${tag.prefix} ${base64.encode(raw)}${comment}`;
  }

  fromString(str) {
    assert(typeof str === 'string');

    const parts = str.split(' ', 3);

    if (parts.length < 2)
      throw new Error('Invalid SSH key text.');

    const [prefix, rest] = parts;

    if (!isPrefix(prefix))
      throw new Error(`Unknown SSH public key type: ${prefix}.`);

    const data = base64.decode(rest);

    this.decode(data);

    if (this.getPrefix() !== prefix)
      throw new Error('Unexpected prefix.');

    return this;
  }

  format() {
    switch (this.type) {
      case 'dsa': {
        return {
          type: this.type,
          p: this.p.toString('hex'),
          q: this.q.toString('hex'),
          g: this.g.toString('hex'),
          y: this.y.toString('hex')
        };
      }

      case 'rsa': {
        return {
          type: this.type,
          n: this.n.toString('hex'),
          e: this.q.toString('hex')
        };
      }

      case 'ecdsa':
      case 'eddsa': {
        return {
          type: this.type,
          curve: this.curve,
          point: this.point.toString('hex')
        };
      }

      default: {
        throw new assert.AssertionError('Invalid key.');
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

    this.type = 'rsa';
    this.curve = null;

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
    this.key = EMPTY;
  }

  getTag() {
    const tag = algToTag(this);

    if (!tag)
      throw new Error('Invalid key type.');

    return tag;
  }

  getPrefix() {
    return this.getTag().prefix;
  }

  encodeSSH(passwd) {
    assert(this.type === 'eddsa' && this.curve === 'ed25519');
    assert(!passwd || typeof passwd === 'string');

    const kdf = new KDFOptions();
    const pub = new SSHPublicKey();
    const priv = new RawPrivateKey();

    const bw = bio.write(4096);

    bw.writeString(AUTH_MAGIC);
    bw.writeU8(0);

    if (passwd) {
      kdf.name = 'bcrypt';
      kdf.salt = crypto.randomBytes(16);
      kdf.rounds = 16;

      writeString(bw, 'aes256-ctr');
      kdf.write(bw);
    } else {
      writeString(bw, 'none');
      kdf.write(bw);
    }

    writeInt(bw, 1);

    pub.type = this.type;
    pub.curve = this.curve;

    writeBytes(bw, pub.encode());

    priv.prefix = this.getPrefix();
    priv.privateKey = this.key;

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

    if (rawKey.prefix !== 'ssh-ed25519')
      throw new Error('Invalid key.');

    if (rawKey.prefix !== publicKey.getPrefix())
      throw new Error('Public/private mismatch.');

    this.type = publicKey.type;
    this.curve = publicKey.curve;
    this.key = rawKey.privateKey;

    return this;
  }

  encode(passwd) {
    switch (this.type) {
      case 'dsa': {
        const key = new openssl.DSAPrivateKey(0,
          this.p,
          this.q,
          this.g,
          this.y,
          this.x
        );
        return key.encode();
      }

      case 'rsa': {
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

      case 'ecdsa': {
        const key = new sec1.ECPrivateKey(1, this.key, this.curve);
        return key.encode();
      }

      case 'eddsa': {
        return this.encodeSSH(passwd);
      }

      default: {
        throw new assert.AssertionError();
      }
    }
  }

  toString(passwd) {
    const block = new pem.PEMBlock();

    switch (this.type) {
      case 'dsa': {
        block.type = 'DSA PRIVATE KEY';
        break;
      }

      case 'rsa': {
        block.type = 'RSA PRIVATE KEY';
        break;
      }

      case 'ecdsa': {
        block.type = 'EC PRIVATE KEY';
        break;
      }

      case 'eddsa': {
        block.type = 'OPENSSH PRIVATE KEY';
        break;
      }

      default: {
        throw new assert.AssertionError();
      }
    }

    block.data = this.encode(passwd);

    if (this.type !== 'eddsa' && passwd)
      block.encrypt('AES-128-CBC', passwd);

    return block.toString();
  }

  fromString(str, passwd) {
    const [type, data] = pem.readPrivateKey(str, passwd);

    switch (type) {
      case 'DSA PRIVATE KEY': { // OpenSSL PKCS1-like format
        const key = openssl.DSAPrivateKey.decode(data);

        this.type = 'dsa';
        this.p = key.p.value;
        this.q = key.q.value;
        this.g = key.g.value;
        this.y = key.y.value;
        this.x = key.x.value;

        return this;
      }

      case 'RSA PRIVATE KEY': { // PKCS1
        const key = pkcs1.RSAPrivateKey.decode(data);

        this.type = 'rsa';
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
        const key = sec1.ECPrivateKey.decode(data);
        const curve = key.namedCurveOID.getCurve();

        if (!curve)
          throw new Error(`Unknown curve: ${key.namedCurveOID.toString()}.`);

        if (!isCurve(curve))
          throw new Error(`Unsupported curve: ${curve}.`);

        this.type = curve === 'ed25519' ? 'eddsa' : 'ecdsa';
        this.curve = curve;
        this.key = key.privateKey.value;

        return this;
      }

      case 'OPENSSH PRIVATE KEY': { // OpenSSH format
        return this.decodeSSH(data, passwd);
      }

      default: {
        throw new Error(`Unknown private key type: ${type}.`);
      }
    }
  }

  format() {
    switch (this.type) {
      case 'dsa': {
        return {
          type: this.type,
          p: this.p.toString('hex'),
          q: this.q.toString('hex'),
          g: this.g.toString('hex'),
          y: this.y.toString('hex'),
          x: this.x.toString('hex')
        };
      }

      case 'rsa': {
        return {
          type: this.type,
          n: this.n.toString('hex'),
          e: this.q.toString('hex'),
          d: this.d.toString('hex'),
          p: this.p.toString('hex'),
          q: this.q.toString('hex'),
          dp: this.dp.toString('hex'),
          dq: this.dq.toString('hex'),
          qi: this.qi.toString('hex')
        };
      }

      case 'ecdsa':
      case 'eddsa': {
        return {
          type: this.type,
          curve: this.curve,
          key: this.key.toString('hex')
        };
      }

      default: {
        throw new assert.AssertionError('Invalid key.');
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

    this.prefix = 'ssh-rsa';
    this.publicKey = EMPTY;
    this.privateKey = EMPTY;
    this.comment = '';
  }

  getAlg() {
    const alg = prefixToAlg(this.prefix);

    if (!alg)
      throw new Error('Invalid key prefix.');

    return alg;
  }

  getSize(passwd) {
    let size = 0;

    let publicKey = this.publicKey;

    if (publicKey.length === 0)
      publicKey = this.privateKey;

    size += sizeInt(0);
    size += sizeInt(0);
    size += sizeString(this.prefix);
    size += sizeBytes(publicKey);
    size += sizeInt(0);
    size += this.privateKey.length;
    size += publicKey.length;
    size += sizeString(this.comment);
    size += 8 - (size & 7);

    return size;
  }

  write(bw, passwd) {
    const offset = bw.offset;

    let n = 0;
    let publicKey = this.publicKey;

    if (publicKey.length === 0)
      publicKey = Buffer.alloc(this.privateKey.length, 0x00);

    if (passwd)
      n = (Math.random() * 0x100000000) >>> 0;

    writeInt(bw, n);
    writeInt(bw, n);
    writeString(bw, this.prefix);
    writeBytes(bw, publicKey);
    writeBytes(bw, bio.concat(this.privateKey, publicKey)); // wtf?
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

    const prefix = readString(br);

    if (!isPrefix(prefix))
      throw new Error('Invalid prefix.');

    let publicKey = readBytes(br);

    const blob = readBytes(br);

    if (blob.length & 1)
      throw new Error('Invalid key pair.');

    const mid = blob.length >>> 1;
    const privateKey = blob.slice(0, mid);
    const publicKey2 = blob.slice(mid);

    if (!publicKey.equals(publicKey2))
      throw new Error('Public key mismatch.');

    const comment = readString(br);
    const padding = br.readBytes(br.left(), true);

    for (let i = 0; i < padding.length; i++) {
      if (padding[i] !== i + 1)
        throw new Error('Invalid padding.');
    }

    const zeroKey = Buffer.alloc(mid, 0x00);

    if (publicKey.equals(zeroKey))
      publicKey = EMPTY;

    this.prefix = prefix;
    this.publicKey = publicKey;
    this.privateKey = privateKey;
    this.comment = comment;

    return this;
  }
}

/*
 * Encryption
 */

function derive(cipher, passwd, salt, rounds) {
  assert(typeof cipher === 'string');
  assert(typeof passwd === 'string');
  assert(Buffer.isBuffer(salt));
  assert((rounds >>> 0) === rounds);

  if (!ciphers.hasOwnProperty(cipher))
    throw new Error(`Unknown cipher: ${cipher}.`);

  const name = ciphers[cipher];
  const {blockSize, keySize} = crypto.getCipher(name);

  const size = blockSize + keySize;
  const secret = bcrypt.pbkdf(passwd, salt, rounds, size);

  const key = secret.slice(0, keySize);
  const iv = secret.slice(keySize, keySize + blockSize);

  return [name, key, iv];
}

function encrypt(data, cipher, passwd, salt, rounds) {
  assert(Buffer.isBuffer(data));

  const [name, key, iv] = derive(cipher, passwd, salt, rounds);
  const ctx = crypto.encipher(name, key, iv);

  return bio.concat(
    ctx.update(data),
    ctx.final()
  );
}

function decrypt(data, cipher, passwd, salt, rounds) {
  assert(Buffer.isBuffer(data));

  const [name, key, iv] = derive(cipher, passwd, salt, rounds);
  const ctx = crypto.decipher(name, key, iv);

  return bio.concat(
    ctx.update(data),
    ctx.final()
  );
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
 * Helpers
 */

function prefixToAlg(str) {
  assert(typeof str === 'string');

  if (!algs.hasOwnProperty(str))
    return null;

  return algs[str];
}

function isPrefix(str) {
  return prefixToAlg(str) !== null;
}

function isCurve(str) {
  assert(typeof str === 'string');

  if (str === 'ed25519')
    return true;

  return tags.hasOwnProperty(`ecdsa-${str}`);
}

function algToTag(alg) {
  assert(alg && typeof alg === 'object');
  assert(typeof alg.type === 'string');
  assert(!alg.curve || typeof alg.curve === 'string');

  let key = alg.type;

  if (alg.curve)
    key = `${alg.type}-${alg.curve}`;

  if (!tags.hasOwnProperty(key))
    return null;

  return tags[key];
}

/*
 * Expose
 */

exports.SSHPublicKey = SSHPublicKey;
exports.SSHPrivateKey = SSHPrivateKey;
exports.KDFOptions = KDFOptions;
exports.RawPrivateKey = RawPrivateKey;
