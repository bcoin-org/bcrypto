'use strict';

const assert = require('bsert');
const fs = require('fs');
const {Cipher, Decipher} = require('../lib/cipher');

const algs = [
  {
    name: 'AES-128',
    keyLen: 16,
    ivLen: 16,
    ids: [
      'AES-128-ECB',
      'AES-128-CBC',
      'AES-128-CTR',
      'AES-128-CFB',
      'AES-128-OFB',
      'AES-128-GCM'
    ]
  },
  {
    name: 'AES-192',
    keyLen: 24,
    ivLen: 16,
    ids: [
      'AES-192-ECB',
      'AES-192-CBC',
      'AES-192-CTR',
      'AES-192-CFB',
      'AES-192-OFB',
      'AES-192-GCM'
    ]
  },
  {
    name: 'AES-256',
    keyLen: 32,
    ivLen: 16,
    ids: [
      'AES-256-ECB',
      'AES-256-CBC',
      'AES-256-CTR',
      'AES-256-CFB',
      'AES-256-OFB',
      'AES-256-GCM'
    ]
  },
  {
    name: 'Blowfish',
    keyLen: 32,
    ivLen: 8,
    ids: [
      'BF-ECB',
      'BF-CBC',
      'BF-CFB',
      'BF-OFB'
    ]
  },
  {
    name: 'CAMELLIA-128',
    keyLen: 16,
    ivLen: 16,
    ids: [
      'CAMELLIA-128-ECB',
      'CAMELLIA-128-CBC',
      'CAMELLIA-128-CTR',
      'CAMELLIA-128-CFB',
      'CAMELLIA-128-OFB'
    ]
  },
  {
    name: 'CAMELLIA-192',
    keyLen: 24,
    ivLen: 16,
    ids: [
      'CAMELLIA-192-ECB',
      'CAMELLIA-192-CBC',
      'CAMELLIA-192-CTR',
      'CAMELLIA-192-CFB',
      'CAMELLIA-192-OFB'
    ]
  },
  {
    name: 'CAMELLIA-256',
    keyLen: 32,
    ivLen: 16,
    ids: [
      'CAMELLIA-256-ECB',
      'CAMELLIA-256-CBC',
      'CAMELLIA-256-CTR',
      'CAMELLIA-256-CFB',
      'CAMELLIA-256-OFB'
    ]
  },
  {
    name: 'CAST5',
    keyLen: 16,
    ivLen: 8,
    ids: [
      'CAST5-ECB',
      'CAST5-CBC',
      'CAST5-CFB',
      'CAST5-OFB'
    ]
  },
  {
    name: 'DES',
    keyLen: 8,
    ivLen: 8,
    ids: [
      'DES-ECB',
      'DES-CBC',
      'DES-CFB',
      'DES-OFB'
    ]
  },
  {
    name: 'IDEA',
    keyLen: 16,
    ivLen: 8,
    ids: [
      'IDEA-ECB',
      'IDEA-CBC',
      'IDEA-CFB',
      'IDEA-OFB'
    ]
  },
  {
    name: 'RC2',
    keyLen: 8,
    ivLen: 8,
    ids: [
      'RC2-64-CBC'
    ]
  },
  {
    name: 'Triple-DES (EDE)',
    keyLen: 16,
    ivLen: 8,
    ids: [
      'DES-EDE-ECB',
      'DES-EDE-CBC',
      'DES-EDE-CFB',
      'DES-EDE-OFB'
    ]
  },
  {
    name: 'Triple-DES (EDE3)',
    keyLen: 24,
    ivLen: 8,
    ids: [
      'DES-EDE3-ECB',
      'DES-EDE3-CBC',
      'DES-EDE3-CFB',
      'DES-EDE3-OFB'
    ]
  }
];

const key = Buffer.from(
  '3a0c0bf669694ac7685e6806eeadee8e56c9b9bd22c3caa81c718ed4bbf809a1',
  'hex');

const iv = Buffer.from('6dd26d9045b73c377a9ed2ffeca72ffd', 'hex');

function encipher(name, data, key, iv) {
  const gcm = name.endsWith('-GCM');
  const ctx = new Cipher(name);

  ctx.init(key, iv);

  return Buffer.concat([
    ctx.update(data),
    ctx.final(),
    gcm ? ctx.getAuthTag() : Buffer.alloc(0)
  ]);
}

function decipher(name, data, key, iv) {
  const gcm = name.endsWith('-GCM');
  const ctx = new Decipher(name);

  ctx.init(key, iv);

  if (gcm) {
    const tag = data.slice(-16);
    data = data.slice(0, -16);
    ctx.setAuthTag(tag);
  }

  return Buffer.concat([
    ctx.update(data),
    ctx.final()
  ]);
}

describe('Cipher', function() {
  it('should encrypt and decrypt with 2 blocks (AES-256-CBC)', () => {
    const data = Buffer.from(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      'hex');

    const expected = Buffer.from(''
      + '83de502a9c83112ca6383f2214a892a0cdad5ab2b3e192e'
      + '9921ddb126b25262c41f1dcff4d67ccfb40e4116e5a4569c1',
      'hex');

    const ciphertext = encipher('AES-256-CBC', data, key, iv);
    assert.bufferEqual(ciphertext, expected);

    const plaintext = decipher('AES-256-CBC', ciphertext, key, iv);
    assert.bufferEqual(plaintext, data);
  });

  it('should encrypt and decrypt with uneven blocks (AES-256-CBC)', () => {
    const data = Buffer.from(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855010203',
      'hex');

    const expected = Buffer.from(''
      + '83de502a9c83112ca6383f2214a892a0cdad5ab2b3e192e9'
      + '921ddb126b25262c5211801019a30c0c6f795296923e0af8',
      'hex');

    const ciphertext = encipher('AES-256-CBC', data, key, iv);
    assert.bufferEqual(ciphertext, expected);

    const plaintext = decipher('AES-256-CBC', ciphertext, key, iv);
    assert.bufferEqual(plaintext, data);
  });

  for (const alg of algs) {
    describe(alg.name, function() {
      for (const id of alg.ids) {
        const file = `${__dirname}/data/ciphers/${id.toLowerCase()}.json`;
        const text = fs.readFileSync(file, 'utf8');
        const vectors = JSON.parse(text);

        for (const [key_, iv_, data_, expect_] of vectors) {
          const key = Buffer.from(key_, 'hex');
          const iv = Buffer.from(iv_, 'hex');
          const data = Buffer.from(data_, 'hex');
          const expect = Buffer.from(expect_, 'hex');
          const hex = data_.slice(0, 32);

          it(`should encrypt and decrypt ${hex} with ${id}`, () => {
            assert.bufferEqual(encipher(id, data, key, iv), expect);
            assert.bufferEqual(decipher(id, expect, key, iv), data);
          });
        }
      }
    });
  }
});
