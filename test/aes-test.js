/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const crypto = require('crypto');
const aes = require('../lib/aes');
const {Cipher, Decipher} = require('../lib/cipher');
const random = require('../lib/random');

const key = Buffer.from(
  '3a0c0bf669694ac7685e6806eeadee8e56c9b9bd22c3caa81c718ed4bbf809a1',
  'hex');

const iv = Buffer.from('6dd26d9045b73c377a9ed2ffeca72ffd', 'hex');

function testVector() {
  const key = random.randomBytes(32);
  const iv = random.randomBytes(16);
  const data = random.randomBytes((Math.random() * 0x10000) >>> 0);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const expect = Buffer.concat([cipher.update(data), cipher.final()]);
  return {
    key,
    iv,
    data,
    expect
  };
}

function encipher(data, key, iv) {
  const c = new Cipher('AES-256-CBC');
  c.init(key, iv);
  return Buffer.concat([
    c.update(data),
    c.final()
  ]);
}

function decipher(data, key, iv) {
  const c = new Decipher('AES-256-CBC');
  c.init(key, iv);
  return Buffer.concat([
    c.update(data),
    c.final()
  ]);
}

describe('AES', function() {
  it('should encrypt and decrypt with 2 blocks', () => {
    const data = Buffer.from(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      'hex');

    const expected = Buffer.from(''
      + '83de502a9c83112ca6383f2214a892a0cdad5ab2b3e192e'
      + '9921ddb126b25262c41f1dcff4d67ccfb40e4116e5a4569c1',
      'hex');

    const ciphertext = aes.encipher(data, key, iv);
    assert.bufferEqual(ciphertext, expected);

    const plaintext = aes.decipher(ciphertext, key, iv);
    assert.bufferEqual(plaintext, data);
  });

  it('should encrypt and decrypt with uneven blocks', () => {
    const data = Buffer.from(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855010203',
      'hex');

    const expected = Buffer.from(''
      + '83de502a9c83112ca6383f2214a892a0cdad5ab2b3e192e9'
      + '921ddb126b25262c5211801019a30c0c6f795296923e0af8',
      'hex');

    const ciphertext = aes.encipher(data, key, iv);
    assert.bufferEqual(ciphertext, expected);

    const plaintext = aes.decipher(ciphertext, key, iv);
    assert.bufferEqual(plaintext, data);
  });

  for (let i = 0; i < 50; i++) {
    const {key, iv, data, expect} = testVector();
    const d = data.toString('hex', 0, 32);

    it(`should encrypt and decrypt ${d}`, () => {
      const ciphertext = aes.encipher(data, key, iv);
      assert.bufferEqual(ciphertext, expect);

      const plaintext = aes.decipher(ciphertext, key, iv);
      assert.bufferEqual(plaintext, data);
    });
  }

  it('should encrypt and decrypt with 2 blocks', () => {
    const data = Buffer.from(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      'hex');

    const expected = Buffer.from(''
      + '83de502a9c83112ca6383f2214a892a0cdad5ab2b3e192e'
      + '9921ddb126b25262c41f1dcff4d67ccfb40e4116e5a4569c1',
      'hex');

    const ciphertext = encipher(data, key, iv);
    assert.bufferEqual(ciphertext, expected);

    const plaintext = decipher(ciphertext, key, iv);
    assert.bufferEqual(plaintext, data);
  });

  it('should encrypt and decrypt with uneven blocks', () => {
    const data = Buffer.from(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855010203',
      'hex');

    const expected = Buffer.from(''
      + '83de502a9c83112ca6383f2214a892a0cdad5ab2b3e192e9'
      + '921ddb126b25262c5211801019a30c0c6f795296923e0af8',
      'hex');

    const ciphertext = encipher(data, key, iv);
    assert.bufferEqual(ciphertext, expected);

    const plaintext = decipher(ciphertext, key, iv);
    assert.bufferEqual(plaintext, data);
  });

  for (let i = 0; i < 50; i++) {
    const {key, iv, data, expect} = testVector();
    const d = data.toString('hex', 0, 32);

    it(`should encrypt and decrypt ${d}`, () => {
      const ciphertext = encipher(data, key, iv);
      assert.bufferEqual(ciphertext, expect);

      const plaintext = decipher(ciphertext, key, iv);
      assert.bufferEqual(plaintext, data);
    });
  }
});
