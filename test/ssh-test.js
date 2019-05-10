'use strict';

const assert = require('bsert');
const fs = require('fs');
const path = require('path');
const ssh = require('../lib/ssh');
const {resolve, basename} = path;
const {SSHPublicKey, SSHPrivateKey} = ssh;

const pubs = [
  resolve(__dirname, 'data', 'id_dsa.pub'),
  resolve(__dirname, 'data', 'id_rsa.pub'),
  resolve(__dirname, 'data', 'id_ecdsa.pub'),
  resolve(__dirname, 'data', 'id_dsa_modern.pub'),
  resolve(__dirname, 'data', 'id_dsa_modern_unenc.pub'),
  resolve(__dirname, 'data', 'id_rsa_modern.pub'),
  resolve(__dirname, 'data', 'id_rsa_modern_unenc.pub'),
  resolve(__dirname, 'data', 'id_ecdsa_modern.pub'),
  resolve(__dirname, 'data', 'id_ecdsa_modern_unenc.pub'),
  resolve(__dirname, 'data', 'id_ed25519.pub'),
  resolve(__dirname, 'data', 'id_ed25519_unenc.pub')
];

const privs = [
  resolve(__dirname, 'data', 'id_dsa'),
  resolve(__dirname, 'data', 'id_rsa'),
  resolve(__dirname, 'data', 'id_ecdsa'),
  resolve(__dirname, 'data', 'id_dsa_modern'),
  resolve(__dirname, 'data', 'id_dsa_modern_unenc'),
  resolve(__dirname, 'data', 'id_rsa_modern'),
  resolve(__dirname, 'data', 'id_rsa_modern_unenc'),
  resolve(__dirname, 'data', 'id_ecdsa_modern'),
  resolve(__dirname, 'data', 'id_ecdsa_modern_unenc'),
  resolve(__dirname, 'data', 'id_ed25519'),
  resolve(__dirname, 'data', 'id_ed25519_unenc')
];

const PASSPHRASE = '1234567890';

describe('SSH', function() {
  this.timeout(60000);

  for (const file of pubs) {
    const str = fs.readFileSync(file, 'utf8');

    it(`should reserialize public keys (${basename(file)})`, () => {
      const key1 = SSHPublicKey.fromString(str);
      const str1 = key1.toString();
      const key2 = SSHPublicKey.fromString(str1);
      const str2 = key2.toString();

      assert.deepStrictEqual(key1, key2);
      assert.strictEqual(str1, str2);
      assert.strictEqual(key2.toString(), str.trim());
    });
  }

  for (const file of privs) {
    const str = fs.readFileSync(file, 'utf8');

    let passphrase = PASSPHRASE;

    if (file.includes('modern'))
      passphrase = 'foo';

    it(`should reserialize private keys (${basename(file)})`, () => {
      const key1 = SSHPrivateKey.fromString(str, passphrase);
      const str1 = key1.toString();
      const key2 = SSHPrivateKey.fromString(str1);
      const str2 = key2.toString();

      assert.deepStrictEqual(key1, key2);
      assert.strictEqual(str1, str2);

      const str3 = key2.toString(passphrase);
      const key3 = SSHPrivateKey.fromString(str3, passphrase);

      let err;
      try {
        SSHPrivateKey.fromString(str3, 'bar');
      } catch (e) {
        err = e;
      }

      assert(err);
      assert(err.message.indexOf('Decryption failed')
        || err.message.indexOf('bad decrypt'));

      assert(key3.toString());
    });
  }
});
