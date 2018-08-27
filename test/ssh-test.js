/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const fs = require('fs');
const Path = require('path');
const ssh = require('../lib/internal/ssh');
const {SSHPublicKey, SSHPrivateKey} = ssh;

const pubs = [
  Path.resolve(__dirname, 'data', 'id_dsa.pub'),
  Path.resolve(__dirname, 'data', 'id_rsa.pub'),
  Path.resolve(__dirname, 'data', 'id_ecdsa.pub'),
  Path.resolve(__dirname, 'data', 'id_ed25519_unenc.pub'),
  Path.resolve(__dirname, 'data', 'id_ed25519.pub')
];

const privs = [
  Path.resolve(__dirname, 'data', 'id_dsa'),
  Path.resolve(__dirname, 'data', 'id_rsa'),
  Path.resolve(__dirname, 'data', 'id_ecdsa'),
  Path.resolve(__dirname, 'data', 'id_ed25519_unenc'),
  Path.resolve(__dirname, 'data', 'id_ed25519')
];

const PASSPHRASE = '1234567890';

describe('SSH', function() {
  for (const file of pubs) {
    const str = fs.readFileSync(file, 'utf8');

    it('should deserialize and reserialize public keys', () => {
      const key1 = SSHPublicKey.fromString(str);
      const str1 = key1.toString();
      const key2 = SSHPublicKey.fromString(str1);
      const str2 = key2.toString();

      assert.deepStrictEqual(key1, key2);
      assert.strictEqual(str1, str2);
      assert.strictEqual(key2.toString('chjj@slickrick'), str.trim());
    });
  }

  for (const file of privs) {
    const str = fs.readFileSync(file, 'utf8');

    it('should deserialize and reserialize private keys', () => {
      const key1 = SSHPrivateKey.fromString(str, PASSPHRASE);
      const str1 = key1.toString();
      const key2 = SSHPrivateKey.fromString(str1);
      const str2 = key2.toString();

      assert.deepStrictEqual(key1, key2);
      assert.strictEqual(str1, str2);

      const str3 = key2.toString(PASSPHRASE);
      const key3 = SSHPrivateKey.fromString(str3, PASSPHRASE);

      let err;
      try {
        SSHPrivateKey.fromString(str3, 'foo');
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
