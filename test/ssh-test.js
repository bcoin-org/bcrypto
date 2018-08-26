/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

/*
const assert = require('./util/assert');
const fs = require('fs');
const Path = require('path');
const ssh = require('../lib/internal/ssh');

const pubs = [
  Path.resolve(__dirname, 'data', 'key_dsa_1024.pub'),
  Path.resolve(__dirname, 'data', 'key_rsa_1024.pub'),
  Path.resolve(__dirname, 'data', 'key_ecdsa_384.pub')
];

const privs = [
  Path.resolve(__dirname, 'data', 'key_dsa_1024'),
  Path.resolve(__dirname, 'data', 'key_rsa_1024'),
  Path.resolve(__dirname, 'data', 'key_ecdsa_384')
];

const PASSPHRASE = '';

describe('SSH', function() {
  for (const file of pubs) {
    const str = fs.readFileSync(file, 'utf8');

    it('should deserialize and reserialize public keys', () => {
      const pub = ssh.parsePublicKey(str);
    });
  }

  for (const file of privs) {
    const str = fs.readFileSync(file, 'utf8');

    it('should deserialize and reserialize private keys', () => {
      const key = ssh.parsePrivateKey(str, PASSPHRASE);
    });
  }
});
*/
