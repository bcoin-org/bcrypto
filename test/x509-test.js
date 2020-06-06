'use strict';

const assert = require('bsert');
const fs = require('fs');
const Path = require('path');
const x509 = require('../lib/encoding/x509');
const pem = require('../lib/encoding/pem');
const rsa = require('../lib/rsa');
const sha256 = require('../lib/sha256');

const certs = Path.resolve(__dirname, 'data', 'certs.pem');
const certsData = fs.readFileSync(certs, 'utf8');

const certificate = Path.resolve(__dirname, 'data', 'x509', 'certificate.crt');
const certificateData = fs.readFileSync(certificate, 'utf8');

describe('X509', function() {
  if (process.env.BMOCHA_VALGRIND)
    this.skip();

  let i = 0;
  for (const block of pem.decode(certsData)) {
    it(`should deserialize and reserialize certificate (${i++})`, () => {
      const crt1 = x509.Certificate.decode(block.data);
      const raw1 = crt1.encode();
      const crt2 = x509.Certificate.decode(raw1);
      const raw2 = crt2.encode();

      assert.deepStrictEqual(crt1, crt2);
      assert.bufferEqual(raw1, raw2);
      assert.bufferEqual(raw1, block.data);
    });

    it(`should read JSON and write JSON (${i++})`, () => {
      const crt1 = x509.Certificate.decode(block.data);
      const json1 = crt1.getJSON();

      const crt2 = x509.Certificate.fromJSON(json1);
      const raw2 = crt2.encode();
      const json2 = crt1.getJSON();

      assert.deepStrictEqual(json1, json2);
      assert.bufferEqual(raw2, block.data);
    });
  }

  i = 0;
  for (const block of pem.decode(certificateData)) {
    it(`should verify self-signed certificate from JSON (${i++})`, () => {
      const crt1 = x509.Certificate.decode(block.data);
      const json1 = crt1.getJSON();

      const keyInfo = json1.tbsCertificate.subjectPublicKeyInfo;
      if (keyInfo.algorithm.algorithm !== 'RSAPublicKey')
        this.skip();

      const key = rsa.publicKeyImport({
        n: Buffer.from(keyInfo.publicKey.modulus, 'hex'),
        e: Buffer.from(keyInfo.publicKey.publicExponent, 'hex')
      });

      const sigAlg = json1.signatureAlgorithm.algorithm;
      if (sigAlg !== 'RSASHA256')
        this.skip();

      const sig = Buffer.from(json1.signature.value, 'hex');

      const r = rsa.verify(
        'SHA256',
        sha256.digest(crt1.tbsCertificate.encode()),
        sig,
        key);
      assert(r);
    });
  }
});
