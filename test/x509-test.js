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

let certFromJSON;

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

    it(`should read JSON and write JSON (${i})`, () => {
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

  it('should create a self-signed certificate using JSON', () => {
    // Create key pair and get JSON for pubkey
    const priv = rsa.privateKeyGenerate(2048);
    const pub = rsa.publicKeyCreate(priv);
    const pubJSON = rsa.publicKeyExport(pub);

    // Basic details, leave out optional and more complex stuff
    const json = {
      version: 2,
      serialNumber: 'deadbeef0101',
      signature: {
        algorithm: 'RSASHA256',
        parameters: {
          type: 'NULL',
          node: null
        }
      },
      issuer: [],
      validity: {
        notBefore: { type: 'UTCTime', node: '2020-04-20T18:53:25Z' },
        notAfter: { type: 'UTCTime', node: '2021-04-20T18:53:25Z' }
      },
      subject: [],
      subjectPublicKeyInfo: {
        algorithm: {
          algorithm: 'RSAPublicKey',
          parameters: {
            type: 'NULL',
            node: null
          }
        },
        publicKey: {
          modulus: pubJSON.n,
          publicExponent: pubJSON.e
        }
      },
      extensions: [
        {
          extnID: 'SubjectAltName',
          critical: false,
          extnValue: [
            { type: 'DNSName', node: '*.bcoin.io' },
            { type: 'DNSName', node: 'bcoin.io' }
          ]
        },
        {
          extnID: 'BasicConstraints',
          critical: false,
          extnValue: {cA: false, pathLenConstraint: 0}
        },
        {
          extnID: 'KeyUsage',
          critical: false,
          extnValue: [
            'digitalSignature',
            'nonRepudiation',
            'keyEncipherment',
            'dataEncipherment'
          ]
        }
      ]
    };

    // Create to-be-signed certificate object
    const tbs = x509.TBSCertificate.fromJSON(json);

    // Use helper functions for the complicated details
    tbs.issuer = x509.Entity.fromJSON({
      COUNTRY: 'US',
      PROVINCE: 'CA',
      LOCALITY: 'San Francisco',
      ORGANIZATION: 'bcrypto',
      ORGANIZATIONALUNIT: 'encodings',
      COMMONNAME: 'bcoin.io',
      EMAILADDRESS: 'satoshi@bcoin.io'
    });
    tbs.subject = x509.Entity.fromJSON({
      COUNTRY: 'US',
      PROVINCE: 'CA',
      LOCALITY: 'San Francisco',
      ORGANIZATION: 'bcrypto',
      ORGANIZATIONALUNIT: 'encodings',
      COMMONNAME: 'bcoin.io',
      EMAILADDRESS: 'satoshi@bcoin.io'
    });

    // Serialize
    const msg = sha256.digest(tbs.encode());

    // Sign
    const sig = rsa.sign('SHA256', msg, priv);

    // Complete
    certFromJSON = new x509.Certificate();
    certFromJSON.tbsCertificate = tbs;
    certFromJSON.signatureAlgorithm.fromJSON({
      algorithm: 'RSASHA256',
      parameters: {
        type: 'NULL',
        node: null
      }});
    certFromJSON.signature.fromJSON({bits: sig.length * 8, value: sig.toString('hex')});
  });

  it.skip('should verify with openssl', () => {
    const os = require('os');
    const {exec} = require('child_process');

    // Write file
    let tmp = Path.join(os.tmpdir(), 'bcrypto-test.crt');
    fs.writeFileSync(tmp, certFromJSON.toPEM());

    // Test
    exec(`openssl verify -check_ss_sig ${tmp}`, (error, stdout, stderr) => {
      assert(!error);
      assert.strictEqual('OK\n', stdout.slice(-3));
    });

    // Sanity check 1: certificate produced by openssl
    exec(`openssl verify -check_ss_sig ${certificate}`, (error, stdout, stderr) => {
      assert(!error);
      assert.strictEqual('OK\n', stdout.slice(-3));
    });

    // Sanity check 2: malleated signature fails verification
    certFromJSON.signature.value[100]++;
    tmp = Path.join(os.tmpdir(), 'bcrypto-test2.crt');
    fs.writeFileSync(tmp, certFromJSON.toPEM());
    exec(`openssl verify -check_ss_sig ${tmp}`, (error, stdout, stderr) => {
      assert(error);
      const msg = 'certificate signature failure\n';
      assert.strictEqual(msg, stdout.slice(-1 * msg.length));
    });
  });
});
