/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */
/* eslint no-unused-vars: "off" */

'use strict';

const assert = require('./util/assert');
const fs = require('fs');
const Path = require('path');
const bio = require('bufio');
const dsa = require('../lib/dsa');
const asn1 = require('../lib/encoding/asn1');
const x509 = require('../lib/encoding/x509');
const params = require('./data/dsa-params.json');

const {
  DSAParams,
  DSAPublicKey,
  DSAPrivateKey
} = dsa;

const DSA_PATH = Path.resolve(__dirname, 'data', 'testdsa.pem');
const DSA_PUB_PATH = Path.resolve(__dirname, 'data', 'testdsapub.pem');

const dsaPem = fs.readFileSync(DSA_PATH, 'utf8');
const dsaPubPem = fs.readFileSync(DSA_PUB_PATH, 'utf8');

const {
  P1024_160,
  P2048_244,
  P2048_256,
  P3072_256
} = params;

function createParams(json) {
  const p = Buffer.from(json.p, 'hex');
  const q = Buffer.from(json.q, 'hex');
  const g = Buffer.from(json.g, 'hex');
  return new dsa.DSAParams(p, q, g);
}

describe('DSA', function() {
  this.timeout(20000);

  it('should sign and verify', () => {
    // const priv = dsa.privateKeyGenerate(1024);
    const params = createParams(P2048_256);
    const priv = dsa.privateKeyCreate(params);
    const pub = dsa.publicKeyCreate(priv);

    assert(dsa.privateKeyVerify(priv));
    assert(dsa.publicKeyVerify(pub));

    const msg = Buffer.alloc(priv.size(), 0x01);
    const sig = dsa.sign(msg, priv);
    assert(sig);

    const result = dsa.verify(msg, sig, pub);
    assert(result);

    sig[(Math.random() * sig.length) | 0] ^= 1;

    const result2 = dsa.verify(msg, sig, pub);
    assert(!result2);

    assert.deepStrictEqual(
      dsa.privateKeyImport(dsa.privateKeyExport(priv)),
      priv);

    assert.deepStrictEqual(
      dsa.publicKeyImport(dsa.publicKeyExport(pub)),
      pub);
  });

  it('should sign and verify (async)', async () => {
    const size = dsa.native < 2 ? 1024 : 2048;
    const params = await dsa.paramsGenerateAsync(size);
    const priv = dsa.privateKeyCreate(params);
    const pub = dsa.publicKeyCreate(priv);

    assert(dsa.privateKeyVerify(priv));
    assert(dsa.publicKeyVerify(pub));

    const msg = Buffer.alloc(priv.size(), 0x01);
    const sig = dsa.sign(msg, priv);
    assert(sig);

    const result = dsa.verify(msg, sig, pub);
    assert(result);

    sig[(Math.random() * sig.length) | 0] ^= 1;

    const result2 = dsa.verify(msg, sig, pub);
    assert(!result2);
  });

  it('should parse SPKI', () => {
    const info = x509.SubjectPublicKeyInfo.fromPEM(dsaPubPem);
    assert(info.algorithm.algorithm.getKey() === 'dsa');
    assert(info.algorithm.parameters.type === 16); // SEQ
    assert(info.subjectPublicKey.type === 3); // BITSTRING

    const br = bio.read(info.algorithm.parameters.value);
    const p = asn1.Integer.read(br);
    const q = asn1.Integer.read(br);
    const g = asn1.Integer.read(br);
    const y = asn1.Integer.decode(info.subjectPublicKey.value);
    const key = new DSAPublicKey();

    key.setP(p.value);
    key.setQ(q.value);
    key.setG(g.value);
    key.setY(y.value);

    assert(dsa.publicKeyVerify(key));
  });
});
