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

const DSA_PUB_PATH = Path.resolve(__dirname, 'data', 'testdsapub.pem');

const dsaPubPem = fs.readFileSync(DSA_PUB_PATH, 'utf8');

describe('SPKI', function() {
  it('should parse SPKI', () => {
    const spki = x509.SubjectPublicKeyInfo.fromPEM(dsaPubPem);

    assert(Buffer.isBuffer(spki.raw));
    assert.strictEqual(spki.raw.length, 444);
    assert.strictEqual(spki.algorithm.algorithm.getKeyAlgorithmName(), 'DSA');
    assert.strictEqual(spki.algorithm.parameters.node.type, 16); // SEQ
    assert.strictEqual(spki.subjectPublicKey.type, 3); // BITSTRING
    assert.strictEqual(spki.subjectPublicKey.bits, 1056);

    const br = bio.read(spki.algorithm.parameters.node.value);
    const p = asn1.Integer.read(br);
    const q = asn1.Integer.read(br);
    const g = asn1.Integer.read(br);
    const y = asn1.Integer.decode(spki.subjectPublicKey.align());
    const key = new dsa.DSAPublicKey();

    key.setP(p.value);
    key.setQ(q.value);
    key.setG(g.value);
    key.setY(y.value);

    assert(dsa.publicKeyVerify(key));

    assert.strictEqual(spki.toPEM(), dsaPubPem);
  });
});
