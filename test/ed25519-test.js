'use strict';

const assert = require('bsert');
const random = require('../lib/random');
const ed25519 = require('../lib/ed25519');
const SHA512 = require('../lib/sha512');
const derivations = require('./data/ed25519.json');
const json = require('./data/ed25519-input.json');
const rfc8032 = require('./data/rfc8032-vectors.json');
const vectors = process.env.CI || ed25519.native ? json : json.slice(0, 128);

describe('Ed25519', function() {
  this.timeout(15000);

  it('should generate keypair and sign', () => {
    const msg = random.randomBytes(ed25519.size);
    const secret = ed25519.privateKeyGenerate();
    const pub = ed25519.publicKeyCreate(secret);

    assert(ed25519.publicKeyVerify(pub));

    const sig = ed25519.sign(msg, secret);

    assert(ed25519.verify(msg, sig, pub));

    sig[0] ^= 1;

    assert(!ed25519.verify(msg, sig, pub));

    assert.bufferEqual(
      ed25519.privateKeyImport(ed25519.privateKeyExport(secret)),
      secret);

    assert.bufferEqual(
      ed25519.privateKeyImportPKCS8(ed25519.privateKeyExportPKCS8(secret)),
      secret);

    assert.bufferEqual(
      ed25519.publicKeyImport(ed25519.publicKeyExport(pub)),
      pub);

    assert.bufferEqual(
      ed25519.publicKeyImportSPKI(ed25519.publicKeyExportSPKI(pub)),
      pub);
  });

  it('should disallow points at infinity', () => {
    // Fun fact about edwards curves: points
    // at infinity can actually be serialized.
    const msg = Buffer.from(
      '03d95e0b801ab94cfe723bc5243284a32b19a629b9cb36a8a46fcc000b6e7191',
      'hex');

    const sig = Buffer.from(''
      + '0100000000000000000000000000000000000000000000000000000000000000'
      + '0000000000000000000000000000000000000000000000000000000000000000'
      , 'hex');

    const pub = Buffer.from(
      'b85ea579c036d355451fc523b9e760a9a0bc21bbeda4fb86df90acdbcd39b410',
      'hex');

    assert(!ed25519.verify(msg, sig, pub));

    const inf = Buffer.from(
      '0100000000000000000000000000000000000000000000000000000000000000',
      'hex');

    assert(!ed25519.publicKeyVerify(inf));
    assert(!ed25519.verify(msg, sig, inf));
  });

  it('should validate small order points', () => {
    const small = [
      // 0 (order 1)
      '0100000000000000000000000000000000000000000000000000000000000000',
      // 0 (order 2)
      'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      // 1 (order 4)
      '0000000000000000000000000000000000000000000000000000000000000080',
      '0000000000000000000000000000000000000000000000000000000000000000',
      // 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
      'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
      'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
      // 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
      '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
      '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05'
    ];

    const key = ed25519.scalarGenerate();

    for (let i = 0; i < small.length; i++) {
      const str = small[i];
      const pub = Buffer.from(str, 'hex');

      if (i > 0)
        assert(ed25519.publicKeyVerify(pub));

      assert.throws(() => ed25519.deriveWithScalar(pub, key));
    }
  });

  it('should validate signatures with small order points', () => {
    const json = [
      // (-1, -1)
      [
        'afe9a024a60f51dadb0353824aba4ee1395a0eda2bb27348768472f948b6c0db',
        '1000000000000000000000000000000000000000000000000000000000000000',
        '0000000000000000000000000000000000000000000000000000000000000000',
        '1000000000000000000000000000000000000000000000000000000000000000',
        false,
        false
      ],

      // (-1, -1)
      [
        'afe9a024a60f51dadb0353824aba4ee1395a0eda2bb27348768472f948b6c0db',
        '1000000000000000000000000000000000000000000000000000000000000000',
        '0000000000000000000000000000000000000000000000000000000000000000',
        'b85ea579c036d355451fc523b9e760a9a0bc21bbeda4fb86df90acdbcd39b410',
        false,
        false
      ],

      // (0, 0)
      [
        'afe9a024a60f51dadb0353824aba4ee1395a0eda2bb27348768472f948b6c0db',
        'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
        '0000000000000000000000000000000000000000000000000000000000000000',
        'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
        false,
        true
      ],

      // (0, 1)
      [
        'ccc1291d1c67dcbb960894b4b9d4a9e2240d15bcb4d9fbcfce72b214ea6fad88',
        '0000000000000000000000000000000000000000000000000000000000000080',
        '0000000000000000000000000000000000000000000000000000000000000000',
        'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
        false,
        true
      ],

      // (1, 1)
      [
        '111fe159fd919f9569a0732de49c0f03e75f93e221edaf1e9c3ead59fa742527',
        '0000000000000000000000000000000000000000000000000000000000000080',
        '0000000000000000000000000000000000000000000000000000000000000000',
        '0000000000000000000000000000000000000000000000000000000000000080',
        false,
        true
      ],

      // (1, 2)
      [
        'cafea1043bb0f7c3600772f5e3e4710f2d9d2e8e2043496125975fb169c5a2e5',
        '0000000000000000000000000000000000000000000000000000000000000000',
        '0000000000000000000000000000000000000000000000000000000000000000',
        '0000000000000000000000000000000000000000000000000000000000000080',
        false,
        true
      ],

      // (1, 3)
      [
        '70e7cfc26ae590053b2234614a1323fca01dd3f3965f58b4b40ae7ed4858f341',
        'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
        '0000000000000000000000000000000000000000000000000000000000000000',
        '0000000000000000000000000000000000000000000000000000000000000080',
        false,
        true
      ],

      // (2, 2)
      [
        'd01dc52fbbf471b81bb8592d7461ad459f7cf74da0e8d027fcf2932aeb03a468',
        '0000000000000000000000000000000000000000000000000000000000000000',
        '0000000000000000000000000000000000000000000000000000000000000000',
        '0000000000000000000000000000000000000000000000000000000000000000',
        false,
        true
      ],

      // (2, 5)
      [
        'ea6ca21cc5e5da0363ce87883412ed774a11eed97068920030e13b9c984f21e1',
        '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
        '0000000000000000000000000000000000000000000000000000000000000000',
        '0000000000000000000000000000000000000000000000000000000000000000',
        false,
        true
      ],

      // (4, 6)
      [
        'f9ff9b3dbbf2b6dc3d5d49fbd6fe03ec0bc014abcee4a04134cd9043dbe33237',
        '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
        '0000000000000000000000000000000000000000000000000000000000000000',
        'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
        true,
        true
      ]
    ];

    const vectors = [];

    for (const [m, r, s, p, r1, r2] of json) {
      const msg = Buffer.from(m, 'hex');
      const sig = Buffer.from(r + s, 'hex');
      const pub = Buffer.from(p, 'hex');

      vectors.push([msg, sig, pub, r1, r2]);
    }

    const batch = [];

    for (const [msg, sig, pub, res1, res2] of vectors) {
      assert.strictEqual(ed25519.verify(msg, sig, pub), res1);
      assert.strictEqual(ed25519.verifySingle(msg, sig, pub), res2);

      if (res2)
        batch.push([msg, sig, pub]);
    }

    batch.sort(() => Math.random() > 0.5 ? 1 : -1);

    assert.strictEqual(ed25519.verifyBatch(batch), true);
  });

  it('should validate signatures with torsion components', () => {
    const json = [
      // (0, 0)
      [
        'ea3001a37ed97f712b5ccac99a46ee3c1bd55dfa4489c169b91a284c94cf6870',
        '2974febee11b1373fbec0546ab43ec72f62777ff2d476f590fe98e2bb0adc4fd',
        'ee089ecff4a991e098c51638ce220a146dbd29be75dddae996d746c44286440e',
        '66c2d7d3b5a0264fb039b6d1d735192ff7157a664fe87ed15c254dc59fa14067',
        true,
        true
      ],

      // (0, 1)
      [
        '567c6518fa1cfac1f48878034b028e62325b80f8c556dfe1018dc2b9c3a96d0b',
        'a3d0566b5714e5de2e46d928ff09d1a7b1bf7d539503f2bfb351771b6e643674',
        '227319f7f4e72d996bcfe4461a66d71f70e2944e50dd1d86ebd7a065f2549f00',
        '884e2fb0e43cfe5252ff71404fcb2985e0a428670a3d75c844b2cc54bf751c14',
        false,
        true
      ],

      // (0, 1)
      [
        '1984db29072800cb09ff16971af888746d8d94998175ce7c02ce020c0b2e3ecd',
        '7467982669dee781d1a6e0c1df56f5a306256b153c1a44c2823f488b524979e5',
        '333a6ef747af4b8f17855ffdd813e8ff55d4d76b71d059c8213b763bdd41fd0c',
        'a7c4cb985dce43fa2ed7449bab14c646392c195d2e47808e586d1056659b9dd0',
        false,
        true
      ],

      // (1, 1)
      [
        '2a8c1b6cb31ef9f741ed13877bb59c1e17396b48519f5b0754635d8ec86c98ae',
        '5bc95e8daaa4fad481188ee87a29119dc3fc68ad2a059332173cb313f1301eb5',
        '89589b3efbcad293bd3ba337de613b779b70c2f2cc8656b538459988290fa208',
        'a2148a3e153c374b623f3342c9e7c36c2edaae0b8e3fa84f0134510da82045b5',
        true,
        true
      ],

      // (1, 1)
      [
        'cd383acf53cbfe295aee065c26fca46ca9aa86029e3d3fc90fc7c5cc21d9ce93',
        '92c316d4cbac2d9510dd1010f4a3837afec490038590d39ba1e391ce416a0008',
        '210d0615fa72b60e6b8abada74f8270953cf4717cb74de9c97940fec8e911906',
        'd6ffa0f51ffd05af7d45204f1d4056ba25ab995ca8eb01456a73ef26b5ec387d',
        false,
        true
      ],

      // (1, 2)
      [
        '48f2729c8a13616b8b0db7eacb553656ef5c39fb62dd6a05abffdfe53dfeec81',
        'c453b2478fc5bdfe3c8fd7d69d49185aa692612cb40f435a9bf8d9d7a8325a74',
        '08898cf81ff73ac863eed98800822cf27fcc9602218c2476114456ab5988b50d',
        'e44163cfc9c9ea02e35ba0fc8954cfc507b870e065ae853237bc76f83d5f8462',
        true,
        true
      ],

      // (1, 2)
      [
        'cdfb29c9b5a7f7b340739b8f4baf39300bd3d312ef4ae2a0c63309b7b85ec1ab',
        '26726e6488e2d1b99cd0fb568d6e50c1fe0e6d9f15104e7e59f8c3503468f7d4',
        'f7a4c3e9b54e81fbe527adde9161f81533132835e69c97f2ade7cce88677ca06',
        'cac20c3e0629d24031d4cb2cdb0e3730e5872aa4c4438e635713ad2e6917f35d',
        false,
        true
      ],

      // (1, 3)
      [
        '44975fe9ac5860e0adb44fd9da2601561ee9e2bd0d9330e8de6099218a44c4a1',
        'ffa0aa4312edb6747cef1d9d741491e190b232d46b303faf13dfda4ce3ccc186',
        '6dbdae5f7214efa4e0167eac864838b9ccb6a918e7879e3f8e92c3b3a1deee08',
        '489f4c34ae338622ed3e6dd133562f883c6871736df1aa0fe896d5e1214763a9',
        false,
        true
      ],

      // (2, 2)
      [
        '1e8f7bf9b6bbc6f44f4d0dad6d4ac73dd22df672a80b3b43009be13fdb90e6e9',
        '51c1dd5b9341dc93e9fb1d513f928d47a7fac5094316687ef569aeab728f0ad6',
        '6d258d8bcc0c7be0687c6ee3572fdb3df4188893462052aabd6bd7750ed2c209',
        '6a0c515aef13743ff0583cb4f7eace9bfce78d6a736a819b2c33f6f611aceffd',
        true,
        true
      ],

      // (2, 2)
      [
        '4892f822507861306a5eae42994ecd4ab67c0792f40595feb00a53345975269d',
        '7326662b35af2dcb8bc2208c8d1c266dd649075a251c7d6a5cd122fe41e4a96c',
        '8176e3769b3045e96f0379a78238b189984394fa91adf21046be3d29d317cb03',
        'b666f127f6bb54322d0ab1f36325ae9aeb6d33bfb27dac09721d00a7013b715b',
        false,
        true
      ],

      // (2, 5)
      [
        'a3865d3ba7c56bc4a939ffc4073c7df6a3489646a0742532d27a75a369991b0d',
        '0457d9578c8c349e5775667c48f6f295fee3d0dc9e9cac2c97a3829dda444c68',
        'd15945e767da3d1d7c774a31e85657b466348fb964ef486d765b3673cfa4ab0e',
        'f6d8e06fac3582ebcedbaa7c6092eae6bb876f157758a4a25017e44de5bc58d8',
        false,
        true
      ],

      // (4, 6)
      [
        '495f28fc18822be697001eab9ddd6deac91da5f4ba907be8f6cb71c3a330a08c',
        '6937da177a34ec59d03aa4bb97f85029521d89dabdea024c2e2347aa5cd4cc16',
        '93d0e2b229abc79ead84c4eadaab388cdcc99f4b9e912fd040190f2888f85d07',
        'e984754a3e1d218a12aa4bd8497dc11fa7eb094dc5cc5962a775df2dc4a430d0',
        false,
        true
      ]
    ];

    const vectors = [];

    for (const [m, r, s, p, r1, r2] of json) {
      const msg = Buffer.from(m, 'hex');
      const sig = Buffer.from(r + s, 'hex');
      const pub = Buffer.from(p, 'hex');

      vectors.push([msg, sig, pub, r1, r2]);
    }

    const batch = [];

    for (const [msg, sig, pub, res1, res2] of vectors) {
      assert.strictEqual(ed25519.verify(msg, sig, pub), res1);
      assert.strictEqual(ed25519.verifySingle(msg, sig, pub), res2);

      batch.push([msg, sig, pub]);
    }

    batch.sort(() => Math.random() > 0.5 ? 1 : -1);

    assert.strictEqual(ed25519.verifyBatch(batch), true);
  });

  it('should reject non-canonical R value', () => {
    const json = [
      '9323f5ce965d97fd569c9af87dfe70ae599f6e178e63f210f7d8a0e15d98b0ef',
      'e9170093b59dff6472fc2705d576d1e0d51880c5ccc51ab2bf3531c0bf505ca5',
      '4d993bd274ce76684af9a6fef3a899ac4f2568fd501f3e5685d57b8c6e993200',
      'e3555db00fad12998e0d4d107e6b78d541f4f796bd747a25fc66e52ec68de8fe'
    ];

    const [m, r, s, p] = json;
    const msg = Buffer.from(m, 'hex');
    const sig = Buffer.from(r + s, 'hex');
    const pub = Buffer.from(p, 'hex');

    assert.strictEqual(ed25519.verify(msg, sig, pub), false);
    assert.strictEqual(ed25519.verifySingle(msg, sig, pub), false);
  });

  it('should reject non-canonical S value', () => {
    const json = [
      'f36eb2b77b4a45381753b3911a1d209384b591a64172968dd2dd0983a82fb835',
      'bf06a03fb431df03ddf943a0423ba3a96e1e08d3d8c35c40f31a19f476780e12',
      '52d25d60730fc3752f2795721ac98dbc2c1df63f10b7f9a007552bbf8db69d15',
      'd8c6f482b515dd8443d1835f6ed31bf3afe8a588d59617e26a18495d8824aa6d'
    ];

    const [m, r, s, p] = json;
    const msg = Buffer.from(m, 'hex');
    const sig = Buffer.from(r + s, 'hex');
    const pub = Buffer.from(p, 'hex');

    assert.strictEqual(ed25519.verify(msg, sig, pub), false);
    assert.strictEqual(ed25519.verifySingle(msg, sig, pub), false);
  });

  it('should reject non-canonical key', () => {
    const json = [
      '380b028b7e0124a0add4ee2b579b36851e0d739089b275648ea289185fd8cdb0',
      '6170b83c58abc3cd3e3d7c0df5a789d0d3b63b608c84f2cf8ebe3d0635422309',
      'a78437dec59823120b16d782b1c787273f8aee12c70dc3f0cc7efd508684060e',
      'c26ba75556c9a6124a9d1a5168ec71458009b8b5650593ea7264974511397c48'
    ];

    const [m, r, s, p] = json;
    const msg = Buffer.from(m, 'hex');
    const sig = Buffer.from(r + s, 'hex');
    const pub = Buffer.from(p, 'hex');

    assert.strictEqual(ed25519.verify(msg, sig, pub), false);
    assert.strictEqual(ed25519.verifySingle(msg, sig, pub), false);
  });

  it('should expand key', () => {
    const secret = Buffer.from(
      '5bc1d80b378c350663a6862f21599ee3b09fb4255a0dfad3d907d5ca7ab2b223',
      'hex');

    const [key, prefix] = ed25519.privateKeyExpand(secret);

    assert.bufferEqual(key,
      '00f8b1bd40cbf4c9642270f5b4eb4645514097f8ebe31c9f08be5e4fee6f9d5b',
      'hex');

    assert.bufferEqual(prefix,
      '93e1f48384097145d1981875ef22a4e64dc47e43e997beb9894a4603e09cc290',
      'hex');

    assert.bufferEqual(ed25519.privateKeyConvert(secret), key);
  });

  it('should do ECDH', () => {
    const alicePriv = ed25519.privateKeyGenerate();
    const alicePub = ed25519.publicKeyCreate(alicePriv);

    const bobPriv = ed25519.privateKeyGenerate();
    const bobPub = ed25519.publicKeyCreate(bobPriv);

    const aliceSecret = ed25519.derive(bobPub, alicePriv);
    const bobSecret = ed25519.derive(alicePub, bobPriv);

    assert.bufferEqual(aliceSecret, bobSecret);

    const secret = aliceSecret;
    const xsecret = ed25519.publicKeyConvert(secret);
    const xalicePub = ed25519.publicKeyConvert(alicePub);
    const xbobPub = ed25519.publicKeyConvert(bobPub);

    assert.notBufferEqual(xsecret, secret);

    const xaliceSecret = ed25519.exchange(xbobPub, alicePriv);
    const xbobSecret = ed25519.exchange(xalicePub, bobPriv);

    assert.bufferEqual(xaliceSecret, xsecret);
    assert.bufferEqual(xbobSecret, xsecret);
  });

  it('should do ECDH (with scalar)', () => {
    const aliceSeed = ed25519.privateKeyGenerate();
    const alicePriv = ed25519.privateKeyConvert(aliceSeed);
    const alicePub = ed25519.publicKeyFromScalar(alicePriv);

    assert.bufferEqual(alicePub, ed25519.publicKeyCreate(aliceSeed));

    const bobSeed = ed25519.privateKeyGenerate();
    const bobPriv = ed25519.privateKeyConvert(bobSeed);
    const bobPub = ed25519.publicKeyFromScalar(bobPriv);

    assert.bufferEqual(bobPub, ed25519.publicKeyCreate(bobSeed));

    const aliceSecret = ed25519.deriveWithScalar(bobPub, alicePriv);
    const bobSecret = ed25519.deriveWithScalar(alicePub, bobPriv);

    assert.bufferEqual(aliceSecret, bobSecret);

    const xalicePub = ed25519.publicKeyConvert(alicePub);
    const xbobPub = ed25519.publicKeyConvert(bobPub);

    const xaliceSecret = ed25519.exchangeWithScalar(xbobPub, alicePriv);
    const xbobSecret = ed25519.exchangeWithScalar(xalicePub, bobPriv);

    assert.bufferEqual(xaliceSecret, xbobSecret);
  });

  it('should do ECDH (vector)', () => {
    const alicePriv = Buffer.from(
      '50ec6e55b18b882e06bdc12ff2f80f8f8fa68b04370b45439cf80b4e02610e1e',
      'hex');

    const bobPriv = Buffer.from(
      'c3fb48a8c4e961ab3edb799eea22ff1d07b803140734266748ea4c753dd3655d',
      'hex');

    const alicePub = ed25519.publicKeyCreate(alicePriv);
    const bobPub = ed25519.publicKeyCreate(bobPriv);

    const xsecret = Buffer.from(
      '4084c076e4ff79e8af71425c0c0b573057e9ebf36185ec8572ec161ddf6f2731',
      'hex');

    const aliceSecret = ed25519.derive(bobPub, alicePriv);
    const xaliceSecret = ed25519.publicKeyConvert(aliceSecret);
    const bobSecret = ed25519.derive(alicePub, bobPriv);
    const xbobSecret = ed25519.publicKeyConvert(bobSecret);

    assert.notBufferEqual(aliceSecret, xsecret);
    assert.bufferEqual(xaliceSecret, xsecret);
    assert.bufferEqual(xbobSecret, xsecret);

    const xalicePub = ed25519.publicKeyConvert(alicePub);
    const xbobPub = ed25519.publicKeyConvert(bobPub);

    const xaliceSecret2 = ed25519.exchange(xbobPub, alicePriv);
    const xbobSecret2 = ed25519.exchange(xalicePub, bobPriv);

    assert.bufferEqual(xaliceSecret2, xsecret);
    assert.bufferEqual(xbobSecret2, xsecret);
  });

  it('should generate keypair and sign with additive tweak', () => {
    const key = ed25519.privateKeyGenerate();
    const pub = ed25519.publicKeyCreate(key);
    const tweak = ed25519.scalarGenerate();
    const msg = random.randomBytes(32);
    const child = ed25519.publicKeyTweakAdd(pub, tweak);
    const sig = ed25519.signTweakAdd(msg, key, tweak);

    assert(ed25519.scalarVerify(tweak));
    assert.notBufferEqual(child, pub);

    const childPriv = ed25519.scalarTweakAdd(ed25519.privateKeyConvert(key), tweak);
    const childPub = ed25519.publicKeyFromScalar(childPriv);

    assert.bufferEqual(childPub, child);

    assert(ed25519.verify(msg, sig, child));

    const sig2 = ed25519.signWithScalar(msg, childPriv, msg);

    assert(ed25519.verify(msg, sig2, child));

    const real = ed25519.scalarReduce(ed25519.privateKeyConvert(key));
    const parent = ed25519.scalarTweakAdd(childPriv, ed25519.scalarNegate(tweak));

    assert.bufferEqual(parent, real);

    const tweakPub = ed25519.publicKeyFromScalar(tweak);
    const parentPub = ed25519.publicKeyAdd(childPub, ed25519.publicKeyNegate(tweakPub));

    assert.bufferEqual(parentPub, pub);
  });

  it('should generate keypair and sign with additive tweak (vector)', () => {
    const key = Buffer.from(
      'd0e9d24169a720d5e3d07f71bf68802ba365be3e85c3c20f974a8dd3e0c97f79',
      'hex');

    const pub = Buffer.from(
      'b85ea579c036d355451fc523b9e760a9a0bc21bbeda4fb86df90acdbcd39b410',
      'hex');

    const tweak = Buffer.from(
      'fff3c02b12bf6670ada449160e3e586043766dcc7beb12e804cc375a4cd319ff',
      'hex');

    const msg = Buffer.from(
      '03d95e0b801ab94cfe723bc5243284a32b19a629b9cb36a8a46fcc000b6e7191',
      'hex');

    const childExpect = Buffer.from(
      '1098877517226435d2ac8021b47fc87b4b8a9d15f6a19431eae10a6576c21837',
      'hex');

    const sigExpect = Buffer.from(''
      + '493d2b108b8350405d08672e6b5c3c6f9a5501aa07d4a44d40ae7f4d781fb146'
      + '941b4d9e7ac7a70e8fbf466ef806d791b431e6c832b4ad1d7310f45d5545200a'
      , 'hex');

    const child = ed25519.publicKeyTweakAdd(pub, tweak);
    const sig = ed25519.signTweakAdd(msg, key, tweak);

    assert.bufferEqual(child, childExpect);
    assert.bufferEqual(sig, sigExpect);

    assert(ed25519.verify(msg, sig, child));
  });

  it('should generate keypair and sign with multiplicative tweak', () => {
    const key = ed25519.privateKeyGenerate();
    const pub = ed25519.publicKeyCreate(key);
    const tweak = ed25519.scalarGenerate();
    const msg = random.randomBytes(32);
    const child = ed25519.publicKeyTweakMul(pub, tweak);

    assert(ed25519.scalarVerify(tweak));
    assert.notBufferEqual(child, pub);

    const sig = ed25519.signTweakMul(msg, key, tweak);

    const childPriv = ed25519.scalarTweakMul(ed25519.privateKeyConvert(key), tweak);
    const childPub = ed25519.publicKeyFromScalar(childPriv);

    assert.bufferEqual(childPub, child);

    assert(ed25519.verify(msg, sig, child));

    const sig2 = ed25519.signWithScalar(msg, childPriv, msg);

    assert(ed25519.verify(msg, sig2, child));

    const real = ed25519.scalarReduce(ed25519.privateKeyConvert(key));
    const parent = ed25519.scalarTweakMul(childPriv, ed25519.scalarInvert(tweak));

    assert.bufferEqual(parent, real);
  });

  it('should generate keypair and sign with multiplicative tweak (vector)', () => {
    const key = Buffer.from(
      '5bc1d80b378c350663a6862f21599ee3b09fb4255a0dfad3d907d5ca7ab2b223',
      'hex');

    const pub = Buffer.from(
      'f921f787e3e4e829a4be69a499f06e69d7bddbb7f6a90ccfba785faebd8d7a02',
      'hex');

    const tweak = Buffer.from(
      '7623971ec36c8557a8b1debe80f5f305989d0e51b62805c88590ee5b586a648a',
      'hex');

    const msg = Buffer.from(
      'e4a733e761eb1d0263fd713e7f815c947b29ed5a9140fa893bf59b11e1c32b80',
      'hex');

    const childExpect = Buffer.from(
      '78103d0a0342dca9a5044834f6dcf9472b8c1c3308fc4b49b13d451ddb7792f0',
      'hex');

    const sigExpect = Buffer.from(''
      + '4d1fa52a9dada415d4fff323257cfbdbaa571164873bcbd3e88acbe0a12d7e46'
      + 'e8b45144ed4ef9db77ac7e453e78aa4cd038f189bcff20d62de3339f80e51c01'
      , 'hex');

    const child = ed25519.publicKeyTweakMul(pub, tweak);
    const sig = ed25519.signTweakMul(msg, key, tweak);

    assert.bufferEqual(child, childExpect);
    assert.bufferEqual(sig, sigExpect);

    assert(ed25519.verify(msg, sig, child));
  });

  it('should generate keypair and sign with multiplicative tweak * cofactor', () => {
    const cofactor = Buffer.alloc(32, 0x00);
    cofactor[0] = 8;

    const key = ed25519.privateKeyGenerate();
    const pub = ed25519.publicKeyCreate(key);
    const tweak_ = ed25519.scalarGenerate();
    const msg = random.randomBytes(32);
    const tweak = ed25519.scalarTweakMul(tweak_, cofactor);
    const child = ed25519.publicKeyTweakMul(pub, tweak);
    const child_ = ed25519.publicKeyTweakMul(
      ed25519.publicKeyTweakMul(pub, tweak_),
      cofactor);

    assert.bufferEqual(child, child_);
    assert(ed25519.scalarVerify(tweak_));
    assert.notBufferEqual(child, pub);

    const sig = ed25519.signTweakMul(msg, key, tweak);

    const childPriv = ed25519.scalarTweakMul(ed25519.privateKeyConvert(key), tweak);
    const childPub = ed25519.publicKeyFromScalar(childPriv);

    assert.bufferEqual(childPub, child);

    assert(ed25519.verify(msg, sig, child));

    const sig2 = ed25519.signWithScalar(msg, childPriv, msg);

    assert(ed25519.verify(msg, sig2, child));
  });

  it('should generate keypair and sign with multiplicative tweak * cofactor (vector)', () => {
    const cofactor = Buffer.alloc(32, 0x00);
    cofactor[0] = 8;

    const key = Buffer.from(
      '5bc1d80b378c350663a6862f21599ee3b09fb4255a0dfad3d907d5ca7ab2b223',
      'hex');

    const pub = Buffer.from(
      'f921f787e3e4e829a4be69a499f06e69d7bddbb7f6a90ccfba785faebd8d7a02',
      'hex');

    const tweak_ = Buffer.from(
      '7623971ec36c8557a8b1debe80f5f305989d0e51b62805c88590ee5b586a648a',
      'hex');

    const msg = Buffer.from(
      'e4a733e761eb1d0263fd713e7f815c947b29ed5a9140fa893bf59b11e1c32b80',
      'hex');

    const childExpect = Buffer.from(
      'c616988e326d0b8be64e028942c68db3bc2f0808d5ca7c2e8b041e12b7b133fa',
      'hex');

    const sigExpect = Buffer.from(''
      + 'b958f47421ddb4fa1d012ab40a9b0c6d3850c85acf5ba313ffe77dd9b212f8a9'
      + '84ae985e13f77a441c012c5f3b16735de3a94bd2e3e72c80be6b41bbe2338305'
      , 'hex');

    const tweak = ed25519.scalarTweakMul(tweak_, cofactor);
    const child = ed25519.publicKeyTweakMul(pub, tweak);
    const sig = ed25519.signTweakMul(msg, key, tweak);

    assert.bufferEqual(child, childExpect);
    assert.bufferEqual(sig, sigExpect);

    assert(ed25519.verify(msg, sig, child));
  });

  it('should modulo scalar', () => {
    const scalar0 = Buffer.alloc(0);
    const mod0 = ed25519.scalarReduce(scalar0);

    assert.bufferEqual(mod0,
      '0000000000000000000000000000000000000000000000000000000000000000',
      'hex');

    const scalar1 = Buffer.alloc(1, 0x0a);
    const mod1 = ed25519.scalarReduce(scalar1);

    assert.bufferEqual(mod1,
      '0a00000000000000000000000000000000000000000000000000000000000000',
      'hex');

    const scalar2 = Buffer.alloc(32, 0xff);
    const mod2 = ed25519.scalarReduce(scalar2);

    assert.bufferEqual(mod2,
      '1c95988d7431ecd670cf7d73f45befc6feffffffffffffffffffffffffffff0f',
      'hex');

    const scalar3 = Buffer.alloc(33, 0xff);

    scalar3[32] = 0x0a;

    const mod3 = ed25519.scalarReduce(scalar3);

    assert.bufferEqual(mod3, mod2);
  });

  it('should convert to montgomery and back', () => {
    const secret = ed25519.privateKeyGenerate();
    const pub = ed25519.publicKeyCreate(secret);
    const sign = (pub[31] & 0x80) !== 0;
    const xpub = ed25519.publicKeyConvert(pub);
    const pub2 = ed25519.publicKeyDeconvert(xpub, sign);

    assert.bufferEqual(pub2, pub);
  });

  it('should do elligator2 (edwards)', () => {
    const u1 = random.randomBytes(32);
    const p1 = ed25519.publicKeyFromUniform(u1);
    const u2 = ed25519.publicKeyToUniform(p1);
    const p2 = ed25519.publicKeyFromUniform(u2);
    const u3 = ed25519.publicKeyToUniform(p2);
    const p3 = ed25519.publicKeyFromUniform(u3);

    assert.bufferEqual(p1, p2);
    assert.bufferEqual(p2, p3);
  });

  it('should do elligator2 (mont)', () => {
    const u1 = random.randomBytes(32);
    const p1 = ed25519.pointFromUniform(u1);
    const u2 = ed25519.pointToUniform(p1, false);
    const p2 = ed25519.pointFromUniform(u2);
    const u3 = ed25519.pointToUniform(p2, false);
    const p3 = ed25519.pointFromUniform(u3);

    assert.bufferEqual(p1, p2);
    assert.bufferEqual(p2, p3);
  });

  it('should do elligator2 on curve25519 basepoint', () => {
    const p = Buffer.alloc(32, 0x00);
    p[0] = 9;

    const u = ed25519.pointToUniform(p, false);
    const b = u[31] & 0x80;

    u[31] &= ~0x80;

    assert.bufferEqual(u,
      '3489d2523e24d6bb0f7514be6289094e619902b813ef892018585e3b1f0f5654');

    u[31] |= b;

    const q = ed25519.pointFromUniform(u);

    assert.bufferEqual(q, p);
  });

  it('should do elligator2 (vector)', () => {
    const u1 = Buffer.from(
      'be6d3d8d621562f8e1e9fdd93a760e7e7f27b93c0879a5414525b59bded49b61',
      'hex');

    const p1 = ed25519.publicKeyFromUniform(u1);

    assert.bufferEqual(p1,
      'cc2947ef03b978b3c7b418e2acdf52bc26f51457d7b21730c551bbcf4cb2e27d');

    const u2 = ed25519.publicKeyToUniform(p1);

    u2[31] &= ~0x80;
    assert.bufferEqual(u2, u1);

    const p2 = ed25519.publicKeyFromUniform(u2);

    const u3 = ed25519.publicKeyToUniform(p2);

    u3[31] &= ~0x80;
    assert.bufferEqual(u3, u1);

    const p3 = ed25519.publicKeyFromUniform(u3);

    assert.bufferEqual(p1, p2);
    assert.bufferEqual(p2, p3);
  });

  it('should invert elligator2 on troublesome point', () => {
    const p = Buffer.from(
      '6da9f400aefa72f6510793baaee019971b66114230d43802858f6e776fef7658',
      'hex');

    const u = ed25519.pointToUniform(p, false);

    u[31] &= ~0x80;

    assert.bufferEqual(u,
      'be6d3d8d621562f8e1e9fdd93a760e7e7f27b93c0879a5414525b59bded49b61');
  });

  it('should pass elligator2 test vectors', () => {
    const preimages = [
      '031515eaf0c89d80b9c53045143fd6f2964000525031faed20ef78072af336d7',
      '3b711832ccac412eb3b7d05255cb08a827cce31462d0578951fd1360563e975e',
      'fec4f15e310b1a99acb645e88d20f6924e0fdc00dcc5d19aaf7365cd46ed9d00',
      '20288b154f4780b149070d2052d45bf6c5b8aa33d73c1e0e0673a7ff94aa9eb3',
      '0b1ae9649e90b763b4dc6ad41a7e25c78e7c2e0cf96ff80842884a864038c010',
      '994a92eb0553aaf10c391efa03ccf32536f85ee2fe345a3d81ac08080a616681',
      '210c050fafa9565b9cb91f37a0cb194b9616ece3dc089cd2d27525353ba553ab',
      '4c8c847b0d328c479dadd5c98ecdb9f4ff5b6714b7e47ded99475c9ef0fe2a0f',
      'e2a380393a2249a87bd9bff48bd2daa48e59aa891cce57bcd2db531778ae0950',
      'd17e4047be6bb60c2d5d5f2bf4d0a747f14cbc08eb876e0f3cb83e0dab7fa8e7',
      '54e6ac2a4431025712f68d7ac310ec1257e541decfe968e5c70f80529efbfb94',
      '94bab539b817bbfea03585d6a0f34cebd34a3266f14dcf83dcfe92057375e4f3',
      'b46981fdb99dae76e1b1f722c09140ee9958f3bd3529de088fea75f279259755',
      'f945c0ece4291f4920969ec7b6face8044acfe345b8c167db9e30857b434d4a5',
      '9a619fe612013118a65f0e629f6f1c3d6029575e4dbf5f75cfa82ee3cac14d1f',
      'a94ebddd48f3f1860288a68afa9993463b90e80505abc3ae00466dae9cfdabc5'
    ];

    const keys = [
      '8e41460d830ff06e0aa61b48236a2c59e3f9f4bfdbfad0ea689693a0bb4202fe',
      'dd0018537463f9a6b7d8ad2835239068c1ec823300b2f8512f6c21254c1ef7af',
      '56b39eac3ed8a21170d43d1fc3eb9652ba3c59f0056a9c5a297b84a22b69d451',
      'dcbb3f5ac49349e7649b7046551bf8b91252ed1e253ffebf2103b39959acf375',
      'dda2618dea7954be90132989f633cd27aab8c2d34a27baa600d2248465baffeb',
      '937504cd60a50f8ed765353093b03a184d97c4329d5c15d007c81d9b8577058b',
      'e5ccb7d4087ef376abe83c65e723ef92ce4055e71fc4d16806a11571b01bef88',
      'e607775e58eb1940872c777045ec95c1d3a411f84978207a7525027fb5262413',
      'f16082b21fe30308185b9abf6a968fd177d950dbc11278150ae1c584f4604f66',
      '3ca574e0f07775f1ce61dfb3aaff2f080d253701b0e98617600e0b056b573bf1',
      'd88e8ac43439cc47af52ab76575e3d3f2de1a2670ac66ed9cdd219e12def9803',
      '233febde461178fbd36fc25ed8c796b62bff8da0abdad1a7decefb68f94d986b',
      'f1a8f5ba88cc36322c05ebb3c16ea24472c88b83436bbbe5fcbd321d91bd9a3f',
      '11e876de9dda80763d9632e2ac57b1a7e10ed09ff76d58e1adaeea96ae0e2d92',
      'f39869347e89e1a3dc4962a76895db6ee169cd92d3c506698d642b1942ab5046',
      '879ed3d4d9d1c6bdc0ad1e6b4a22b06f6eff495b487e5a8b31d5ec2215aca1d0'
    ];

    const points = [
      '189012a627d9a4aab9ffd5b12614c12ece595cb2de6659ee0115434aa43d0c17',
      '994c53b397403ec428b6a115a600bfadd11248a5740fbcf9340fa2b8bd6a3e1a',
      '50eb7d75bfc701454ba80ac8cd0d75881894e757e2af74ab3a55a3a2eb7d5048',
      'cecfd58de6e95501d41833036ab884d93b4ac4beefcdf0a3798c3f653e6b794a',
      'bf8794f00f3508b81bed449962576d2b56428cb663ac85c599b06a914ce0f81d',
      '64affcfb5b73b8f072b21cce93e28b4b5c7183333e58ae529bd8310131e96306',
      '513cdbfb163ccc5f3b5ca6829cfd6c2ecab2e6bc265f00af1daf60dedc818968',
      '39607313cd028cbae4c413dee9d5568b35861e4308d02d7089b2ff3fa6fcfa77',
      '00874b22081923de306395a0d6e2aa845e2b2a95060a2ef198fa5b952682db76',
      'ddb322575b23a4583824b42e018fec37eb4fe97063d73f8713f8cd4adc65c56a',
      '9017c54cf142f3c129aafc84d23f52b30da92b69bcb7564fd37c68721c838531',
      '374160d46e928a1f656da9737279bb7af6463d771b8d64d2cd38f7906e14be2f',
      '0d7a2c2d450400a11467972044c011d22057822d9089bf8933f0fece595a746b',
      '78e9cb2565185d5bab8f8dfb14c894d277ba34f48b68641af1ccfe0d80676555',
      'd82e34a35eca1e3eee274505eecb164361ab6cd0128be9a56b8d536234e06b47',
      '278d52eec3671c4b0b838cb3750e5f069c246fef327d958f59c2621697a2401e'
    ];

    const raws1 = [
      '031515eaf0c89d80b9c53045143fd6f2964000525031faed20ef78072af33657',
      '3b711832ccac412eb3b7d05255cb08a827cce31462d0578951fd1360563e97de',
      'e82f53000fe126d48f88ea89b1dd1bfad7739b2324ccd56b68e3d785cd3c65d9',
      '20288b154f4780b149070d2052d45bf6c5b8aa33d73c1e0e0673a7ff94aa9e33',
      'bde7cd91b521bf048448e07932a58c1d4bba7c0174f8c5c1415e618345280c42',
      '994a92eb0553aaf10c391efa03ccf32536f85ee2fe345a3d81ac08080a616601',
      '210c050fafa9565b9cb91f37a0cb194b9616ece3dc089cd2d27525353ba5532b',
      '4c8c847b0d328c479dadd5c98ecdb9f4ff5b6714b7e47ded99475c9ef0fe2a0f',
      'e2a380393a2249a87bd9bff48bd2daa48e59aa891cce57bcd2db531778ae0950',
      'd17e4047be6bb60c2d5d5f2bf4d0a747f14cbc08eb876e0f3cb83e0dab7fa8e7',
      '54e6ac2a4431025712f68d7ac310ec1257e541decfe968e5c70f80529efbfb14',
      '766237971fefeb79c20e2d9a518f1ed58349f24e9649c654a90a6c5149ee0a3a',
      'b46981fdb99dae76e1b1f722c09140ee9958f3bd3529de088fea75f2792597d5',
      '817a2d7eefc695c585bb67ead7b0a18774ec6b535cb2975641b17e02141392ea',
      '120a06954108d6e782650f9be46f0aac8f98b9106bc2a46800f35ebd31aa893f',
      '1740d2a716c9ed67628e67a6317a05800bdec35de88debe67f6b7f6b78455cdd'
    ];

    const raws2 = [
      'e42ae1e98c4b5fce683f2735c18c8a499ff0c9df7c7847841fdffb7684d22daa',
      'f25a93b21096c8db1d2be577e813c0c20a1e5e3a6118f147c6540290d78f0aab',
      'e82f53000fe126d48f88ea89b1dd1bfad7739b2324ccd56b68e3d785cd3c6559',
      '20288b154f4780b149070d2052d45bf6c5b8aa33d73c1e0e0673a7ff94aa9e33',
      'e2e5169b616f489c4b23952be581da387183d1f3069007f7bd77b579bfc73fef',
      'e41c000d542424a85abf3df77a41aac37802b9a13d41666733ff37f6ab0cdfb8',
      'e635d31cf9a7d0d8e33bd59b616dfc440ba1c04ecc48d3a5f65ab19be01e8bfd',
      '4c8c847b0d328c479dadd5c98ecdb9f4ff5b6714b7e47ded99475c9ef0fe2a8f',
      'e2a380393a2249a87bd9bff48bd2daa48e59aa891cce57bcd2db531778ae09d0',
      'f2adce6d1db7834a2f08bb615e82696b4d046a7bb94db4edfc1228df09a02fb3',
      '54e6ac2a4431025712f68d7ac310ec1257e541decfe968e5c70f80529efbfb94',
      '766237971fefeb79c20e2d9a518f1ed58349f24e9649c654a90a6c5149ee0a3a',
      'b46981fdb99dae76e1b1f722c09140ee9958f3bd3529de088fea75f2792597d5',
      'f4b93f131bd6e0b6df6961384905317fbb5301cba473e982461cf7a84bcb2b5a',
      '120a06954108d6e782650f9be46f0aac8f98b9106bc2a46800f35ebd31aa893f',
      '44b14222b70c0e79fd77597505666cb9c46f17fafa543c51ffb992516302543a'
    ];

    const un = (r) => {
      r = Buffer.from(r);
      r[31] &= ~0x80;
      return r;
    };

    for (let i = 0; i < 16; i++) {
      const preimage = Buffer.from(preimages[i], 'hex');
      const key = Buffer.from(keys[i], 'hex');
      const point = Buffer.from(points[i], 'hex');
      const raw1 = Buffer.from(raws1[i], 'hex');
      const raw2 = Buffer.from(raws2[i], 'hex');

      assert.strictEqual(ed25519.publicKeyVerify(key), true);
      assert.bufferEqual(ed25519.publicKeyFromUniform(preimage), key);
      assert.bufferEqual(ed25519.pointFromUniform(preimage), point);
      assert.bufferEqual(un(ed25519.publicKeyToUniform(key)), un(raw1));
      assert.bufferEqual(un(ed25519.pointToUniform(point, false)), un(raw2));
      assert.bufferEqual(ed25519.publicKeyFromUniform(raw1), key);
      assert.bufferEqual(ed25519.pointFromUniform(raw2), point);
    }
  });

  it('should test random oracle encoding', () => {
    const bytes = SHA512.digest(Buffer.from('turn me into a point'));
    const pub = ed25519.publicKeyFromHash(bytes);
    const point = ed25519.pointFromHash(bytes);
    const sign = (pub[31] & 0x80) !== 0;

    assert.bufferEqual(pub,
      '37e3fe7969358395d6de5062f5a2ae4d80f88331a844bcd2058a1f3e2652e0e6');

    assert.bufferEqual(point,
      '88ddc62a46c484db54b6d6cb6badb173e0e7d9785385691443233983865acc4d');

    assert.strictEqual(ed25519.publicKeyVerify(pub), true);
    assert.bufferEqual(ed25519.publicKeyConvert(pub), point);
    assert.bufferEqual(ed25519.publicKeyDeconvert(point, sign), pub);
  });

  describe('ed25519 derivations', () => {
    for (const [i, test] of derivations.entries()) {
      it(`should compute correct a and A for secret #${i}`, () => {
        const secret = Buffer.from(test.secret_hex, 'hex');
        const priv = ed25519.privateKeyConvert(secret);
        const pub = ed25519.publicKeyCreate(secret);

        assert(ed25519.publicKeyVerify(pub));

        assert.bufferEqual(priv, Buffer.from(test.a_hex, 'hex'));
        assert.bufferEqual(pub, Buffer.from(test.A_hex, 'hex'));
      });
    }
  });

  describe('sign.input ed25519 test vectors', () => {
    const batch = [];

    // https://ed25519.cr.yp.to/software.html
    for (const [i, [secret_, pub_, msg_, sig_]] of vectors.entries()) {
      const secret = Buffer.from(secret_, 'hex');
      const pub = Buffer.from(pub_, 'hex');
      const msg = Buffer.from(msg_, 'hex');
      const sig = Buffer.from(sig_, 'hex');

      batch.push([msg, sig, pub]);

      it(`should pass ed25519 vector #${i}`, () => {
        const pub_ = ed25519.publicKeyCreate(secret);

        assert(ed25519.publicKeyVerify(pub_));

        assert.bufferEqual(pub_, pub);

        const sig_ = ed25519.sign(msg, secret);

        assert.bufferEqual(sig_, sig);

        assert(ed25519.verify(msg, sig, pub));
        assert(ed25519.verifySingle(msg, sig, pub));

        let forged = Buffer.from([0x78]); // ord('x')

        if (msg.length > 0) {
          forged = Buffer.from(msg);
          forged[forged.length - 1] += 1;
        }

        assert(!ed25519.verify(forged, sig, pub));
        assert(!ed25519.verifySingle(forged, sig, pub));
        assert(!ed25519.verifyBatch([[forged, sig, pub]]));
      });
    }

    it('should do batch verification', () => {
      const [msg] = batch[0];

      assert.strictEqual(ed25519.verifyBatch([]), true);
      assert.strictEqual(ed25519.verifyBatch(batch), true);

      if (msg.length > 0) {
        msg[0] ^= 1;
        assert.strictEqual(ed25519.verifyBatch(batch), false);
        msg[0] ^= 1;
      }
    });
  });

  describe('RFC 8032 vectors', () => {
    for (const [i, vector] of rfc8032.entries()) {
      if (!vector.algorithm.startsWith('Ed25519'))
        continue;

      let ph = null;
      let ctx = null;

      if (vector.algorithm === 'Ed25519ph') {
        ph = true;
      } else if (vector.algorithm === 'Ed25519ctx') {
        ctx = Buffer.from(vector.ctx, 'hex');
        ph = false;
      }

      let msg = Buffer.from(vector.msg, 'hex');

      if (ph)
        msg = SHA512.digest(msg);

      const sig = Buffer.from(vector.sig, 'hex');
      const pub = Buffer.from(vector.pub, 'hex');
      const priv = Buffer.from(vector.priv, 'hex');

      it(`should pass RFC 8032 vector (${vector.algorithm} #${i})`, () => {
        assert(ed25519.privateKeyVerify(priv));
        assert(ed25519.publicKeyVerify(pub));

        const sig_ = ed25519.sign(msg, priv, ph, ctx);

        assert.bufferEqual(sig_, sig);

        assert(ed25519.verify(msg, sig, pub, ph, ctx));
        assert(!ed25519.verify(msg, sig, pub, !ph, ctx));

        if (msg.length > 0) {
          const msg_ = Buffer.from(msg);
          msg_[i % msg_.length] ^= 1;
          assert(!ed25519.verify(msg_, sig, pub, ph, ctx));
          assert(!ed25519.verifyBatch([[msg_, sig, pub]], ph, ctx));
        }

        {
          const sig_ = Buffer.from(sig);
          sig_[i % sig_.length] ^= 1;
          assert(!ed25519.verify(msg, sig_, pub, ph, ctx));
        }

        {
          const pub_ = Buffer.from(pub);
          pub_[i % pub_.length] ^= 1;
          assert(!ed25519.verify(msg, sig, pub_, ph, ctx));
        }

        if (ctx && ctx.length > 0) {
          const ctx_ = Buffer.from(ctx);
          ctx_[i % ctx_.length] ^= 1;
          assert(!ed25519.verify(msg, sig, pub, ph, ctx_));
          assert(!ed25519.verify(msg, sig, pub, ph, null));
        } else {
          const ctx_ = Buffer.alloc(1);
          assert(!ed25519.verify(msg, sig, pub, true, ctx_));
          assert(!ed25519.verify(msg, sig, pub, false, ctx_));
        }
      });
    }
  });

  it('should test serialization formats', () => {
    const priv = ed25519.privateKeyGenerate();
    const pub = ed25519.publicKeyCreate(priv);
    const rawPriv = ed25519.privateKeyExport(priv);
    const rawPub = ed25519.publicKeyExport(pub);

    assert.bufferEqual(ed25519.privateKeyImport(rawPriv), priv);
    assert.bufferEqual(ed25519.publicKeyImport(rawPub), pub);

    const jsonPriv = ed25519.privateKeyExportJWK(priv);
    const jsonPub = ed25519.publicKeyExportJWK(pub);

    assert.bufferEqual(ed25519.privateKeyImportJWK(jsonPriv), priv);
    assert.bufferEqual(ed25519.publicKeyImportJWK(jsonPub), pub);

    const asnPriv = ed25519.privateKeyExportPKCS8(priv);
    const asnPub = ed25519.publicKeyExportSPKI(pub);

    assert.bufferEqual(ed25519.privateKeyImportPKCS8(asnPriv), priv);
    assert.bufferEqual(ed25519.publicKeyImportSPKI(asnPub), pub);
  });

  it('should import standard JWK', () => {
    // https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves-06#appendix-A.1
    const json = {
      'kty': 'OKP',
      'crv': 'Ed25519',
      'd': 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
      'x': '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
      'ext': true
    };

    const priv = ed25519.privateKeyImportJWK(json);
    const pub = ed25519.publicKeyImportJWK(json);

    assert.bufferEqual(ed25519.publicKeyCreate(priv), pub);
    assert.deepStrictEqual(ed25519.privateKeyExportJWK(priv), json);
  });
});
