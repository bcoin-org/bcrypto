'use strict';

const assert = require('bsert');
const random = require('../lib/random');
const ed25519 = require('../lib/ed25519');
const x25519 = require('../lib/x25519');
const SHA256 = require('../lib/sha256');
const SHA512 = require('../lib/sha512');
const derivations = require('./data/ed25519.json');
const json = require('./data/ed25519-input.json');
const rfc8032 = require('./data/rfc8032-vectors.json');
const {env} = process;
const vectors = env.CI || ed25519.native === 2 ? json : json.slice(0, 128);

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

  it('should allow points at infinity', () => {
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

    assert(ed25519.publicKeyVerify(inf));
    assert(ed25519.publicKeyIsInfinity(inf));
    assert(ed25519.scalarIsZero(sig.slice(32)));
    assert(ed25519.verify(msg, sig, inf));
  });

  it('should fail to validate malleated keys', () => {
    // x = 0, y = 1, sign = 1
    const hex1 = '01000000000000000000000000000000'
               + '00000000000000000000000000000080';

    // x = 0, y = -1, sign = 1
    const hex2 = 'ecffffffffffffffffffffffffffffff'
               + 'ffffffffffffffffffffffffffffffff';

    const key1 = Buffer.from(hex1, 'hex');
    const key2 = Buffer.from(hex2, 'hex');

    assert(!ed25519.publicKeyVerify(key1));
    assert(!ed25519.publicKeyVerify(key2));

    key1[31] &= ~0x80;
    key2[31] &= ~0x80;

    assert(ed25519.publicKeyVerify(key1));
    assert(ed25519.publicKeyVerify(key2));
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

      assert(ed25519.publicKeyVerify(pub));
      assert.throws(() => ed25519.deriveWithScalar(pub, key));
    }
  });

  it('should test small order points', () => {
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

    {
      const pub = Buffer.from(small[0], 'hex');

      assert(ed25519.publicKeyIsInfinity(pub));
      assert(!ed25519.publicKeyIsSmall(pub));
      assert(!ed25519.publicKeyHasTorsion(pub));
    }

    for (let i = 1; i < small.length; i++) {
      const str = small[i];
      const pub = Buffer.from(str, 'hex');

      assert(!ed25519.publicKeyIsInfinity(pub));
      assert(ed25519.publicKeyIsSmall(pub));
      assert(ed25519.publicKeyHasTorsion(pub));
    }

    {
      const priv = ed25519.privateKeyGenerate();
      const pub = ed25519.publicKeyCreate(priv);

      assert(!ed25519.publicKeyIsInfinity(pub));
      assert(!ed25519.publicKeyIsSmall(pub));
      assert(!ed25519.publicKeyHasTorsion(pub));
    }
  });

  it('should test scalar zero', () => {
    // n = 0
    const hex1 = 'edd3f55c1a631258d69cf7a2def9de14'
               + '00000000000000000000000000000010';

    // n - 1 = -1
    const hex2 = 'ecd3f55c1a631258d69cf7a2def9de14'
               + '00000000000000000000000000000010';

    assert(ed25519.scalarIsZero(Buffer.alloc(32, 0x00)));
    assert(!ed25519.scalarIsZero(Buffer.alloc(32, 0x01)));

    assert(ed25519.scalarIsZero(Buffer.from(hex1, 'hex')));
    assert(!ed25519.scalarIsZero(Buffer.from(hex2, 'hex')));
  });

  it('should validate signatures with small order points', () => {
    const json = [
      // (-1, -1)
      [
        'afe9a024a60f51dadb0353824aba4ee1395a0eda2bb27348768472f948b6c0db',
        '0100000000000000000000000000000000000000000000000000000000000000',
        '0000000000000000000000000000000000000000000000000000000000000000',
        '0100000000000000000000000000000000000000000000000000000000000000',
        true,
        true
      ],

      // (-1, -1)
      [
        'afe9a024a60f51dadb0353824aba4ee1395a0eda2bb27348768472f948b6c0db',
        '0100000000000000000000000000000000000000000000000000000000000000',
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
      assert(!ed25519.publicKeyIsSmall(pub));
      assert(ed25519.publicKeyHasTorsion(pub));

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

    const xaliceSecret = x25519.derive(xbobPub,
      ed25519.privateKeyConvert(alicePriv));

    const xbobSecret = x25519.derive(xalicePub,
      ed25519.privateKeyConvert(bobPriv));

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

    const xaliceSecret = x25519.derive(xbobPub, alicePriv);
    const xbobSecret = x25519.derive(xalicePub, bobPriv);

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

    const xaliceSecret2 = x25519.derive(xbobPub,
      ed25519.privateKeyConvert(alicePriv));

    const xbobSecret2 = x25519.derive(xalicePub,
      ed25519.privateKeyConvert(bobPriv));

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
    const pub2 = x25519.publicKeyConvert(xpub, sign);

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
    const p1 = x25519.publicKeyFromUniform(u1);
    const u2 = x25519.publicKeyToUniform(p1);
    const p2 = x25519.publicKeyFromUniform(u2);
    const u3 = x25519.publicKeyToUniform(p2);
    const p3 = x25519.publicKeyFromUniform(u3);

    assert.bufferEqual(p1, p2);
    assert.bufferEqual(p2, p3);
  });

  it('should do elligator2 on curve25519 basepoint', () => {
    const p = Buffer.alloc(32, 0x00);
    p[0] = 9;

    const u = x25519.publicKeyToUniform(p, 0);
    const b = u[31] & 0x80;

    u[31] &= ~0x80;

    assert.bufferEqual(u,
      'b9762dadc1db2944f08aeb419d76f6b19e66fd47ec1076dfe7a7a1c4e0f0a92b');

    u[31] |= b;

    const q = x25519.publicKeyFromUniform(u);

    assert.bufferEqual(q, p);
  });

  it('should do elligator2 (vector)', () => {
    const u1 = Buffer.from(
      'be6d3d8d621562f8e1e9fdd93a760e7e7f27b93c0879a5414525b59bded49b61',
      'hex');

    const p1 = ed25519.publicKeyFromUniform(u1);

    assert.bufferEqual(p1,
      'cc2947ef03b978b3c7b418e2acdf52bc26f51457d7b21730c551bbcf4cb2e2fd');

    const u2 = ed25519.publicKeyToUniform(p1, 0);

    u2[31] &= ~0x80;
    assert.bufferEqual(u2, u1);

    const p2 = ed25519.publicKeyFromUniform(u2);

    const u3 = ed25519.publicKeyToUniform(p2, 0);

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

    const u = x25519.publicKeyToUniform(p, 1);

    u[31] &= ~0x80;

    assert.bufferEqual(u,
      '65ec0b839037aed89162a872de9ae7e6effdc53a6d81ddf1f1965bf088a82d1a');
  });

  it('should pass elligator2 test vectors', () => {
    const preimages = [
      'c9adf824cd85731f20dc1c6a9c749c99a8844420dcebfadbda711ca05202f362',
      'd95bab25f5c276bd876011cf9490668669e209b3bbac71b5b0e7ebc8b91f9924',
      '1ed2fb25520b55aa8cd587b55ff12cde689c82b94cac41a564d0fc5980416836',
      '4aaf71b1830164e9bf75c7b2fa90cc3fd1acf4ab2d882fb7626f05420cb41852',
      'c676ec90758d04ec4cc57afdbef7d99450fe8e69a2364fce301d60b565cee0af',
      '978b073a732823841eb94e080084896c5dec4adbba8d12e2488686e92eda2159',
      'f469163dccf13968f6f9cde8d90fc8ffc9c18b583312198480c54a01162b67b4',
      'c0e7791e79dcb5a70bdba297f6e29535f72ce4524d8901e88a42992927f9e2a7',
      '45c6b31e75cd541106ad80c3aab79ff36738c3465939e82d5e4d7a1a7c39c3fb',
      '92afda3eaa89f79c3e93e58ff6e43cb1841e1549839d6f0f488a59686f452399',
      'd58163e503546c1072f8eac4f8117ecae2ff9f5ef3da562d2916ea660360566d',
      '21a376b3d43cb612d635a2e22b4c51d0552bce9e0deec604b7d35d9a7d1b4918',
      '73f19eb397c8511f2d12cb728373a33169d3c3d2bc703a3106fb5d8327178c73',
      'e84fabcb9796acaba658c7aa2db7cb89862a3fc997f3b7acf708ee426105b20b',
      'b02ba87cd0a98c3ef3fa2ba009b9943e5801f5922a16335dc7b26180dc181288',
      '12280007b43ac0c2dca0c4e1f1afadb36cad06a69c66fa44d29471b3bf8dae49'
    ];

    const keys = [
      '095aa6447f2c0bc38da8c87338dcb0e94162d89fa2e76856fd4e07e95dc2e5bb',
      '9b085d55d9b565d2dafb50a18ff6976597e5e3b01c8f68c4e60f83170ea1a52e',
      '2654a006f8bb52c5f4109299a017857fd74a4e76fdda8cf7443b0038337e52c6',
      '66114fe708f29c303dfcfd4a586d9a1aac3aa6addb60e166ce7e9228053acc74',
      '21681e4705dd848e542c9b076a8f18cbd8e4bed23c067d9b81055c3859c67fe3',
      '80b087e5af2a3b03f19a53ac2bb03d6e6b422f0cb9cb67dbafe292528105a5f6',
      'cccbf2857681d7291c956b10d09fe215e93bb59ff417ce42672b6b8cc29e67de',
      '14cc09d659fcc1583a7d062c32516374854a2ff78e75d948e88eb632520f501e',
      '344fd658d566a52215ce0f549eac263d628efaab8c7b3dd745c380d7154809ef',
      '50c869fd754154200c1eb027ddd55acd50a5aa3517ddbc1099f7f6196b19e7f1',
      '58aa1a6280e2d9dadb7f81f97c43d98b6e2643697d93de0428f89f79ad12be58',
      'f30a970193889a801ee61b7ddc97592d0554932c8ecd860b0d99ac85e3dcec07',
      '9181c312ba7ba941c8452850fa43ff63a0da8f4dc7eb047734b74e96259ffd78',
      '29be63ddf2dfafef646983be21c902f6196b52a3e43df33bb576ea3bd28a23ad',
      '57710782f1fb3b9d73ea9f5cf77903307d321fdb5f462dd3a1b5cbbe6753c397',
      '80f67a15875cc36fc4e28c0d72ff3a81babaae384167bf7384b7b48f5f636908'
    ];

    const points = [
      '04aed9e255f7d6c2772ba9ecc9cf3d97c0deb91ed5da6826f35da16ede0abe7e',
      '160a0ab252c9ce59b5f4f483b80a3577489606052c9cb4ab04b98684aeb98e01',
      '41214466fdc3b40eaec83a50f1a1d8b7300ad6db6115a951cd0a592b5bead73e',
      'd90fd4ab11da2c572d0570719a455af92d73e9458c89af31ef04ecc45d095b2c',
      '973ce29e94b2269c38a8ef528758812b6ff72edf4372657fead5f87ed4f9210f',
      '0e40bead56ba625f1555277587754b9a6d081989258822562a2a9c22f6723e26',
      'b96028c632605091652642f5dcabb19b1771f8f85ddbae10ededf5f48a42db78',
      'fa393f71811ee31ae7a2ad9f1a0fb3323728b386509dbdb03fba3f833e7b3e2f',
      '14fec3d893a51b4d4d8e3fe7b6b798a8dd2c7252d96c6442b35e8b76addce732',
      '122f2409378ff2a41b4e1c37ce7ac770ac10fab843713df188e1af7bca6a765d',
      'db7b23f18724b30ad9529182c1da830285cfb8b1ebf064bb4da004743f1f5271',
      '8b28c6a77102adb7882d8460277581e69aa181a31d01d82f614f02aa17d2131e',
      'ec46f2fdbac409caae18d5a31425bf93f65d66832e46b9b10278706f2949bf3a',
      'e1f9cba8fea6169a37bc175b07d3a28a0918db1706df3a645cf0d910ffc3aa64',
      '0d8e43bcf3d32bbe3660ac28543bdcd63e7ce537a13c469f43191484a7d67e0d',
      '778506d4f0d6f64dd1f2c975264bd22d1e9584b58c40f64c0567e5b208315e5c'
    ];

    const raws1 = [
      'c9adf824cd85731f20dc1c6a9c749c99a8844420dcebfadbda711ca05202f362',
      'd95bab25f5c276bd876011cf9490668669e209b3bbac71b5b0e7ebc8b91f9924',
      '34f11f1e28c2f89e9d7681885c3c58825c392b3b366a9d68506f18eda8675110',
      'b578809ca2c6a285668c68fbca5ee41df9f90b0ddce281a5d3907d3710c28f7a',
      'c969e3293a9ad7a52bda129223d44c34b67fd44fc982bb4d3b2c412889870a17',
      '978b073a732823841eb94e080084896c5dec4adbba8d12e2488686e92eda2159',
      'f469163dccf13968f6f9cde8d90fc8ffc9c18b583312198480c54a01162b6734',
      'c0e7791e79dcb5a70bdba297f6e29535f72ce4524d8901e88a42992927f9e227',
      '45c6b31e75cd541106ad80c3aab79ff36738c3465939e82d5e4d7a1a7c39c37b',
      '92afda3eaa89f79c3e93e58ff6e43cb1841e1549839d6f0f488a59686f452319',
      'c9f06ee0bda590854b05c4ec6c217da5e379f1b5e6a11c88c2ec116e45939a75',
      '21a376b3d43cb612d635a2e22b4c51d0552bce9e0deec604b7d35d9a7d1b4918',
      '73f19eb397c8511f2d12cb728373a33169d3c3d2bc703a3106fb5d8327178c73',
      'e84fabcb9796acaba658c7aa2db7cb89862a3fc997f3b7acf708ee426105b20b',
      'b02ba87cd0a98c3ef3fa2ba009b9943e5801f5922a16335dc7b26180dc181208',
      '12280007b43ac0c2dca0c4e1f1afadb36cad06a69c66fa44d29471b3bf8dae49'
    ];

    const raws2 = [
      'c9adf824cd85731f20dc1c6a9c749c99a8844420dcebfadbda711ca05202f362',
      'd95bab25f5c276bd876011cf9490668669e209b3bbac71b5b0e7ebc8b91f9924',
      '34f11f1e28c2f89e9d7681885c3c58825c392b3b366a9d68506f18eda8675110',
      '38877f635d395d7a9973970435a11be20606f4f2231d7e5a2c6f82c8ef3d7005',
      '24961cd6c565285ad425ed6ddc2bb3cb49802bb0367d44b2c4d3bed77678f568',
      '978b073a732823841eb94e080084896c5dec4adbba8d12e2488686e92eda2159',
      'f469163dccf13968f6f9cde8d90fc8ffc9c18b583312198480c54a01162b6734',
      '2d1886e186234a58f4245d68091d6aca08d31badb276fe1775bd66d6d8061d58',
      'a8394ce18a32abeef9527f3c5548600c98c73cb9a6c617d2a1b285e583c63c04',
      '92afda3eaa89f79c3e93e58ff6e43cb1841e1549839d6f0f488a59686f452319',
      '240f911f425a6f7ab4fa3b1393de825a1c860e4a195ee3773d13ee91ba6c650a',
      '21a376b3d43cb612d635a2e22b4c51d0552bce9e0deec604b7d35d9a7d1b4918',
      '73f19eb397c8511f2d12cb728373a33169d3c3d2bc703a3106fb5d8327178c73',
      '05b054346869535459a73855d248347679d5c036680c485308f711bd9efa4d74',
      '3dd457832f5673c10c05d45ff6466bc1a7fe0a6dd5e9cca2384d9e7f23e7ed77',
      'dbd7fff84bc53f3d235f3b1e0e50524c9352f959639905bb2d6b8e4c40725136'
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
      assert.bufferEqual(x25519.publicKeyFromUniform(preimage), point);
      assert.bufferEqual(un(ed25519.publicKeyToUniform(key, i)), raw1);
      assert.bufferEqual(un(x25519.publicKeyToUniform(point, i)), raw2);
      assert.bufferEqual(ed25519.publicKeyFromUniform(raw1), key);
      assert.bufferEqual(x25519.publicKeyFromUniform(raw2), point);
    }
  });

  it('should test random oracle encoding', () => {
    const bytes = SHA512.digest(Buffer.from('turn me into a point'));
    const pub = ed25519.publicKeyFromHash(bytes, true);
    const point = x25519.publicKeyFromHash(bytes, true);

    assert.bufferEqual(pub,
      '37e3fe7969358395d6de5062f5a2ae4d80f88331a844bcd2058a1f3e2652e0e6');

    assert.bufferEqual(point,
      '88ddc62a46c484db54b6d6cb6badb173e0e7d9785385691443233983865acc4d');

    assert.strictEqual(ed25519.publicKeyVerify(pub), true);
    assert.bufferEqual(ed25519.publicKeyConvert(pub), point);
    assert.bufferEqual(x25519.publicKeyConvert(point, true), pub);
  });

  it('should test random oracle encoding (doubling)', () => {
    const bytes0 = SHA256.digest(Buffer.from('turn me into a point'));
    const bytes = Buffer.concat([bytes0, bytes0]);
    const pub = ed25519.publicKeyFromHash(bytes, true);
    const point = x25519.publicKeyFromHash(bytes, true);

    assert.bufferEqual(pub,
      '5694d147542d2c08657a203cea81c6f0e39caa5219a2eeb0dedc37e59cd31ec0');

    assert.bufferEqual(point,
      '7b9965e30b586bab509c34d657d8be30fad1b179470f2f70a6c728092e000062');

    assert.strictEqual(ed25519.publicKeyVerify(pub), true);
    assert.bufferEqual(ed25519.publicKeyConvert(pub), point);
    assert.bufferEqual(x25519.publicKeyConvert(point, true), pub);
  });

  if (x25519.native === 2) {
    const native = ed25519;
    const curve = require('../lib/js/ed25519');

    it('should invert elligator (native vs. js)', () => {
      const priv = native.privateKeyGenerate();
      const pub = native.publicKeyCreate(priv);

      for (let i = 0; i < 2; i++) {
        let bytes1 = null;
        let bytes2 = null;

        try {
          bytes1 = native.publicKeyToUniform(pub, i);
        } catch (e) {
          ;
        }

        try {
          bytes2 = curve.publicKeyToUniform(pub, i);
        } catch (e) {
          ;
        }

        if (!bytes1) {
          assert(!bytes2);
          continue;
        }

        bytes1[31] &= ~0x80;
        bytes2[31] &= ~0x80;

        assert(bytes2);
        assert.bufferEqual(bytes1, bytes2);
        assert.bufferEqual(native.publicKeyFromUniform(bytes1), pub);
      }

      const bytes = native.publicKeyToHash(pub);

      assert.bufferEqual(native.publicKeyFromHash(bytes), pub);
    });
  }

  it('should invert elligator squared', () => {
    const priv = ed25519.privateKeyGenerate();
    const pub = ed25519.publicKeyCreate(priv);
    const bytes = ed25519.publicKeyToHash(pub);
    const out = ed25519.publicKeyFromHash(bytes);

    assert.bufferEqual(out, pub);
  });

  it('should test equivalence edge cases', () => {
    const inf = ed25519.publicKeyCombine([]);
    const x = Buffer.alloc(32, 0x00);
    const e = Buffer.from('ecffffffffffffffffffffffffffffff'
                        + 'ffffffffffffffffffffffffffffff7f', 'hex');

    assert.bufferEqual(ed25519.publicKeyConvert(e), x);
    assert.bufferEqual(x25519.publicKeyConvert(x, false), e);
    assert.throws(() => ed25519.publicKeyConvert(inf));
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
