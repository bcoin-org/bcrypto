'use strict';

const assert = require('bsert');
const random = require('../lib/random');
const ed448 = require('../lib/ed448');
const x448 = require('../lib/x448');
const SHAKE256 = require('../lib/shake256');
const rfc8032 = require('./data/rfc8032-vectors.json');

describe('Ed448', function() {
  this.timeout(15000);

  it('should generate keypair and sign', () => {
    const msg = random.randomBytes(ed448.size);
    const secret = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(secret);

    assert(ed448.publicKeyVerify(pub));

    const sig = ed448.sign(msg, secret);

    assert(ed448.verify(msg, sig, pub));

    sig[0] ^= 1;

    assert(!ed448.verify(msg, sig, pub));

    assert.bufferEqual(
      ed448.privateKeyImport(ed448.privateKeyExport(secret)),
      secret);

    assert.bufferEqual(
      ed448.privateKeyImportPKCS8(ed448.privateKeyExportPKCS8(secret)),
      secret);

    assert.bufferEqual(
      ed448.publicKeyImport(ed448.publicKeyExport(pub)),
      pub);

    assert.bufferEqual(
      ed448.publicKeyImportSPKI(ed448.publicKeyExportSPKI(pub)),
      pub);
  });

  it('should allow points at infinity', () => {
    // Fun fact about edwards curves: points
    // at infinity can actually be serialized.
    const msg = Buffer.from(''
      + 'bd0f6a3747cd561bdddf4640a332461a'
      + '4a30a12a434cd0bf40d766d9c6d458e5'
      + '512204a30c17d1f50b5079631f64eb31'
      + '12182da3005835461113718d1a5ef944',
      'hex');

    const sig = Buffer.from(''
      + '01000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '0000',
      'hex');

    const pub = Buffer.from(''
      + 'df9705f58edbab802c7f8363cfe5560a'
      + 'b1c6132c20a9f1dd163483a26f8ac53a'
      + '39d6808bf4a1dfbd261b099bb03b3fb5'
      + '0906cb28bd8a081f00',
      'hex');

    assert(!ed448.verify(msg, sig, pub));

    const inf = Buffer.from(''
      + '01000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '000000000000000000',
      'hex');

    assert(ed448.publicKeyVerify(inf));
    assert(ed448.publicKeyIsInfinity(inf));
    assert(ed448.scalarIsZero(sig.slice(57, 57 + 56)));
    assert(ed448.verify(msg, sig, inf));
  });

  it('should fail to validate malleated keys', () => {
    // x = 0, y = 1, sign = 1
    const hex1 = '0100000000000000000000000000'
               + '0000000000000000000000000000'
               + '0000000000000000000000000000'
               + '000000000000000000000000000080';

    // x = 0, y = -1, sign = 1
    const hex2 = 'feffffffffffffffffffffffffff'
               + 'ffffffffffffffffffffffffffff'
               + 'feffffffffffffffffffffffffff'
               + 'ffffffffffffffffffffffffffff80';

    const key1 = Buffer.from(hex1, 'hex');
    const key2 = Buffer.from(hex2, 'hex');

    assert(!ed448.publicKeyVerify(key1));
    assert(!ed448.publicKeyVerify(key2));

    key1[56] &= ~0x80;
    key2[56] &= ~0x80;

    assert(ed448.publicKeyVerify(key1));
    assert(ed448.publicKeyVerify(key2));
  });

  it('should test scalar zero', () => {
    // n = 0
    const hex1 = 'f34458ab92c27823558fc58d72c2'
               + '6c219036d6ae49db4ec4e923ca7c'
               + 'ffffffffffffffffffffffffffff'
               + 'ffffffffffffffffffffffffff3f';

    // n - 1 = -1
    const hex2 = 'f24458ab92c27823558fc58d72c2'
               + '6c219036d6ae49db4ec4e923ca7c'
               + 'ffffffffffffffffffffffffffff'
               + 'ffffffffffffffffffffffffff3f';

    assert(ed448.scalarIsZero(Buffer.alloc(56, 0x00)));
    assert(!ed448.scalarIsZero(Buffer.alloc(56, 0x01)));

    assert(ed448.scalarIsZero(Buffer.from(hex1, 'hex')));
    assert(!ed448.scalarIsZero(Buffer.from(hex2, 'hex')));
  });

  it('should validate small order points', () => {
    const small = [
      // 0, c (order 1)
      ['01000000000000000000000000000000000000000000000000000000',
       '0000000000000000000000000000000000000000000000000000000000'].join(''),
      // 0, -c (order 2, rejected)
      ['feffffffffffffffffffffffffffffffffffffffffffffffffffffff',
       'feffffffffffffffffffffffffffffffffffffffffffffffffffffff00'].join(''),
      // c, 0 (order 4)
      ['00000000000000000000000000000000000000000000000000000000',
       '0000000000000000000000000000000000000000000000000000000080'].join(''),
      // -c, 0 (order 4)
      ['00000000000000000000000000000000000000000000000000000000',
       '0000000000000000000000000000000000000000000000000000000000'].join('')
    ];

    const key = ed448.scalarGenerate();

    for (let i = 0; i < small.length; i++) {
      const str = small[i];
      const pub = Buffer.from(str, 'hex');

      assert(ed448.publicKeyVerify(pub));
      assert.throws(() => ed448.deriveWithScalar(pub, key));
    }
  });

  it('should test small order points', () => {
    const small = [
      // 0, c (order 1)
      ['01000000000000000000000000000000000000000000000000000000',
       '0000000000000000000000000000000000000000000000000000000000'].join(''),
      // 0, -c (order 2, rejected)
      ['feffffffffffffffffffffffffffffffffffffffffffffffffffffff',
       'feffffffffffffffffffffffffffffffffffffffffffffffffffffff00'].join(''),
      // c, 0 (order 4)
      ['00000000000000000000000000000000000000000000000000000000',
       '0000000000000000000000000000000000000000000000000000000080'].join(''),
      // -c, 0 (order 4)
      ['00000000000000000000000000000000000000000000000000000000',
       '0000000000000000000000000000000000000000000000000000000000'].join('')
    ];

    {
      const pub = Buffer.from(small[0], 'hex');

      assert(ed448.publicKeyIsInfinity(pub));
      assert(!ed448.publicKeyIsSmall(pub));
      assert(!ed448.publicKeyHasTorsion(pub));
    }

    for (let i = 1; i < small.length; i++) {
      const str = small[i];
      const pub = Buffer.from(str, 'hex');

      assert(!ed448.publicKeyIsInfinity(pub));
      assert(ed448.publicKeyIsSmall(pub));
      assert(ed448.publicKeyHasTorsion(pub));
    }

    {
      const priv = ed448.privateKeyGenerate();
      const pub = ed448.publicKeyCreate(priv);

      assert(!ed448.publicKeyIsInfinity(pub));
      assert(!ed448.publicKeyIsSmall(pub));
      assert(!ed448.publicKeyHasTorsion(pub));
    }
  });

  it('should validate signatures with small order points', () => {
    const json = [
      // (-1, -1)
      [
        '56d69147eb80b6d3c1a909aa74286ee8e69729152de2ffb1cf10670b6893e8e8e0f22d85144c3073ef0d3dac36577eaaae42d7d9f65b6d6e05',
        '010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        '010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        true,
        true
      ],

      // (-1, -1)
      [
        '56d69147eb80b6d3c1a909aa74286ee8e69729152de2ffb1cf10670b6893e8e8e0f22d85144c3073ef0d3dac36577eaaae42d7d9f65b6d6e05',
        '010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        'df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081f00',
        false,
        false
      ],

      // (0, 0)
      [
        '56d69147eb80b6d3c1a909aa74286ee8e69729152de2ffb1cf10670b6893e8e8e0f22d85144c3073ef0d3dac36577eaaae42d7d9f65b6d6e05',
        'fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff00',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        'fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff00',
        true,
        true
      ],

      // (0, 1)
      [
        '8e1ea3e1a3fc6849154b8def1158c3112c89027eafe01e0f81ca0c62abbad6f110c72bc6be497a3eedda1b558f296326b385f56a7d1ce7e6bc',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        'fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff00',
        false,
        true
      ],

      // (1, 0)
      [
        '8e1ea3e1a3fc6849154b8def1158c3112c89027eafe01e0f81ca0c62abbad6f110c72bc6be497a3eedda1b558f296326b385f56a7d1ce7e6bc',
        'fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff00',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080',
        true,
        true
      ],

      // (1, 1)
      [
        'c9e836c4fb92425ab41261ef55a9ca7187fa31278ebf5a73101542298ec49e8102b3d554abc9bdcf35f5c7bea7ea48e960cc41ef694d08cd39',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080',
        false,
        true
      ],

      // (1, 2)
      [
        'd131c7443a0fe4389c1e81db609b1098ddb2716d80507c696b6c44b7989db3a218e635ce9214bb1fa3e438e2733a107d3f90f16fbecf6f564f',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080',
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
      assert.strictEqual(ed448.verify(msg, sig, pub), res1);
      assert.strictEqual(ed448.verifySingle(msg, sig, pub), res2);

      if (res2)
        batch.push([msg, sig, pub]);
    }

    batch.sort(() => Math.random() > 0.5 ? 1 : -1);

    assert.strictEqual(ed448.verifyBatch(batch), true);
  });

  it('should validate signatures with torsion components', () => {
    const json = [
      // (0, 0)
      [
        '2a596cd0f0326747960ff7f36014472dd2faaff3e137f1d7bd7625ca1a632c86ea9c2a12c2111a4b682f8a69051f553777db77a93f287e991b',
        '848aa10e0baf75c788c9ae5aa59239cdc9eeadec4465e404f6d79064020cf5056ea5f9c9af78d0894db751c3ad2e6607a58f9f88d31536c300',
        '8e7a1f893fdf95fbde0980ae999167ac6090255c0453c7631c1a28e9810c6a4e2e0ab3215d8767181052fc86ab8808d5c19d1de6b049963400',
        '4b84907faf16cda003cf134b162d400a864fb300f9ad09b33d5f6b5679b5e7b653017d0893d47137668ebe4015176f3d54b9f00af047f14080',
        true,
        true
      ],

      // (0, 0)
      [
        '6998833d4e3dd4a7f7049e8e334ea7204ed7fef0b094e898b5d126239c953f9fc306982d1946561d0a799cdd0ea84465dd7c133b518ac1e3ba',
        'c7e1d289b350b1924ffdf2e81e6ef8bc29984a9066983b091b1d26772ede920f6720f5fee5c564e2571a170bb7d92f776393a7d50100729000',
        '2ed4a2ecca6c445af18026482e515596ffeb632c48e5e4d03d0a244f4141463b4ab4987459730447fa00fde0333c249d9158295670179a2000',
        '8b7ab2c01bed9b08a4c14fae468c0f701d82cfe4e470b9f5af682c58b15679961e841abe551eec528be5cb50201ae740a71e6e9457eb656680',
        false,
        true
      ],

      // (0, 1)
      [
        'c63f7c1e3cd8a7fcef1c4667a40c42f29d547cc4648799e324f7d23a7b0ea79c3940f00001b56ff59bea114c56e219082efc21714ce8b50afc',
        '521f59fa4c4cd55f47ecca8c95a9ea835a939db0636eefefa057521bce1ac53809f03f64f2ba901e0bc2218a6044486ca0eeb5212ee4adc500',
        'f4b99f1dc93be7d9ef2eb98c68169b368ccff3a65a7b370d5320c5b48edde50ae060f65862db08dfbeb24d8d8164024740c67240ebd32f2100',
        '05cad01e0be214e8a720a789e6e195aa8613f12010754769fe5440ddb3b67563406fde3890d22aa2867ece11ce9121dffaeeebd44b44346000',
        false,
        true
      ],

      // (1, 1)
      [
        '9f3c41e784fc34a6040e3fbc56fb7a133a47f96067c22d6f5dcd95c3eeddeae330980748470eceba52e46983a662fbf753bcde3b0d39eeff1f',
        'caf7da877bef663ad35841d31aab19d87ea4c0b551120631d8641b3f4fcf43460c222e4f83f5b18697be269ba5af1dde9b0ff96baa8d3d1d00',
        'faff63d451d3a7f1de112b37bc7a991a022bf876b5f9f1a10c4c493e9e33e78689064166a166739bf7ae5bd7b52541af9b775cff76304b3200',
        '8818a84042578578f2f96c01146b4067ed21ddd4f725caa988422c513123e728bbb54dae863e264b46774944fe3ab0eeff67f07d619d629500',
        true,
        true
      ],

      // (1, 1)
      [
        '8079b84b8476da19ae62721e5b8eca9e14d8f5cc2c09b34624530e7f2f61ab2a9824127183d674893686ab79d22552f6397616a759bb512d58',
        'b9cf91018948f955c3df0752f075c0c3553be8f0a380b4a5692d0c513f632e7b700f8b2183d987d81efb4449f0b32766b2034a54837cbc1180',
        'fa8eb259a60bcb2107f4aa5d7c33fb2f61b9b0110a018fbd7acf4d14ce2ad54065c5defb9311ee8c7fa4b83d927aa625f4d2932b17cc9a1200',
        'bd38ceea0e894dd3c6c21324161f350bcc553765092d81e287cdc368908de825e4b74e8dc142b2fe435ec557780d2d4fecbb5c93ff10609780',
        false,
        true
      ],

      // (1, 2)
      [
        'eaaedfadb7591be2f32303d1483f0f322f7bcc14124a4e1577d9bcfe454f00352e6362c1c66dd2b0cadeb2535af6d19850a27a5e47217e8fef',
        '37ccae0439012245098ef808df88472df479fee60bbe8fe899248096c09ee5296f8a25d16bfb4365be77b34e6df8da1110f8fcf0e6151c2a80',
        '8800d4ce199f99a94b7abf0246780cde0b2f559f922af849073cd47c09d01384c330f2e5234cd749f0a8f95625f8119ab8a34c9d6fb11e2100',
        '470b5f5ea3f7b3ad61dffcb3f17fb5532fbe5428ce501d11ad0db9294947322c6eaaba06450732ba851fd2ffbf7a22d645e906d40f83980c80',
        true,
        true
      ],

      // (1, 2)
      [
        'f2a8a2825f0e8b6d3629787039674a626e809cf65b6755b37263645c4f1a5031e5ed789299c0b7ff4d27eae2818a261a5b9e779585f46e1e07',
        'af881c54bd8dc2b8dba024b3939ebce13f9394287282f13017c89b99786d586ca5ea71a215caae44041a646689f386c4047ed656bab0cda980',
        '18923a6ce396d90cdfe147ee8c01f3f94cd4b8a6ebf9a49f33339e4e76b1d8b325800c474e1b904e913a6277c33024778d2e33d5106b051900',
        'bca27341df8ecd9c6be51cef237d13aa0caf86c1ea1eccb382c10b480b89d7b12a2c3f3b575f002a2c0baf015c41bd1adf023d103dce8e1700',
        false,
        true
      ],

      // (2, 2)
      [
        '66fe3f2570c564837d4877ebbc4acbf19e83af3f68c904ab751b2a3dd6578fdc7e9f1b6626f6b0ef5bf653a2fd97d41b214c38cf022d74aa59',
        'b85a45f025d112bc923942842ffb548539cb99afa2f8bf727486cc053667452c016ceef72f6695fae2d2e98b1bd2c0ad1c106e112cab924c00',
        '1579a45a05056bb4f8e3f40b7710b55c5f23c35f98efefb8cdf8e2666a96c23ca7fa2c8b7c1003a5cf64695db0e0eb95617f165ebaa7633a00',
        '4e7d7ab89f6938959bb4ee9b7aded93c596e758feae5c910055cd5f1c577df04f7871837b0b6ba2210918284a6aa588c88be8f40e55d82dd80',
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
      assert.strictEqual(ed448.verify(msg, sig, pub), res1);
      assert.strictEqual(ed448.verifySingle(msg, sig, pub), res2);
      assert(!ed448.publicKeyIsSmall(pub));
      assert(ed448.publicKeyHasTorsion(pub));

      batch.push([msg, sig, pub]);
    }

    batch.sort(() => Math.random() > 0.5 ? 1 : -1);

    assert.strictEqual(ed448.verifyBatch(batch), true);
  });

  it('should reject non-canonical R value', () => {
    const json = [
      '3dea88afc3a2802ef17ba72a90c512924902de5777df89a9ff7a4dd580e84fbc25bf33fa7b03e21002391a07ea170f57bd8b1b888ed2c3b568',
      '7a49c363d75f51ad32fa5952631e30285bbc954b1ed44612e23dba86d7430a6e398912fc88f6d3fabfbe05971aa5f11098b87eac97a8664c01',
      '07fa7072b4eab22219df35fffb85c91d1e67079d44e2aa8dee7d03dba792ff8309815efcab7ee04931790975854105d94f16beac4f67cb1500',
      'a675030aaf9ffcf7cd49d415b70582b08963b7ae22af601ed61436815164b91d10f86e9a8276d6f5a8a99f3c557eee161dd85ed2a5ab8b4700'
    ];

    const [m, r, s, p] = json;
    const msg = Buffer.from(m, 'hex');
    const sig = Buffer.from(r + s, 'hex');
    const pub = Buffer.from(p, 'hex');

    assert.strictEqual(ed448.verify(msg, sig, pub), false);
    assert.strictEqual(ed448.verifySingle(msg, sig, pub), false);
  });

  it('should reject non-canonical S value', () => {
    const json = [
      'd5158e4e16d9ea0d584245abcde079bdbdaa6658a30fc4ed7ae23bebe364037ade875736879557b00cbe19f2d53979e336882bff5f3390547d',
      'bbad6011448fc0f16527340aa35ff00ffd621b6b4035a3315f404e5294ee9159526617153801c8e8dfd939475d945f689d3a4e2b642be45900',
      '0e2284ac9848c25e0efa26971fd79c514c6e076dc824fb63ebda9cf8a363916bf023eeea94f9f28b8c109937ce1a6dd32e0775b59e39d14100',
      '1eb228ad82bf5d96c4c5f197169d4131de8732df5ce5b22dd9e9e1b9b3ed7417071e840a7582fc6b366ede96c9b7d79e066e963098c4402380'
    ];

    const [m, r, s, p] = json;
    const msg = Buffer.from(m, 'hex');
    const sig = Buffer.from(r + s, 'hex');
    const pub = Buffer.from(p, 'hex');

    assert.strictEqual(ed448.verify(msg, sig, pub), false);
    assert.strictEqual(ed448.verifySingle(msg, sig, pub), false);
  });

  it('should reject non-canonical key', () => {
    const json = [
      '1e9b34e04e51dd6da9c0dbcb7509d4408f25da9b47afa2734d36e6a7a40a3283e52e98e4f5e77fe07d0ba997aadb95cd78bb8dc3a1b1cc298c',
      '0b45ed34130a4966033f99ccf1d20d53031a147d6a55dabc9d8c65398e381a951cba6a47a591fb42abad1c6b446dc60cb8c81d9acc43fe5880',
      'efea554ad7a2b66e696f9382dcbd08aa6c7d65ab04d1fa41ac91c50c7a18b7b353e2bfac2a2414feb2f2084a5c17a513f5f877480b6cb63000',
      'a6e5c2c10b05a26c7502d3d1d7e5e59e9c96d9fe5151be56d8ccd429e97501a48f4f6f18d15c6fe244569672f789c290b2cb6dffec255f6100'
    ];

    const [m, r, s, p] = json;
    const msg = Buffer.from(m, 'hex');
    const sig = Buffer.from(r + s, 'hex');
    const pub = Buffer.from(p, 'hex');

    assert.strictEqual(ed448.verify(msg, sig, pub), false);
    assert.strictEqual(ed448.verifySingle(msg, sig, pub), false);
  });

  it('should expand key', () => {
    const secret = Buffer.from(''
      + 'a18d4e50f52e78a24e68288b3496'
      + 'd8881066a65b970ded82aac98b59'
      + '8d062648daf289640c830e9098af'
      + '286e8d1a19c7a1623c05d817d78c'
      + '3d', 'hex');

    const [key, prefix] = ed448.privateKeyExpand(secret);

    assert.bufferEqual(key, ''
      + '041a89beaebf4c118b34b4aa66afa8a150c464ca9c3eb46b15c599e4'
      + '3a9439e9131cd01b2c146d8b47d0d590f3938887db82e1334d43b9f2',
      'hex');

    assert.bufferEqual(prefix, '26'
      + 'a3b2541854b72b95c11775490069c50c5ccf64d94ae3648221a7c254'
      + '539834d04102266838a5c75ca340d885a3c318acc0f7dd6b5e398dbb',
      'hex');

    assert.bufferEqual(ed448.privateKeyConvert(secret), key);
  });

  it('should do ECDH', () => {
    const alicePriv = ed448.privateKeyGenerate();
    const alicePub = ed448.publicKeyCreate(alicePriv);

    const bobPriv = ed448.privateKeyGenerate();
    const bobPub = ed448.publicKeyCreate(bobPriv);

    const aliceSecret = ed448.derive(bobPub, alicePriv);
    const bobSecret = ed448.derive(alicePub, bobPriv);

    assert.bufferEqual(aliceSecret, bobSecret);

    const secret = aliceSecret;
    const xsecret = ed448.publicKeyConvert(secret);
    const xalicePub = ed448.publicKeyConvert(alicePub);
    const xbobPub = ed448.publicKeyConvert(bobPub);

    assert.notBufferEqual(xsecret, secret);

    const xaliceSecret = x448.derive(xbobPub,
      ed448.privateKeyConvert(alicePriv));

    const xbobSecret = x448.derive(xalicePub,
      ed448.privateKeyConvert(bobPriv));

    assert.bufferEqual(xaliceSecret, xsecret);
    assert.bufferEqual(xbobSecret, xsecret);
  });

  it('should do ECDH (with scalar)', () => {
    const aliceSeed = ed448.privateKeyGenerate();
    const alicePriv = ed448.privateKeyConvert(aliceSeed);
    const alicePub = ed448.publicKeyFromScalar(alicePriv);

    assert.bufferEqual(alicePub, ed448.publicKeyCreate(aliceSeed));

    const bobSeed = ed448.privateKeyGenerate();
    const bobPriv = ed448.privateKeyConvert(bobSeed);
    const bobPub = ed448.publicKeyFromScalar(bobPriv);

    assert.bufferEqual(bobPub, ed448.publicKeyCreate(bobSeed));

    const aliceSecret = ed448.deriveWithScalar(bobPub, alicePriv);
    const bobSecret = ed448.deriveWithScalar(alicePub, bobPriv);

    assert.bufferEqual(aliceSecret, bobSecret);

    const xalicePub = ed448.publicKeyConvert(alicePub);
    const xbobPub = ed448.publicKeyConvert(bobPub);

    const xaliceSecret = x448.derive(xbobPub, alicePriv);
    const xbobSecret = x448.derive(xalicePub, bobPriv);

    assert.bufferEqual(xaliceSecret, xbobSecret);
  });

  it('should do ECDH (vector)', () => {
    const pub = Buffer.from(''
      + '93890d139f2e5fedfdaa552aae92'
      + 'e5cc5c716719c28a2e2273962d10'
      + 'a83fc02f0205b1e2478239e4a267'
      + 'f5edd9489a3556f48df899424b4b'
      + '00', 'hex');

    const priv = Buffer.from(''
      + 'a18d4e50f52e78a24e68288b3496'
      + 'd8881066a65b970ded82aac98b59'
      + '8d062648daf289640c830e9098af'
      + '286e8d1a19c7a1623c05d817d78c'
      + '3d', 'hex');

    const xsecret = Buffer.from(''
      + 'e198182f06c67c8fe5e080088d5c'
      + '5b23be7c46782ed24774feeba6fb'
      + '37536ada82b71564818fa3df6af8'
      + '22af3dd09dd0529518b42a3d9655', 'hex');

    const secret2 = ed448.derive(pub, priv);
    const xsecret2 = ed448.publicKeyConvert(secret2);

    assert.notBufferEqual(secret2, xsecret);
    assert.bufferEqual(xsecret2, xsecret);

    const xpub = ed448.publicKeyConvert(pub);
    const xsecret3 = x448.derive(xpub, ed448.privateKeyConvert(priv));

    assert.bufferEqual(xsecret3, xsecret);
  });

  it('should generate keypair and sign with additive tweak', () => {
    const key = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(key);
    const tweak = ed448.scalarGenerate();
    const msg = random.randomBytes(57);
    const child = ed448.publicKeyTweakAdd(pub, tweak);
    const sig = ed448.signTweakAdd(msg, key, tweak);

    assert(ed448.scalarVerify(tweak));
    assert.notBufferEqual(child, pub);

    const childPriv = ed448.scalarTweakAdd(ed448.privateKeyConvert(key), tweak);
    const childPub = ed448.publicKeyFromScalar(childPriv);

    assert.bufferEqual(childPub, child);

    assert(ed448.verify(msg, sig, child));

    const sig2 = ed448.signWithScalar(msg, childPriv, msg);

    assert(ed448.verify(msg, sig2, child));

    const real = ed448.scalarReduce(ed448.privateKeyConvert(key));
    const parent = ed448.scalarTweakAdd(childPriv, ed448.scalarNegate(tweak));

    assert.bufferEqual(parent, real);

    const tweakPub = ed448.publicKeyFromScalar(tweak);
    const parentPub = ed448.publicKeyAdd(childPub, ed448.publicKeyNegate(tweakPub));

    assert.bufferEqual(parentPub, pub);
  });

  it('should generate keypair and sign with multiplicative tweak', () => {
    const key = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(key);
    const tweak = ed448.scalarGenerate();
    const msg = random.randomBytes(57);
    const child = ed448.publicKeyTweakMul(pub, tweak);

    assert(ed448.scalarVerify(tweak));
    assert.notBufferEqual(child, pub);

    const sig = ed448.signTweakMul(msg, key, tweak);

    const childPriv = ed448.scalarTweakMul(ed448.privateKeyConvert(key), tweak);
    const childPub = ed448.publicKeyFromScalar(childPriv);

    assert.bufferEqual(childPub, child);

    assert(ed448.verify(msg, sig, child));

    const sig2 = ed448.signWithScalar(msg, childPriv, msg);

    assert(ed448.verify(msg, sig2, child));

    const real = ed448.scalarReduce(ed448.privateKeyConvert(key));
    const parent = ed448.scalarTweakMul(childPriv, ed448.scalarInvert(tweak));

    assert.bufferEqual(parent, real);
  });

  it('should generate keypair and sign with multiplicative tweak * cofactor', () => {
    const cofactor = Buffer.alloc(56, 0x00);
    cofactor[0] = 4;

    const key = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(key);
    const tweak_ = ed448.scalarGenerate();
    const msg = random.randomBytes(57);
    const tweak = ed448.scalarTweakMul(tweak_, cofactor);
    const child = ed448.publicKeyTweakMul(pub, tweak);
    const child_ = ed448.publicKeyTweakMul(
      ed448.publicKeyTweakMul(pub, tweak_),
      cofactor);

    assert.bufferEqual(child, child_);
    assert(ed448.scalarVerify(tweak_));
    assert.notBufferEqual(child, pub);

    const sig = ed448.signTweakMul(msg, key, tweak);

    const childPriv = ed448.scalarTweakMul(ed448.privateKeyConvert(key), tweak);
    const childPub = ed448.publicKeyFromScalar(childPriv);

    assert.bufferEqual(childPub, child);

    assert(ed448.verify(msg, sig, child));

    const sig2 = ed448.signWithScalar(msg, childPriv, msg);

    assert(ed448.verify(msg, sig2, child));
  });

  it('should modulo scalar', () => {
    const scalar0 = Buffer.alloc(0);
    const mod0 = ed448.scalarReduce(scalar0);

    assert.bufferEqual(mod0, ''
      + '00000000000000000000000000000000000000000000000000000000'
      + '00000000000000000000000000000000000000000000000000000000',
      'hex');

    const scalar1 = Buffer.alloc(1, 0x0a);
    const mod1 = ed448.scalarReduce(scalar1);

    assert.bufferEqual(mod1, ''
      + '0a000000000000000000000000000000000000000000000000000000'
      + '00000000000000000000000000000000000000000000000000000000',
      'hex');

    const scalar2 = Buffer.alloc(56, 0xff);
    const mod2 = ed448.scalarReduce(scalar2);

    assert.bufferEqual(mod2, ''
      + '33ec9e52b5f51c72abc2e9c835f64c7abf25a744d992c4ee5870d70c'
      + '02000000000000000000000000000000000000000000000000000000',
      'hex');

    const scalar3 = Buffer.alloc(57, 0xff);

    scalar3[56] = 0x0a;

    const mod3 = ed448.scalarReduce(scalar3);

    assert.bufferEqual(mod3, mod2);
  });

  it('should convert to montgomery (vector)', () => {
    const pub = Buffer.from(''
      + '3167a5f7ce692bcf3af9094f792c'
      + 'b3618ea034371703a3ffd222254e'
      + '6edba0156aa236c2b3ef406e700c'
      + '55a0beff8e141348cfd354682321'
      + '00', 'hex');

    const xpub = Buffer.from(''
      + '5c8ae0100ddb3f5320924bef698c'
      + 'd78fa7456b6d9b5af66a9a99b5d2'
      + 'a7f7e789a81e2f539b24c69bdf4f'
      + '4f1cfcb881a5e9205e21ca27ff25', 'hex');

    const xpub2 = ed448.publicKeyConvert(pub);

    assert.bufferEqual(xpub2, xpub);
  });

  it('should convert to montgomery and back', () => {
    const secret = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(secret);
    const sign = (pub[56] & 0x80) !== 0;
    const xpub = ed448.publicKeyConvert(pub);
    const pub2 = x448.publicKeyConvert(xpub, sign);

    assert.bufferEqual(pub2, pub);
  });

  it('should sign and verify (vector)', () => {
    const priv = Buffer.from(''
      + 'd65df341ad13e008567688baedda8e9d'
      + 'cdc17dc024974ea5b4227b6530e339bf'
      + 'f21f99e68ca6968f3cca6dfe0fb9f4fa'
      + 'b4fa135d5542ea3f01',
      'hex');

    const pub = Buffer.from(''
      + 'df9705f58edbab802c7f8363cfe5560a'
      + 'b1c6132c20a9f1dd163483a26f8ac53a'
      + '39d6808bf4a1dfbd261b099bb03b3fb5'
      + '0906cb28bd8a081f00',
      'hex');

    const msg = Buffer.from(''
      + 'bd0f6a3747cd561bdddf4640a332461a'
      + '4a30a12a434cd0bf40d766d9c6d458e5'
      + '512204a30c17d1f50b5079631f64eb31'
      + '12182da3005835461113718d1a5ef944',
      'hex');

    const sig = Buffer.from(''
      + '554bc2480860b49eab8532d2a533b7d5'
      + '78ef473eeb58c98bb2d0e1ce488a98b1'
      + '8dfde9b9b90775e67f47d4a1c3482058'
      + 'efc9f40d2ca033a0801b63d45b3b722e'
      + 'f552bad3b4ccb667da350192b61c508c'
      + 'f7b6b5adadc2c8d9a446ef003fb05cba'
      + '5f30e88e36ec2703b349ca229c267083'
      + '3900',
      'hex');

    const pub2 = ed448.publicKeyCreate(priv);

    assert.bufferEqual(pub2, pub);

    const sig2 = ed448.sign(msg, priv);

    assert.bufferEqual(sig2, sig);

    const result = ed448.verify(msg, sig, pub);

    assert.strictEqual(result, true);
  });

  it.skip('should do elligator2 (edwards)', () => {
    const u1 = Buffer.from(''
      + '72ad074f3dbfbb3927125fab1f4023a408adc0ab1cbbbd6556615e3d'
      + '67501a428120ac1556a467734b1ad6820734d2100f0ed88510bd3e14', 'hex');

    const p1 = ed448.publicKeyFromUniform(u1);

    assert.bufferEqual(p1, ''
      + '133bf6517c0375c17d1e6d6bd715f6d58050bfe3dc571248628a0b19'
      + '39ac87ac79524363b120b449aa107ab2159476946a584878247bb76c80', 'hex');

    const u2 = ed448.publicKeyToUniform(p1);
    const p2 = ed448.publicKeyFromUniform(u2);
    const u3 = ed448.publicKeyToUniform(p2);
    const p3 = ed448.publicKeyFromUniform(u3);

    assert.bufferEqual(p1, p2);
    assert.bufferEqual(p2, p3);
  });

  it.skip('should do elligator2 (mont)', () => {
    const u1 = Buffer.from(''
      + '72ad074f3dbfbb3927125fab1f4023a408adc0ab1cbbbd6556615e3d'
      + '67501a428120ac1556a467734b1ad6820734d2100f0ed88510bd3e14', 'hex');

    const p1 = x448.publicKeyFromUniform(u1);

    assert.bufferEqual(p1, ''
      + '6bd0c1ee9599249bff3276e2a8279bea5e62e47f6507656826fe0182'
      + '3a0580129b6df46dabe81c7559a7028344b50da7682423586d6e80dd');

    const u2 = x448.publicKeyToUniform(p1);
    const p2 = x448.publicKeyFromUniform(u2);
    const u3 = x448.publicKeyToUniform(p2);
    const p3 = x448.publicKeyFromUniform(u3);

    assert.bufferEqual(p1, p2);
    assert.bufferEqual(p2, p3);
  });

  it('should test elligator2 exceptional case (r=1)', () => {
    const u1 = Buffer.alloc(56, 0x00);

    u1[0] = 1;

    const p1 = x448.publicKeyFromUniform(u1);

    assert.bufferEqual(p1, Buffer.alloc(56, 0x00));

    const u2 = x448.publicKeyToUniform(p1, 1);
    const p2 = x448.publicKeyFromUniform(u2);
    const u3 = x448.publicKeyToUniform(p2, 1);
    const p3 = x448.publicKeyFromUniform(u3);

    assert.bufferEqual(p1, p2);
    assert.bufferEqual(p2, p3);
  });

  it.skip('should pass elligator2 test vectors', () => {
    const preimages = [
      '79f605234dd0ab29033f70d7e93072f047968d06cb8cc2ef1cf0c7ea',
      '19251d13e3a951cbb406dbcac68ee36f9bcf2c517a201d72e7e7d4d2',
      '30592e52837433de734638ba7edf682da40f6d854be17e9e1c2e7b47',
      'a44316109eafc5eddbaeba288725514c8089337a9fd79b8b1b71c924',
      'c29f7a4b996d1bf0be827ad18443394310c32c5310b9c5813affa5e9',
      '53beba9eb96f369a4176fa5eb5c122ab83519db62838fb77a7f77009',
      'f712ade076f36cc6c15d15598814aedb2a6e061338a51671f70a5bbf',
      'e2c68652edf2c845033abe4d43224ad512273b5410231eb4663a99b3',
      '5cc236ebacd76d5cadfe68c3febe4e9194539c24cec1ebc1d7ac3244',
      'bc849fd0a5a9d307c8108c362016b9f9d88f0243a2ab2a0c75954308',
      '0e345f2cf7a8944d2d8f16e30dda8fe83c53da67bf5eb56f8dac257d',
      '8a96e8ab24fde542872e560002fb731066dedf470aebe6255ef9f67c',
      '8cee2408c0ce06079df45baf4dde0d72c59330dddbe05268eb3d2b3d',
      '8a287ee7637269fd14ab1004b222e3670022dfa0d583241ca43cb69f',
      '2a79dd9e95f17a06642af0baa01ddc15ad073b0622e9a6997617cc05',
      '9be02d1ea9d221a295fd6ceab7c2090668ee4e3b9ce3c1050fc061ae',
      'bbd7d4ded6cf61b886c9ff3c33ff1bb6be8b9321872334c452c70598',
      'e306a835a100d5c038a24ac933b9e59cd7377703df14ff4d23fa3b51',
      '5b5cd4ffac674b2dd160d484afb7775a833bc2ab7b418ac69aa57f9a',
      'e76fd0b77345f8f9ef158395e934d7ab4b6408ef4e9b6381a046f476',
      '8b6315d151ca4ac575f820a4d68fc4465a168e5ce2970193add6d45a',
      'ecbe8e03ab9bae4a1d2c5189847acd93c7fdc50312a364234c9e0f05',
      '0ab397b6557c0b8bdd22445998d7ca5fed2e2413218cac4c95866e70',
      '8184b741978153dff85710629db44caf9b2c99cd2c43196022290d52',
      'f2a28948fc3b0ff61357f322035eaebd09803de3670c70e3eb7ee5ec',
      '06ee00aaf285b259813c6f1501230f671907cac8b759dae19a81bb4e',
      'c1ab75a933da839e219b31d3925eeaf0ad390ead7ed0eb8cf9c4423a',
      '4c48aa3be5e62566b2c3fa95dc7154c13fef273558ea59c469208b59',
      '5f13b076ed42ee752e5b7877053d20c6307224bd95d88e899278821e',
      'ee185d0b4405955e0966015497c2521a8402a65fc8bebf8aa274d7f0',
      'a87a6d07bcf5b5b28ebe2724e3326c955d584839fed671d0a138c14e',
      'cf3d72edd8e521c219c279d22e95bfd08787c74116aa0fe176372365'
    ];

    const keys = [
      '36afee94a317ba45d83bbb48d1badd1f02021bab76f24c1ab0234190',
      '7984f6b2fe8d27ed1749695dc01ec95b684627db68403b30d688b3b180',
      'fb06ef06bf5a7275ddc602c2e4b641f3c129bef3707c6cffb7359f12',
      '09a292f827ce7bdb9a9e17769378019edca8407408cc50729f0fedfb00',
      '1f851ee312ac12e280900c21dcaa02cbf3d3877e7df9377e7920bf87',
      '3a5f5b768afd27605719b233113612974b4896f71e18310a735d08fa80',
      '3c552864f39b1c1643acbda5220044b04b7f220b621f49176e93653f',
      '1e8456183b914aaf4a3a8ebb69f18ae11f8905cdc8db68def2336eec80',
      'd2190606dcfd1a9894a60fc3e598211281dcb15e050bb190ba163132',
      '0393cbb5c459d0c47a713122990e9cec6ec63d43cc43f6c523fab08180',
      '6cc15a0470397d5b735ffe6d0b3afa7cbf27230e4aa62e5b27e72cdc',
      '1a2a59386a665e7a5a3fd83225beb26a17ccc43427aaa0d3e08a764480',
      'd542be9f762ffbccbd6dc7a558498f8c0793d9f06a996cecc1b58690',
      '085a6ffe1eddc4c4ea8c1de0b8ba08daf5399b428e2d2f14ca8cd86c80',
      'f2616aac5e4662676131086576f9b0529b6b7a794d290875a7c87982',
      'f5eae44435df9eaaab4fcf475c32d97e01bfd6354a6355dab383b7d080',
      '375aa981d5c0187c32493769c701ce184f99a7140a1032334b583b24',
      '52b76bd850e0efa34bb1b15fde1711a3496e0c15221052f3340d5dc300',
      '54c053a38c402b321d502d6b7c2530dcd527c18256c05be184143399',
      'cbb734e524619328fdf9cf628eda0d890612bcda175248e7794a7cc700',
      'f4b78425f413096c0bdcefcf0d4f34cd4372d36b5415086b6c3223c9',
      'a797a1fc51f8da7e610cf76afcf0568346cf8db63b377926f7f7635300',
      '76b22f8e436d6ef418a1ab0b051294bf0ef2445a7969a0be4b3924c9',
      'fb125fb407aacf1c72b71413f574120f3238627404693ad8f8a53fe580',
      '01264aafb0f6ad39aef5dd03db3aa70863ddb97426e7f167461e4322',
      'd8647da0722342db638739306aff8508df166809c644013f0ba03beb80',
      '9fa9a8ff77814069cefb74163d74e48c5fa66b436501cf4438050434',
      'c3d6ae2e8bbc39ec9509cd04c87079419ea1982d9b0ca1869046702580',
      '99cb86dc4420a0f038bd72c41c981903fdc2021d1daaf09a5c9ae587',
      'a1f5074c57e07cbb657177b1767b377ef009b05f658bc564d846b07000',
      '37e10d55289356e48444906c3a555597ae9177a8d2e25cf698599c2e',
      'b7ceb98f339afe329a398065260b0b451704eb01c75f0b736f58b40980'
    ];

    const points = [
      '14c77ffac3352dda3fbcc814f78db260a365a9c512e91e8e8861e471',
      'a822ff253b1f2b76b66a1c912afb89fddb115a5fdcc4f81eff095570',
      '3b564b3cb33ae1e41dca46c78d12d9e978975d2d5ce40f9f8e08c72d',
      'a5b39ee10a95ace9ca77716943b0eb3c4cc84330a9b41539d1d67cd4',
      '384e44cfd9b5cd110a7489b4555e74a0f4d4d1762ae620bfad0d76e9',
      '0fa7e6e92cfb51011329a2ba99970849905e00b6c9d538dfdd4c3032',
      'ec63a08b50da7fb2e43759dc0e5391323ed481926c00afcaf1fd6d07',
      '05a66708ff377fbe81d40efa36016b62bcdb80400ef4b454a7d0c9dd',
      '28a361194f36a01b353c99cd02a9636140738ef7b32cbe671d09551d',
      '199f3486b0527e7bc6dedc7cd9291b5c3c6eea6a6b89ff20ffa687b8',
      '705987723930f47c721da863f51e7bbfd6d51b9e1c4bdab178dbabd4',
      '6e7e19644434861a558a70d94d618e34e129deb7f55c3bf88d950c35',
      'c60d49bb29eff7b4e113e1bc5850a69b348fd7034643d5c7ed48faa9',
      'd2787a29f86b9d9fa1b7ad6489e6631726e064ed470e5152db47d93a',
      'aa93fa29bf1cc477d6adee878763bce7276a89ec49225ebcbd195db9',
      '22cf107a884699ea4b4b360b97b89c4888990beb72a9d8f3679a7b03',
      '1e036c8e78ebf8dcb4867dcccbd88573424fad69ce567cc15c885919',
      'a613135e3ce1d8e04b28abec4de5cd5701da944897b2b43dbc3c6afb',
      'becdcb7ee78b518a275b9b983a686aa9c3ac5c9b8c3626d46f42fb5e',
      '7e4a5c1fda925bb71d2897e7499e063f1ecc9b3d6656a42f75115036',
      'b47a6a490a554a40cde75cc8da5f9e1fca1570c9547a25533bbded40',
      '1fdd0c8ef6c251c880b7a0209dbf72dbec930db91c9a147ae595afb4',
      'bf05b01b662bcfe707294fdd6a227919c940bb5d651bfba648391bed',
      'a7c02262933fa7af2abac271db9f73472a80a62f2cf7ccdd3805c671',
      'f8cc7cd7d5f9b95b28eb80a4e701d7e957e899f56acb9c692d3fdcb9',
      'b74df3256214588c3b32ca2fe049e15e7860112835f997e4ae906027',
      'f2239605e8c9c9bd2ee8653a2f6c963ed79964e0f7d61d292d5747ab',
      'b140a3724078ea3758ec3f2492d57b7d5e76d24044b74df64af6cad0',
      '0d20721ac54c39e29b3c7f11e8ec57f5c5c487a601e1e4fd06495b5a',
      '367d6ab0c81eb40a8990516aec0ed1a86ff9e950b86d8769f322fbe6',
      '3028be07b011a96b944b3ecbaa46c78c9224a5e265288a9899fe5d72',
      '8b9354c92223ef6c9fd56f592a4cf11a37ff1f2af94081d013376bcf'
    ];

    const raws1 = [
      '5a5bc5e18dd3d597673c8e6b85220cd13624c570130daeeb221b616d',
      'f82b91f393bc3257075b9d3f0083720429415b76f11aff4af1b78ca7',
      '1c1fe51d704587f7712cd5a40d08753ef7dee5861591c35121dad243',
      '87c327d491bc6d1349db9779f69e00b92a9ef6c1eb5f6ca020bdccdb',
      'c29f7a4b996d1bf0be827ad18443394310c32c5310b9c5813affa5e9',
      '53beba9eb96f369a4176fa5eb5c122ab83519db62838fb77a7f77009',
      '6f4ac2b27ce817a6a55c8d789a981149da23d3ebdbd024556177e8d2',
      '46f09450d3d8409b1083e0bf6d3fb320d2183fd115eb82aaa3d817f5',
      'c721389587c4f5a3f849c323b46c4ef65f6e4d1952256bdf25110c72',
      'dc6171ba6f41e92d0e4741717bb3461493361573fc776106f85b545f',
      '5247d5b9a85b0add826057e5aae7204c6ee23acb996f82b5fa8b432a',
      'e1ded62cae807feb6e42db268b2f6050c017cb328a209f112c4ca711',
      'e02a0efa59f29e64ef3b9eeae6cd19a5febc50fd48da52e4b6a6615e',
      'b4a64059cedb325d9ff29a382805a5fd264d03fcbac2b1f88021ef74',
      '2197d457fb1997f87e67228fdd73796020bc353f4ba5c29fdddac4ce',
      '1c1c54851e8bac83fc05d2c6ec4570a7756a6509b4d67ef24549bf48',
      'bbd7d4ded6cf61b886c9ff3c33ff1bb6be8b9321872334c452c70598',
      'e306a835a100d5c038a24ac933b9e59cd7377703df14ff4d23fa3b51',
      '712b18808eda2d232e05872af282fb47a57e2cd017ca5f00f01b8dcd',
      'ff918d88851a5c7724e5a293a00486e5686d31b424ac0a0d9bc32056',
      '8b6315d151ca4ac575f820a4d68fc4465a168e5ce2970193add6d45a',
      'ecbe8e03ab9bae4a1d2c5189847acd93c7fdc50312a364234c9e0f05',
      '0ab397b6557c0b8bdd22445998d7ca5fed2e2413218cac4c95866e70',
      '8184b741978153dff85710629db44caf9b2c99cd2c43196022290d52',
      '950d2b0de19fa9dfbc9a1a0b2b2b641b62b3fd45a9f6c1a82cf7b52b',
      'ecdf055246ca7433fa8296972a1d96d61d25b52fb3950b3f3d30d63d',
      '071d66b0288316c78670ee8ac30aaa9fc301ba7e8e59b50c114afe5c',
      'b0cd506c6b32c23766e3994fd05511c6274bd77c44f254e40feec34f',
      '7755e4d926c0474743b48dcaac855482bd26cc000529423904019487',
      'eb411288898b3ad008574c4d79b18a8fbba09cb2592ecf140b07ed3c',
      'a8027f60a03a2b0060e4fe0bf911903f617cb92be1040618d5e26934',
      '5bef7ae78020af60eb4000480c243765740fee94e2f398b19e39b308'
    ];

    const raws2 = [
      '8609fadcb22f54d6fcc08f2816cf8d0fb86972f934733d10e30f3815',
      'e5dae2ec1c56ae344bf9243539711c906430d3ae85dfe28d18182b2d',
      '8f0f7b296007d6e57aeef2f3c8c4489b105a830db8b57c2f722cef79',
      'd18ce8f5ad874675917ccdd604ac91b266a1bc62fb62a57f380aae06',
      '3d6085b46692e40f417d852e7bbcc6bcef3cd3acef463a7ec5005a16',
      'ab4145614690c965be8905a14a3edd547cae6249d7c7048858088ff6',
      '90b53d4d8317e8595aa372876567eeb625dc2c14242fdbaa9e88172d',
      'b80f6baf2c27bf64ef7c1f4092c04cdf2de7c02eea147d555c27e80a',
      '62577d1b76546b35f8d4c603d9c1f5ebc6b6e6e2135de077aa57530b',
      'ecc5e8e96c2c4dbbe199477f6fba8e9236cbcc233ec15d1d9e1f574e',
      '5247d5b9a85b0add826057e5aae7204c6ee23acb996f82b5fa8b432a',
      'e1ded62cae807feb6e42db268b2f6050c017cb328a209f112c4ca711',
      '8cee2408c0ce06079df45baf4dde0d72c59330dddbe05268eb3d2b3d',
      '8a287ee7637269fd14ab1004b222e3670022dfa0d583241ca43cb69f',
      'd58622616a0e85f99bd50f455fe223ea52f8c4f9dd16596689e833fa',
      '631fd2e1562dde5d6a029315483df6f99711b1c4631c3efaf03f9e51',
      'bbd7d4ded6cf61b886c9ff3c33ff1bb6be8b9321872334c452c70598',
      'e306a835a100d5c038a24ac933b9e59cd7377703df14ff4d23fa3b51',
      '712b18808eda2d232e05872af282fb47a57e2cd017ca5f00f01b8dcd',
      'ff918d88851a5c7724e5a293a00486e5686d31b424ac0a0d9bc32056',
      '749cea2eae35b53a8a07df5b29703bb9a5e971a31d68fe6c52292ba5',
      '124171fc546451b5e2d3ae767b85326c38023afced5c9bdcb361f0fa',
      '0ab397b6557c0b8bdd22445998d7ca5fed2e2413218cac4c95866e70',
      '8184b741978153dff85710629db44caf9b2c99cd2c43196022290d52',
      '0d5d76b703c4f009eca80cddfca15142f67fc21c98f38f1c14811a13',
      'f811ff550d7a4da67ec390eafedcf098e6f8353748a6251e657e44b1',
      'f8e2994fd77ce938798f11753cf555603cfe458171a64af3eeb501a3',
      '4e32af9394cd3dc8991c66b02faaee39d8b42883bb0dab1bf0113cb0',
      'a0ec4f8912bd118ad1a48788fac2df39cf8ddb426a2771766d877de1',
      '10e7a2f4bbfa6aa1f699feab683dade57bfd59a0374140755d8b280f',
      'a87a6d07bcf5b5b28ebe2724e3326c955d584839fed671d0a138c14e',
      'cf3d72edd8e521c219c279d22e95bfd08787c74116aa0fe176372365'
    ];

    for (let i = 0; i < 32; i += 2) {
      const preimage = Buffer.from(preimages[i] + preimages[i + 1], 'hex');
      const key = Buffer.from(keys[i] + keys[i + 1], 'hex');
      const point = Buffer.from(points[i] + points[i + 1], 'hex');
      const raw1 = Buffer.from(raws1[i] + raws1[i + 1], 'hex');
      const raw2 = Buffer.from(raws2[i] + raws2[i + 1], 'hex');

      assert.strictEqual(ed448.publicKeyVerify(key), true);
      assert.bufferEqual(ed448.publicKeyFromUniform(preimage), key);
      assert.bufferEqual(x448.publicKeyFromUniform(preimage), point);
      assert.bufferEqual(ed448.publicKeyToUniform(key, i / 2), raw1);
      assert.bufferEqual(x448.publicKeyToUniform(point, i / 2), raw2);
      assert.bufferEqual(ed448.publicKeyFromUniform(raw1), key);
      assert.bufferEqual(x448.publicKeyFromUniform(raw2), point);
    }
  });

  it.skip('should test random oracle encoding', () => {
    const bytes = SHAKE256.digest(Buffer.from('turn me into a point'), 112);
    const pub = ed448.publicKeyFromHash(bytes, true);
    const point = x448.publicKeyFromHash(bytes, true);

    assert.bufferEqual(pub, ''
      + '661a0e31d29cd4a698b7a10821b656a1ec1ac62b95984f073f8ed8a9'
      + '4585d8ecf770b310bec537e0b9a1096c8c84de51126710646d90262b'
      + '80');

    assert.bufferEqual(point, ''
      + 'bbf9b3970b4f192c2615dd66abbfe4f51b2b695da44d1578389de049'
      + '043d83433a011ef906f7154c96fefd592d1981283fb99e8925a45f30');

    assert.strictEqual(ed448.publicKeyVerify(pub), true);
    assert.bufferEqual(ed448.publicKeyConvert(pub), point);
    assert.bufferEqual(x448.publicKeyConvert(point, true), pub);
  });

  it.skip('should test random oracle encoding (doubling)', () => {
    const bytes0 = SHAKE256.digest(Buffer.from('turn me into a point'), 56);
    const bytes = Buffer.concat([bytes0, bytes0]);
    const pub = ed448.publicKeyFromHash(bytes, true);
    const point = x448.publicKeyFromHash(bytes, true);

    assert.bufferEqual(pub, ''
      + 'e54d0e650d175799577247b7bc9ed88628bc0123a602f9f3f4a8da17'
      + '5e49cbf33912aca9396ded8b88b46807be5325f865587092ef71bc5e'
      + '80');

    assert.bufferEqual(point, ''
      + '6fee3c18014c2c61dc1bc145c224d2b5c2e48ccbb41e007927d08435'
      + '6dd0a932c189fa810622612d982a0326760c6e74b39866bbd905f9df');

    assert.strictEqual(ed448.publicKeyVerify(pub), true);
    assert.bufferEqual(ed448.publicKeyConvert(pub), point);
    assert.bufferEqual(x448.publicKeyConvert(point, true), pub);
  });

  if (ed448.native === 2) {
    const native = ed448;
    const curve = require('../lib/js/ed448');

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

        assert(bytes2);
        assert.bufferEqual(bytes1, bytes2);
        assert.bufferEqual(native.publicKeyFromUniform(bytes1), pub);
      }

      const bytes = native.publicKeyToHash(pub);

      assert.bufferEqual(native.publicKeyFromHash(bytes), pub);
    });
  }

  it('should invert elligator squared', () => {
    const priv = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(priv);
    const bytes = ed448.publicKeyToHash(pub);
    const out = ed448.publicKeyFromHash(bytes);

    assert.bufferEqual(out, pub);
  });

  it('should test equivalence edge cases', () => {
    const inf = ed448.publicKeyCombine([]);
    const x = Buffer.alloc(56, 0x00);
    const e = Buffer.from('feffffffffffffffffffffffffff'
                        + 'ffffffffffffffffffffffffffff'
                        + 'feffffffffffffffffffffffffff'
                        + 'ffffffffffffffffffffffffffff00', 'hex');

    assert.bufferEqual(ed448.publicKeyConvert(e), x);
    assert.bufferEqual(x448.publicKeyConvert(x, false), inf);
    assert.throws(() => ed448.publicKeyConvert(inf));
  });

  describe('RFC 8032 vectors', () => {
    const batch = [];

    for (const [i, vector] of rfc8032.entries()) {
      if (!vector.algorithm.startsWith('Ed448'))
        continue;

      const ph = vector.algorithm === 'Ed448ph';
      const ctx = vector.ctx != null
                ? Buffer.from(vector.ctx, 'hex')
                : null;

      let msg = Buffer.from(vector.msg, 'hex');

      if (ph)
        msg = SHAKE256.digest(msg, 64);

      const sig = Buffer.from(vector.sig, 'hex');
      const pub = Buffer.from(vector.pub, 'hex');
      const priv = Buffer.from(vector.priv, 'hex');

      if (ph === false && ctx === null)
        batch.push([msg, sig, pub]);

      it(`should pass RFC 8032 vector (${vector.algorithm} #${i})`, () => {
        assert(ed448.privateKeyVerify(priv));
        assert(ed448.publicKeyVerify(pub));

        const sig_ = ed448.sign(msg, priv, ph, ctx);

        assert.bufferEqual(sig_, sig);

        assert(ed448.verify(msg, sig, pub, ph, ctx));
        assert(!ed448.verify(msg, sig, pub, !ph, ctx));

        if (msg.length > 0) {
          const msg_ = Buffer.from(msg);
          msg_[i % msg_.length] ^= 1;
          assert(!ed448.verify(msg_, sig, pub, ph, ctx));
          assert(!ed448.verifyBatch([[msg_, sig, pub]], ph, ctx));
        }

        {
          const sig_ = Buffer.from(sig);
          sig_[i % sig_.length] ^= 1;
          assert(!ed448.verify(msg, sig_, pub, ph, ctx));
        }

        {
          const pub_ = Buffer.from(pub);
          pub_[i % pub_.length] ^= 1;
          assert(!ed448.verify(msg, sig, pub_, ph, ctx));
        }

        if (ctx && ctx.length > 0) {
          const ctx_ = Buffer.from(ctx);
          ctx_[i % ctx_.length] ^= 1;
          assert(!ed448.verify(msg, sig, pub, ph, ctx_));
          assert(!ed448.verify(msg, sig, pub, ph, null));
        } else {
          const ctx_ = Buffer.alloc(1);
          assert(!ed448.verify(msg, sig, pub, true, ctx_));
          assert(!ed448.verify(msg, sig, pub, false, ctx_));
        }
      });
    }

    it('should do batch verification', () => {
      const [msg] = batch[0];

      assert.strictEqual(ed448.verifyBatch([]), true);
      assert.strictEqual(ed448.verifyBatch(batch), true);

      if (msg.length > 0) {
        msg[0] ^= 1;
        assert.strictEqual(ed448.verifyBatch(batch), false);
        msg[0] ^= 1;
      }
    });
  });

  it('should test serialization formats', () => {
    const priv = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(priv);
    const rawPriv = ed448.privateKeyExport(priv);
    const rawPub = ed448.publicKeyExport(pub);

    assert.bufferEqual(ed448.privateKeyImport(rawPriv), priv);
    assert.bufferEqual(ed448.publicKeyImport(rawPub), pub);

    const jsonPriv = ed448.privateKeyExportJWK(priv);
    const jsonPub = ed448.publicKeyExportJWK(pub);

    assert.bufferEqual(ed448.privateKeyImportJWK(jsonPriv), priv);
    assert.bufferEqual(ed448.publicKeyImportJWK(jsonPub), pub);

    const asnPriv = ed448.privateKeyExportPKCS8(priv);
    const asnPub = ed448.publicKeyExportSPKI(pub);

    assert.bufferEqual(ed448.privateKeyImportPKCS8(asnPriv), priv);
    assert.bufferEqual(ed448.publicKeyImportSPKI(asnPub), pub);
  });
});
