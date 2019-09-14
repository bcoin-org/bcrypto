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

    for (const [msg, sig, pub,, res2] of vectors) {
      assert.strictEqual(ed448.verify(msg, sig, pub), res2);
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

    for (const [msg, sig, pub,, res2] of vectors) {
      assert.strictEqual(ed448.verify(msg, sig, pub), res2);
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

  it('should do elligator2 (edwards)', () => {
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

  it('should do elligator2 (mont)', () => {
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

    const u2 = x448.publicKeyToUniform(p1);
    const p2 = x448.publicKeyFromUniform(u2);
    const u3 = x448.publicKeyToUniform(p2);
    const p3 = x448.publicKeyFromUniform(u3);

    assert.bufferEqual(p1, p2);
    assert.bufferEqual(p2, p3);
  });

  it('should pass elligator2 test vectors', () => {
    const preimages = [
      'caacad1ca9d3201b58ef77c927f9ef4834b634a80c6710e71f0524e3',
      'e4db956a3a35b9468a2288842de235e33ca058c4552197ee439ee7d9',
      '6a5ce2159ad7d9d300763c834506156960c942224abcee0342cedfc8',
      '228c0c8e65dc380d2da287cb70b56c5bda4c55b8d9a396126b6caf74',
      '80204646917b47781bffdd095aff481cdd37439b5d864d7c740d27c4',
      'bed70cfc493817300ca43bd0443b614811b3a360aa39edb93072178c',
      '416c11fb5ad638eb34ac6478bad1d29c49039d680570683f2e6c4179',
      'f5ae015dad92a385c46fa8424c107f7dbe15e7395b5854449beac2a6',
      '8ba4bb6193a1442109f975e6225a8b82ed0c892cd7a1d22ef0a1693a',
      'f53fe066d12576e468b99aea67c11e08810344a56e9bfb964cd7bc47',
      'c45c5a4cadd17cb6ba86ceacd547c846e6fec8d9089a7bfe3b413821',
      'f4eb7469ea9138125112f42a6caa24d0adc2458ce4957c80c959e0ca',
      '7824cef672724f64e706e13169c621e164baee9a9b5b8d1c3934f175',
      'f682fe025437694b33dde63e9309eac430b74addde2aca05d0af3434',
      'bb6ff2caa698b0b8deed1323266fde88218881465f95c2413db88213',
      '3e34c04ce8bd6ee8ab61888b1b1c30efedfbf8e218a77bf7beb8a792',
      '27d6eb515b9ed0a9ffc6b51c1c4f8ec8bc69fca5f9619e3d6205340f',
      '7469f4ac1d68e643f9d4689866120e14a1f4d87ec9ded25ddde4cef7',
      '0b1d446c9d0f5a06130000bdf97a264cc001275afedb95a88298bf67',
      '8a5f39aa192dcbc1ec40e79e540ed031bbd701d23c0909d451079419',
      'da4ac444454227ff96e570bd5d5daa9f942f7eb3c30bf23c0f696d50',
      'f76982e0e1c97e03c30c192b2cb09162db445793a8d894f33d618741',
      'b774d0fb90ee9f6416a6056c768d51e38f834c6172067bc03e49edd4',
      '84a7a4932b4a69490ad8ef7fa19643a0cbcb5d79ad011863631f9945',
      'bc9fe8711d8b63bf16b436b40f49f53ed51c164255e4eea7cb13692c',
      '7a56bd2b987d132793a7aaffd4b14aa323705d13c9dcaba582897a65',
      '55e96f39bb173588c46db9379e9209cfc80e44d09c0c6785a83b8c12',
      '8a16e78ec607e3f93a41f250413618f78252a150cb0e6c40e904f026',
      '5f8aa2271e8ab3fe71f654877024affdba8599e7ebe149ab67e688b1',
      'aa774c7ea6a9ab0f43f77fb09a3c144e15f232e8ec2a278961b41913',
      'a2677cded2eae650f80fd9701ef6aa2c99823c7571f7985dc101258a',
      '2527aec7e97f426ba04c920056ca44bbd3afb71afc7cb8c952cfd0ed'
    ];

    const keys = [
      '7cfd93ce8d09f20277bb196d2e486b34c9d15983781e6b4a9e8855d1',
      '53a0972c375230d093866882484c14a93c43dc94a7b7ea7aaaebbc3c80',
      '9c2a0dfcbb06a17db17ef60078576210adc7e5d7c5e0c33e7a319005',
      '4960ac8accdd8e46c0dabe8da944ea47c242d46f16b02be08892c4ba80',
      'd88d28b13e0e49068d64eddeb20afdee18e9e8083ded79e0e448217b',
      '141564f26e88a1ade79687c359edadf17d025d5566c63378e1acac6080',
      '2b97d5840c16388921062365d5b5e979bbe4ea91fa5e7492a7474348',
      '8c5f8475e56a1eeae39b50050d2c1b6dd5109048026d64fdeca2917700',
      '81cfd3084bcbf0fe79ad5e551b2cdc6a57353d551645f7a90a136492',
      'ba7e039759c5833524b8f70cc01cda837ea1430cf20c49355d7f082000',
      '3e14c84c41eaaf8e9cc81f5d874674eed5e3414c2872f94ddaea386c',
      '002e0ebf95701d78423f3e7255972eaad7776ef00463f8614dc0ea7980',
      '8cd399062925cbfd2a48e88fb935f57f73beb25755e70961993438d3',
      'd63476581b2148909d29baaa5bc2567058ff1f9a83b298c61e65e39c80',
      '31253d6e178e6a63383ae0761e4ded962dd98c8e8e975363b825ff22',
      'b204ec4c23f9bcc932c9866e97969f252fddb61d1362688b9c21ad0600',
      '4290298f541d76507eddf62471ecd434e22814f0b26f7c674f5e35ec',
      '59ad8dc9c18aab35120b2a64e4eec58d653896e8d9cd3cc8d4bf964e00',
      'cfe5f767c5f93343d220b22ccdc741cae1b89691ecf3dcf99648da9c',
      'a66acb390d86cd7e98d867437f45c41132d7d9435e436b9859f2871b00',
      'bc44782bbd9ec79df36c1a6c33cd84e54fac5a82ac7ac24577a7ba79',
      '92f1e7ce34b675a3b67b7e4af53aa78516481a1026f2124853fde67900',
      '0eaa3620405f613758498ba6f02117f0d8066db7a910f7f59e17571f',
      '5f5aa3fcc55331dba9a2e59fb9b954e0525ead29c7a24a65b7ef83da80',
      '9d397566a289d82e41ac87ee3f76b0d82f38518894b24650a209c341',
      '7374ce87a35b86fae1ba3d3ce6d0d5eeee4fd3680d51d05a077705e880',
      'a47546f59e9663ae7df06e4f23adc421c29c941ece89c537bfb20260',
      '44d015b0b83c13a22d3940c4bd3f9ba0ba8192a089f44072d63d583200',
      'fa4c8a0a3804737c7ddbbf4cbc2b23f3ba4896e28ff8b1f0e3a7a78f',
      '8546464c36c179300c41f4714a4a603ce2be7d10319620a2c3e5b5c100',
      '38a05ed15e3ea2e336cae8518e2bde3b50f1bc27a7f4d6de4799f1ea',
      'badd6d682a4bdceae5e913ed7df7ef53784f6eed8e864be6ff7eecb900'
    ];

    const points = [
      '353dfd034861859ca6d2d55b94feee6fcdbd92262db5fa7f8ff050cd',
      '0bef67c78a0230a466db31e370462345c6e16b409655ed91ab1b9846',
      '2ebdb4d35d3685befc4c7c4351d3d7f58a6113cc6532fc231731d080',
      'df6ec037f3923d48be188658c48443875ce98c91992d86167d28d0e1',
      'b8eff1ce3ccbf147f92b6c3ee7835c5e75587c6cd8f69a8d8573cd85',
      '19031cb29b83397e77b58ef8d991bf6c7fe39c3a5908172990064861',
      'f62bc4e8eda4e8f47bc96e93e2d94efd052c0ad7bc6ffdd2fbe20efd',
      '644a9aa924f2332b023c61bd8b716aa6b82fb70b637181bcfcd0f3aa',
      'b066c6ba23614d8b8a863e6055b1c5d6f584c6f134807de4cd95074a',
      '6618c087583dab630a8fbd921ad726941f4b8911ee7c85c1e7d5bff5',
      'cda966d321b165f9849d0858df07e847f4139505f8ecfc3f115b2686',
      '6f3eb168c9de84ca900b3346cbb77d8e2867ec91c90ffa1225003d59',
      'f3346e1773f38ee47fc7503ae2a7182d537d332bca963efeb090d026',
      '286ca32dde54c517097c828e8553a590c89b2d466532198cf701fc2c',
      '8ebdf6badddd3691119eb28110cfba4d00a64261f45278b5da68d748',
      'ab2c7c7267870fcc68ac9b5a9ffefa0dd50fc6b5aa88fc647d343fb4',
      'd0441f4157f1602bcf0eef2581567f90ddcc441226c950a90a344a04',
      'f2d17a919f4a4e98c71ce8d1ba35576d8e33e4a8fc11f10277d94e76',
      'e9b892cf1c0cb5065a0c8f1c87bdac3a6dd4676e943d56b9fd1d4667',
      'c5cd0c1b79b9fde17711f1786d02a36b89b404b0044c16a03b3a7e7a',
      'e8030d3a5a3b9f9b3e7c5bf017471c025fafc76f75610c0575db96cd',
      'bdbf13637a71def679150349e1e86d63dc5c77a865801d6ba288a426',
      '765b1c605ebe73716414cf21e3974db386f179f6d17ae367a3174e17',
      '9d601067cb9f02a219070828bb7181d101bf8e8038dcd7a163683eca',
      '6c5b2398f4436eb86c821a1d8498db3ff3effe5af27805b9fff2f16e',
      'bf7ba53f47ff378be21ca886c13583627eaf9ad48da9b6d776cb6077',
      '5999f1f248ece09564c8579c73dbee2052c7cc4e52aea09ab8fdd4db',
      '37fc946a63a0cfaabfca0ee616980e9a6cbc9ba6efb6ff7174a53bdb',
      'b570728f3d136ba7b22b833e96206510fc75c11ffd6b26b091c30e8a',
      '60bf6721d0bc333ba09eb8d1007003fbd63d318d8a3c6f13840f9b8b',
      'abbc60caf2065275f565a35121c0d8ae076c77e4278004ef4c143891',
      '82709820e3315b5fa0d216c1cd3ffd25afe9c4f6459544b90c993a28'
    ];

    const raws1 = [
      '705d54ae2fd279456842d0a13668d574bf39ecabdac2868d1a08f519',
      'ca44cfdbd581b260432f089e331c98b226542572a2fb98b9c2e60d3f',
      'ce568a6660c32b3b0796491973ccfd93a4629907720084aa377053aa',
      'ddeadd42306042528bf55d0d151f59a6cdaef26a25c382d7dc89940c',
      'e7f8c8f3255b7e1800a62ccdbe9f30604ab56519c1e07fb6e2a708e0',
      '630249705d6fd8cf6995951c65c062ad64ea2b027357390ae3d12d32',
      'be93ee04a529c714cb539b87452e2d63b6fc6297fa8f97c0d193be86',
      '0951fea2526d5c7a3b9057bdb3ef808241ea18c6a4a7abbb64153d59',
      '8ba4bb6193a1442109f975e6225a8b82ed0c892cd7a1d22ef0a1693a',
      'f53fe066d12576e468b99aea67c11e08810344a56e9bfb964cd7bc47',
      'df20379c352b1356379f0f5e50b3328a43349936f9f613aa002608f4',
      'c0f7d2b374c83710bb3f95b696807c7f25d9b56bed9e02e51728da74',
      '87db31098d8db09b18f91ece9639de1e9b45116564a472e3c6cb0e8a',
      '087d01fdabc896b4cc2219c16cf6153bcf48b52221d535fa2f50cbcb',
      'bb6ff2caa698b0b8deed1323266fde88218881465f95c2413db88213',
      '3e34c04ce8bd6ee8ab61888b1b1c30efedfbf8e218a77bf7beb8a792',
      'd8386e8bc47349c54832891e23fb306b0efbd2d8d6755f3e6e094ecf',
      '7a8ce0c4e9114b9f5b702a1ba0ec4983d0dbd024d71c897a4b8412bd',
      'ec94d11f18853fab99f4b1a280a7182e040f6120779c9d63c6908230',
      '9553dd1ce8e0e5bdcecaf49a8ec10f8f93fc8d5c6a4fe12b4f5bae14',
      'a39e0c8e560282f03982232dbe47e09248191c97ad6acd745db99a74',
      '6b7d9be6a46c40597d1ba95b32e0fed63fb65babe47d8413ffe7e592',
      '36fa4b29106aa3783d37fd43132ac3d0b7fbbf3b64e911fd9957f8e4',
      '418a5a535d1b0aa0a0812e1019d0792e44ab15baf9aad449c5f6d789',
      '4360178ee2749c40e94bc94bf0b60ac12ae3e9bdaa1b115834ec96d3',
      '84a942d46782ecd86c5855002b4eb55cdc8fa2ec3623545a7d76859a',
      'b99ad7b17415f0221a4e2b60b58a93c24678dfba1b2b777b2f5ace8f',
      '6999c459d47c599ada2af3c74223662fd7a9295fc7487b97cca2e162',
      'cc52c24e20ac50fb74483cc54eaa034708c6ce6f60dfbf5e0154ed54',
      '7006645f1ecfd73e3dd249c2391b1554fba9cf2d5030b2e26d671321',
      '45665ebad1d3733e1f0d7ffac7164fa22e08cbc65b3f051f135990cb',
      '4ed643769e107eb8f1725f9d1f1e078399184f54c4331f966e3aef96'
    ];

    const raws2 = [
      '355352e3562cdfe4a7108836d80610b7cb49cb57f398ef18e0fadb1c',
      '1a246a95c5ca46b975dd777bd21dca1cc35fa73baade6811bc611826',
      'd9b76081129974727f97d80278e6ed478a0ba642d6dfab0b29a901cb',
      '6f2faa49df16e9ddadf86415a9466a2252eaa23a5e9ccf517f7af89b',
      '7fdfb9b96e84b887e40022f6a500b7e322c8bc64a279b2838bf2d83b',
      '4028f303b6c7e8cff35bc42fbbc49eb7ee4c5c9f55c61246cf8de873',
      'be93ee04a529c714cb539b87452e2d63b6fc6297fa8f97c0d193be86',
      '0951fea2526d5c7a3b9057bdb3ef808241ea18c6a4a7abbb64153d59',
      '63e46333340f7e2366f2a06812d5f8e41e12edf9c5690bf4ab4b1532',
      'd881eff29cbb03c69d76aeab2dca00cc3cb5c3d0cfc8db2295d25c4f',
      'b320db469edfd989c45e35d8a33b4232b74d6659f61967fc26bb7aef',
      '18909402c17f25683e7b0cdb03fb17c15df28441e3a973f7388a7906',
      '8f35224b5fca037eaad767ece5996afb2d1364ffe8933376e70a9821',
      '6ae05e18041b4f3c6998462ebc8a04b18bcb5c5da5013f12697c3ea1',
      'ae6ae0ba1e38e3c91e08031a0188d00152919f44b09d9a8841f35f12',
      '6eda361668afac3d50c24b97414c8fcb2670dfe67ca806496005bfea',
      '27d6eb515b9ed0a9ffc6b51c1c4f8ec8bc69fca5f9619e3d6205340f',
      '7469f4ac1d68e643f9d4689866120e14a1f4d87ec9ded25ddde4cef7',
      '0b1d446c9d0f5a06130000bdf97a264cc001275afedb95a88298bf67',
      '8a5f39aa192dcbc1ec40e79e540ed031bbd701d23c0909d451079419',
      'da4ac444454227ff96e570bd5d5daa9f942f7eb3c30bf23c0f696d50',
      'f76982e0e1c97e03c30c192b2cb09162db445793a8d894f33d618741',
      '488b2f046f11609be959fa938972ae1c707cb39e8df9843fc1b6122b',
      '7a585b6cd4b596b6f52710805e69bc5f3434a28652fee79c9ce066ba',
      'a0793b526f5d4d0fa03338be2838c233660ac6d229f12df3dd48f7ba',
      '6d85ced41a136abcfdef2a7b17480838344d3dc821c8953af2132e51',
      'd2b60a16bfe2f0839af12a142fc9f2e8ddf8d7fa75fab53ce7d92323',
      'f07a576a7a270efcb10dd35433360e8d2408582bd53d06955aaf85a2',
      'a0755dd8e1754c018e09ab788fdb5002457a6618141eb6549819774e',
      '5488b381595654f0bc08804f65c3ebb1ea0dcd1713d5d8769e4be6ec',
      'e3f04214d839b22253ae4a93d4c5cc3fd4be31d0c4f2cb8cbd10003f',
      '58c5e8cf83e7cfc14b717f1fa4b4cda98682672b1f8f73ab0eb5dc50'
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
      assert.bufferEqual(ed448.publicKeyToUniform(key), raw1);
      assert.bufferEqual(x448.publicKeyToUniform(point), raw2);
      assert.bufferEqual(ed448.publicKeyFromUniform(raw1), key);
      assert.bufferEqual(x448.publicKeyFromUniform(raw2), point);
    }
  });

  it('should test random oracle encoding', () => {
    const bytes = SHAKE256.digest(Buffer.from('turn me into a point'), 112);
    const pub = ed448.publicKeyFromHash(bytes);
    const point = x448.publicKeyFromHash(bytes);

    assert.bufferEqual(pub, ''
      + 'a5f7d148e75933ec9c99348179d0f105a1bbffb84d2a03313e2724cf'
      + '3647e1db13c2d6c41be53ffe9e8bf53c4c2e3242ef0066260ec04bf3'
      + '00');

    assert.bufferEqual(point, ''
      + '9f3d68330e24951bdbc200ed6d25ef4e90bc678d68282af081e6204f'
      + 'c2f36dcc5d6611b41042d708caebbe80724e48d09adb9782a9a2d9ea');

    assert.strictEqual(ed448.publicKeyVerify(pub), true);
    assert.bufferEqual(ed448.publicKeyConvert(pub), point);
    assert.bufferEqual(x448.publicKeyConvert(point, false), pub);
  });

  it('should test random oracle encoding (doubling)', () => {
    const bytes0 = SHAKE256.digest(Buffer.from('turn me into a point'), 56);
    const bytes = Buffer.concat([bytes0, bytes0]);
    const pub = ed448.publicKeyFromHash(bytes);
    const point = x448.publicKeyFromHash(bytes);

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
