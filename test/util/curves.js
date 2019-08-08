'use strict';

const elliptic = require('../../lib/js/elliptic');

const {
  ShortCurve,
  MontCurve,
  EdwardsCurve
} = elliptic;

/**
 * SECP192K1
 * https://www.secg.org/SEC2-Ver-1.0.pdf (page 12, section 2.5.1)
 * https://www.secg.org/sec2-v2.pdf (page 6, section 2.2.1)
 */

class SECP192K1 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'SECP192K1',
      ossl: 'secp192k1',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prefix: null,
      context: false,
      iso4: false,
      prime: null,
      // 2^192 − 2^32 − 2^12 − 2^8 − 2^7 − 2^6 − 2^3 − 1
      p: 'ffffffff ffffffff ffffffff ffffffff'
       + 'fffffffe ffffee37',
      a: '0',
      b: '3',
      n: 'ffffffff ffffffff fffffffe 26f2fc17'
       + '0f69466a 74defd8d',
      h: '1',
      g: [
        ['db4ff10e c057e9ae 26b07d02 80b7f434',
         '1da5d1b1 eae06c7d'].join(''),
        ['9b2f2f6d 9c5628a7 844163d0 15be8634',
         '4082aa88 d95e2f9d'].join('')
      ]
    });
  }
}

/**
 * SECP224K1
 * https://www.secg.org/SEC2-Ver-1.0.pdf (page 13, section 2.6.1)
 * https://www.secg.org/sec2-v2.pdf (page 7, section 2.3.1)
 */

class SECP224K1 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'SECP224K1',
      ossl: 'secp224k1',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prefix: null,
      context: false,
      iso4: false,
      prime: null,
      // 2^224 − 2^32 − 2^12 − 2^11 − 2^9 − 2^7 − 2^4 − 2 − 1
      p: 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff fffffffe ffffe56d',
      a: '0',
      b: '5',
      n: '01'
       + '00000000 00000000 00000000 0001dce8'
       + 'd2ec6184 caf0a971 769fb1f7',
      h: '1',
      g: [
        ['a1455b33 4df099df 30fc28a1 69a467e9',
         'e47075a9 0f7e650e b6b7a45c'].join(''),
        ['7e089fed 7fba3442 82cafbd6 f7e319f7',
         'c0b0bd59 e2ca4bdb 556d61a5'].join('')
      ]
    });
  }
}

/**
 * ISOED448
 * https://tools.ietf.org/html/rfc7748#section-4.2
 * https://git.zx2c4.com/goldilocks/tree/_aux/ristretto/ristretto.sage#n658
 */

class ISOED448 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'ISOED448',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHAKE256',
      prefix: 'SigEd448',
      context: true,
      iso4: false,
      prime: 'p448',
      // 2^448 - 2^224 - 1
      p: 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff fffffffe ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff',
      a: '1',
      c: '1',
      // 39082 / 39081 mod p
      d: 'd78b4bdc 7f0daf19 f24f38c2 9373a2cc'
       + 'ad461572 42a50f37 809b1da3 412a12e7'
       + '9ccc9c81 264cfe9a d0809970 58fb61c4'
       + '243cc32d baa156b9',
      n: '3fffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff 7cca23e9'
       + 'c44edb49 aed63690 216cc272 8dc58f55'
       + '2378c292 ab5844f3',
      h: '4',
      g: [
        ['79a70b2b 70400553 ae7c9df4 16c792c6',
         '1128751a c9296924 0c25a07d 728bdc93',
         'e21f7787 ed697224 9de732f3 8496cd11',
         '69871309 3e9c04fc'].join(''),
        // Note: the RFC has this wrong.
        ['7fffffff ffffffff ffffffff ffffffff',
         'ffffffff ffffffff ffffffff 80000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000001'].join(''),
        pre
      ]
    });
  }
}

/**
 * ED1174
 * http://elligator.cr.yp.to/elligator-20130828.pdf
 */

class ED1174 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'ED1174',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHA512',
      prefix: 'SigEd1174',
      context: false,
      prime: null,
      // 2^251 - 9
      p: '07ffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff fffffff7',
      a: '1',
      c: '1',
      // -1174 mod p
      d: '07ffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff fffffb61',
      n: '01ffffff ffffffff ffffffff ffffffff'
       + 'f77965c4 dfd30734 8944d45f d166c971',
      h: '4',
      g: [
        ['037fbb0c ea308c47 9343aee 7c029a190',
         'c021d96a 492ecd65 16123f2 7bce29eda'].join(''),
        ['06b72f82 d47fb7cc 66568411 69840e0c',
         '4fe2dee2 af3f976b a4ccb1bf 9b46360e'].join(''),
        pre
      ]
    });
  }
}

/**
 * ED41417 (also known as Curve3617)
 * https://cr.yp.to/ecdh/curve41417-20140706.pdf
 * https://tools.ietf.org/html/draft-ladd-safecurves-02
 */

class ED41417 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'ED41417',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHAKE256',
      prefix: 'SigEd41417',
      context: false,
      prime: null,
      // 2^414 - 17
      p: '3fffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffef',
      a: '1',
      c: '1',
      // 3617
      d: '00000000 00000000 00000000 00000000'
       + '00000000 00000000 00000000 00000000'
       + '00000000 00000000 00000000 00000000'
       + '00000e21',
      n: '07ffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffeb3c c92414cf'
       + '706022b3 6f1c0338 ad63cf18 1b0e71a5'
       + 'e106af79',
      h: '8',
      g: [
        ['1a334905 14144330 0218c063 1c326e5f',
         'cd46369f 44c03ec7 f57ff354 98a4ab4d',
         '6d6ba111 301a73fa a8537c64 c4fd3812',
         'f3cbc595'].join(''),
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000022'].join(''),
        pre
      ]
    });
  }
}

/**
 * M221
 * http://eprint.iacr.org/2013/647.pdf
 */

class M221 extends MontCurve {
  constructor() {
    super({
      id: 'M221',
      ossl: null,
      type: 'mont',
      endian: 'le',
      hash: 'SHA256',
      prefix: null,
      context: false,
      iso4: false,
      prime: null,
      // 2^221 - 3
      p: '1fffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff fffffffd',
      // 117050
      a: '1c93a',
      b: '1',
      n: '04000000 00000000 00000000 000015a0'
       + '8ed730e8 a2f77f00 5042605b',
      h: '8',
      u: '2',
      g: [
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000004'].join(''),
        ['0f7acdd2 a4939571 d1cef14e ca37c228',
         'e61dbff1 0707dc6c 08c5056d'].join('')
      ]
    });
  }
}

/**
 * E222
 * http://eprint.iacr.org/2013/647.pdf
 */

class E222 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'E222',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHA512',
      prefix: 'SigE222',
      context: false,
      prime: null,
      // 2^222 - 117
      p: '3fffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffff8b',
      a: '1',
      c: '1',
      // 160102
      d: '00000000 00000000 00000000 00000000'
       + '00000000 00000000 00027166',
      n: '0fffffff ffffffff ffffffff fffff70c'
       + 'bc95e932 f802f314 23598cbf',
      h: '4',
      g: [
        ['19b12bb1 56a389e5 5c9768c3 03316d07',
         'c23adab3 736eb2bc 3eb54e51'].join(''),
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 0000001c'].join(''),
        pre
      ]
    });
  }
}

/**
 * M383
 * http://eprint.iacr.org/2013/647.pdf
 * http://tools.ietf.org/html/draft-ladd-safecurves-02
 */

class M383 extends MontCurve {
  constructor() {
    super({
      id: 'M383',
      ossl: null,
      type: 'mont',
      endian: 'le',
      hash: 'SHAKE256',
      prefix: null,
      context: false,
      iso4: false,
      prime: null,
      // 2^383 - 187
      p: '7fffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffff45',
      // 2065150
      a: '1f82fe',
      b: '1',
      n: '10000000 00000000 00000000 00000000'
       + '00000000 00000000 06c79673 ac36ba6e'
       + '7a32576f 7b1b249e 46bbc225 be9071d7',
      h: '8',
      u: '2',
      g: [
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 0000000c'].join(''),
        ['1ec7ed04 aaf834af 310e304b 2da0f328',
         'e7c165f0 e8988abd 39928612 90f617aa',
         '1f1b2e7d 0b6e332e 969991b6 2555e77e'].join('')
      ]
    });
  }
}

/**
 * E382
 * http://eprint.iacr.org/2013/647.pdf
 * http://tools.ietf.org/html/draft-ladd-safecurves-02
 */

class E382 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'E382',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHAKE256',
      prefix: 'SigE382',
      context: false,
      iso4: false,
      prime: null,
      // 2^382 - 105
      p: '3fffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffff97',
      a: '1',
      c: '1',
      // -67254 mod p
      d: '3fffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff fffef8e1',
      n: '0fffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff d5fb21f2 1e95eee1'
       + '7c5e6928 1b102d27 73e27e13 fd3c9719',
      h: '4',
      g: [
        ['196f8dd0 eab20391 e5f05be9 6e8d20ae',
         '68f84003 2b0b6435 2923bab8 53648411',
         '93517dbc e8105398 ebc0cc94 70f79603'].join(''),
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000011'].join(''),
        pre
      ]
    });
  }
}

/**
 * M511
 * http://eprint.iacr.org/2013/647.pdf
 * http://tools.ietf.org/html/draft-ladd-safecurves-02
 */

class M511 extends MontCurve {
  constructor() {
    super({
      id: 'M511',
      ossl: null,
      type: 'mont',
      endian: 'le',
      hash: 'SHAKE256',
      prefix: null,
      context: false,
      iso4: false,
      prime: null,
      // 2^511 - 187
      p: '7fffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffff45',
      // 530438
      a: '81806',
      b: '1',
      n: '10000000 00000000 00000000 00000000'
       + '00000000 00000000 00000000 00000000'
       + '17b5feff 30c7f567 7ab2aeeb d13779a2'
       + 'ac125042 a6aa10bf a54c15ba b76baf1b',
      h: '8',
      u: '2',
      g: [
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000005'].join(''),
        ['2fbdc0ad 8530803d 28fdbad3 54bb488d',
         '32399ac1 cf8f6e01 ee3f9638 9b90c809',
         '422b9429 e8a43dbf 49308ac4 455940ab',
         'e9f1dbca 542093a8 95e30a64 af056fa5'].join('')
      ]
    });
  }
}

/**
 * E521
 * http://eprint.iacr.org/2013/647.pdf
 * http://tools.ietf.org/html/draft-ladd-safecurves-02
 */

class E521 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'E521',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHAKE256',
      prefix: 'SigE521',
      context: false,
      iso4: false,
      prime: 'p521',
      // 2^521 - 1
      p: '000001ff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff',
      a: '1',
      c: '1',
      // -376014 mod p
      d: '000001ff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'fffa4331',
      n: '0000007f ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'fffffffd 15b6c647 46fc85f7 36b8af5e'
       + '7ec53f04 fbd8c456 9a8f1f45 40ea2435'
       + 'f5180d6b',
      h: '4',
      g: [
        ['00000075 2cb45c48 648b189d f90cb229',
         '6b2878a3 bfd9f42f c6c818ec 8bf3c9c0',
         'c6203913 f6ecc5cc c72434b1 ae949d56',
         '8fc99c60 59d0fb13 364838aa 302a940a',
         '2f19ba6c'].join(''),
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '0000000c'].join(''),
        pre
      ]
    });
  }
}

/*
 * Expose
 */

module.exports = {
  SECP192K1,
  SECP224K1,
  ISOED448,
  ED1174,
  ED41417,
  M221,
  E222,
  M383,
  E382,
  M511,
  E521
};
