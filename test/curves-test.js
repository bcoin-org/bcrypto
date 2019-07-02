'use strict';

const assert = require('bsert');
const BN = require('../lib/bn.js');
const curves = require('../lib/js/curves');
const rng = require('../lib/random');

const {
  ShortCurve,
  EdwardsCurve,
  P192,
  P224,
  P256,
  P384,
  P521,
  SECP256K1,
  ED25519,
  X25519,
  ED448,
  X448,
  BRAINPOOLP256,
  BRAINPOOLP384,
  BRAINPOOLP512
} = curves;

let p256 = null;
let secp256k1 = null;
let ed25519 = null;
let x25519 = null;
let ed448 = null;
let x448 = null;

describe('Curves', function() {
  describe('Vectors', () => {
    const test = (curve, vector) => {
      it(`should test curve ${curve.id}`, () => {
        for (let i = 0; i < 2; i++) {
          const ak = new BN(vector.a.k, 16, curve.endian);
          const ap = curve.g.mul(ak);

          assert.equal(ap.getX().toString(16), vector.a.x);
          assert.equal(ap.getY().toString(16), vector.a.y);
          assert(curve.type === 'mont' || curve.g.mulSlow(ak).eq(ap));

          const bk = new BN(vector.b.k, 16, curve.endian);
          const bp = curve.g.mul(bk);

          assert.equal(bp.getX().toString(16), vector.b.x);
          assert.equal(bp.getY().toString(16), vector.b.y);
          assert(curve.type === 'mont' || curve.g.mulSlow(bk).eq(bp));

          const p1 = bp.mul(ak);
          const p2 = ap.mul(bk);

          assert(p1.eq(p2));
          assert.equal(p1.getX().toString(16), vector.s.x);
          assert.equal(p1.getY().toString(16), vector.s.y);
          assert(curve.type === 'mont' || bp.mulSlow(ak).eq(p1));
          assert(curve.type === 'mont' || ap.mulSlow(bk).eq(p1));

          curve.precompute(rng);
        }
      });
    };

    test(new P192(), {
      a: {
        k: 'e8c74e99092a9c2ef5c9d0826697ba7b0dfab11ab17c059d',
        x: 'c6e75a4b307136b15e6fcd818f7293172daed8a6ee60322c',
        y: 'c9f41596800c4ccf49fb1c269f884a3d579d12a27f9b2d96'
      },
      b: {
        k: '5d41ac4d405c63962e4e54012641c786a9159ce76459815a',
        x: '90fe10587acc6225b838c713b5b57229350e101ee617cc12',
        y: '802b7be71b58520f10a34645fcaa5d5f60b3f810d24b997c'
      },
      s: {
        x: '9f2dece64a07592fb7decd76a9d05b5a20625518791a199f',
        y: 'e8741f00bef890a7e4ae24553206cae441031968df5ec32c'
      }
    });

    test(new P224(), {
      a: {
        k: 'abb9950e547809ad079ba8fde54779758933b032ec672b295a9deaf6',
        x: '534394a69b2691518977f518e7beed689f6fd9c27d0dc1f6d32d2c3b',
        y: '29cf860ff12256838a40a67d73adf4122be7c2df1bbca7f75c14ceb0'
      },
      b: {
        k: '4745aa8211b380bdc4b255c2c6da9b99d906b5b18e2290a99f195d67',
        x: '9ea0592b17e215614e1f183250dfa34c749ff0d8a5226c3258042e2e',
        y: '71a37e1e2dd0c89e3a0188bbb715a2aa945c38fb0f3335d8727ac7ac'
      },
      s: {
        x: 'ca2597e841478ae363e20a8b081676c201aef595036df5d3633b8f5f',
        y: 'f1c70b6d66af764eb5b0ccc586e7a8639396204ff0cafe998d3d07b6'
      }
    });

    test(new P256(), {
      a: {
        k: '7d31b3980a670adb31fd5943b87453e7c19e30b90be2f6fe1698e0f5796df55e',
        x: '647293c0e08ae35140ba371f67883bfc848ead975e27dd7f8a6db2a259bc2e1b',
        y: 'aba8d40f11322dcd93d1d88b9907cd9e0c15be4a50f7850cca86c0e9492c1bf3'
      },
      b: {
        k: '05a0d3d015d0c82732b29c4c5e671c623b3360c58490baa84e3e43ca8d596097',
        x: '7040bad247e0508acde9df1b495304808c6b87428a0cd4a5e4940c63ab0abd34',
        y: 'd4be56bb2eadc8be86880bbbc8c13dd2e36096b1f3377679129f4a40526bb8f6'
      },
      s: {
        x: 'ee80975a3db44157e862133724380f84169059a3ab8bac331f4c4892a9119182',
        y: 'e37df17f1e7064d1b12a192ae65ca6ca20ffc470d88d91b66f94da700e107cd4'
      }
    });

    test(new P384(), {
      a: {
        k: 'f1ac3d7aa847c2235e393fdbe353d4408bf603207da7918eda6c9c9d66db6e04f9d13bad8b554a04b690bcbfc125c540',
        x: 'eb4aec872170c5b79205de6ba8b0196cc3d8c75e4291eff800ba3dcf88a581a5281b3b860586147b6d926bf6829f4ac5',
        y: 'e12abdd483df66b6b7c210ee927d549e6eb58a2ce66b2abe41cab3eb05743c05802d580752f09c4872e86f5965ce2f22'
      },
      b: {
        k: '79fba6a1a13caa899d9829ba5c5a0431a954980a559b747c11071816babb13868744800879dbcdfb40120087917da3e0',
        x: '63b9eb16e3c999692b5ec009863cb57e8fb849659eac50b507ee651f3d1b93869a956386e31c11574cc948ceae95a704',
        y: '8a116cb2bc9fe827fb7c6cb9af4649fd278e2c0af7dcecb062f17c716049cc57a975028bbaf57987f35fc4f1ac9803ff'
      },
      s: {
        x: 'e79e3a3c14c5405b74dcd86fdd1d03b81e7a8c394fe451d104ca3f99e3f57a674e548f61dfde54fd9ed6558ea62c9ade',
        y: '1213c4a9e0b996824455694d9af2a7573ff00dc35cdb1decce45931c089d2f9d1b07c85500af3d6ec6e70f8834759c87'
      }
    });

    test(new P521(), {
      a: {
        k: '007783085a324b70832c4d6e5607d25fb291459bf9d7c620f658d8f01903861dcfba056756cad95a6628cf0084eb778baddbe71a47f177e3e09c0f278b8585dd7ea4',
        x: '3654feaa311aae18d74d021f3fb12c9ba193b1673a298aadce1214f17d41640f222650b66dec1fe98559a4e9b0a3f4523099f98371c808cf6360fae7258b166192',
        y: '12c4c3fc89547a2697b567b9fb226b204336faa06e963751baad4000e16105a5230d890f2e867ee9fe3538e6babc442688850d5bb469035621ad38d45724d7ca3fd'
      },
      b: {
        k: '01891acf4771cf31fae03c1c1e37e4fa7cfba3cc53ce3941d9cbc5cf57c2a2a0524ecf805418485e2157f900f7a4d490dd97f3191b1bf1b27fe50a190196d2517b79',
        x: '121936da291d82d91a2a2c7b5395b0fa1b5ec78c7997f2947ff2c818f737df8c62583d4b9833b3889616c483cde977e79b593c0f03b497e40e0412ca04ed6e518e',
        y: '10afd2ae9c4a86a7bb732270da25504d1ffbba1805386bb83acbd25b085419ccda4c56bf3af4fa62b4060a333718e199d73e6830f81c0e7beb2ffd959acf3bb7512'
      },
      s: {
        x: '1b0d33c6c257eaf624fa379ce1db07e47910dde06f9e60568a17372439ab058873d9c29a220631b9873ed451e911ff6069f95f68c6ac6dfb69f5133437b31e0194d',
        y: '12b6bc4b6cc2da4584489f2179ccd70c016a746f1acd67c4bd040fb9a048ddc100d08240b3ffea8a8054fac4307ef10f66e8fad2986f2fddf41092847b40de38e41'
      }
    });

    test(new SECP256K1(), {
      a: {
        k: 'f40749b74e7454a808fe318349129d7956bfe4df271d7ad31b3daf9866d538b6',
        x: 'eef57567a6beda8b2307bdb2e2d64649ca3da5e99b0e6e600b258ed7fc5c6432',
        y: '76cdd5f153bd292bc5c0aa451f70d4adc43f0fb6944cc75dea850bf87701061a'
      },
      b: {
        k: 'b13d3ceda8e56c900005788a822a432a42cadd11f690a260c71418eb8e44d683',
        x: 'f96e09c5f26fa15c38fd52282087c96a53411a75d4a65a9faed9c1113955b28f',
        y: 'cf867faf174f422673a146bec0fc41e0d1082e4a6e2711012c30ed49cfa7c360'
      },
      s: {
        x: '42fb130736618fcf3b70c6b44d8317fd754ec46b8ad4cd83b75571374b33a268',
        y: 'd920e5c9a283600917e38540bcebea9e56543c30055958b60fca0a4ff26ad8db'
      }
    });

    test(new X25519(), {
      a: {
        k: '0023598e8367f24bf223cd1829653714ab8df7156e63dc699843de240ef9c041',
        x: '4e855a3acc67d76456afc5a2c854bb4ee83f0df16d3010e9cfeb02854b518370',
        y: '1f966b62a728f2649d31d61f644d70e827a967090880cb540924db14a71fe2d9'
      },
      b: {
        k: '6894cb8966019cedbe56bc7fe70cef2fadfa399e3b1e348c54dc284c00d80d66',
        x: '2820cf502c9d9e227c785b4c58c0911cd3b6421c507f6a54dab413b0488ab82d',
        y: '243f45f6f3822a93121cd88e36c7ffbfdec7c706c5278e09cd5b189f60e191c4'
      },
      s: {
        x: '1af9818fd4ea2348a3695c730e647d4f0cbe9ad193e4d1d37b653afbc1ca27ed',
        y: '176a274d4360fdc2567d1a4c251e28367fce8f9f451abdf8cdd4c898b7103d45'
      }
    });

    test(new ED25519(), {
      a: {
        k: '0023598e8367f24bf223cd1829653714ab8df7156e63dc699843de240ef9c041',
        x: '7143fec2823a20e85bbfedff1a30468136983c8b32c09bba6991f4055b213613',
        y: '3b1dd63ace37221fd9bc0d11b2196938c32d92bf04aff3913bfb90b5489e19bf'
      },
      b: {
        k: '6894cb8966019cedbe56bc7fe70cef2fadfa399e3b1e348c54dc284c00d80d66',
        x: 'dc96522329ccd49233ade48a29fdbfe8dd46f23974d9b5ee5ec41ddf9f9ab44',
        y: '7cb80d4fc3336a3e7e7e63b18616cef9d269c580059f1842bd814b06280740d'
      },
      s: {
        x: '41ba2e23566ad6a2b41e08bb389c96aa71a470b03f0ed0a0137e91017e2cdd3b',
        y: '45b57e51719ec114cc1cb17d74aead651946293166152e90223a82b4b5b449eb'
      }
    });

    test(new X448(), {
      a: {
        k: 'bc2f31e6e46f63537427138e0bb398241c0c33df1190e1ab54bfec56b97751a5693676345c535aa401f909c99ce83f2acdfa83ec35687dc1',
        x: 'a31700b63788e5b28616a3528c361f15abb59af9541bc66b74dd5dffaf9a0e31ccd32e032e843bd199870a255b22cdedce637b680ec68786',
        y: '2cdb7c77ee22cc2b25cf9a143d1efdc8326e3dbdfc2e1b95448dd0b7449dea313c82135b621db02d9edee8b1f7ecc55b5af77d3dfe200ad6'
      },
      b: {
        k: 'c8634c85eb57eb4ef9d002fcdfc803cdf625ad0e1ab4f076b1d09c29c3f1be89638a60e716f502684bd9f773b324fe8e755f917be4d9e3a6',
        x: 'a9989ad97dc0c1a53cd6b25c3277f51aef5b285c4aa2d9def8db83021deea334878cd056eaecbf6bf1d1b8bb9748bd95f3199c707bd24874',
        y: '5929d6987b87ecc1d97a54bd9f9b22b697e502efffffc9fa6d8ac99f1eb377203d4618b980fa64ed4556290321355326bfad06c5ea49362d'
      },
      s: {
        x: 'd46033d9447dd8beb58504e511b007e09050e6009f605e55ee923ce61dca73a204d20cd0bb02209f9c67ba95dac759108d62299981d46e91',
        y: '9383c4ef7666196fda743ebea49cbcfd4410e8f12bf66241f36ee1bd0f10ba1c34da4205755f03816cccda96e2fb84801ceb7c33c32dec53'
      }
    });

    test(new ED448(), {
      a: {
        k: 'bc2f31e6e46f63537427138e0bb398241c0c33df1190e1ab54bfec56b97751a5693676345c535aa401f909c99ce83f2acdfa83ec35687dc1',
        x: '5a261d8379f0a2eba1f937c1be72cd54459c42f0510488f12828f2e455cd774d3ac17a7fa5a774403b9f3109c6035b9212e0923add16bcf4',
        y: '7765689f859de84d0feb418644db17e1ac2c3040a294d904a21930e23114d14db8c60f07e65ff133e56fd2295e5b215d4d4034a52ec6e1c6'
      },
      b: {
        k: 'c8634c85eb57eb4ef9d002fcdfc803cdf625ad0e1ab4f076b1d09c29c3f1be89638a60e716f502684bd9f773b324fe8e755f917be4d9e3a6',
        x: 'f9034affb5ae198a8a50934f86dfdabe74ea4a0b9379c1d71d1539c99c60d353a3b85185f45e6a53106346a7b1e2f01099e39587a50e968',
        y: 'd17800e9860f2eeaa7d2f9955969b981304351841eff8390a398d0af9b0219b6accd974ef729c31cf88bb723cb9b218096a9632106a8c64d'
      },
      s: {
        x: 'f99f4dbebd341334940a4215151a69d5ebb0412343a07efe4ba205c534713ca5110ea9683d734d05e3b706d92466311d0e99c3284dc6dab2',
        y: '9ff6d9d30735cf9f8cd25042ba28f40c9ab34da9aec2ff743601be24a32cb36d8d19184a75f20b9dad183be6791ec2a17dac7433232581d4'
      }
    });

    // https://github.com/indutny/elliptic/pull/144
    // https://tools.ietf.org/html/rfc7027
    test(new BRAINPOOLP256(), {
      a: {
        k: '81db1ee100150ff2ea338d708271be38300cb54241d79950f77b063039804f1d',
        x: '44106e913f92bc02a1705d9953a8414db95e1aaa49e81d9e85f929a8e3100be5',
        y: '8ab4846f11caccb73ce49cbdd120f5a900a69fd32c272223f789ef10eb089bdc'
      },
      b: {
        k: '55e40bc41e37e3e2ad25c3c6654511ffa8474a91a0032087593852d3e7d76bd3',
        x: '8d2d688c6cf93e1160ad04cc4429117dc2c41825e1e9fca0addd34e6f1b39f7b',
        y: '990c57520812be512641e47034832106bc7d3e8dd0e4c7f1136d7006547cec6a'
      },
      s: {
        x: '89afc39d41d3b327814b80940b042590f96556ec91e6ae7939bce31f3a18bf2b',
        y: '49c27868f4eca2179bfd7d59b1e3bf34c1dbde61ae12931648f43e59632504de'
      }
    });

    test(new BRAINPOOLP384(), {
      a: {
        k: '1e20f5e048a5886f1f157c74e91bde2b98c8b52d58e5003d57053fc4b0bd65d6f15eb5d1ee1610df870795143627d042',
        x: '68b665dd91c195800650cdd363c625f4e742e8134667b767b1b476793588f885ab698c852d4a6e77a252d6380fcaf068',
        y: '55bc91a39c9ec01dee36017b7d673a931236d2f1f5c83942d049e3fa20607493e0d038ff2fd30c2ab67d15c85f7faa59'
      },
      b: {
        k: '032640bc6003c59260f7250c3db58ce647f98e1260acce4acda3dd869f74e01f8ba5e0324309db6a9831497abac96670',
        x: '4d44326f269a597a5b58bba565da5556ed7fd9a8a9eb76c25f46db69d19dc8ce6ad18e404b15738b2086df37e71d1eb4',
        y: '62d692136de56cbe93bf5fa3188ef58bc8a3a0ec6c1e151a21038a42e9185329b5b275903d192f8d4e1f32fe9cc78c48'
      },
      s: {
        x: 'bd9d3a7ea0b3d519d09d8e48d0785fb744a6b355e6304bc51c229fbbce239bbadf6403715c35d4fb2a5444f575d4f42',
        y: 'df213417ebe4d8e40a5f76f66c56470c489a3478d146decf6df0d94bae9e598157290f8756066975f1db34b2324b7bd'
      }
    });

    test(new BRAINPOOLP512(), {
      a: {
        k: '16302ff0dbbb5a8d733dab7141c1b45acbc8715939677f6a56850a38bd87bd59b09e80279609ff333eb9d4c061231fb26f92eeb04982a5f1d1764cad57665422',
        x: 'a420517e406aac0acdce90fcd71487718d3b953efd7fbec5f7f27e28c6149999397e91e029e06457db2d3e640668b392c2a7e737a7f0bf04436d11640fd09fd',
        y: '72e6882e8db28aad36237cd25d580db23783961c8dc52dfa2ec138ad472a0fcef3887cf62b623b2a87de5c588301ea3e5fc269b373b60724f5e82a6ad147fde7'
      },
      b: {
        k: '230e18e1bcc88a362fa54e4ea3902009292f7f8033624fd471b5d8ace49d12cfabbc19963dab8e2f1eba00bffb29e4d72d13f2224562f405cb80503666b25429',
        x: '9d45f66de5d67e2e6db6e93a59ce0bb48106097ff78a081de781cdb31fce8ccbaaea8dd4320c4119f1e9cd437a2eab3731fa9668ab268d871deda55a5473199f',
        y: '2fdc313095bcdd5fb3a91636f07a959c8e86b5636a1e930e8396049cb481961d365cc11453a06c719835475b12cb52fc3c383bce35e27ef194512b71876285fa'
      },
      s: {
        x: 'a7927098655f1f9976fa50a9d566865dc530331846381c87256baf3226244b76d36403c024d7bbf0aa0803eaff405d3d24f11a9b5c0bef679fe1454b21c4cd1f',
        y: '7db71c3def63212841c463e881bdcf055523bd368240e6c3143bd8def8b3b3223b95e0f53082ff5e412f4222537a43df1c6d25729ddb51620a832be6a26680a2'
      }
    });
  });

  describe('Precomputation', () => {
    it('should have precomputed curves', () => {
      p256 = new P256();
      p256.precompute(rng);

      secp256k1 = new SECP256K1();
      secp256k1.precompute(rng);

      ed25519 = new ED25519();
      ed25519.precompute(rng);

      x25519 = new X25519();
      x25519.precompute(rng);

      ed448 = new ED448();
      ed448.precompute(rng);

      x448 = new X448();
      x448.precompute(rng);

      assert(p256.g.precomputed);
      assert(secp256k1.g.precomputed);
      assert(ed25519.g.precomputed);
      assert(!x25519.g.precomputed);
      assert(ed448.g.precomputed);
      assert(!x448.g.precomputed);
    });
  });

  describe('Curve', () => {
    it('should work with example curve', () => {
      const curve = new ShortCurve({
        p: '1d',
        a: '4',
        b: '14'
      });

      const p = curve.point(new BN('18', 16), new BN('16', 16));

      assert(p.validate());
      assert(p.dbl().validate());
      assert(p.dbl().add(p).validate());
      assert(p.dbl().add(p.dbl()).validate());
      assert(p.dbl().add(p.dbl()).eq(p.add(p).add(p).add(p)));
    });

    it('should dbl points on edwards curve using proj coordinates', () => {
      const curve = new EdwardsCurve({
        p: '3fffffffffffffffffffffffffffffffffffffffffffffff'
         + 'ffffffffffffffffffffffffffffffffffffffffffffff97',
        n: '0fffffffffffffffffffffffffffffffffffffffffffffff'
         + 'd5fb21f21e95eee17c5e69281b102d2773e27e13fd3c9719',
        h: '8',
        a: '1',
        c: '1',
        // -67254 mod p
        d: '3fffffffffffffffffffffffffffffffffffffffffffffff'
         + 'fffffffffffffffffffffffffffffffffffffffffffef8e1',
        g: [
          ['196f8dd0eab20391e5f05be96e8d20ae68f840032b0b6435',
           '2923bab85364841193517dbce8105398ebc0cc9470f79603'].join(''),
          '11'
        ]
      });

      const point = [
        ['21fd21b36cbdbe0d77ad8692c25d918774f5d3bc179c4cb0',
         'ae3c364bf1bea981d02e9f97cc62f20acacf0c553887e5fb'].join(''),
        ['29f994329799dba72aa12ceb06312300167b6e18fbed607c',
         '63709826c57292cf29f5bab4f5c99c739cf107a3833bb553'].join('')
      ];

      const double = [
        ['0561c8722cf82b2f0d7c36bc72e34539dcbf181e8d98f524',
         '4480e79f5b51a4a541457016c9c0509d49078eb5909a1121'].join(''),
        ['05b7812fae9d164ee9249c56a16e29a1ad2cdc6353227074',
         'dd96d59df363a0bcb5bc67d50b44843ea833156bdc0ac6a2'].join('')
      ];

      const p = curve.pointFromJSON(point);
      const d = curve.pointFromJSON(double);

      assert(p.dbl().eq(d));
    });

    it('should be able to find a point given y coordinate (edwards)', () => {
      const curve = new EdwardsCurve({
        p: '07fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7',
        n: '01fffffffffffffffffffffffffffffff77965c4dfd307348944d45fd166c971',
        h: '4',
        a: '1',
        // -1174 mod p
        d: '07fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb61',
        c: '1'
      });

      const target = curve.point(
        new BN('05d040ddaa645bf27d2d2f302c569723'
             + '1425185fd9a410f220ac5c5c7fbeb8a1', 16),
        new BN('02f8ca771306cd23e929775177f2c213'
             + '843a017a6487b2ec5f9b2a3808108ef2', 16)
      );

      const point = curve.pointFromY(
        new BN('02f8ca771306cd23e929775177f2c213'
             + '843a017a6487b2ec5f9b2a3808108ef2', 16),
        true
      );

      assert(point.eq(target));
    });

    it('should find an odd point given a y coordinate', () => {
      const curve = new EdwardsCurve({
        p: '7fffffffffffffff ffffffffffffffff'
         + 'ffffffffffffffff ffffffffffffffed',
        a: '-1',
        c: '1',
        // -121665 * (121666^(-1)) (mod P)
        d: '52036cee2b6ffe73 8cc740797779e898'
         + '00700a4d4141d8ab 75eb4dca135978a3',
        n: '1000000000000000 0000000000000000'
         + '14def9dea2f79cd6 5812631a5cf5d3ed',
        g: [
          '216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a',
          // 4/5
          '6666666666666666666666666666666666666666666666666666666666666658'
        ]
      });

      const y = new BN(
        '4627191eb12f51005d2a7f3ef570376a3403801aae928c8ffd13feabadf84505',
        16);

      const point = curve.pointFromY(y, true);

      const target =
        '2cd591ae3789fd62dc420a152002f79973a387eacecadc6a9a00c1a89488c15d';

      assert.deepStrictEqual(point.getX().toString(16), target);
    });

    it('should work with secp112k1', () => {
      const curve = new ShortCurve({
        p: 'db7c 2abf62e3 5e668076 bead208b',
        n: 'db7c 2abf62e3 5e7628df ac6561c5',
        a: 'db7c 2abf62e3 5e668076 bead2088',
        b: '659e f8ba0439 16eede89 11702b22'
      });

      const p = curve.point(
        new BN('0948 7239995a 5ee76b55 f9c2f098', 16),
        new BN('a89c e5af8724 c0a23e0e 0ff77500', 16));

      assert(p.validate());
      assert(p.dbl().validate());
    });

    it('should work with secp256k1', () => {
      const curve = new ShortCurve({
        p: 'ffffffff ffffffff ffffffff ffffffff'
         + 'ffffffff ffffffff fffffffe fffffc2f',
        a: '0',
        b: '7',
        n: 'ffffffff ffffffff ffffffff fffffffe'
         + 'baaedce6 af48a03b bfd25e8c d0364141',
        g: [
          '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
          '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
        ]
      });

      const p = curve.point(
        new BN('79be667e f9dcbbac 55a06295 ce870b07'
             + '029bfcdb 2dce28d9 59f2815b 16f81798', 16),
        new BN('483ada77 26a3c465 5da4fbfc 0e1108a8'
             + 'fd17b448 a6855419 9c47d08f fb10d4b8', 16)
      );

      const s = new BN('79be667e f9dcbbac 55a06295 ce870b07', 16);

      assert(p.validate());
      assert(p.dbl().validate());
      assert(p.toJ().dbl().toP().validate());
      assert(p.mul(s).validate());

      const j = p.toJ();
      assert(j.trpl().eq(j.dbl().add(j)));

      // Endomorphism test
      assert(curve.endo);

      assert.strictEqual(
        curve.endo.beta.fromRed().toString(16),
        '7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee');

      assert.strictEqual(
        curve.endo.lambda.toString(16),
        '5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72');

      assert.strictEqual(curve.endo.basis[0].a.toString(16),
                         '3086d221a7d46bcde86c90e49284eb15');
      assert.strictEqual(curve.endo.basis[0].b.toString(16),
                         '-e4437ed6010e88286f547fa90abfe4c3');
      assert.strictEqual(curve.endo.basis[1].a.toString(16),
                         '114ca50f7a8e2f3f657c1108d9d44cfd8');
      assert.strictEqual(curve.endo.basis[1].b.toString(16),
                         '3086d221a7d46bcde86c90e49284eb15');

      const k = new BN('1234567890123456789012345678901234', 16);
      const [k1, k2] = curve._endoSplit(k);

      const testK = k1.add(k2.mul(curve.endo.lambda)).mod(curve.n);

      assert.strictEqual(testK.toString(16), k.toString(16));
    });

    it('should compute this problematic secp256k1 multiplication', () => {
      const curve = secp256k1;

      const g1 = curve.g; // precomputed g
      assert(g1.precomputed);

      const g2 = curve.point(g1.getX(), g1.getY()); // not precomputed g
      assert(!g2.precomputed);

      const a = new BN(
        '6d1229a6b24c2e775c062870ad26bc261051e0198c67203167273c7c62538846',
        16);

      const p1 = g1.mul(a);
      const p2 = g2.mul(a);

      assert(p1.eq(p2));
    });

    it('should not use fixed NAF when k is too large', () => {
      const curve = secp256k1;
      const g1 = curve.g; // precomputed g

      assert(g1.precomputed);

      const g2 = curve.point(g1.getX(), g1.getY()); // not precomputed g
      assert(!g2.precomputed);

      const a = new BN('6d1229a6b24c2e775c062870ad26bc26105'
                     + '1e0198c67203167273c7c6253884612345678', 16);

      const p1 = g1.mul(a);
      const p2 = g2.mul(a);

      assert(p1.eq(p2));
    });

    it('should not fail on secp256k1 regression', () => {
      const curve = secp256k1;

      const k1 = new BN(
        '32efeba414cd0c830aed727749e816a01c471831536fd2fce28c56b54f5a3bb1',
        16);

      const k2 = new BN(
        '5f2e49b5d64e53f9811545434706cde4de528af97bfd49fde1f6cf792ee37a8c',
        16);

      const p1 = curve.g.mul(k1);
      const p2 = curve.g.mul(k2);

      // 2 + 2 + 1 = 2 + 1 + 2
      const two = p2.dbl();
      const five = two.dbl().add(p2);
      const three = two.add(p2);
      const maybeFive = three.add(two);

      assert(maybeFive.eq(five));

      const p3 = p1.mul(k2);
      const p4 = p2.mul(k1);

      assert(p3.validate());
      assert(p4.validate());
      assert(p3.eq(p4));
    });

    it('should correctly double the affine point on secp256k1', () => {
      const bad = {
        x: new BN(
          '026a2073b1ef6fab47ace18e60e728a05180a82755bbcec9a0abc08ad9f7a3d4',
          16),
        y: new BN(
          '9cd8cb48c3281596139f147c1364a3ede88d3f310fdb0eb98c924e599ca1b3c9',
          16),
        z: new BN(
          'd78587ad45e4102f48b54b5d85598296e069ce6085002e169c6bad78ddc6d9bd',
          16)
      };

      const good = {
        x: new BN(
          'e7789226739ac2eb3c7ccb2a9a910066beeed86cdb4e0f8a7fee8eeb29dc7016',
          16),
        y: new BN(
          '4b76b191fd6d47d07828ea965e275b76d0e3e0196cd5056d38384fbb819f9fcb',
          16),
        z: new BN(
          'cbf8d99056618ba132d6145b904eee1ce566e0feedb9595139c45f84e90cfa7d',
          16)
      };

      const curve = secp256k1;
      const pbad = curve.jpoint(bad.x, bad.y, bad.z);
      const pgood = curve.jpoint(good.x, good.y, good.z);

      // They are the same points
      assert(pbad.add(pgood.neg()).isInfinity());

      // But doubling borks them out
      assert(pbad.dbl().add(pgood.dbl().neg()).isInfinity());
    });

    it('should multiply with blinding', () => {
      const curve = secp256k1;
      const {blind} = curve.g.precomputed.blinding;
      const neg = blind.neg().imod(curve.n);
      const point1 = curve.g.mulBlind(neg);
      const point2 = curve.g.mul(neg);
      const point3 = curve.g.mulBlind(blind);
      const point4 = curve.g.mul(blind);

      assert(point1.eq(point2));
      assert(point3.eq(point4));
      assert(point3.neg().eq(point1));
    });

    it('should match multiplications', () => {
      for (const curve of [p256, secp256k1, ed25519]) {
        const N = curve.n;
        const s = BN.random(rng, 1, N);

        const p1 = curve.g.mul(s);
        const p2 = curve.g.mulSlow(s);

        assert(p1.eq(p2));

        const j1 = curve.g.jmul(s);
        const j2 = curve.g.jmulSlow(s);

        assert(j1.eq(j2));

        const j3 = curve.g.toJ().mul(s);
        const j4 = curve.g.toJ().mulSlow(s);

        assert(j3.eq(j4));

        const p3 = curve.g.mul(s.divn(3).mul(s));
        const p4 = curve.g.mulSlow(s.divn(3).mul(s).imod(N));

        assert(p3.eq(p4));

        const p5 = curve.g.mul(s.divn(3).mul(s).ineg());
        const p6 = curve.g.mulSlow(s.divn(3).mul(s).ineg().imod(N));

        assert(p5.eq(p6));
      }
    });

    it('should match multiplications (fixed)', () => {
      const curve = secp256k1;
      const N = curve.n;

      const mul = (p, k) => curve._fixedNafMul(p, k, null, false);
      const jmul = (p, k) => curve._fixedNafMul(p, k, null, true);

      const s = BN.random(rng, 1, N);

      const p1 = mul(curve.g, s);
      const p2 = curve.g.mulSlow(s);

      assert(p1.eq(p2));

      const p3 = mul(curve.g, s.neg());
      const p4 = curve.g.mulSlow(s.neg().imod(N));

      assert(p3.eq(p4));

      const j1 = jmul(curve.g, s);
      const j2 = curve.g.jmulSlow(s);

      assert(j1.eq(j2));

      const j3 = jmul(curve.g, s.neg());
      const j4 = curve.g.jmulSlow(s.neg().imod(N));

      assert(j3.eq(j4));
    });

    it('should match multiplications (wnaf)', () => {
      const curve = secp256k1;
      const N = curve.n;

      const mul = (p, k) => curve._wnafMul(p, k, null, false);
      const jmul = (p, k) => curve._wnafMul(p, k, null, true);
      const pre = curve.g.precomputed;

      let g = curve.g;

      for (let i = 0; i < 3; i++) {
        const s = BN.random(rng, 1, N);

        const p1 = mul(g, s);
        const p2 = g.mulSlow(s);

        assert(p1.eq(p2));

        const j1 = jmul(g, s);
        const j2 = g.jmulSlow(s);

        assert(j1.eq(j2));

        const p3 = mul(g, s.divn(3).mul(s));
        const p4 = g.mulSlow(s.divn(3).mul(s).imod(N));

        assert(p3.eq(p4));

        const p5 = mul(g, s.divn(3).mul(s).ineg());
        const p6 = g.mulSlow(s.divn(3).mul(s).ineg().imod(N));

        assert(p5.eq(p6));

        if (i === 0) {
          g.precomputed = null;
          continue;
        }

        if (i === 1) {
          assert(g === curve.g);
          g.precomputed = pre;
        }

        if (i === 2)
          assert(g !== curve.g);

        g = p6;
      }

      assert(curve.g.precomputed === pre);
    });

    it('should match multiplications (muladd)', () => {
      const curve = secp256k1;
      const N = curve.n;

      const mul = (p, k) => curve._wnafMulAdd(1, [p], [k], null, false);
      const jmul = (p, k) => curve._wnafMulAdd(1, [p], [k], null, true);
      const pre = curve.g.precomputed;

      let g = curve.g;

      for (let i = 0; i < 3; i++) {
        const s = BN.random(rng, 1, N);

        const p1 = mul(g, s);
        const p2 = g.mulSlow(s);

        assert(p1.eq(p2));

        const j1 = jmul(g, s);
        const j2 = g.jmulSlow(s);

        assert(j1.eq(j2));

        const p3 = mul(g, s.divn(3).mul(s));
        const p4 = g.mulSlow(s.divn(3).mul(s).imod(N));

        assert(p3.eq(p4));

        const p5 = mul(g, s.divn(3).mul(s).ineg());
        const p6 = g.mulSlow(s.divn(3).mul(s).ineg().imod(N));

        assert(p5.eq(p6));

        if (i === 0) {
          g.precomputed = null;
          continue;
        }

        if (i === 1) {
          assert(g === curve.g);
          g.precomputed = pre;
        }

        if (i === 2)
          assert(g !== curve.g);

        g = p6;
      }

      assert(curve.g.precomputed === pre);
    });

    it('should match multiplications (endo)', () => {
      const curve = secp256k1;
      const N = curve.n;

      const mul = (p, k) => curve._endoWnafMulAdd([p], [k], null, false);
      const jmul = (p, k) => curve._endoWnafMulAdd([p], [k], null, true);
      const pre = curve.g.precomputed;

      let g = curve.g;

      for (let i = 0; i < 3; i++) {
        const s = BN.random(rng, 1, N);

        const p1 = mul(g, s);
        const p2 = g.mulSlow(s);

        assert(p1.eq(p2));

        const j1 = jmul(g, s);
        const j2 = g.jmulSlow(s);

        assert(j1.eq(j2));

        const p3 = mul(g, s.divn(3).mul(s));
        const p4 = g.mulSlow(s.divn(3).mul(s).imod(N));

        assert(p3.eq(p4));

        const p5 = mul(g, s.divn(3).mul(s).ineg());
        const p6 = g.mulSlow(s.divn(3).mul(s).ineg().imod(N));

        assert(p5.eq(p6));

        if (i === 0) {
          g.precomputed = null;
          continue;
        }

        if (i === 1) {
          assert(g === curve.g);
          g.precomputed = pre;
        }

        if (i === 2)
          assert(g !== curve.g);

        g = p6;
      }

      assert(curve.g.precomputed === pre);
    });

    it('should match multiplications (blind)', () => {
      const curve = secp256k1;
      const N = curve.n;

      const mul = (p, k) => p.mulBlind(k, rng);
      const jmul = (p, k) => p.jmulBlind(k, rng);
      const pre = curve.g.precomputed;

      let g = curve.g;

      for (let i = 0; i < 3; i++) {
        const s = BN.random(rng, 1, N);

        const p1 = mul(g, s);
        const p2 = g.mulSlow(s);

        assert(p1.eq(p2));

        const j1 = jmul(g, s);
        const j2 = g.jmulSlow(s);

        assert(j1.eq(j2));

        const p3 = mul(g, s.divn(3).mul(s));
        const p4 = g.mulSlow(s.divn(3).mul(s).imod(N));

        assert(p3.eq(p4));

        const p5 = mul(g, s.divn(3).mul(s).ineg());
        const p6 = g.mulSlow(s.divn(3).mul(s).ineg().imod(N));

        assert(p5.eq(p6));

        if (i === 0) {
          g.precomputed = null;
          continue;
        }

        if (i === 1) {
          assert(g === curve.g);
          g.precomputed = pre;
        }

        if (i === 2)
          assert(g !== curve.g);

        g = p6;
      }

      assert(curve.g.precomputed === pre);
    });

    it('should match multiply+add', () => {
      for (const curve of [p256, secp256k1, ed25519]) {
        const N = curve.n;
        const s = BN.random(rng, 1, N);
        const A = curve.g.mul(BN.random(rng, 1, N));
        const J = A.toJ();
        const s0 = BN.random(rng, 1, N);

        const p1 = curve.g.mulAdd(s, A, s0);
        const p2 = curve.g.mulAddSlow(s, A, s0);

        assert(p1.eq(p2));

        const j1 = curve.g.jmulAdd(s, A, s0);
        const j2 = curve.g.jmulAddSlow(s, A, s0);

        assert(j1.eq(j2));

        const j3 = curve.g.toJ().mulAdd(s, J, s0);
        const j4 = curve.g.toJ().mulAddSlow(s, J, s0);

        assert(j3.eq(j4));

        const p3 = curve.g.mulAdd(s.divn(3).mul(s), A, s0);
        const p4 = curve.g.mulAddSlow(s.divn(3).mul(s).imod(N), A, s0);

        assert(p3.eq(p4));

        const p5 = curve.g.mulAdd(s.divn(3).mul(s).ineg(), A, s0);
        const p6 = curve.g.mulAddSlow(s.divn(3).mul(s).ineg().imod(N), A, s0);

        assert(p5.eq(p6));
      }
    });

    it('should multiply negative scalar', () => {
      for (const curve of [p256, secp256k1, ed25519]) {
        const N = curve.n;
        const s1 = BN.random(rng, 1, N);

        {
          const p1 = curve.g.mul(s1);
          const p2 = curve.g.mul(s1.neg());

          assert(!p2.isInfinity());
          assert(p2.eq(p1.neg()));

          const s2 = s1.sqr();

          const p3 = curve.g.mul(s2);
          const p4 = curve.g.mul(s2.neg());

          assert(!p4.isInfinity());
          assert(p4.eq(p3.neg()));

          const s3 = s2.divn(17);
          const p5 = p1.mul(s3);
          const p6 = p1.mul(s3.neg());

          assert(!p6.isInfinity());
          assert(p6.eq(p5.neg()));

          const s4 = s3.mod(N);
          const p7 = p2.mul(s4);
          const p8 = p2.mul(s4.neg());

          assert(!p8.isInfinity());
          assert(p8.eq(p7.neg()));
        }

        {
          const p1 = curve.g.jmul(s1);
          const p2 = curve.g.jmul(s1.neg());

          assert(!p2.isInfinity());
          assert(p2.eq(p1.neg()));

          const s2 = s1.sqr();

          const p3 = curve.g.jmul(s2);
          const p4 = curve.g.jmul(s2.neg());

          assert(!p4.isInfinity());
          assert(p4.eq(p3.neg()));

          const s3 = s2.divn(17);
          const p5 = p1.jmul(s3);
          const p6 = p1.jmul(s3.neg());

          assert(!p6.isInfinity());
          assert(p6.eq(p5.neg()));

          const s4 = s3.mod(N);
          const p7 = p2.jmul(s4);
          const p8 = p2.jmul(s4.neg());

          assert(!p8.isInfinity());
          assert(p8.eq(p7.neg()));
        }

        {
          const p1 = curve.g.mulBlind(s1, rng);
          const p2 = curve.g.mulBlind(s1.neg(), rng);

          assert(!p2.isInfinity());
          assert(p2.eq(p1.neg()));

          const s2 = s1.sqr();

          const p3 = curve.g.mulBlind(s2, rng);
          const p4 = curve.g.mulBlind(s2.neg(), rng);

          assert(!p4.isInfinity());
          assert(p4.eq(p3.neg()));

          const s3 = s2.divn(17);
          const p5 = p1.mulBlind(s3, rng);
          const p6 = p1.mulBlind(s3.neg(), rng);

          assert(!p6.isInfinity());
          assert(p6.eq(p5.neg()));

          const s4 = s3.mod(N);
          const p7 = p2.mulBlind(s4, rng);
          const p8 = p2.mulBlind(s4.neg(), rng);

          assert(!p8.isInfinity());
          assert(p8.eq(p7.neg()));
        }
      }
    });

    it('should multiply+add negative scalar', () => {
      for (const curve of [p256, secp256k1, ed25519]) {
        const N = curve.n;
        const A = curve.g.mul(BN.random(rng, 1, N));
        const J = A.toJ();
        const s0 = BN.random(rng, 1, N);
        const as0 = A.mul(s0);
        const js0 = as0.toJ();
        const s1 = BN.random(rng, 1, N);

        {
          const p1 = curve.g.mul(s1).neg().add(as0);
          const p2 = curve.g.mulAdd(s1.neg(), A, s0);

          assert(!p2.isInfinity());
          assert(p2.eq(p1));

          const s2 = s1.sqr();

          const p3 = curve.g.mul(s2).neg().add(as0);
          const p4 = curve.g.mulAdd(s2.neg(), A, s0);

          assert(!p4.isInfinity());
          assert(p4.eq(p3));

          const s3 = s2.divn(17);
          const p5 = p1.mul(s3).neg().add(as0);
          const p6 = p1.mulAdd(s3.neg(), A, s0);

          assert(!p6.isInfinity());
          assert(p6.eq(p5));

          const s4 = s3.mod(N);
          const p7 = p2.mul(s4).neg().add(as0);
          const p8 = p2.mulAdd(s4.neg(), A, s0);

          assert(!p8.isInfinity());
          assert(p8.eq(p7));
        }

        {
          const p1 = curve.g.jmul(s1).neg().add(js0);
          const p2 = curve.g.jmulAdd(s1.neg(), A, s0);

          assert(!p2.isInfinity());
          assert(p2.eq(p1));

          const s2 = s1.sqr();

          const p3 = curve.g.jmul(s2).neg().add(js0);
          const p4 = curve.g.jmulAdd(s2.neg(), A, s0);

          assert(!p4.isInfinity());
          assert(p4.eq(p3));

          const s3 = s2.divn(17);
          const p5 = p1.jmul(s3).neg().add(js0);
          const p6 = p1.jmulAdd(s3.neg(), J, s0);

          assert(!p6.isInfinity());
          assert(p6.eq(p5));

          const s4 = s3.mod(N);
          const p7 = p2.jmul(s4).neg().add(js0);
          const p8 = p2.jmulAdd(s4.neg(), J, s0);

          assert(!p8.isInfinity());
          assert(p8.eq(p7));
        }
      }
    });

    it('should have basepoint for x25519', () => {
      // https://tools.ietf.org/html/rfc7748#section-4.1
      const v = x25519.p.sub(x25519.g.getY());

      // Note: this is negated.
      const e = new BN('147816194475895447910205935684099868872'
                     + '64606134616475288964881837755586237401', 10);

      assert(v.cmp(e) === 0);
      assert(x25519.g.validate());
    });

    it('should have basepoint for x448', () => {
      // https://tools.ietf.org/html/rfc7748#section-4.2
      const v = x448.p.sub(x448.g.getY());

      // Note: this is negated.
      const e = new BN('355293926785568175264127502063783334808'
                     + '976399387714271831880898435169088786967'
                     + '410002932673765864550910142774147268105'
                     + '838985595290606362', 10);

      assert(v.cmp(e) === 0);
      assert(x448.g.validate());
    });

    it('should test birational equivalence', () => {
      const edwardsG = ed25519.pointFromMont(x25519.g, false);
      const montG = x25519.pointFromEdwards(ed25519.g);

      assert(edwardsG.eq(ed25519.g));
      assert(montG.eq(x25519.g));
    });

    it('should test 4-isogeny equivalence', () => {
      const montG = x448.pointFromEdwards(ed25519.g);

      assert(montG.eq(x25519.g));

      assert.throws(() => ed448.pointFromMont(x25519.g, false));
    });
  });

  describe('Point codec', () => {
    const makeShortTest = (definition) => {
      return () => {
        const curve = secp256k1;
        const co = definition.coordinates;
        const p = curve.point(new BN(co.x, 16), new BN(co.y, 16));

        // Encodes as expected
        assert.strictEqual(p.encode(false).toString('hex'), definition.encoded);
        assert.strictEqual(p.encode(true).toString('hex'), definition.compactEncoded);

        // Decodes as expected
        assert(curve.decodePoint(Buffer.from(definition.encoded, 'hex')).eq(p));
        assert(curve.decodePoint(
          Buffer.from(definition.compactEncoded, 'hex')).eq(p));
        assert(curve.decodePoint(Buffer.from(definition.hybrid, 'hex')).eq(p));
      };
    };

    const makeMontTest = (definition) => {
      return () => {
        const curve = x25519;
        const co = definition.coordinates;
        const p = curve.point(new BN(co.x, 16), new BN(co.z, 16));
        const scalar = new BN(definition.scalar, 16);
        const encoded = p.encode();
        const decoded = curve.decodePoint(encoded);

        assert(decoded.eq(p));
        assert.strictEqual(encoded.toString('hex'), definition.encoded);

        assert.bufferEqual(curve.g.mul(scalar).encode(), encoded);
      };
    };

    const shortPointEvenY = {
      coordinates: {
        x: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
        y: '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
      },
      compactEncoded: '02'
        + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
      encoded: '04'
        + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
        + '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
      hybrid: '06'
        + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
        + '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
    };

    const shortPointOddY = {
      coordinates: {
        x: 'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556',
        y: 'ae12777aacfbb620f3be96017f45c560de80f0f6518fe4a03c870c36b075f297'
      },
      compactEncoded: '03'
        + 'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556',
      encoded: '04'
        + 'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556'
        + 'ae12777aacfbb620f3be96017f45c560de80f0f6518fe4a03c870c36b075f297',
      hybrid: '07'
        + 'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556'
        + 'ae12777aacfbb620f3be96017f45c560de80f0f6518fe4a03c870c36b075f297'
    };

    it('should throw when trying to decode random bytes', () => {
      assert.throws(() => {
        secp256k1.decodePoint(Buffer.from(
          '0579be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
          'hex'));
      });
    });

    it('should be able to encode/decode a short curve point with even Y',
        makeShortTest(shortPointEvenY));

    it('should be able to encode/decode a short curve point with odd Y',
        makeShortTest(shortPointOddY));

    it('should be able to encode/decode a mont curve point', makeMontTest({
      scalar: '6',
      coordinates: {
        x: '743bcb585f9990edc2cfc4af84f6ff300729bb5facda28154362cd47a37de52f',
        z: '1'
      },
      encoded:
        '2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74'
    }));
  });
});
