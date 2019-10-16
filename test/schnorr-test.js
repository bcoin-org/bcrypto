'use strict';

const assert = require('bsert');
const schnorr = require('../lib/js/schnorr');
const rng = require('../lib/random');
const vectors = require('./data/schnorr.json');

describe('Schnorr', function() {
  const valid = [];
  const invalid = [];

  for (const [key_, pub_, msg_, sig_, result, comment_] of vectors) {
    const key = Buffer.from(key_, 'hex');
    const pub = Buffer.from(pub_, 'hex');
    const msg = Buffer.from(msg_, 'hex');
    const sig = Buffer.from(sig_, 'hex');
    const text = sig_.slice(0, 32).toLowerCase() + '...';
    const comment = comment_ || `should verify ${text}`;
    const batch = result ? valid : invalid;

    batch.push([msg, sig, pub]);

    it(comment, () => {
      if (key.length > 0) {
        assert(schnorr.privateKeyVerify(key));
        assert.bufferEqual(schnorr.publicKeyCreate(key), pub);
        assert.bufferEqual(schnorr.sign(msg, key), sig);
      }

      assert.strictEqual(schnorr.verify(msg, sig, pub), result);
    });
  }

  it('should do batch verification', () => {
    assert.strictEqual(schnorr.verifyBatch([]), true);
    assert.strictEqual(schnorr.verifyBatch(valid), true);

    for (const item of valid)
      assert.strictEqual(schnorr.verifyBatch([item]), true);
  });

  it('should do fail batch verification', () => {
    for (const item of invalid) {
      assert.strictEqual(schnorr.verifyBatch([item, ...valid]), false);
      assert.strictEqual(schnorr.verifyBatch([...valid, item]), false);
      assert.strictEqual(schnorr.verifyBatch([item]), false);
    }
  });

  it('should do HD derivation (additive)', () => {
    const priv = schnorr.privateKeyGenerate();
    const pub = schnorr.publicKeyCreate(priv);
    const tweak = rng.randomBytes(32);
    const cpriv = schnorr.privateKeyTweakAdd(priv, tweak);
    const cpub = schnorr.publicKeyTweakAdd(pub, tweak);

    assert.bufferEqual(schnorr.publicKeyCreate(cpriv), cpub);
  });

  it('should do HD derivation (multiplicative)', () => {
    const priv = schnorr.privateKeyGenerate();
    const pub = schnorr.publicKeyCreate(priv);
    const tweak = rng.randomBytes(32);
    const cpriv = schnorr.privateKeyTweakMul(priv, tweak);
    const cpub = schnorr.publicKeyTweakMul(pub, tweak);

    assert.bufferEqual(schnorr.publicKeyCreate(cpriv), cpub);
  });

  it('should create point from uniform bytes (svdw)', () => {
    const preimages = [
      '98ba02ac9490595c56f5b26535d54423cfb080e4a46405c19dcf3b54aeaab558',
      '1c7c3badac99fed06d129f3dc15feabcd46c792976c67e1417f1a369f26e2e09',
      'a130f72bab2dcb46ef9d94a786bb41b474048727a47c5bf9a673fbda9cdc01e8',
      '590d074cc54ada1ef5c9afc6f8a0a17567cf23f49a43d37f9a5ffb7e8a338a2a',
      '8a94d2b7df26b4e88b59215b2893a9919e0643ebacab4f046c6fb420c33f4163',
      '2b356b20cde0351b369b15e29bb029266fae7c852f2e1de6e8722b4e3e57aa40',
      'fccf102b9ad4ed1a3c03cce2c8a967594788ea16d9d97572fcf4056fe98742a6',
      '41eb1aedb739a3f8da0dfc32cd181fb108280616bafaab7f0eac0c3f1fb2a8d9',
      '4e956e149e4041d0e934c85379d83ddfc031445e024768305584732fd9ad59c9',
      '3162126b8dd7f301a7853a06a68e92c314822a3afa6553dea98e41f0c290d1cf',
      '11ce1c8ac299f7e50ee8fb156e4509deedf0b0c84f006522e6d7daf14bff2612',
      '203e288aac39df62fc90b6e6097af8e71f48f54b4858de59f1a39162b5052d1e',
      'a396553643d566c85be5a03ac919db3c337c0500b3bb510ead3f06db39a4a275',
      'da6f211c5a90a7d778d0fb5dbdb701f95b59e35439e2d2ce02398d5b361c073d',
      'c167f71ae957bd28813b1b21df6e621bda5a4ce4f18c75451a92643fc757a60d',
      '32252987a98877d5adbba2aab3e410b8d650f56ab45f0d555f183632205fc6ec'
    ];

    const keys = [
      '37041c8307506c6e430d65d6ce11ee2b2667e11df690c2de10c5689b888244f7',
      '43d85c8b8dbee240e0ad26d7f8ada59d25b6090e1efd1852ea8ea94e0bb818d7',
      '961a1f0f411501ab15207ce7c501ba5a466de78330722934bc2ff5f87f49c4b6',
      'a9f1af61c25fde6502596dce27753db079531600e3097ca8da8d9016ae321e74',
      '0b9d913ec1bd65a4b92d0bee833e9636fb9e62e5e2668e024dde8fbb44732946',
      '2e994b4c724413eea863198c1650fff40cda195dc8f2cb030cf49f3504d3d0da',
      'c061aa3bbaab5e61cd8bdc154273efc64ab9beb82a08850c41ac57f3de7d4b04',
      '73bb63a5a3c6672708bb52d1b216ac4540342f249fe5bfb6975fcb54eaea9fa6',
      '401579164f8e6c8eb33e9208355565489cb9dcb9271bde4fb0dc778b5491d73c',
      'b7a464f2a74cae6ae0a8654a860a359ef97d1d50b90e56f7398a9f58f4296938',
      'b779f1628bbc1cde9931fc267a45abbd707a97961d700a91b7af41c4b8b371ef',
      '08c4157fd70b1f1e4bdfc0e4f9f2da6a26b6d36f27bfcb636be0923169d3cfa5',
      '50c9caa36051845acae8eefc002186c4af012d27a73b952cc2d1326eeb0786e1',
      'a0b13d06514c0ab5f33b79fcc4f2efad3bce7cba84b52f3f3bda59de00120b33',
      '3df848e48fdc0045151b81ce4c362b9749591caba5f15ced3d2dc0c2dbe676b6',
      '609602e75352034cc3b9cc148b93bc30e35fec9a65c39c100283d02975d9c209'
    ];

    for (let i = 0; i < 16; i++) {
      const preimage = Buffer.from(preimages[i], 'hex');
      const key = Buffer.from(keys[i], 'hex');

      assert.strictEqual(schnorr.publicKeyVerify(key), true);
      assert.bufferEqual(schnorr.publicKeyFromUniform(preimage), key);
    }
  });

  it('should invert elligator', () => {
    let priv, pub, bytes;

    for (;;) {
      priv = schnorr.privateKeyGenerate();
      pub = schnorr.publicKeyCreate(priv);

      try {
        bytes = schnorr.publicKeyToUniform(pub, rng.randomInt());
      } catch (e) {
        continue;
      }

      break;
    }

    const out = schnorr.publicKeyFromUniform(bytes);

    assert.bufferEqual(out, pub);
  });

  it('should invert elligator squared', () => {
    const priv = schnorr.privateKeyGenerate();
    const pub = schnorr.publicKeyCreate(priv);
    const bytes = schnorr.publicKeyToHash(pub);
    const out = schnorr.publicKeyFromHash(bytes);

    assert.bufferEqual(out, pub);
  });
});
