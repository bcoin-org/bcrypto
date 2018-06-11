'use strict';

const zero = Buffer.allocUnsafe(128, 0x00);

const ZERO_HASH128 = zero;
const ZERO_HASH64 = zero.slice(0, 64);
const ZERO_HASH48 = zero.slice(0, 48);
const ZERO_HASH32 = zero.slice(0, 32);
const ZERO_HASH28 = zero.slice(0, 28);
const ZERO_HASH20 = zero.slice(0, 20);
const ZERO_HASH16 = zero.slice(0, 16);

function zeroHash(size) {
  switch (size) {
    case 128:
      return ZERO_HASH128;
    case 64:
      return ZERO_HASH64;
    case 48:
      return ZERO_HASH48;
    case 32:
      return ZERO_HASH32;
    case 28:
      return ZERO_HASH28;
    case 20:
      return ZERO_HASH20;
    case 16:
      return ZERO_HASH16;
  }

  throw new Error('Bad hash size.');
}

module.exports = zeroHash;
