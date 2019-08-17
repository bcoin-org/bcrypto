'use strict';

const assert = require('bsert');
const BN = require('../lib/bn');
const elliptic = require('../lib/js/elliptic');
const extra = require('../test/util/curves');
const id = (process.argv[2] || '').toUpperCase();
const Curve = elliptic.curves[id] || extra[id];

if (!Curve)
  throw new Error(`Curve not found (${id}).`);

function printZ(curve) {
  assert(curve instanceof elliptic.Curve);

  const z = findZ(curve);

  let sign = '';

  if (z.redNeg().bitLength() < z.bitLength()) {
    sign = '-';
    z.redINeg();
  }

  let alg;

  if (curve.type === 'short') {
    if (curve.p.modrn(3) === 2)
      alg = 'icart';
    else if (!curve.a.isZero() && !curve.b.isZero())
      alg = 'sswu';
    else if (curve.p.modrn(3) === 1 && !curve.b.isZero())
      alg = 'svdw';
  } else {
    alg = 'elligator2';
  }

  const str = sign + z.fromRed().toString(16);

  console.log('%s Z: %s (%s)', curve.id, str, alg);
}

function findZ(curve) {
  assert(curve instanceof elliptic.Curve);

  if (curve.type === 'short') {
    // p = 2 mod 3
    if (curve.p.modrn(3) === 2)
      return findSSWUZ(curve); // Icart.

    // a != 0, b != 0
    if (!curve.a.isZero() && !curve.b.isZero())
      return findSSWUZ(curve);

    // p = 1 mod 3, b != 0
    if (curve.p.modrn(3) === 1 && !curve.b.isZero())
      return findSVDWZ(curve);

    throw new Error('Not implemented.');
  }

  if (curve.type === 'mont')
    return findElligator2Z(curve);

  if (curve.type === 'edwards')
    return findElligator2Z(curve);

  throw new Error('Not implemented.');
}

function findElligator2Z(curve) {
  assert(curve instanceof elliptic.Curve);

  // Find non-square in F(q).
  const z = curve.one.clone();

  for (;;) {
    if (z.redJacobi() === -1)
      return z;

    if (z.redNeg().redJacobi() === -1)
      return z.redNeg();

    z.redIAdd(curve.one);
  }
}

function findSSWUZ(curve) {
  assert(curve instanceof elliptic.Curve);

  // Find non-square in F(q) where
  // g(B / (Z * A)) is square.
  const z = curve.one.clone();

  for (;;) {
    if (isSSWUZ(curve, z))
      return z;

    if (isSSWUZ(curve, z.redNeg()))
      return z.redNeg();

    z.redIAdd(curve.one);
  }
}

function isSSWUZ(curve, z) {
  assert(curve instanceof elliptic.Curve);
  assert(z instanceof BN);

  if (z.redJacobi() !== -1)
    return false;

  const zai = z.redMul(curve.a).redInvert();

  return curve.solveY2(curve.b.redMul(zai)).redJacobi() === 1;
}

function findSVDWZ(curve) {
  assert(curve instanceof elliptic.Curve);

  // Find element in F(q) where
  // g((sqrt(-3 * Z^2) - Z) / 2) is square.
  const z = curve.one.clone();

  for (;;) {
    if (isSVDWZ(curve, z))
      return z;

    if (isSVDWZ(curve, z.redNeg()))
      return z.redNeg();

    z.redIAdd(curve.one);
  }
}

function isSVDWZ(curve, z) {
  assert(curve instanceof elliptic.Curve);
  assert(z instanceof BN);

  const z2 = z.redSqr();

  let c;

  try {
    c = curve.three.redNeg().redMul(z2).redSqrt();
  } catch (e) {
    return false;
  }

  const d = c.redISub(z).redMul(curve.i2);

  return curve.solveY2(d).redJacobi() === 1;
}

printZ(new Curve());
