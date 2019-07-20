'use strict';

const {curves} = require('../lib/js/curves');
const id = process.argv[2] || '';
const Curve = curves[id.toUpperCase()];

if (!Curve)
  throw new Error(`Curve not found (${id}).`);

const curve = new Curve();

curve.precompute();

const json = curve.g.pre.toJSON();

console.log(JSON.stringify(json, null, 2));
