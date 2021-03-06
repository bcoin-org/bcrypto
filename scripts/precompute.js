'use strict';

const elliptic = require('../lib/js/elliptic');

require('../test/util/curves');

const id = process.argv[2];
const curve = elliptic.curve(id);

curve.precompute();

const json = curve.g.pre.toJSON();

console.log(JSON.stringify(json, null, 2));
