'use strict';

const elliptic = require('../lib/js/elliptic');

require('../test/util/curves');

const id = process.argv[2];
const invert = process.argv.includes('--invert');
const curve = elliptic.curve(id);

console.log(curve.toSage(invert));
