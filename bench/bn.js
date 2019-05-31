'use strict';

const bench = require('./bench');
const BN = require('../lib/bn');
const red = BN.red('p192');
const rounds = 1000000;

const n = new BN('e2a8e04946f31d753c27dc3054430c013d54cfaf1335d929', 16);
const r = n.toRed(red);

bench('mul', rounds, () => {
  r.redISqr();
});
