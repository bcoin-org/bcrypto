/*!
 * x448.js - x448 for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/elliptic:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/elliptic
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Curve448
 *   https://eprint.iacr.org/2015/625.pdf
 *   https://tools.ietf.org/html/rfc7748
 *   https://tools.ietf.org/html/rfc7748#section-5
 */

'use strict';

const ECDH = require('./ecdh');

/*
 * Expose
 */

module.exports = new ECDH('X448', 'ED448');
