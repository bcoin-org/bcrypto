/*!
 * ed25519.js - EDDSA-ED25519 for bcoin
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const EDDSA = require('./internal/eddsa');

/*
 * Expose
 */

module.exports = new EDDSA('ed25519');
