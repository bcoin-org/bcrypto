#!/usr/bin/env node

'use strict';

const fs = require('bfile');
const bpkg = require('bpkg');
const {join, resolve} = require('path');

const ROOT = resolve(__dirname);
const INPUT = resolve(process.argv[2]);
const DEPS = join(ROOT, 'deps');
const PKG = join(ROOT, 'package');
const MAIN = join(PKG, 'elliptic');
const PKG_JSON = join(MAIN, 'package.json');
const NM = join(MAIN, 'node_modules');
const JS = join(ROOT, 'elliptic.js');
const OUT = resolve(ROOT, '..', 'vendor', 'elliptic.js');

const deps = [
  [join(DEPS, 'bn.js'), join(NM, 'bn.js')],
  [join(DEPS, 'brorand.js'), join(NM, 'brorand.js')],
  [join(DEPS, 'hash.js'), join(NM, 'hash.js')],
  [join(DEPS, 'hmac-drbg.js'), join(NM, 'hmac-drbg.js')],
  [join(DEPS, 'inherits.js'), join(NM, 'inherits.js')]
];

// Complicated build.
(async () => {
  await fs.remove([PKG, JS]);

  await bpkg({
    input: INPUT,
    output: PKG,
    multi: true
  });

  const json = await fs.readJSON(PKG_JSON);

  await fs.writeJSON(PKG_JSON, {
    name: json.name,
    version: json.version,
    description: json.description,
    homepage: json.homepage,
    license: json.license,
    main: json.main
  });

  for (const [from, to] of deps) {
    await fs.remove(to);
    await fs.copy(from, to);
  }

  await bpkg({
    input: MAIN,
    output: JS
  });

  let code = await fs.readFile(JS, 'utf8');

  code = code.replace(/, require,/g, ', _,');
  code = code.replace(/var _require = require;/g, 'var _require = null;');
  code = code.replace(/\n\/\* global __require__ \*\/\n/g, '');
  code = code.replace(/__require__/g, 'require');
  code = code.replace(/(message = parseBytes\(message\);)/g, '// $1');

  await fs.writeFile(OUT, code);
  await fs.remove(PKG);
  await fs.remove(JS);
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
