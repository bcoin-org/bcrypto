#!/usr/bin/env node

'use strict';

const cp = require('child_process');
const path = require('path');

function spawn(file, args) {
  const result = cp.spawnSync(file, args, {
    stdio: 'inherit',
    windowsHide: true
  });

  if (result.error)
    throw result.error;

  return result;
}

function exec(file, args) {
  const result = spawn(file, args);

  if (result.signal)
    process.kill(process.pid, result.signal);

  if (result.status)
    process.exit(result.status);
}

function rm(file) {
  try {
    if (process.platform === 'win32') {
      cp.spawnSync('rd', ['/s', '/q', path.normalize(file)], {
        shell: 'cmd.exe',
        stdio: 'inherit',
        windowsHide: true
      });
    } else {
      spawn('rm', ['-rf', file]);
    }
  } catch (e) {
    ;
  }
}

function configure() {
  if (process.platform === 'win32')
    exec('cmake.exe', ['.']);
  else
    exec('cmake', ['-G', 'Unix Makefiles', '.']);
}

function build() {
  if (process.platform === 'win32')
    exec('cmake.exe', ['--build', '.', '--config', 'Release']);
  else
    exec('make', []);
}

function clean() {
  rm('bcrypto.node');
  rm('CMakeCache.txt');
  rm('CMakeFiles');
  rm('cmake_install.cmake');
  rm('Makefile');
  rm('deps/secp256k1/CMakeFiles');
  rm('deps/secp256k1/cmake_install.cmake');
  rm('deps/secp256k1/libsecp256k1.a');
  rm('deps/secp256k1/Makefile');
  rm('deps/torsion/CMakeFiles');
  rm('deps/torsion/cmake_install.cmake');
  rm('deps/torsion/libtorsion.a');
  rm('deps/torsion/Makefile');
}

function reconfigure() {
  rm('CMakeCache.txt');
  configure();
}

function rebuild() {
  clean();
  configure();
  build();
}

const commands = {
  __proto__: null,
  configure,
  build,
  clean,
  reconfigure,
  rebuild
};

function main(argv) {
  process.chdir(__dirname);

  if (argv.length === 0) {
    rebuild();
    return;
  }

  if (!commands[argv[0]])
    throw new Error('Invalid command.');

  commands[argv[0]](...argv.slice(1));
}

main(process.argv.slice(2));
