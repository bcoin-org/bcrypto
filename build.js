#!/usr/bin/env node

'use strict';

const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const projects = [
  // Project Name, Target Name, Directory
  ['bcrypto', 'bcrypto', '.'],
  ['libsecp256k1', 'secp256k1', 'deps/secp256k1'],
  ['libtorsion', 'torsion', 'deps/torsion']
];

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
      file = path.normalize(file);
      cp.spawnSync('rd', ['/s', '/q', `"${file}"`], {
        shell: 'cmd.exe',
        stdio: 'ignore',
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
  if (process.platform === 'win32') {
    const node = path.basename(process.execPath);

    // Explanation: It's impossible to build a DLL
    // with unresolved symbols. As a result, when
    // node.js is built, a .lib file is created,
    // exposing all the necessary symbols.
    //
    // When building an addon, MSVS must link to
    // this .lib file. Typical windows node.js
    // installs bundle npm, which in turn bundles
    // node-gyp. We can abuse this to download the
    // node.lib file.
    //
    // Further reading: http://edll.sourceforge.net/
    //
    // Node.js uses the ".def & .a" solution.
    const gyp = path.resolve(process.execPath,
                             '..',
                             'node_modules',
                             'npm',
                             'node_modules',
                             'node-gyp',
                             'bin',
                             'node-gyp.js');

    // See: https://github.com/sindresorhus/env-paths
    let {LOCALAPPDATA} = process.env;

    if (!LOCALAPPDATA)
      LOCALAPPDATA = path.resolve(os.homedir(), 'AppData', 'Local');

    const lib = path.resolve(LOCALAPPDATA,
                             'node-gyp',
                             'Cache',
                             process.versions.node,
                             process.arch,
                             'node.lib');

    try {
      fs.statSync(lib);
    } catch (e) {
      exec(process.execPath, [gyp, 'install']);
    }

    exec('cmake.exe', ['.',
                       '-D', 'NODE_EXE_NAME=' + node,
                       '-D', 'NODE_LIB_FILE=' + lib]);
  } else {
    exec('cmake', ['-G', 'Unix Makefiles', '.']);
  }
}

function build() {
  if (process.platform === 'win32')
    exec('cmake.exe', ['--build', '.', '--config', 'Release']);
  else
    exec('make', []);
}

function clean() {
  for (const [project, target, dir] of projects) {
    rm(`${dir}/CMakeCache.txt`); // root
    rm(`${dir}/CMakeFiles`);
    rm(`${dir}/cmake_install.cmake`);
    rm(`${dir}/${target}.node`); // root

    if (process.platform === 'win32') {
      rm(`${dir}/ALL_BUILD.vcxproj`);
      rm(`${dir}/ALL_BUILD.vcxproj.filters`);
      rm(`${dir}/Debug`);
      rm(`${dir}/Release`);
      rm(`${dir}/x64`); // root
      rm(`${dir}/ZERO_CHECK.vcxproj`); // root
      rm(`${dir}/ZERO_CHECK.vcxproj.filters`); // root
      rm(`${dir}/${target}.dir`);
      rm(`${dir}/${project}.sln`);
      rm(`${dir}/${target}.vcxproj`);
      rm(`${dir}/${target}.vxxproj.filters`);
    } else {
      rm(`${dir}/Makefile`);
      rm(`${dir}/lib${target}.a`);
      rm(`${dir}/lib${target}.so`);
    }
  }
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
