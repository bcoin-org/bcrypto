'use strict';

const rc = require('bslintrc');

module.exports = [
  rc.configs.recommended,
  rc.configs.bcoin,
  {
    languageOptions: {
      globals: {
        ...rc.globals.node
      },
      ecmaVersion: 'latest'
    }
  },
  {
    files: [
      '**/*.js',
      '*.js'
    ],
    languageOptions: {
      sourceType: 'commonjs'
    }
  },
  {
    files: ['test/{,**/}*.{js,cjs,mjs}'],
    languageOptions: {
      globals: {
        ...rc.globals.mocha,
        register: 'readable'
      }
    },
    rules: {
      'max-len': 'off',
      'prefer-arrow-callback': 'off'
    }
  }
];
