{
  "variables": {
    "bcrypto_byteorder%":
      "<!(python -c 'from __future__ import print_function; import sys; print(sys.byteorder)')",
  },
  "targets": [{
    "target_name": "bcrypto",
    "sources": [
      "./src/poly1305/poly1305.c",
      "./src/chacha20/chacha20.c",
      "./src/scrypt/insecure_memzero.c",
      "./src/scrypt/sha256.c",
      "./src/scrypt/scrypt.c",
      "./src/pbkdf2/pbkdf2.c",
      "./src/blake2b/blake2b.c",
      "./src/sha3/sha3.c",
      "./src/cipher/cipher.c",
      "./src/chacha20.cc",
      "./src/poly1305.cc",
      "./src/pbkdf2_async.cc",
      "./src/scrypt_async.cc",
      "./src/ripemd160.cc",
      "./src/md5.cc",
      "./src/sha1.cc",
      "./src/sha224.cc",
      "./src/sha256.cc",
      "./src/sha384.cc",
      "./src/sha512.cc",
      "./src/hash160.cc",
      "./src/hash256.cc",
      "./src/keccak.cc",
      "./src/blake2b.cc",
      "./src/rsa.cc",
      "./src/bcrypto.cc"
    ],
    "cflags": [
      "-Wall",
      "-Wno-implicit-fallthrough",
      "-Wno-maybe-uninitialized",
      "-Wno-uninitialized",
      "-Wno-unused-function",
      "-Wno-cast-function-type",
      "-Wextra",
      "-O3"
    ],
    "cflags_c": [
      "-std=c99"
    ],
    "cflags_cc+": [
      "-std=c++0x"
    ],
    "include_dirs": [
      "<!(node -e \"require('nan')\")"
    ],
    "variables": {
      "conditions": [
        ["OS=='win'", {
          "conditions": [
            ["target_arch=='ia32'", {
              "openssl_root%": "C:/OpenSSL-Win32"
            }, {
              "openssl_root%": "C:/OpenSSL-Win64"
            }]
          ]
        }]
      ]
    },
    "conditions": [
      ["bcrypto_byteorder=='little'", {
        "defines": [
          "BCRYPTO_LITTLE_ENDIAN"
        ]
      }, {
        "defines": [
          "BCRYPTO_BIG_ENDIAN"
        ]
      }],
      ["target_arch=='x64' and OS!='win'", {
        "defines": [
          "BCRYPTO_POLY1305_64BIT"
        ]
      }, {
        "defines": [
          "BCRYPTO_POLY1305_32BIT"
        ]
      }],
      ["OS=='win'", {
        "libraries": [
          "-l<(openssl_root)/lib/libeay32.lib",
        ],
        "include_dirs": [
          "<(openssl_root)/include",
        ]
      }, {
        "include_dirs": [
          "<(node_root_dir)/deps/openssl/openssl/include"
        ]
      }]
    ]
  }]
}
