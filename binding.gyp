{
  "variables": {
    "bcrypto_byteorder%":
      "<!(python -c 'from __future__ import print_function; import sys; print(sys.byteorder)')",
  },
  "targets": [{
    "target_name": "bcrypto",
    "sources": [
      "./src/poly1305/poly1305-donna.c",
      "./src/chacha20/chacha20.c",
      "./src/scrypt/insecure_memzero.c",
      "./src/scrypt/sha256.c",
      "./src/scrypt/crypto_scrypt.c",
      "./src/sha3/byte_order.c",
      "./src/sha3/sha3.c",
      "./src/blake2b/blake2b.c",
      "./src/chacha20.cc",
      "./src/poly1305.cc",
      "./src/cipher.cc",
      "./src/pbkdf2.cc",
      "./src/pbkdf2_async.cc",
      "./src/scrypt.cc",
      "./src/scrypt_async.cc",
      "./src/ripemd160.cc",
      "./src/sha1.cc",
      "./src/sha256.cc",
      "./src/sha512.cc",
      "./src/hash160.cc",
      "./src/hash256.cc",
      "./src/keccak.cc",
      "./src/blake2b.cc",
      "./src/bcrypto.cc"
    ],
    "cflags": [
      "-Wall",
      "-Wno-implicit-fallthrough",
      "-Wno-maybe-uninitialized",
      "-Wno-uninitialized",
      "-Wno-unused-function",
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
          "POLY1305_64BIT"
        ]
      }, {
        "defines": [
          "POLY1305_32BIT"
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
