{
  "variables": {
    "bcrypto_byteorder%":
      "<!(python -c 'from __future__ import print_function; import sys; print(sys.byteorder)')",
  },
  "targets": [{
    "target_name": "bcrypto",
    "sources": [
      "./src/aead/aead.c",
      "./src/blake2b/blake2b.c",
      "./src/chacha20/chacha20.c",
      "./src/cipher/cipher.c",
      "./src/ecdsa/ecdsa.c",
      "./src/pbkdf2/pbkdf2.c",
      "./src/poly1305/poly1305.c",
      "./src/random/random.c",
      "./src/rsa/rsa.c",
      "./src/scrypt/insecure_memzero.c",
      "./src/scrypt/sha256.c",
      "./src/scrypt/scrypt.c",
      "./src/sha3/sha3.c",
      "./src/aead.cc",
      "./src/bcrypto.cc",
      "./src/blake2b.cc",
      "./src/chacha20.cc",
      "./src/ecdsa.cc",
      "./src/hash160.cc",
      "./src/hash256.cc",
      "./src/keccak.cc",
      "./src/md5.cc",
      "./src/pbkdf2_async.cc",
      "./src/poly1305.cc",
      "./src/ripemd160.cc",
      "./src/rsa.cc",
      "./src/rsa_async.cc",
      "./src/scrypt_async.cc",
      "./src/sha1.cc",
      "./src/sha224.cc",
      "./src/sha256.cc",
      "./src/sha384.cc",
      "./src/sha512.cc"
    ],
    "cflags": [
      "-Wall",
      "-Wno-implicit-fallthrough",
      "-Wno-uninitialized",
      "-Wno-unused-function",
      "-Wextra",
      "-O3"
    ],
    "cflags_c": [
      "-std=c99"
    ],
    "cflags_cc+": [
      "-std=c++0x",
      "-Wno-maybe-uninitialized",
      "-Wno-cast-function-type"
    ],
    "include_dirs": [
      "<!(node -e \"require('nan')\")"
    ],
    "variables": {
      "conditions": [
        ["OS!='win'", {
          "cc": "<!(echo $CC)",
        }],
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
      ["target_arch=='x64' and OS!='win' and cc=='clang'", {
        "cflags": [
          "-msse4.1"
        ]
      }],
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
          "BCRYPTO_POLY1305_64BIT",
          "BCRYPTO_USE_ASM",
          "BCRYPTO_USE_SSE",
          "BCRYPTO_USE_SSE41"
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
