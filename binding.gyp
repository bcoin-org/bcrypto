{
  "targets": [{
    "target_name": "bcrypto",
    "sources": [
      "../torsion/src/aead.c",
      "../torsion/src/chacha20.c",
      "../torsion/src/drbg.c",
      "../torsion/src/ecc.c",
      "../torsion/src/hash.c",
      "../torsion/src/kdf.c",
      "../torsion/src/poly1305.c",
      "../torsion/src/rsa.c",
      "../torsion/src/salsa20.c",
      "../torsion/src/util.c",
      "./src/aead/aead.c",
      "./src/aes/aes.c",
      "./src/base58/base58.c",
      "./src/bech32/bech32.c",
      "./src/cash32/cash32.c",
      "./src/chacha20/chacha20.c",
      "./src/dsa/dsa.c",
      "./src/murmur3/murmur3.c",
      "./src/poly1305/poly1305.c",
      "./src/random/random.c",
      "./src/salsa20/salsa20.c",
      "./src/secp256k1/src/secp256k1.c",
      "./src/secp256k1/contrib/lax_der_parsing.c",
      "./src/secp256k1/contrib/lax_der_privatekey_parsing.c",
      "./src/siphash/siphash.c",
      "./src/aead.cc",
      "./src/aes.cc",
      "./src/base58.cc",
      "./src/bech32.cc",
      "./src/bcrypto.cc",
      "./src/blake2b.cc",
      "./src/blake2s.cc",
      "./src/cash32.cc",
      "./src/chacha20.cc",
      "./src/cipherbase.cc",
      "./src/dsa.cc",
      "./src/dsa_async.cc",
      "./src/ecdh.cc",
      "./src/ecdsa.cc",
      "./src/eddsa.cc",
      "./src/hash160.cc",
      "./src/hash256.cc",
      "./src/keccak.cc",
      "./src/md4.cc",
      "./src/md5.cc",
      "./src/murmur3.cc",
      "./src/pbkdf2.cc",
      "./src/pbkdf2_async.cc",
      "./src/poly1305.cc",
      "./src/random.cc",
      "./src/ripemd160.cc",
      "./src/rsa.cc",
      "./src/rsa_async.cc",
      "./src/salsa20.cc",
      "./src/scrypt.cc",
      "./src/scrypt_async.cc",
      "./src/secp256k1.cc",
      "./src/sha1.cc",
      "./src/sha224.cc",
      "./src/sha256.cc",
      "./src/sha384.cc",
      "./src/sha512.cc",
      "./src/siphash.cc",
      "./src/whirlpool.cc"
    ],
    "cflags": [
      "-Wall",
      "-Wextra",
      "-Wno-implicit-fallthrough",
      "-Wno-nonnull-compare",
      "-Wno-unknown-warning",
      "-Wno-unused-function",
      "-O3"
    ],
    "cflags_c": [
      "-std=c99"
    ],
    "cflags_cc+": [
      "-std=c++0x",
      "-Wno-cast-function-type",
      "-Wno-unused-parameter"
    ],
    "include_dirs": [
      "<!(node -e \"require('nan')\")",
      "../torsion/include"
    ],
    "defines": [
      "USE_ENDOMORPHISM",
      "ENABLE_MODULE_ECDH",
      "ENABLE_MODULE_ELLIGATOR",
      "ENABLE_MODULE_EXTRA",
      "ENABLE_MODULE_RECOVERY",
      "ENABLE_MODULE_SCHNORRLEG"
    ],
    "variables": {
      "conditions": [
        ["OS=='win'", {
          "with_gmp%": "false"
        }, {
          "with_gmp%": "<!(./utils/has_gmp.sh)"
        }]
      ]
    },
    "conditions": [
      ["node_byteorder=='big'", {
        "defines": [
          "WORDS_BIGENDIAN"
        ]
      }],
      ["target_arch=='x64' and OS!='win'", {
        "defines": [
          "TORSION_64BIT",
          "BCRYPTO_POLY1305_64BIT",
          "BCRYPTO_SIPHASH_64BIT",
          "BCRYPTO_USE_ASM",
          "BCRYPTO_USE_SSE",
          "HAVE___INT128",
          "USE_ASM_X86_64",
          "USE_FIELD_5X52",
          "USE_FIELD_5X52_INT128",
          "USE_SCALAR_4X64"
        ]
      }, {
        "defines": [
          "BCRYPTO_POLY1305_32BIT",
          "USE_FIELD_10X26",
          "USE_SCALAR_8X32"
        ]
      }],
      ["with_gmp=='true'", {
        "defines": [
          "TORSION_HAS_GMP",
          "HAVE_LIBGMP",
          "USE_NUM_GMP",
          "USE_FIELD_INV_NUM",
          "USE_SCALAR_INV_NUM"
        ],
        "libraries": [
          "-lgmp"
        ]
      }, {
        "defines": [
          "USE_NUM_NONE",
          "USE_FIELD_INV_BUILTIN",
          "USE_SCALAR_INV_BUILTIN"
        ],
        "sources": [
          "../torsion/src/mini-gmp.c"
        ]
      }]
    ]
  }]
}
