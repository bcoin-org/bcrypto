{
  "variables": {
    "with_secp256k1%": "true"
  },
  "target_defaults": {
    # Remove flags inherited from common.gypi.
    # This gives us a clean slate. Note that
    # we have to use `cflags_c` down below
    # because of this.
    "cflags!": [
      "-Wall",
      "-Wextra",
      "-Wno-unused-parameter",
      "-pthread",
      "-pthreads"
    ],
    "ldflags!": [
      "-pthread",
      "-pthreads"
    ],
    "xcode_settings": {
      # As low as we can go without losing support
      # for clock_gettime(2) and getentropy(2).
      "MACOSX_DEPLOYMENT_TARGET": "10.12"
    }
  },
  "targets": [
    {
      "target_name": "torsion",
      "type": "static_library",
      "sources": [
        "./src/torsion/src/aead.c",
        "./src/torsion/src/asn1.c",
        "./src/torsion/src/cipher.c",
        "./src/torsion/src/drbg.c",
        "./src/torsion/src/dsa.c",
        "./src/torsion/src/ecc.c",
        "./src/torsion/src/encoding.c",
        "./src/torsion/src/entropy/env.c",
        "./src/torsion/src/entropy/hw.c",
        "./src/torsion/src/entropy/sys.c",
        "./src/torsion/src/hash.c",
        "./src/torsion/src/ies.c",
        "./src/torsion/src/internal.c",
        "./src/torsion/src/kdf.c",
        "./src/torsion/src/mac.c",
        "./src/torsion/src/mpi.c",
        "./src/torsion/src/rand.c",
        "./src/torsion/src/rsa.c",
        "./src/torsion/src/stream.c",
        "./src/torsion/src/util.c"
      ],
      "cflags_c": [
        "-std=c89",
        "-pedantic",
        "-Wall",
        "-Wextra",
        "-Wcast-align",
        "-Wno-declaration-after-statement",
        "-Wno-implicit-fallthrough",
        "-Wno-long-long",
        "-Wno-overlength-strings",
        "-Wshadow"
      ],
      "msvs_disabled_warnings=": [
        4146, # negation of unsigned integer
        4244, # implicit integer demotion
        4267, # implicit size_t demotion
        4334  # implicit 32->64 bit shift
      ],
      "include_dirs": [
        "./src/torsion/include"
      ]
    },
    {
      "target_name": "secp256k1",
      "type": "static_library",
      "sources": [
        "./src/secp256k1/contrib/lax_der_parsing.c",
        "./src/secp256k1/src/secp256k1.c"
      ],
      "cflags_c": [
        "-std=c89",
        "-pedantic",
        "-Wall",
        "-Wextra",
        "-Wcast-align",
        "-Wnested-externs",
        "-Wno-long-long",
        "-Wno-nonnull-compare", # GCC only
        "-Wno-overlength-strings",
        "-Wno-unknown-warning", # GCC
        "-Wno-unknown-warning-option", # Clang
        "-Wno-unused-function",
        "-Wshadow",
        "-Wstrict-prototypes"
      ],
      "msvs_disabled_warnings=": [
        4244, # implicit integer demotion
        4267, # implicit size_t demotion
        4334  # implicit 32->64 bit shift
      ],
      "include_dirs": [
        "./src/secp256k1",
        "./src/secp256k1/include",
        "./src/secp256k1/src"
      ],
      "defines": [
        "USE_NUM_NONE=1",
        "USE_FIELD_INV_BUILTIN=1",
        "USE_SCALAR_INV_BUILTIN=1",
        "ECMULT_WINDOW_SIZE=15",
        "ECMULT_GEN_PREC_BITS=4",
        "USE_ENDOMORPHISM=1",
        "ENABLE_MODULE_ECDH=1",
        "ENABLE_MODULE_ELLIGATOR=1",
        "ENABLE_MODULE_EXTRA=1",
        "ENABLE_MODULE_RECOVERY=1",
        "ENABLE_MODULE_SCHNORRLEG=1"
      ],
      "conditions": [
        ["node_byteorder=='big'", {
          "defines": [
            "WORDS_BIGENDIAN=1"
          ]
        }],
        ["target_arch=='x64' and OS!='win'", {
          "defines": [
            "HAVE___INT128=1",
            "USE_ASM_X86_64=1",
            "USE_FIELD_5X52=1",
            "USE_SCALAR_4X64=1"
          ]
        }, {
          "defines": [
            "USE_FIELD_10X26=1",
            "USE_SCALAR_8X32=1"
          ]
        }]
      ]
    },
    {
      "target_name": "bcrypto",
      "dependencies": [
        "torsion"
      ],
      "sources": [
        "./src/bcrypto.c"
      ],
      "cflags_c": [
        "-std=c99",
        "-Wall",
        "-Wextra"
      ],
      "msvs_disabled_warnings=": [
        4244, # implicit integer demotion
        4267, # implicit size_t demotion
      ],
      "include_dirs": [
        "./src/torsion/include"
      ],
      "conditions": [
        ["with_secp256k1=='true'", {
          "dependencies": [
            "secp256k1"
          ],
          "include_dirs": [
            "./src/secp256k1/contrib",
            "./src/secp256k1/include"
          ],
          "defines": [
            "BCRYPTO_USE_SECP256K1"
          ]
        }]
      ]
    }
  ]
}
