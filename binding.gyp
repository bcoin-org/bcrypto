{
  "variables": {
    "enable_secp256k1%": "yes",
    "conditions": [
      ["OS == 'win'", {
        "enable_asm%": "no",
        "enable_int128%": "no",
        "tls_keyword%": "__declspec(thread)"
      }, {
        "enable_asm%": "<!(./deps/checks/check_asm.sh)",
        "enable_int128%": "<!(./deps/checks/check_int128.sh)",
        "tls_keyword%": "<!(./deps/checks/check_tls.sh)"
      }],
      ["OS in 'mac linux freebsd openbsd solaris aix'", {
        "enable_pthread%": "yes"
      }, {
        "enable_pthread%": "no"
      }]
    ]
  },
  "targets": [
    {
      "target_name": "torsion",
      "type": "static_library",
      "sources": [
        "./deps/torsion/src/aead.c",
        "./deps/torsion/src/asn1.c",
        "./deps/torsion/src/cipher.c",
        "./deps/torsion/src/drbg.c",
        "./deps/torsion/src/dsa.c",
        "./deps/torsion/src/ecc.c",
        "./deps/torsion/src/encoding.c",
        "./deps/torsion/src/entropy/hw.c",
        "./deps/torsion/src/entropy/sys.c",
        "./deps/torsion/src/hash.c",
        "./deps/torsion/src/ies.c",
        "./deps/torsion/src/internal.c",
        "./deps/torsion/src/kdf.c",
        "./deps/torsion/src/mac.c",
        "./deps/torsion/src/mpi.c",
        "./deps/torsion/src/rand.c",
        "./deps/torsion/src/rsa.c",
        "./deps/torsion/src/stream.c",
        "./deps/torsion/src/util.c"
      ],
      "include_dirs": [
        "./deps/torsion/include"
      ],
      "direct_dependent_settings": {
        "include_dirs": [
          "./deps/torsion/include"
        ]
      },
      "defines": [
        "TORSION_HAVE_CONFIG"
      ],
      "conditions": [
        ["OS != 'mac' and OS != 'win'", {
          "cflags": [
            "-fvisibility=hidden",
            "-pedantic",
            "-Wcast-align",
            "-Wmissing-prototypes",
            "-Wno-implicit-fallthrough",
            "-Wno-long-long",
            "-Wno-overlength-strings",
            "-Wshadow",
            "-Wstrict-prototypes",
            "-Wundef"
          ]
        }],
        ["OS == 'mac'", {
          "xcode_settings": {
            "GCC_SYMBOLS_PRIVATE_EXTERN": "YES",
            "MACOSX_DEPLOYMENT_TARGET": "10.7",
            "WARNING_CFLAGS": [
              "-pedantic",
              "-Wcast-align",
              "-Wmissing-prototypes",
              "-Wno-implicit-fallthrough",
              "-Wno-long-long",
              "-Wno-overlength-strings",
              "-Wshadow",
              "-Wstrict-prototypes",
              "-Wundef"
            ]
          }
        }],
        ["OS == 'win'", {
          "msvs_disabled_warnings=": [
            4146, # negation of unsigned integer
            4244, # implicit integer demotion
            4267, # implicit size_t demotion
            4334  # implicit 32->64 bit shift
          ]
        }],
        ["enable_asm == 'yes'", {
          "defines": ["TORSION_HAVE_ASM"]
        }],
        ["enable_int128 == 'yes'", {
          "defines": ["TORSION_HAVE_INT128"]
        }],
        ["enable_pthread == 'yes'", {
          "defines": ["TORSION_HAVE_PTHREAD"]
        }],
        ["tls_keyword != 'none'", {
          "defines": ["TORSION_TLS=<(tls_keyword)"]
        }],
        ["OS == 'solaris'", {
          "defines": ["_TS_ERRNO"]
        }],
        ["OS == 'aix'", {
          "defines": ["_THREAD_SAFE_ERRNO"]
        }]
      ]
    },
    {
      "target_name": "secp256k1",
      "type": "static_library",
      "sources": [
        "./deps/secp256k1/contrib/lax_der_parsing.c",
        "./deps/secp256k1/src/secp256k1.c"
      ],
      "include_dirs": [
        "./deps/secp256k1",
        "./deps/secp256k1/include",
        "./deps/secp256k1/src"
      ],
      "direct_dependent_settings": {
        "include_dirs": [
          "./deps/secp256k1/contrib",
          "./deps/secp256k1/include"
        ]
      },
      "defines": [
        "USE_NUM_NONE=1",
        "USE_FIELD_INV_BUILTIN=1",
        "USE_SCALAR_INV_BUILTIN=1",
        "ECMULT_WINDOW_SIZE=15",
        "ECMULT_GEN_PREC_BITS=4",
        "USE_ENDOMORPHISM=1",
        "ENABLE_MODULE_ECDH=1",
        "ENABLE_MODULE_RECOVERY=1",
        "ENABLE_MODULE_EXTRAKEYS=1",
        "ENABLE_MODULE_SCHNORRSIG=1",
        "ENABLE_MODULE_SCHNORRLEG=1",
        "ENABLE_MODULE_ELLIGATOR=1",
        "ENABLE_MODULE_EXTRA=1"
      ],
      "conditions": [
        ["OS != 'mac' and OS != 'win'", {
          "cflags": [
            "-fvisibility=hidden",
            "-std=c89",
            "-pedantic",
            "-Wcast-align",
            "-Wnested-externs",
            "-Wno-long-long",
            "-Wno-nonnull-compare", # Used to be GCC only
            "-Wno-overlength-strings",
            "-Wno-unknown-warning-option", # Clang
            "-Wno-unused-function",
            "-Wshadow",
            "-Wstrict-prototypes",
            "-Wundef"
          ]
        }],
        ["OS == 'mac'", {
          "xcode_settings": {
            "GCC_SYMBOLS_PRIVATE_EXTERN": "YES",
            "GCC_C_LANGUAGE_STANDARD": "c89",
            "WARNING_CFLAGS": [
              "-pedantic",
              "-Wcast-align",
              "-Wnested-externs",
              "-Wno-long-long",
              "-Wno-nonnull-compare", # Used to be GCC only
              "-Wno-overlength-strings",
              "-Wno-unknown-warning-option", # Clang
              "-Wno-unused-function",
              "-Wshadow",
              "-Wstrict-prototypes",
              "-Wundef"
            ]
          }
        }],
        ["OS == 'win'", {
          "msvs_disabled_warnings=": [
            4244, # implicit integer demotion
            4267, # implicit size_t demotion
            4334  # implicit 32->64 bit shift
          ]
        }],
        ["enable_asm == 'yes' and target_arch == 'x64'", {
          "defines": ["USE_ASM_X86_64=1"]
        }],
        ["enable_int128 == 'yes'", {
          "defines": ["USE_FORCE_WIDEMUL_INT128=1"]
        }, {
          "defines": ["USE_FORCE_WIDEMUL_INT64=1"]
        }],
        ["node_byteorder == 'big'", {
          "defines": ["SECP256K1_BIG_ENDIAN"]
        }, {
          "defines": ["SECP256K1_LITTLE_ENDIAN"]
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
      "conditions": [
        ["OS != 'mac' and OS != 'win'", {
          "cflags": [
            "-Wcast-align",
            "-Wshadow"
          ]
        }],
        ["OS == 'mac'", {
          "xcode_settings": {
            "WARNING_CFLAGS": [
              "-Wcast-align",
              "-Wshadow"
            ]
          }
        }],
        ["OS == 'win'", {
          "msvs_disabled_warnings=": [
            4244, # implicit integer demotion
            4267  # implicit size_t demotion
          ]
        }],
        ["enable_secp256k1 == 'yes'", {
          "dependencies": ["secp256k1"],
          "defines": ["BCRYPTO_USE_SECP256K1"]
        }]
      ]
    }
  ]
}
