#!/bin/sh

if test x"$CC_target" != x; then
  CC="$CC_target"
fi

cat > conftest.c <<EOF
typedef signed __int128 xint128_t;
typedef unsigned __int128 xuint128_t;
typedef char check_voidptr_t[sizeof(void *) >= 8 ? 1 : -1];
typedef char check_int128_t[sizeof(xint128_t) == 16 ? 1 : -1];
typedef char check_uint128_t[sizeof(xuint128_t) == 16 ? 1 : -1];
int main(int argc, char **argv) {
  xint128_t c = argv[0][0];
  xuint128_t r = argc + c;
  while (argc--) r *= r;
  return r >> 121;
}
EOF

rm -f conftest

if ${CC-cc} -o conftest conftest.c > /dev/null 2>& 1; then
  echo yes
else
  echo no
fi

rm -f conftest.c
rm -f conftest
