#!/bin/sh

if test x"$CC_target" != x; then
  CC="$CC_target"
fi

cat > conftest.c <<EOF
int main(void) {
  unsigned long z = 953;
  unsigned long x = 109;
  unsigned long y = 577;
  unsigned long c;
  __asm__ __volatile__ (
    ""
    : "+r" (z), "=&r" (c)
    : "%rm" (x), "rm" (y)
    : "cc", "memory"
  );
  return z ^ 953;
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
