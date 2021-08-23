#!/bin/sh

if test x"$CC_target" != x; then
  CC="$CC_target"
fi

tls=none

for keyword in __thread '__declspec(thread)' _Thread_local; do
  echo "$keyword int x; int main(void) { x = 1; return !x; }" > conftest.c

  rm -f conftest

  if ! ${CC-cc} -o conftest conftest.c > /dev/null 2>& 1; then
    continue
  fi

  if ! ./conftest > /dev/null 2>& 1; then
    continue
  fi

  rm -f conftest.s

  if ${CC-cc} -S -o conftest.s conftest.c > /dev/null 2>& 1; then
    if grep __emutls_get_address conftest.s > /dev/null 2>& 1; then
      break
    fi
  fi

  tls="$keyword"
  break
done

rm -f conftest.c
rm -f conftest.s
rm -f conftest

echo "$tls"
