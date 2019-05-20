#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include "random.h"

#ifdef BCRYPTO_WITH_OPENSSL
#include "random-openssl.h"
#else
#include "random-nettle.h"
#endif
