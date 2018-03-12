#ifndef _BCRYPTO_BCRYPTO_H
#define _BCRYPTO_BCRYPTO_H

#include <node.h>
#include <nan.h>

NAN_METHOD(pbkdf2);
NAN_METHOD(pbkdf2_async);
NAN_METHOD(scrypt);
NAN_METHOD(scrypt_async);
NAN_METHOD(cleanse);
NAN_METHOD(encipher);
NAN_METHOD(decipher);
NAN_METHOD(random_bytes);

#endif
