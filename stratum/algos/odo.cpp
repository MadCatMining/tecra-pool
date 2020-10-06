#ifndef ODOCRYPT_H
#define ODOCRYPT_H

#include <assert.h>
#include <string.h>

#include "odocrypt.h"
#ifdef __cplusplus
extern "C" {
#endif

#include "../sha3/KeccakP-800-SnP.h"

void odocrypt_hash(const char* input, char* output, uint32_t len, uint32_t key)
{
    char hash[KeccakP800_stateSizeInBytes] = {};

    assert(len <= OdoCrypt::DIGEST_SIZE);
    assert(OdoCrypt::DIGEST_SIZE < KeccakP800_stateSizeInBytes);
    memcpy(hash, static_cast<const void*>(input), len);
    hash[len] = 1;

    OdoCrypt(key).Encrypt(hash, hash);
    KeccakP800_Permute_12rounds(hash);
    memcpy(output, hash, 32);
}

#ifdef __cplusplus
}
#endif

#endif
