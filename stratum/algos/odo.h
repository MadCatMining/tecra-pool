//#ifndef _odocrypt_h_
//#define _odocrypt_h_

//#ifdef __cplusplus
//extern "C" {
//#endif

//#include "../sha3/KeccakP-800-SnP.h"

//#include "odocrypt.h"
//#include "../sha3/brg_endian.h"
//#include <stdint.h>
//#include <string.h>

//static void odocrypt_hash(const char *input, char *output, uint32_t key);


//#ifdef __cplusplus
//}
//#endif

//#endif

#ifndef HASH_ODO
#define HASH_ODO

#include <assert.h>
#include <string.h>

#include "odocrypt.h"
extern "C" {
#include "../sha3/KeccakP-800-SnP.h"


#define MAINNET_EPOCH_LEN 864000
#define TESTNET_EPOCH_LEN 86400 

}

void odocrypt_hash(const char* input, char* output, uint32_t len)
{
    char cipher[KeccakP800_stateSizeInBytes] = {};

    uint32_t key;
    key = time(NULL) - (time(NULL) % MAINNET_EPOCH_LEN); 

    assert(len <= OdoCrypt::DIGEST_SIZE);
    assert(OdoCrypt::DIGEST_SIZE < KeccakP800_stateSizeInBytes);
    memcpy(cipher, static_cast<const void*>(input), len);
    cipher[len] = 1;

    OdoCrypt(key).Encrypt(cipher, cipher);
    KeccakP800_Permute_12rounds(cipher);
    memcpy(output, cipher, 32);

    len = (input, output, key, len);

}

#endif
