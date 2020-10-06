#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include <time.h>
#include <string.h>


//extern "C" {
#include "../sha3/KeccakP-800-SnP.h"
#include "odocrypt.h"
#include "odo.h"

#define MAINNET_EPOCH_LEN 864000
#define TESTNET_EPOCH_LEN 86400 

static void odocrypt_hash(const char *input, char *output, uint32_t key)

	{ 
		char cipher[KeccakP800_stateSizeInBytes] = {};

//		uint32_t key;
		key = time(NULL) - (time(NULL) % MAINNET_EPOCH_LEN); 
 
		memcpy(cipher, input, 80); 
		cipher[80] = 1;

		OdoCrypt(key).Encrypt(cipher, cipher);
		KeccakP800_Permute_12rounds(cipher);

		memcpy(output, cipher, 32);

	}

//}
