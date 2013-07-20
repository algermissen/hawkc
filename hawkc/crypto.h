#ifndef CRYPTO_H
#define CRYPTO_H 1
#include "hawkc.h"
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Compute an HMAC of the supplied data using the specified algorithm.
 */
HawkcError hawkc_hmac(HawkcContext ctx, HawkcAlgorithm algorithm,
		const unsigned char *password, int password_len,
		const unsigned char *data, int data_len, unsigned char *result,
		int *result_len);


#ifdef __cplusplus
} // extern "C"
#endif

#endif /* !defined CRYPTO_H */

