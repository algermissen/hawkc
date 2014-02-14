#ifndef CRYPTO_H
#define CRYPTO_H 1
#include "hawkc.h"
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Generate a random sequence of bytes and store in buffer hex-encoded.
 *
 * This function generates a byte array of the required length of nbytes and
 * stores it in the provided buffer.
 *
 * The hex-encoding causes the result to be exactly 2xnbytes long. The
 * provided buffer must have at least that size.
 *
 * The result will not be \0 terminated.
 */
HawkcError HAWKCAPI hawkc_generate_nonce(HawkcContext ctx, size_t nbytes,
		unsigned char *buf);

/**
 * Compute an HMAC of the supplied data using the specified algorithm.
 */
HawkcError hawkc_hmac(HawkcContext ctx, HawkcAlgorithm algorithm,
		const unsigned char *password, size_t password_len,
		const unsigned char *data, size_t data_len, unsigned char *result,
		size_t *result_len);


#ifdef __cplusplus
} // extern "C"
#endif

#endif /* !defined CRYPTO_H */

