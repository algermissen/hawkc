/*
 * This file implements the functions declared in crypto.h using libcrypto
 * of the OpenSSL library.
 */
#include <string.h>
#include <assert.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "hawkc.h"
#include "common.h"
#include "crypto.h"
#include "base64.h"

HawkcError hawkc_generate_nonce(HawkcContext ctx, int nbytes, unsigned char *buf) {
	int r;
	unsigned char nonce_bytes[MAX_NONCE_BYTES];
	assert(nbytes <= MAX_NONCE_BYTES);

	if ((r = RAND_bytes(nonce_bytes, nbytes)) != 1) {
		return hawkc_set_error(ctx, HAWKC_ERROR,"Unable to get %d random bytes, last OpenSSL error code: %ld", nbytes,ERR_get_error());
	}
	hawkc_bytes_to_hex(nonce_bytes, nbytes, buf);

	return HAWKC_OK;
}

HawkcError hawkc_hmac(HawkcContext ctx, HawkcAlgorithm algorithm,
		const unsigned char *password, size_t password_len,
		const unsigned char *data, size_t data_len, unsigned char *result,
		size_t *result_len) {

	int result_len_int; /* Used for conversion between int and size_t, see https://github.com/algermissen/hawkc/issues/4 */

	HMAC_CTX md_ctx;
	const EVP_MD *md;
	unsigned char buf[MAX_HMAC_BYTES];
	unsigned int len;

	if (strcmp(algorithm->name, HAWKC_SHA_1->name) == 0) {
		md = EVP_sha1();
	} else if (strcmp(algorithm->name, HAWKC_SHA_256->name) == 0) {
		md = EVP_sha256();
	} else {
		return hawkc_set_error(ctx, HAWKC_ERROR_UNKNOWN_ALGORITHM,
				"Algorithm %s not recognized for HMAC calculation", algorithm->name);
	}
	HMAC_CTX_init(&md_ctx);
	HMAC_Init(&md_ctx, password, password_len, md);
	HMAC_Update(&md_ctx, data, data_len);

	HMAC_Final(&md_ctx, buf, &len);
	HMAC_CTX_cleanup(&md_ctx);
	hawkc_base64_encode(buf, len, result, &result_len_int);

	*result_len = (size_t)result_len_int;

	return HAWKC_OK;
}

