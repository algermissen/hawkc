#ifndef HAWKC_COMMON_H
#define HAWKC_COMMON_H 1

#include <ctype.h>
#include <math.h>
#include "config.h"
#include "hawkc.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Callback function types for the Auth-header parser.
 */
typedef HawkcError (*HawkcSchemeHandler) (HawkcContext ctx, HawkcString scheme, void*data);
typedef HawkcError (*HawkcParamHandler) (HawkcContext ctx, HawkcString key, HawkcString value, void*data);

/** Structure for the Algorithm typedef in hawkc.h
 */
struct HawkcAlgorithm {
	const char* name;
};

/** A macro to calculate byte size from number of bits.
 *
 */
#define NBYTES(bits) (ceil((double) (bits) / 8) )

/**
 * Mocro used to supply a value for cases where an error is a hawkc-level
 * error and not one of the underlying crypto library.
 *
 */
#define NO_CRYPTO_ERROR 0

/**
 * Set the context error for error retrieval by the caller.
 */
HawkcError HAWKCAPI hawkc_set_error(HawkcContext ctx, const char *file, int line, unsigned long crypto_error,HawkcError e, const char *fmt, ...);

/* Calculate the length of the Hawk header base string used for HMAC generation
 *
 * Useful to check or determine buffer sizes.
 */
size_t hawkc_calculate_base_string_length(HawkcContext ctx, AuthorizationHeader header);

/** Create Hawk header base string to be used for HMAC generation.
 *
 */
void hawkc_create_base_string(HawkcContext ctx, AuthorizationHeader header, unsigned char* base_buf, int *base_len);

/** Parse an Authorization or WWW-Authenticate header.
 *
 * This will parse headers conforming to http://tools.ietf.org/html/draft-ietf-httpbis-p7-auth#section-4
 * except for the use of token68 tokens. In other words, you won't be able to parse
 * HTTP Basic Auth Authorization headers with this.
 *
 * Function parses a string 'value' of 'len' bytes and will call the scheme handler for the scheme
 * token and the param_handler for each parameter/value pair encountered.
 *
 * Parsed parts will not be copied, the provided HawkString variables simply point to the portions
 * of the supplied string 'value'.
 *
 * Caveat: This means that extracted quoted strings will contain the escape characters. It is
 * the responsibility of the caller to make a copy of the quoted string and remove the \.
 */
HawkcError hawkc_parse_auth_header(HawkcContext ctx, char *value, size_t len, HawkcSchemeHandler scheme_handler, HawkcParamHandler param_handler, void *data);

/** Fixed time byte-wise comparision.
 *
 * Return 1 if the supplied byte sequences are byte-wise equal, 0 otherwise.
 */
int hawkc_fixed_time_equal(unsigned char *lhs, unsigned char * rhs, int len);


#ifdef __cplusplus
} // extern "C"
#endif


#endif /* !defined HAWKC_COMMON_H */
 
