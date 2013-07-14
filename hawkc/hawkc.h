/*
 * Header file for hawkc.
 *
 * This header file is all you need to include to use hawkc
 * functionality from outside the hawkc library.
 */
#ifndef HAWKC_H
#define HAWKC_H 1

#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAWKCAPI
#define HAWKCAPI
#endif

typedef struct HawkcString {
	size_t len;
	char *data;
} HawkcString;

/** hawkc error codes
 * 
 */
typedef enum {
	HAWKC_OK, /* no error */
	HAWKC_PARSE_ERROR, /* Parse error */
	HAWKC_TOKEN_VALIDATION_ERROR, /* Token cannot be validated */
	HAWKC_ERROR_UNKNOWN_ALGORITHM, /* Unknown algorithm */
	HAWKC_CRYPTO_ERROR, /* Some unrecognized error in the crypo library ocurred */
	HAWKC_TIME_VALUE_ERROR /* Not a valid unix time value */
	/* If you add errors here, add them in common.c also */
} HawkcError;

typedef struct HawkcContext *HawkcContext;

typedef void* (*HawkcMallocFunc)(HawkcContext ctx, size_t size);
typedef void* (*HawkcCallocFunc)(HawkcContext ctx, size_t count, size_t size);
typedef void (*HawkcFreeFunc)(HawkcContext ctx, void *ptr);

typedef struct AuthorizationHeader {
	HawkcString id;
	HawkcString mac;
	HawkcString hash;
	HawkcString nonce;
	time_t ts;
	HawkcString ext;
	char *buf;
	size_t buf_len;
	size_t buf_pos;

} *AuthorizationHeader;

typedef struct WwwAuthenticateHeader {
	HawkcString id;
	time_t ts;
	char *buf;
	size_t buf_len;
	size_t buf_pos;
} *WwwAuthenticateHeader;

struct HawkcContext {
	HawkcMallocFunc malloc;
	HawkcCallocFunc calloc;
	HawkcFreeFunc free;
	/** Hawkc error code */
	HawkcError error;
	/** Error message providing specific error condition details */
	char error_string[1024];
	/** Error code of underlying crypto library, or 0 if not applicable */
	unsigned long crypto_error;

	struct AuthorizationHeader header_in;
	struct AuthorizationHeader header_out;
	struct WwwAuthenticateHeader wwwAuthenticateHeader;

};


HAWKCAPI void hawkc_context_init(HawkcContext ctx);
HAWKCAPI void* hawkc_malloc(HawkcContext ctx, size_t size);
HAWKCAPI void* hawkc_calloc(HawkcContext ctx, size_t count, size_t size);
HAWKCAPI void hawkc_free(HawkcContext ctx, void *ptr);




HAWKCAPI HawkcError hawkc_parse_authorization_header(HawkcContext ctx, char *value, size_t len);

/** Obtain human readable string for the provided error code.
 *
 */
char* HAWKCAPI hawkc_strerror(HawkcError e);

/** Get a human readable message about the last error
 * condition that ocurred for the given context.
 *
 */
char * HAWKCAPI hawkc_get_error(HawkcContext ctx);

/** Get the hawkc error code that occurred last in the
 * given context.
 *
 */
HawkcError HAWKCAPI hawkc_get_error_code(HawkcContext ctx);

/** Get the error code reported by the underlying
 * crypto library. Returns the code or NO_CRYPTO_ERROR if not
 * applicable in a given error case.
 */
unsigned long HAWKCAPI hawkc_get_crypto_error(HawkcContext ctx);


/*
 * Stuff below to be adapted.
 */


typedef struct Options *Options;
typedef struct Algorithm *Algorithm;

/** The algorithms and options defined by hawkc.
 *
 * Please refer to common.c for their definition.
 */
extern Algorithm AES_128_CBC;
extern Algorithm AES_256_CBC;
extern Algorithm SHA_256;
extern Options DEFAULT_ENCRYPTION_OPTIONS;
extern Options DEFAULT_INTEGRITY_OPTIONS;



#ifdef __cplusplus
} // extern "C"
#endif

#endif /* !defined HAWKC_H */

