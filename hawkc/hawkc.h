/*
 * Header file for hawkc.
 *
 * This header file is all you need to include to use hawkc
 * functionality from outside the hawkc library.
 *
 * FIXME:
 * Think about general lib size, e.g. static error buffer and the like.
 * Same in ciron
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

/** The following macros define buffer size constants.
 *
 * These constants are defined for convenience, to allow
 * the callers of functions that require caller-buffer-allocation
 * to use fixed buffers as opposed to dealing with dynamic
 * allocation and deallocation of memory.
 *
 * The buffer sizes are considerably small to justify the
 * space overhead.
 *
 * These buffer sizes depend on the algorithms and options defined
 * in common.c and must be adjusted if new algorithms are added that
 * require increased buffer sizes.
 *
 * They need to be defined in this header because the structs (which
 * we deliberately expose to the user) make use of the macros.
 */

/*
 * Must match the specifications of the supplied HMAC algorithms.
 *
 */
#define MAX_HMAC_BYTES 32

/* 32/3 * 4 */
#define MAX_HMAC_BYTES_B64 40

/**
 * Hawkc mostly uses strings that are not null terminated but are associated with a length
 * information. HawkcString encapsulates a character array combined with a length.
 */
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
	HAWKC_BAD_SCHEME_ERROR, /* Authentication scheme name not Hawk */
	HAWKC_TOKEN_VALIDATION_ERROR, /* Token cannot be validated */
	HAWKC_ERROR_UNKNOWN_ALGORITHM, /* Unknown algorithm */
	HAWKC_CRYPTO_ERROR, /* Some unrecognized error in the crypto library occurred */
	HAWKC_TIME_VALUE_ERROR /* Not a valid unix time value */
	/* If you add errors here, add them in common.c also */
} HawkcError;

typedef struct HawkcContext *HawkcContext;

/** Structure for the Algorithm typedef in hawkc.h
 */

typedef struct HawkcAlgorithm *HawkcAlgorithm;

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

	HawkcString method;
	HawkcString path;
	HawkcString host;
	HawkcString port;

	struct AuthorizationHeader header_in;
	struct AuthorizationHeader header_out;
	struct WwwAuthenticateHeader wwwAuthenticateHeader;

	unsigned char hmac[MAX_HMAC_BYTES_B64];

};


HAWKCAPI void hawkc_context_init(HawkcContext ctx);
HAWKCAPI void* hawkc_malloc(HawkcContext ctx, size_t size);
HAWKCAPI void* hawkc_calloc(HawkcContext ctx, size_t count, size_t size);
HAWKCAPI void hawkc_free(HawkcContext ctx, void *ptr);

HAWKCAPI void hawkc_context_set_method(HawkcContext ctx,char *method, size_t len);
HAWKCAPI void hawkc_context_set_path(HawkcContext ctx,char *path, size_t len);
HAWKCAPI void hawkc_context_set_host(HawkcContext ctx,char *host, size_t len);
HAWKCAPI void hawkc_context_set_port(HawkcContext ctx,char *port, size_t len);

HAWKCAPI HawkcError hawkc_parse_authorization_header(HawkcContext ctx, char *value, size_t len);
HAWKCAPI HawkcError hawkc_validate_hmac(HawkcContext ctx, HawkcAlgorithm algorithm, const unsigned char *password, int password_len,int *is_valid);


/** Obtain HMAC algorithm for specified name.
 *
 * Returns the algorithm or NULL if not found.
 */
HAWKCAPI HawkcAlgorithm hawkc_algorithm_by_name(char *name, int len);

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




/** The algorithms and options defined by hawkc.
 *
 * Please refer to common.c for their definition.
 */
extern HawkcAlgorithm HAWKC_SHA_256;
extern HawkcAlgorithm HAWKC_SHA_1;



#ifdef __cplusplus
} // extern "C"
#endif

#endif /* !defined HAWKC_H */

