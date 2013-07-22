/*
 * Header file for hawkc.
 *
 * This header file is all you need to include to use hawkc
 * functionality from outside the hawkc library.
 *
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
	HAWKC_TIME_VALUE_ERROR, /* Not a valid unix time value */
	HAWKC_NO_MEM, /* Unable to allocate memory */
	HAWKC_REQUIRED_BUFFER_TOO_LARGE, /* Required buffer size is too large */
	HAWKC_ERROR /* unspecific error */
	/* If you add errors here, add them in common.c also */
} HawkcError;

/*
 * Global handle to pass to all functions.
 */
typedef struct HawkcContext *HawkcContext;

/*
 * Type for HMAC algorithms.
 */
typedef struct HawkcAlgorithm *HawkcAlgorithm;

/*
 * Memory allocation function pointers. Hawkc allows setting custom
 * allocation functions. For example, if you need some that do
 * memory pooling.
 */
typedef void* (*HawkcMallocFunc)(HawkcContext ctx, size_t size);
typedef void* (*HawkcCallocFunc)(HawkcContext ctx, size_t count, size_t size);
typedef void (*HawkcFreeFunc)(HawkcContext ctx, void *ptr);

/*
 * Type for holding Hawkc Authorization and Server-Authrization
 * header data. This struct is used for storing parsed data as
 * well as for constructing header data before creating a string representation.
 */
typedef struct AuthorizationHeader {
	HawkcString id;
	HawkcString mac;
	HawkcString hash;
	HawkcString nonce;
	time_t ts;
	HawkcString ext;

} *AuthorizationHeader;

/*
 * Type for holding Hawkc WWW-Authenticate
 * header data. This struct is used for storing parsed data as
 * well as for constructing header data before creating a string representation.
 */
typedef struct WwwAuthenticateHeader {
	HawkcString id;
	time_t ts;
} *WwwAuthenticateHeader;

/* The global Hawkc context.
 *
 * header_in is intended for received Authorization or Server-Authorization header
 * depending on whether the library is used on the server- or client side.
 *
 * header_out is intended for Authorization or Server-Authorization header to send,
 * depending on whether the library is used on the server- or client side.
 *
 * www_authenticate_header is used either way, depending on use on
 * the server- or client side.
 *
 * hmac is used as a buffer to write HMAC signatures to. NOt sure if this is
 * necessary, could probably be replaced by local buffer. Will depend on
 * what happens, when we start implementing *writing* headers. FIXME
 *
 */
struct HawkcContext {
	HawkcMallocFunc malloc;
	HawkcCallocFunc calloc;
	HawkcFreeFunc free;
	HawkcError error;
	char error_string[1024];

	HawkcString method;
	HawkcString path;
	HawkcString host;
	HawkcString port;

	struct AuthorizationHeader header_in;
	struct AuthorizationHeader header_out;
	struct WwwAuthenticateHeader www_authenticate_header;

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

