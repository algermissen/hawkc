#ifndef COMMON_H
#define COMMON_H 1
#include <ctype.h>
#include <math.h>
#include "config.h"
#include "hawkc.h"

#ifdef __cplusplus
extern "C" {
#endif




typedef HawkcError (*HawkcSchemeHandler) (HawkcContext ctx, HawkcString scheme, void*data);
typedef HawkcError (*HawkcParamHandler) (HawkcContext ctx, HawkcString key, HawkcString value, void*data);








/*
 * Following stuff to be adapted.
 */

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
 */

/** Maximum size of salt values.
 *
 * MAX_SALT_BYTES must match the largest salt_bits / 8 of all options
 * supplied.
 *
 * Note that the salts actually generated will be twice as long as this
 * constant due to the hex-encoding.
 */
#define MAX_SALT_BYTES 32


/** Must match the requirements by the supplied algorithms. For CBC algorithms
 * it is always 128 bit.
 */
#define MAX_IV_BYTES 32


/** Maximum size necessary for storing IVs in base64url encoded form.
 *
 * Depends on MAX_IV_BYTES and amounts to ceil( MAX_IV_BYTES * 4/3 )
 *
 */
#define MAX_IV_B64CHARS 44 /* FIXME: try with 43, wich would be the correct value */

/* Maximum size of keys used.
 *
 * Must match the requirements of the supplied algorithms.
 *
 */
#define MAX_KEY_BYTES 32

/*
 * Must match the specifications of the supplied HMAC algorithms.
 *
 */
#define MAX_HMAC_BYTES 32

/*
 * This is arbitrarily chosen
 */
/*
#define MAX_PASSWORD_BYTES 256
*/

/** A macro to calculate byte size from number of bits.
 *
 */
#define NBYTES(bits) (ceil((double) (bits) / 8) )

/** A macro for calculated the maximal size of
 * a base64url encoding of a char array of length n.
 */
#define BASE64URL_ENCODE_SIZE(n) (ceil( (double)( (n) * 4) / 3))

/** A macro for calculated the maximal size of
 * a decoding of a base64url encoded char array
 * of length n.
 */
#define BASE64URL_DECODE_SIZE(n) (floor((double) ( (n) * 3) / 4))


/** Structure for the Algorithm typedef in hawkc.h
 */
struct Algorithm {
	const char* name;
	int key_bits;
	int iv_bits;
};

/** Structure for the Options typedef in hawkc.h
 */
struct Options {
	int salt_bits;
	Algorithm algorithm;
	int iterations;
};


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


/** Turn an unsigned char array into an array of hex-encoded bytes.
 *
 * The result will encode each bye as a two-chars hex value (00 to ff)
 * and thus be twice as long as the input.
 *
 * The caller is responsible to provide a buffer of at least 2xlen
 * bytes to hold the result.
 *
 * Does not \0 terminate the created string.
 */
void HAWKCAPI hawkc_bytes_to_hex(const unsigned char *bytes, int len, unsigned char *buf);

/** Fixed time byte-wise comparision.
 *
 * Return 1 if the supplied byte sequences are byte-wise equal, 0 otherwise.
 */
int fixed_time_equal(unsigned char *lhs, unsigned char * rhs, int len);


/** The remainder of this header file defines utilities for
 * tracing and assertions thathave been used throughout development and
 * debugging.
 */

int HAWKCAPI hawkc_trace_bytes(const char *name, const unsigned char *bytes, int len);

#ifndef NDEBUG
#  undef _
#  define _ ,
#  define TRACE(FMT) do { hawkc_trace(FMT); } while (0)
   int HAWKCAPI hawkc_trace(const char * fmt, ...);
#else
#  define TRACE(FMT)     /* empty */
   /* no prototype for hawkc_trace() ! */
#endif /* !NDEBUG */



/* Uncomment this and '#ifdef 0' the code below to
 *   use C STDLIB assertions.
 * include <assert.h>
 */

#ifdef assert
#undef assert
#endif

void HAWKCAPI hawkc_assert(const char*,const char *,unsigned);

#define assert(f) \
   	do { \
   		if(f) {} \
   		else hawkc_assert(#f,__FILE__,__LINE__); \
   	} while(0);


HAWKCAPI HawkcError hawkc_parse_auth_header(HawkcContext ctx, char *value, size_t len, HawkcSchemeHandler scheme_handler, HawkcParamHandler param_handler, void *data);



#ifdef __cplusplus
} // extern "C"
#endif


#endif /* !defined COMMON_H */
 
