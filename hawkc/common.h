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






/** A macro to calculate byte size from number of bits.
 *
 */
#define NBYTES(bits) (ceil((double) (bits) / 8) )


/** Structure for the Algorithm typedef in hawkc.h
 */
struct Algorithm {
	const char* name;
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


size_t hawkc_calculate_base_string_length(HawkcContext ctx, AuthorizationHeader header);
void hawkc_create_base_string(HawkcContext ctx, AuthorizationHeader header, unsigned char* base_buf, int *base_len);




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
 
