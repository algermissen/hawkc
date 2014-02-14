/* The base64.c for the original license of the base64 code */

#ifndef BASE64_H
#define BASE64_H

#include "hawkc.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Base64 encode the given data.
 *
 * This function encodes the data using Base64 encoding according to RFC 4648
 * http://tools.ietf.org/html/rfc4648
 *
 * Stores the encoded unsigned char sequence in the provided buffer. The caller is responsible for
 * supplying a buffer of sufficient length.
 *
 * The length can be calculated using  result_len = data_len * 4/3 + 2 bytes max. padding
 *
 * The result will not be \0-terminated.
 */
unsigned char* HAWKCAPI hawkc_base64_encode( const unsigned char *data, size_t data_len, unsigned char *res, size_t *result_len );

/** Base64 decode the given data.
 *
 * This function decodes the data using Base64 decoding according to RFC 4648
 * http://tools.ietf.org/html/rfc4648
 *
 * Stores the decoded unsigned char sequence in the provided buffer. The caller is responsible for
 * supplying a buffer of sufficient length.
 *
 * The length can be calculated using  result_len = data_len * 3/4
 *
 * The result will not be \0-terminated.
 */
unsigned char* HAWKCAPI hawkc_base64_decode( const unsigned char *data, size_t data_len, unsigned char *result, size_t *result_len );

#ifdef __cplusplus
} // extern "C"
#endif


#endif