#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "hawkc.h"
#include "common.h"

/* FIXME: docme, cleanme */

/**
 * Algorithms provided by hawkc.
 *
 * If you add more algorithms here, you need to check and maybe adjust the
 * buffer size constants defined in common.h
 *
 * Also, you must add to the selection if-cascades in crypto_openssl.c for them
 * to be recognized.
 */
struct Algorithm _AES_128_CBC = { "aes-128-cbc", 128, 128 };
struct Algorithm _AES_256_CBC = { "aes-256-cbc", 256, 128 };
struct Algorithm _SHA_256 = { "sha256", 256, 0 };

Algorithm AES_128_CBC = &_AES_128_CBC;
Algorithm AES_256_CBC = &_AES_256_CBC;
Algorithm SHA_256 = &_SHA_256;

/** Default options provided by hawkc.
 *
 * You must make sure that MAX_SALT_BYTES defined in common.h
 * matches the largest salt bit value defined by the options.
 *
 * There is currently no support for adding more options through
 * user code. This is an open issue:
 * https://github.com/algermissen/hawkc/issues/2
 *
 *
 */
struct Options _DEFAULT_ENCRYPTION_OPTIONS = { 256, &_AES_256_CBC, 1 };
struct Options _DEFAULT_INTEGRITY_OPTIONS = { 256, &_SHA_256, 1 };

Options DEFAULT_ENCRYPTION_OPTIONS = &_DEFAULT_ENCRYPTION_OPTIONS;
Options DEFAULT_INTEGRITY_OPTIONS = &_DEFAULT_INTEGRITY_OPTIONS;

/** Error strings used by hawkc_strerror
 *
 */
static char *error_strings[] = {
		"No error", /* HAWKC_OK */
		"Token parse error", /* HAWKC_TOKEN_PARSE_ERROR */
		"Token invalid", /* HAWKC_TOKEN_VALIDATION_ERROR */
		"Unknown algorithm", /* HAWKC_ERROR_UNKNOWN_ALGORITHM */
		"Some unrecognized error in the crypto library occurred", /* HAWKC_CRYPTO_ERROR */
		"Not a unix time vallue" , /* HAWKC_TIME_VALUE_ERROR */
		NULL
};

char* hawkc_strerror(HawkcError e) {
	assert(e >= 0 && e <= 0);
	return error_strings[e];
}

HawkcError hawkc_set_error(HawkcContext ctx, const char *file, int line,
		unsigned long crypto_error, HawkcError e, const char *fmt, ...) {
	va_list args;
	char buf[256];
	va_start(args, fmt);
	vsnprintf(ctx->error_string, sizeof(ctx->error_string), fmt, args);
	va_end(args);
	if (crypto_error != NO_CRYPTO_ERROR) {
		snprintf(buf, sizeof(buf), " in %s, line %d (internal error:%ld)", file,
				line, crypto_error);
	} else {
		snprintf(buf, sizeof(buf), " in %s, line %d", file, line);
	}
	strncat(ctx->error_string, buf,
			sizeof(ctx->error_string) - strlen(ctx->error_string) - 1);
	ctx->error = e;
	ctx->crypto_error = crypto_error;
	return e;
}

char *hawkc_get_error(HawkcContext ctx) {
	return ctx->error_string;
}

HawkcError hawkc_get_error_code(HawkcContext ctx) {
	return ctx->error;
}


void hawkc_context_init(HawkcContext ctx) {
	ctx->error = HAWKC_OK;
	ctx->malloc = NULL;
	ctx->calloc = NULL;
	ctx->free = NULL;

	ctx->header_in.buf = NULL;
	ctx->header_in.buf_len = 0;
	ctx->header_in.buf_pos = 0;

}


void* hawkc_malloc(HawkcContext ctx, size_t size) {
	if(ctx->malloc == NULL) {
		return malloc(size);
	}
	return (ctx->malloc)(ctx,size);
}
void* hawkc_calloc(HawkcContext ctx, size_t count, size_t size) {
	if(ctx->calloc == NULL) {
		return calloc(count,size);
	}
	return (ctx->calloc)(ctx,count,size);

}
void hawkc_free(HawkcContext ctx, void *ptr) {
	if(ctx->free == NULL) {
		free(ptr);
		return;
	}
	(ctx->free)(ctx,ptr);
}



/* Lookup 'table' for hex encoding */
static const char hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'a', 'b', 'c', 'd', 'e', 'f' };
void hawkc_bytes_to_hex(const unsigned char *bytes, int len, unsigned char *buf) {
	int j;
	for (j = 0; j < len; j++) {
		int v;
		v = bytes[j] & 0xFF;
		buf[j * 2] = hex[v >> 4];
		buf[j * 2 + 1] = hex[v & 0x0F];
	}
}



int fixed_time_equal(unsigned char *lhs, unsigned char * rhs, int len) {

	int equal = 1;
	int i;
	for(i = 0; i<len;i++) {
		if(lhs[i] != rhs[i]) {
			equal = 0;
		}
	}

	return equal;
}



/** Tracing and assertion utilities below
 *
 */

int hawkc_trace(const char * fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	return 0;
}

int hawkc_trace_bytes(const char *name, const unsigned char *bytes, int len) {
	int i;
	fprintf(stderr, "Byte array %s: ", name);
	for (i = 0; i < len; i++) {
		fprintf(stderr, "%s0x%02x", (i == 0) ? "" : ",", bytes[i]);
	}
	fprintf(stderr, "\n");
	return 0;
}

void hawkc_assert(const char *exp, const char *file, unsigned line) {
	fflush(NULL );
	fprintf(stderr, "\n\nAssertion \"%s\" failed in %s, line %u\n", exp, file,
			line);
	fflush(stderr);
	abort();
}

