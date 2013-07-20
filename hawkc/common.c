#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "hawkc.h"
#include "common.h"
#include "crypto.h"

static const char *HAWK_HEADER_PREFIX = "hawk.1.header";
static const char LF = '\n';


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
struct HawkcAlgorithm _HAWKC_SHA_256 = { "sha256" };
struct HawkcAlgorithm _HAWKC_SHA_1 = { "sha1" };

HawkcAlgorithm HAWKC_SHA_256 = &_HAWKC_SHA_256;
HawkcAlgorithm HAWKC_SHA_1 = &_HAWKC_SHA_1;

/** Error strings used by hawkc_strerror
 *
 */
static char *error_strings[] = {
		"No error", /* HAWKC_OK */
		"Token parse error", /* HAWKC_TOKEN_PARSE_ERROR */
		"Authentication scheme name not Hawk", /* HAWKC_BAD_SCHEME_ERROR */
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
	memset(ctx,0,sizeof(struct HawkcContext));
	ctx->error = HAWKC_OK;
	ctx->malloc = NULL;
	ctx->calloc = NULL;
	ctx->free = NULL;

	/* FIXME kann wohl weg */
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



void hawkc_context_set_method(HawkcContext ctx,char *method, size_t len) {
	ctx->method.data = method;
	ctx->method.len = len;
}
void hawkc_context_set_path(HawkcContext ctx,char *path, size_t len) {
	ctx->path.data = path;
	ctx->path.len = len;

}
void hawkc_context_set_host(HawkcContext ctx,char *host, size_t len) {
	ctx->host.data = host;
	ctx->host.len = len;

}
void hawkc_context_set_port(HawkcContext ctx,char *port, size_t len) {
	ctx->port.data = port;
	ctx->port.len = len;

}

HawkcError hawkc_validate_hmac(HawkcContext ctx, HawkcAlgorithm algorithm, const unsigned char *password, int password_len,int *is_valid) {
	HawkcError e;
	int len,base_len;
	unsigned char base_buf[1024];


	/*
		if( (buf = hawkc_calloc(ctx,1,required_size)) == NULL) {
			assert(!"FIXME");
		}
		*/

	hawkc_create_base_string(ctx,&(ctx->header_in),base_buf,&base_len);

	if( (e = hawkc_hmac(ctx, algorithm, password, password_len, base_buf, base_len,ctx->hmac,&len)) != HAWKC_OK) {
		return e;
	}
	/* FIXME
	fprintf(stderr,"calculated: {%.*s}",len, ctx->hmac);
	fprintf(stderr,"got:        {%.*s}", ctx->header_in.mac.len,ctx->header_in.mac.data);
	*/

	if( ctx->header_in.mac.len != len) {
		*is_valid = 0;
		return HAWKC_OK;
	}
	/*
	printf("{%.*s}",len, ctx->hmac);
	printf("{%.*s}", ctx->header_in.mac.len,ctx->header_in.mac.data);
	*/


	if(!hawkc_fixed_time_equal((unsigned char*)ctx->header_in.mac.data,ctx->hmac,len)) {
		*is_valid = 0;
		return HAWKC_OK;
	}
	/*
	printf("{%.*s}",len, ctx->hmac);
	printf("{%.*s}", ctx->header_in.mac.len,ctx->header_in.mac.data);
	*/
	*is_valid = 1;
	return HAWKC_OK;
}

HawkcAlgorithm hawkc_algorithm_by_name(char *name, int len) {
	if (len == strlen(HAWKC_SHA_1->name) && strncmp(name, HAWKC_SHA_1->name, len) == 0) {
		return HAWKC_SHA_1;
	} else if (len == strlen(HAWKC_SHA_256->name) && strncmp(name, HAWKC_SHA_256->name, len) == 0) {
		return HAWKC_SHA_256;
	} else {
		return NULL;
	}
}


/* internal */
size_t hawkc_calculate_base_string_length(HawkcContext ctx, AuthorizationHeader header) {

	size_t n = 0;
	n += strlen(HAWK_HEADER_PREFIX);
	n++;
	n += 10; /* header->ts; FIXME: dummy for ts len */
	n++;
	n += header->nonce.len;
	n++;
	n += ctx->method.len;
	n++;
	n += ctx->path.len;
	n++;
	n += ctx->host.len;
	n++;
	n += ctx->port.len;
	n++;

	n++; /* empty body hash FIXME:impl */

	n += header->ext.len;
	n++;
	return n;
}

void hawkc_create_base_string(HawkcContext ctx, AuthorizationHeader header, unsigned char* buf, int *len) {
	char *ptr;
	int n;
	ptr = (char*)buf;

	strncpy(ptr,HAWK_HEADER_PREFIX,strlen(HAWK_HEADER_PREFIX));
	ptr += strlen(HAWK_HEADER_PREFIX);
	*ptr = LF; ptr++;

	n = sprintf(ptr,"%ld",header->ts); ptr += n;
	*ptr = LF; ptr++;

	strncpy(ptr,header->nonce.data,header->nonce.len);
	ptr += header->nonce.len;
	*ptr = LF; ptr++;

	strncpy(ptr,ctx->method.data,ctx->method.len);
	ptr += ctx->method.len;
	*ptr = LF; ptr++;

	strncpy(ptr,ctx->path.data,ctx->path.len);
	ptr += ctx->path.len;
	*ptr = LF; ptr++;

	strncpy(ptr,ctx->host.data,ctx->host.len);
	ptr += ctx->host.len;
	*ptr = LF; ptr++;

	strncpy(ptr,ctx->port.data,ctx->port.len);
	ptr += ctx->port.len;
	*ptr = LF; ptr++;

	/* empty body hash FIXME */
	*ptr = LF; ptr++;

	strncpy(ptr,header->ext.data,header->ext.len);
	ptr += header->ext.len;
	*ptr = LF; ptr++;

	*len = ptr - (char*)buf;
	/* FIXME
	fprintf(stderr,"\n---------------------------\n%.*s\n---------------------------\n" , *len , buf);
	*/
}



/* Lookup 'table' for hex encoding */
/* FIXME: kann weg, oder?
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
*/



int hawkc_fixed_time_equal(unsigned char *lhs, unsigned char * rhs, int len) {

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

