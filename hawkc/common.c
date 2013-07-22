#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>
#include "hawkc.h"
#include "common.h"
#include "crypto.h"

static const char *HAWK_HEADER_PREFIX = "hawk.1.header";
static const char LF = '\n';


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
		"Not a unix time value" , /* HAWKC_TIME_VALUE_ERROR */
		"Unable to allocate memory", /* HAWKC_NO_MEM */
		"Required buffer size is too large", /* HAWKC_REQUIRED_BUFFER_TOO_LARGE */
		"Unspecific error", /* HAWKC_ERROR */
		NULL
};

char* hawkc_strerror(HawkcError e) {
	assert(e >= HAWKC_OK && e <= HAWKC_ERROR);
	return error_strings[e];
}

HawkcError hawkc_set_error(HawkcContext ctx, HawkcError e, const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vsnprintf(ctx->error_string, sizeof(ctx->error_string), fmt, args);
	va_end(args);
	ctx->error = e;
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
	ctx->error = HAWKC_OK;
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
	int len,base_len,required_size;
	unsigned char base_buf[BASE_BUFFER_SIZE];
	unsigned char *base_buf_ptr = base_buf;
	unsigned char *dyn_base_buf = NULL;

	/*
	 * If the required size exceeds the static base string buffer, allocate
	 * a temporary larger buffer. But only, if the allocation size stays
	 * below HAWKC_REQUIRED_BUFFER_TOO_LARGE limit.
	 */
	required_size = hawkc_calculate_base_string_length(ctx,&(ctx->header_in));
	if(required_size > sizeof(base_buf)) {
		if(required_size > MAX_DYN_BASE_BUFFER_SIZE) {
			return hawkc_set_error(ctx,
					HAWKC_REQUIRED_BUFFER_TOO_LARGE, "Required base string buffer of %d bytes exceeds MAX_DYN_BASE_BUFFER_SIZE" , required_size);
		}
		if( (dyn_base_buf = hawkc_calloc(ctx,1,required_size)) == NULL) {
			return hawkc_set_error(ctx,
					HAWKC_NO_MEM, "Unable to allocate %d bytes for dynamic base buffer" , required_size);
		}
		base_buf_ptr = dyn_base_buf;
	}

	/*
	 * Create base string and HMAC.
	 */
	hawkc_create_base_string(ctx,&(ctx->header_in),base_buf_ptr,&base_len);
	e = hawkc_hmac(ctx, algorithm, password, password_len, base_buf_ptr, base_len,ctx->hmac,&len);
	/*
	 * Free dynamic buffer immediately when it is not needed anymore.
	 */
	if(dyn_base_buf != NULL) {
		hawkc_free(ctx,dyn_base_buf);
		/* Prevent dangling pointers */
		dyn_base_buf = NULL;
		base_buf_ptr = base_buf;
	}
	/*
	 * If HMAC generation failed, report error.
	 */
	if(e != HAWKC_OK) {
		return e;
	}

	/* FIXME - Remove debug code
	fprintf(stderr,"calculated: {%.*s}",len, ctx->hmac);
	fprintf(stderr,"got:        {%.*s}", ctx->header_in.mac.len,ctx->header_in.mac.data);
	*/

	/*
	 * Compare HMACs
	 */
	if(ctx->header_in.mac.len == len && hawkc_fixed_time_equal((unsigned char*)ctx->header_in.mac.data,ctx->hmac,len)) {
		*is_valid = 1;
	} else {
		*is_valid = 0;
	}
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
	n += 10; /* UNIX timestamp is 10 chars max. */
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

	n++; /* empty body hash See https://github.com/algermissen/hawkc/issues/1 */

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
