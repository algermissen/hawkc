#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>
#include "hawkc.h"
#include "common.h"
#include "crypto.h"

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
 * Must correspond to the array of codes in hawkc.h
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

	ctx->hmac.data = ctx->hmac_buffer;
	ctx->ts_hmac.data = ctx->ts_hmac_buffer;
	ctx->nonce.data = ctx->nonce_buffer;

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


void hawkc_context_set_clock_offset(HawkcContext ctx,int offset) {
	ctx->offset = offset;
}

void hawkc_context_set_password(HawkcContext ctx,unsigned char *password, size_t len) {
	ctx->password.data = password;
	ctx->password.len = len;
}

void hawkc_context_set_algorithm(HawkcContext ctx,HawkcAlgorithm algorithm) {
	ctx->algorithm = algorithm;
}

void hawkc_context_set_id(HawkcContext ctx,unsigned char *id, size_t len) {
	ctx->header_out.id.data = id;
	ctx->header_out.id.len = len;
}

void hawkc_context_set_ext(HawkcContext ctx,unsigned char *ext, size_t len) {
	ctx->header_out.ext.data = ext;
	ctx->header_out.ext.len = len;
}

void hawkc_context_set_method(HawkcContext ctx,unsigned char *method, size_t len) {
	ctx->method.data = method;
	ctx->method.len = len;
}

void hawkc_context_set_path(HawkcContext ctx,unsigned char *path, size_t len) {
	ctx->path.data = path;
	ctx->path.len = len;
}

void hawkc_context_set_host(HawkcContext ctx,unsigned char *host, size_t len) {
	ctx->host.data = host;
	ctx->host.len = len;
}

void hawkc_context_set_port(HawkcContext ctx,unsigned char *port, size_t len) {
	ctx->port.data = port;
	ctx->port.len = len;
}

HawkcAlgorithm hawkc_algorithm_by_name(char *name, size_t len) {
	if (len == strlen(HAWKC_SHA_1->name) && strncmp(name, HAWKC_SHA_1->name, len) == 0) {
		return HAWKC_SHA_1;
	} else if (len == strlen(HAWKC_SHA_256->name) && strncmp(name, HAWKC_SHA_256->name, len) == 0) {
		return HAWKC_SHA_256;
	} else {
		return NULL;
	}
}

int hawkc_fixed_time_equal(unsigned char *lhs, unsigned char * rhs, size_t len) {
	int equal = 1;
	size_t i;
	/* FIXME: try to remove casts - I fail to see why they are needed. Implicit cast by op?*/
	for(i = 0; (int)i<(int)len;i++) {
		if(lhs[i] != rhs[i]) {
			equal = 0;
		}
	}
	return equal;
}



/* Lookup 'table' for hex encoding */
static const char hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'a', 'b', 'c', 'd', 'e', 'f' };
void hawkc_bytes_to_hex(const unsigned char *bytes, size_t len, unsigned char *buf) {
	size_t j;
	for (j = 0; j < len; j++) {
		int v;
		v = bytes[j] & 0xFF;
		buf[j * 2] = hex[v >> 4];
		buf[j * 2 + 1] = hex[v & 0x0F];
	}
}

/* FIXME: try to retval change to size_t */
unsigned int hawkc_number_of_digits(time_t t) {
	unsigned int count=0;
	while(t!=0) {
		t/=10;
		++count;
	}
	return count;
}

HawkcError hawkc_parse_time(HawkcContext ctx, HawkcString ts, time_t *tp) {
	unsigned char *p = ts.data;
	time_t t = 0;
	int i = 0;
	while(i < ts.len) {
		if(!isdigit(*p)) {
			return hawkc_set_error(ctx,
					HAWKC_TIME_VALUE_ERROR, "'%.*s' is not a valid integer" , ts.len,ts.data);
		}
		t = (t * 10) + hawkc_my_digittoint(*p);

		i++;
		p++;
	}

	*tp = t;
	return HAWKC_OK;
}

/* Supplying our own because digittoint() was missing in some compile environments. */
int hawkc_my_digittoint(char ch) {
  int d = ch - '0';
  if ((unsigned) d < 10) {
    return d;
  }
  d = ch - 'a';
  if ((unsigned) d < 6) {
    return d + 10;
  }
  d = ch - 'A';
  if ((unsigned) d < 6) {
    return d + 10;
  }
  return -1;
}

/*
 * Supplying our own 'itoa' because some environments lacked this and related functions
 * strreverse and hawkc_ttoa provide the desired functionality.
 */
static void strreverse(unsigned char* begin, unsigned char* end) {
	unsigned char aux;
	while(end>begin) {
		aux=*end, *end--=*begin, *begin++=aux;
	}

}

size_t hawkc_ttoa(unsigned char* buf, time_t value) {

	static unsigned char num[] = "0123456789";
	unsigned char* wstr=buf;
	int sign;
	div_t res;

	if ((sign=value) < 0) value = -value;

	// Conversion. Number is reversed.

	do {
		res = div(value,10);
		*wstr++ = num[res.rem];
		value=res.quot;
	}while(value);
	if(sign<0) *wstr++='-';
	// Reverse string

	strreverse(buf,wstr-1);
	return wstr-buf;

}





