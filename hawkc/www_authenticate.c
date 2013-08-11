#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>
#include "hawkc.h"
#include "common.h"
#include "crypto.h"

static const char *HAWK_TS_PREFIX = "hawk.1.ts";
static const char LF = '\n';

/*
 * Scheme callback for parsing www-authenticate header.
 */
static HawkcError www_authenticate_scheme_handler(HawkcContext ctx,HawkcString scheme,void *data) {
	if((scheme.len != 4) || memcmp(scheme.data,"Hawk",4) != 0) {
		return hawkc_set_error(ctx,
					HAWKC_BAD_SCHEME_ERROR, "Unsupported authentication scheme '%.*s'" , scheme.len,scheme.data);
	}
	return HAWKC_OK;
}

/*
 * Parameter callback for parsing www-authenticate header.
 */
static HawkcError www_authenticate_param_handler(HawkcContext ctx,HawkcString key, HawkcString value,void *data) {

	WwwAuthenticateHeader h = (WwwAuthenticateHeader)data;
	if(key.len == 3 && !memcmp(key.data,"tsm",key.len)) {
		h->tsm.data = value.data;
		h->tsm.len = value.len;
	} else if(key.len == 2 && !memcmp(key.data,"ts",key.len)) {
		HawkcError e;
		if( (e = hawkc_parse_time(ctx,value,&(h->ts))) != HAWKC_OK) {
			return e;
		}
	} else {
		; /* ignore unknown parameter */
	}

	return HAWKC_OK;
}

/*
 * Parse an www-authenticate header. Using the internal auth header parser with the
 * appropriate callbacks.
 */
HawkcError hawkc_parse_www_authenticate_header(HawkcContext ctx, unsigned char *value, size_t len) {
	return hawkc_parse_auth_header(ctx,value,len,www_authenticate_scheme_handler, www_authenticate_param_handler,&(ctx->www_authenticate_header));
}


/*
 * Create the timestamp-WWW-Authenticate header signature base string.
 */
void hawkc_create_ts_base_string(HawkcContext ctx, WwwAuthenticateHeader header, unsigned char* buf, size_t *len) {
	unsigned char *ptr;
	size_t n;
	ptr = buf;

	memcpy(ptr,HAWK_TS_PREFIX,strlen(HAWK_TS_PREFIX));
	ptr += strlen(HAWK_TS_PREFIX);
	*ptr = LF; ptr++;

	n = hawkc_ttoa(ptr,header->ts); ptr += n;
	*ptr = LF; ptr++;

	*len = ptr - buf;
	/* FIXME
	fprintf(stderr,"\n-TS BASE STRING--------------------------\n%.*s\n---------------------------\n" , *len , buf);
	*/
}

/*
 * Calculate buffer size necessary to store WWW-authenticate header value generated from current
 * state of context and its www_authenticte_header struct.
 *
 * If the internal WWW-Authentiacte header struct contains a time stamp,
 * this will generate the base string internally because that is necessary to calculate the
 * header value length. Otherwise the returned header value will just be "Hawk".
 *
 * FIXME: This might change when we add realms.
 * See https://github.com/algermissen/hawkc/issues/11
 */
HawkcError hawkc_calculate_www_authenticate_header_length(HawkcContext ctx, size_t *required_len) {
	HawkcError e;
	unsigned char base_buf[TS_BASE_BUFFER_SIZE];
	size_t base_len;
	size_t n;
	WwwAuthenticateHeader ah = &(ctx->www_authenticate_header);

	/*
	 * For WWW-Authenticate: Hawk headers.
	 */
	if(ah->ts == 0) {
		*required_len = 4;
		return HAWKC_OK;
	}

	/*
	 * Create base string - this has a fixed max size right now because it only contains time and tsm,
	 * but this might change when we add realms.
	 * See https://github.com/algermissen/hawkc/issues/11
	 *
	 * If we make this somewhat dynamic, we need a strategy for the base string like in the authorization
	 * header base string generation (with fixed and optional dynamic buffer with max-size checking)
	 */
	hawkc_create_ts_base_string(ctx,ah,base_buf,&base_len);

	/*
	 * Create signature.
	 */
	if( (e = hawkc_hmac(ctx, ctx->algorithm, ctx->password.data, ctx->password.len, base_buf, base_len,ctx->ts_hmac.data,&(ctx->ts_hmac.len) )) != HAWKC_OK) {
		return e;
	}

	/*
	 * Point header struct HMAC struct to generated HMAC in context.
	 */
	ah->tsm.data = ctx->ts_hmac.data;
	ah->tsm.len = ctx->ts_hmac.len;
	/*
	 * Calculate the actual size.
	 */
	n = 4;  /* Hawk */
	if(ah->ts != 0) {
		n += 6; /* blank,ts="" */
		n += hawkc_number_of_digits(ah->ts);
		n += 7; /* ,tsm="" */
		n += ah->tsm.len;
	}
	*required_len = n;
	return HAWKC_OK;
}

/*
 * Set the timestamp value.
 */
void hawkc_www_authenticate_header_set_ts(HawkcContext ctx, time_t ts) {
	ctx->www_authenticate_header.ts = ts;
}

/*
 * Create a WWW-authenticate header value from the internal state of the context and
 * its www_authenticate_header struct.
 * Caller is responsible to call hawkc_calculate_www_authenticate_header_length() first
 * to prepare the context and calculate necessary buffer size.
 */
HawkcError hawkc_create_www_authenticate_header(HawkcContext ctx, unsigned char* buf, size_t *len) {

	WwwAuthenticateHeader ah = &(ctx->www_authenticate_header);
	unsigned char *p = buf;
	size_t n;

	if(ah->ts == 0) {
		*len = 4;
		memcpy(buf,"Hawk",4);
		return HAWKC_OK;
	}

	memcpy(p,"Hawk ts=\"",9); p += 9;
	n = hawkc_ttoa(p,ah->ts); p+= n;
	memcpy(p,"\",tsm=\"",7); p += 7;
	memcpy(p,ah->tsm.data,ah->tsm.len); p += ah->tsm.len;
	memcpy(p,"\"",1); p += 1;

	*len = p-buf;

	return HAWKC_OK;
}

