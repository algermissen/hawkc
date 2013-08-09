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

static HawkcError www_authenticate_scheme_handler(HawkcContext ctx,HawkcString scheme,void *data) {
	if((scheme.len != 4) || memcmp(scheme.data,"Hawk",4) != 0) {
		return hawkc_set_error(ctx,
					HAWKC_BAD_SCHEME_ERROR, "Unsupported authentication scheme '%.*s'" , scheme.len,scheme.data);
	}
	return HAWKC_OK;
}

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


HawkcError hawkc_parse_www_authenticate_header(HawkcContext ctx, unsigned char *value, size_t len) {
	return hawkc_parse_auth_header(ctx,value,len,www_authenticate_scheme_handler, www_authenticate_param_handler,&(ctx->www_authenticate_header));
}



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


HawkcError hawkc_calculate_www_authenticate_header_length(HawkcContext ctx, size_t *required_len) {
	HawkcError e;
	unsigned char base_buf[TS_BASE_BUFFER_SIZE];
	size_t base_len;
	size_t n;
	WwwAuthenticateHeader ah = &(ctx->www_authenticate_header);

	if(ah->ts == 0) {
		*required_len = 4;
		return HAWKC_OK;
	}

	hawkc_create_ts_base_string(ctx,ah,base_buf,&base_len);

	if( (e = hawkc_hmac(ctx, ctx->algorithm, ctx->password.data, ctx->password.len, base_buf, base_len,ctx->ts_hmac.data,&(ctx->ts_hmac.len) )) != HAWKC_OK) {
		return e;
	}
	ah->tsm.data = ctx->ts_hmac.data;
	ah->tsm.len = ctx->ts_hmac.len;
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

void hawkc_www_authenticate_header_set_ts(HawkcContext ctx, time_t ts) {
	ctx->www_authenticate_header.ts = ts;
}

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

