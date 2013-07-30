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
		if( (e = parse_time(ctx,value,&(h->ts))) != HAWKC_OK) {
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

	/* FIXME: avoid sprintf */
	n = sprintf((char*)ptr,"%ld",header->ts); ptr += n;
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
	size_t ts_hmac_len;
	size_t n;
	WwwAuthenticateHeader ah = &(ctx->www_authenticate_header);

	hawkc_create_ts_base_string(ctx,ah,base_buf,&base_len);

	if( (e = hawkc_hmac(ctx, ctx->algorithm, ctx->password.data, ctx->password.len, base_buf, base_len,ctx->ts_hmac,&ts_hmac_len)) != HAWKC_OK) {
		return e;
	}
	n = 4;  /* Hawk */
	if(ah->ts != 0) {
		n += 6; /* blank,ts="" */
		n += hawkc_number_of_digits(ah->ts);
		n += 7; /* ,tsm="" */
		n += ts_hmac_len;
	}
	*required_len = n;
	return HAWKC_OK;
}

void hawkc_www_authenticate_header_set_ts(HawkcContext ctx, time_t ts) {
	ctx->www_authenticate_header.ts = ts;
}

HawkcError hawkc_create_www_authenticate_header(HawkcContext ctx, unsigned char* buf, size_t *len) {

	HawkcError e;
	size_t base_len;
	WwwAuthenticateHeader ah = &(ctx->www_authenticate_header);
	/*
	size_t required_size;
	*/
	/* FIXME: make TS_BASE_BUFFER_SIZE macro and also a clac length function for later */
	unsigned char base_buf[BASE_BUFFER_SIZE];
	unsigned char *base_buf_ptr = base_buf;
	/*
	unsigned char *dyn_base_buf = NULL;
	*/
	size_t n;
	size_t xlen;

	if(ah->ts == 0) {
		*len = 4;
		memcpy(buf,"Hawk",4);
		return HAWKC_OK;
	}

	/*
	 * If the required size exceeds the static base string buffer, allocate
	 * a temporary larger buffer. But only, if the allocation size stays
	 * below HAWKC_REQUIRED_BUFFER_TOO_LARGE limit.
	 */
	/*FIXME
	required_size = hawkc_calculate_base_string_length(ctx,ah);
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
	*/

	/*
	 * Create base string and HMAC.
	 */
	hawkc_create_ts_base_string(ctx,ah,base_buf_ptr,&base_len);

	e = hawkc_hmac(ctx, ctx->algorithm, ctx->password.data, ctx->password.len, base_buf_ptr, base_len,ctx->ts_hmac,&xlen);
	/*
	 * Free dynamic buffer immediately when it is not needed anymore.
	 */
	/*
	if(dyn_base_buf != NULL) {
		hawkc_free(ctx,dyn_base_buf);
		* Prevent dangling pointers *
		dyn_base_buf = NULL;
		base_buf_ptr = base_buf;
	}
*/
	/*
	 * If HMAC generation failed, report error.
	 */
	if(e != HAWKC_OK) {
		/* FIXME log - and in other hmac func with same structure */
		return e;
	}
	/* FIXME: control length, provide func to calculate it! */
	/* FIXME avoid sprintf */
	n = sprintf((char*)buf,"Hawk ts=\"%ld\",tsm=\"%.*s\"," ,
			ah->ts,
			(int)xlen, ctx->ts_hmac);
	/*
	fprintf(stderr,"66=%d , %s\n" , n, buf);
	*/

	*len = n;

	/* FIXME - Remove debug code
	*/
	/*
	fprintf(stderr,"calculated: {%.*s}",xlen, ctx->hmac);
	fprintf(stderr,"got:        {%.*s}", ctx->header_in.mac.len,ctx->header_in.mac.data);
	*/
	fprintf(stderr,"77\n" );

	return HAWKC_OK;
}
