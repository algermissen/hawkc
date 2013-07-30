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

/*
 * Scheme callback for parsing authorization header.
 */
static HawkcError authorization_scheme_handler(HawkcContext ctx,HawkcString scheme,void *data) {
	if((scheme.len != 4) || memcmp(scheme.data,"Hawk",4) != 0) {
		return hawkc_set_error(ctx,
					HAWKC_BAD_SCHEME_ERROR, "Unsupported authentication scheme '%.*s'" , scheme.len,scheme.data);
	}
	return HAWKC_OK;
}

/*
 * Parameter callback for parsing authorization header.
 */
static HawkcError param_handler(HawkcContext ctx,HawkcString key, HawkcString value,void *data) {

	AuthorizationHeader h = (AuthorizationHeader)data;
	if(key.len == 2 && !memcmp(key.data,"id",key.len)) {
		h->id.data = value.data;
		h->id.len = value.len;
	} else if(key.len == 3 && !memcmp(key.data,"mac",key.len)) {
		h->mac.data = value.data;
		h->mac.len = value.len;
	} else if(key.len == 4 && !memcmp(key.data,"hash",key.len)) {
		h->hash.data = value.data;
		h->hash.len = value.len;
	} else if(key.len == 5 && !memcmp(key.data,"nonce",key.len)) {
		h->nonce.data = value.data;
		h->nonce.len = value.len;
	} else if(key.len == 2 && !memcmp(key.data,"ts",key.len)) {
		HawkcError e;
		if( (e = parse_time(ctx,value,&(h->ts))) != HAWKC_OK) {
			return e;
		}
	} else if(key.len == 3 && !memcmp(key.data,"ext",key.len)) {
		h->ext.data = value.data;
		h->ext.len = value.len;
	} else {
		; /* ignore unknown parameter */
	}

	return HAWKC_OK;
}



HawkcError hawkc_parse_authorization_header(HawkcContext ctx, unsigned char *value, size_t len) {
	return hawkc_parse_auth_header(ctx,value,len,authorization_scheme_handler, param_handler,&(ctx->header_in));
}



HawkcError hawkc_validate_hmac(HawkcContext ctx,int *is_valid) {
	HawkcError e;
	size_t len,base_len,required_size;
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
	e = hawkc_hmac(ctx, ctx->algorithm, ctx->password.data, ctx->password.len, base_buf_ptr, base_len,ctx->hmac,&len);
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

	/*
	 * Compare HMACs
	 */
	if(ctx->header_in.mac.len == len && hawkc_fixed_time_equal(ctx->header_in.mac.data,ctx->hmac,len) ) {
		*is_valid = 1;
	} else {
		*is_valid = 0;
	}
	return HAWKC_OK;
}

size_t hawkc_calculate_base_string_length(HawkcContext ctx, AuthorizationHeader header) {

	size_t n = 0;
	n += strlen(HAWK_HEADER_PREFIX);
	n++;
	n += hawkc_number_of_digits(header->ts);
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

void hawkc_create_base_string(HawkcContext ctx, AuthorizationHeader header, unsigned char* buf, size_t *len) {
	unsigned char *ptr;
	size_t n;
	ptr = buf;

	memcpy(ptr,HAWK_HEADER_PREFIX,strlen(HAWK_HEADER_PREFIX));
	ptr += strlen(HAWK_HEADER_PREFIX);
	*ptr = LF; ptr++;

	/* FIXME: avoid sprintf here for cleanliness */
	n = sprintf((char*)ptr,"%ld",header->ts); ptr += n;
	*ptr = LF; ptr++;

	memcpy(ptr,header->nonce.data,header->nonce.len);
	ptr += header->nonce.len;
	*ptr = LF; ptr++;

	memcpy(ptr,ctx->method.data,ctx->method.len);
	ptr += ctx->method.len;
	*ptr = LF; ptr++;

	memcpy(ptr,ctx->path.data,ctx->path.len);
	ptr += ctx->path.len;
	*ptr = LF; ptr++;

	memcpy(ptr,ctx->host.data,ctx->host.len);
	ptr += ctx->host.len;
	*ptr = LF; ptr++;

	memcpy(ptr,ctx->port.data,ctx->port.len);
	ptr += ctx->port.len;
	*ptr = LF; ptr++;

	/* empty body hash FIXME */
	*ptr = LF; ptr++;

	memcpy(ptr,header->ext.data,header->ext.len);
	ptr += header->ext.len;
	*ptr = LF; ptr++;

	*len = ptr - buf;
	/* FIXME
	fprintf(stderr,"\n---------------------------\n%.*s\n---------------------------\n" , *len , buf);
	*/
}

HawkcError hawkc_create_authorization_header(HawkcContext ctx, unsigned char* buf, size_t *len) {

	HawkcError e;
	size_t base_len,required_size;
	unsigned char base_buf[BASE_BUFFER_SIZE];
	unsigned char *base_buf_ptr = base_buf;
	unsigned char *dyn_base_buf = NULL;
	AuthorizationHeader ah = &(ctx->header_out);

	size_t n;
	size_t xlen;

	if(ah->id.len == 0) {
		return hawkc_set_error(ctx, HAWKC_ERROR, "ID not set");
	}
	if(ah->ts == 0) {
		time_t t;
		time( &t );
		ah->ts = t + ctx->offset;
	}
	if(ah->nonce.len == 0) {
		hawkc_generate_nonce(ctx,MAX_NONCE_BYTES,ctx->nonce);
		ah->nonce.data = ctx->nonce;
		ah->nonce.len = MAX_NONCE_HEX_BYTES;
	}
	/*
	fprintf(stderr,"11 _%.*s_\n" , ah->nonce.len , ah->nonce.data);
	*/

	/*
	 * If the required size exceeds the static base string buffer, allocate
	 * a temporary larger buffer. But only, if the allocation size stays
	 * below HAWKC_REQUIRED_BUFFER_TOO_LARGE limit.
	 */
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
	/*
	fprintf(stderr,"22 _%.*s_\n" , ah->nonce.len , ah->nonce.data);
	*/

	/*
	 * Create base string and HMAC.
	 */
	hawkc_create_base_string(ctx,ah,base_buf_ptr,&base_len);
	/*
	fprintf(stderr,"33 _%.*s_\n" , ah->nonce.len , ah->nonce.data);
	*/

	e = hawkc_hmac(ctx, ctx->algorithm, ctx->password.data, ctx->password.len, base_buf_ptr, base_len,ctx->hmac,&xlen);
	/*
	 * Free dynamic buffer immediately when it is not needed anymore.
	 */
	/*
	fprintf(stderr,"44 _%.*s_\n" , ah->nonce.len , ah->nonce.data);
	*/
	if(dyn_base_buf != NULL) {
		hawkc_free(ctx,dyn_base_buf);
		/* Prevent dangling pointers */
		dyn_base_buf = NULL;
		base_buf_ptr = base_buf;
	}
	/*
	fprintf(stderr,"55 _%.*s_\n" , ah->nonce.len , ah->nonce.data);
	*/
	/*
	 * If HMAC generation failed, report error.
	 */
	if(e != HAWKC_OK) {
		return e;
	}
	/* FIXME: control length, provide func to calculate it! */
	/* FIXME: avoid use of sprintf and casts */
	n = sprintf((char*)buf,"Hawk id=\"%.*s\",nonce=\"%.*s\",mac=\"%.*s\",ts=\"%ld\"" ,
			(int)ah->id.len, ah->id.data,
			(int)ah->nonce.len, ah->nonce.data,
			(int)xlen, ctx->hmac,

			ah->ts);
	/*
	fprintf(stderr,"66=%d , %s\n" , n, buf);
	fprintf(stderr,"66.1 _%.*s_\n" , ah->nonce.len , ah->nonce.data);
	*/

	*len = n;

	/* FIXME - Remove debug code
	fprintf(stderr,"calculated: {%.*s}",xlen, ctx->hmac);
	*/
	/*
	fprintf(stderr,"got:        {%.*s}", ctx->header_in.mac.len,ctx->header_in.mac.data);
	fprintf(stderr,"77\n" );
	*/

	return HAWKC_OK;
}


