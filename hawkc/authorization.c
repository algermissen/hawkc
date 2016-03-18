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
		if( (e = hawkc_parse_time(ctx,value,&(h->ts))) != HAWKC_OK) {
			return e;
		}
	} else if(key.len == 3 && !memcmp(key.data,"ext",key.len)) {
		h->ext.data = value.data;
		h->ext.len = value.len;
	} else if(key.len == 3 && !memcmp(key.data,"app",key.len)) {
		h->app.data = value.data;
		h->app.len = value.len;
	} else if(key.len == 3 && !memcmp(key.data,"dlg",key.len)) {
		h->dlg.data = value.data;
		h->dlg.len = value.len;
	} else {
		; /* ignore unknown parameter */
	}

	return HAWKC_OK;
}


/*
 * Parse an authorization header. Using the internal auth header parser with the
 * appropriate callbacks.
 */
HawkcError hawkc_parse_authorization_header(HawkcContext ctx, unsigned char *value, size_t len) {
	return hawkc_parse_auth_header(ctx,value,len,authorization_scheme_handler, param_handler,&(ctx->header_in));
}



/*
 * Calculate the number of bytes needed to store the base string.
 */
size_t hawkc_calculate_base_string_length(HawkcContext ctx, AuthorizationHeader header) {

	size_t n = 0;
	n += strlen(HAWK_HEADER_PREFIX);
	n++; /* 1 for \n */
	n += hawkc_number_of_digits(header->ts);
	n++; /* 1 for \n */
	n += header->nonce.len;
	n++; /* 1 for \n */
	n += ctx->method.len;
	n++; /* 1 for \n */
	n += ctx->path.len;
	n++; /* 1 for \n */
	n += ctx->host.len;
	n++; /* 1 for \n */
	n += ctx->port.len;
	n++; /* 1 for \n */

	n++; /* Body hash always empty, but 1 for \n. See https://github.com/algermissen/hawkc/issues/1 */

	n += header->ext.len;
	n++; /* 1 for \n */
	if( header->app.len > 0) {
		n += header->app.len;
		n++; /* 1 for \n */
		n += header->dlg.len;
		n++; /* 1 for \n */
        }
	return n;
}

/*
 * Create the base string for HMAC signature generation.
 */
void hawkc_create_base_string(HawkcContext ctx, AuthorizationHeader header, unsigned char* buf, size_t *len) {
	unsigned char *ptr;
	size_t n;
	ptr = buf;

	memcpy(ptr,HAWK_HEADER_PREFIX,strlen(HAWK_HEADER_PREFIX));
	ptr += strlen(HAWK_HEADER_PREFIX);
	*ptr = LF; ptr++;

	n = hawkc_ttoa(ptr,header->ts); ptr += n;
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

	/* Body hash always empty. See https://github.com/algermissen/hawkc/issues/1 */
	*ptr = LF; ptr++;

	memcpy(ptr,header->ext.data,header->ext.len);
	ptr += header->ext.len;
	*ptr = LF; ptr++;

	if(header->app.len > 0) {
		memcpy(ptr,header->app.data,header->app.len);
		ptr += header->app.len;
		*ptr = LF; ptr++;
		memcpy(ptr,header->dlg.data,header->dlg.len);
		ptr += header->dlg.len;
		*ptr = LF; ptr++;
	}

	*len = ptr - buf;
	/* FIXME
	fprintf(stderr,"\n---------------------------\n%.*s\n---------------------------\n" , *len , buf);
	*/
}

/*
 * Calculate the number of bytes necessary to store the authorization header value we would
 * generate from the context's header_out struct.
 *
 * This will set timestamp and nonce internally if they have not yet been set
 * for this context.
 *
 * This function will then generate the base string internally and calculate the
 * HMAC signature. This must all be done here instead of the actual generation function
 * because otherwise we would not know the length.
 */
HawkcError hawkc_calculate_authorization_header_length(HawkcContext ctx, size_t *required_len) {

		HawkcError e;
		size_t base_len,required_size;
		unsigned char base_buf[BASE_BUFFER_SIZE];
		unsigned char *base_buf_ptr = base_buf;
		unsigned char *dyn_base_buf = NULL;
		AuthorizationHeader ah = &(ctx->header_out);

		size_t n;

		/*
		 * ID is required to be set by caller.
		 */
		if(ah->id.len == 0) {
			return hawkc_set_error(ctx, HAWKC_ERROR, "ID not set");
		}
		/*
		 * If the caller has not yet supplied a timestamp, we do that
		 * here. Otherwise we cannot generate the base string.
		 */
		if(ah->ts == 0) {
			time_t t;
			time( &t );
			ah->ts = t + ctx->offset;
		}
		/*
		 * If the caller has not yet supplied a nonce, we do that
		 * here. Otherwise we cannot generate the base string.
		 */
		if(ah->nonce.len == 0) {
			hawkc_generate_nonce(ctx,MAX_NONCE_BYTES,ctx->nonce.data);
			ctx->nonce.len = MAX_NONCE_HEX_BYTES;
			ah->nonce.data = ctx->nonce.data;
			ah->nonce.len = ctx->nonce.len;
		}

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
			if( (dyn_base_buf = (unsigned char *)hawkc_calloc(ctx,1,required_size)) == NULL) {
				return hawkc_set_error(ctx,
						HAWKC_NO_MEM, "Unable to allocate %d bytes for dynamic base buffer" , required_size);
			}
			base_buf_ptr = dyn_base_buf;
		}

		/*
		 * Create base string and HMAC.
		 */
		hawkc_create_base_string(ctx,ah,base_buf_ptr,&base_len);

		e = hawkc_hmac(ctx, ctx->algorithm, ctx->password.data, ctx->password.len, base_buf_ptr, base_len,ctx->hmac.data,&(ctx->hmac.len));
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
		 * Point header's mac struct to generated hmac.
		 */

		ah->mac.data = ctx->hmac.data;
		ah->mac.len = ctx->hmac.len;

		n = 5; /* 'Hawk ' */


		n += 5; /* id="" */
		n += ah->id.len;

		n++; /* , */
		n += 8; /* nonce="" */
		n += ah->nonce.len;

		n++; /* , */
		n += 6; /* mac="" */
		n += ah->mac.len;

		n++; /* , */
		n += 5; /* ts="" */
		n += hawkc_number_of_digits(ah->ts);

		if(ah->ext.len > 0) {
			n++; /* , */
			n += 6; /* ext="" */
			n += ah->ext.len;
		}

		if(ah->app.len > 0) {
			n++; /* , */
			n += 6; /* app="" */
			n += ah->app.len;
		}
		if(ah->dlg.len > 0) {
			n++; /* , */
			n += 6; /* dlg="" */
			n += ah->dlg.len;
		}

		*required_len = n;

		return HAWKC_OK;
}

/*
 * Create an authorization header value from the internal state of the context and
 * its header_out struct.
 * Caller is responsible to call hawkc_calculate_authorization_header_length() first
 * to prepare the context and calculate necessary buffer size.
 */
HawkcError hawkc_create_authorization_header(HawkcContext ctx, unsigned char* buf, size_t *len) {
	AuthorizationHeader ah = &(ctx->header_out);
	unsigned char *p = buf;
	size_t n;

	/* FIXME enforce length calc func here. See https://github.com/algermissen/hawkc/issues/6 */

	memcpy(p,"Hawk id=\"",9); p += 9;
	memcpy(p,ah->id.data,ah->id.len); p += ah->id.len;

	memcpy(p,"\",nonce=\"",9); p += 9;
	memcpy(p,ah->nonce.data,ah->nonce.len); p += ah->nonce.len;

	memcpy(p,"\",mac=\"",7); p += 7;
	memcpy(p,ah->mac.data,ah->mac.len); p += ah->mac.len;

	memcpy(p,"\",ts=\"",6); p += 6;
	n = hawkc_ttoa(p,ah->ts); p+= n;

	/* Body hash always empty. See https://github.com/algermissen/hawkc/issues/1 */

	if(ah->ext.len > 0) {
		memcpy(p,"\",ext=\"",7); p += 7;
		memcpy(p,ah->ext.data,ah->ext.len); p += ah->ext.len;
	}
	if(ah->app.len > 0) {
		memcpy(p,"\",app=\"",7); p += 7;
		memcpy(p,ah->app.data,ah->app.len); p += ah->app.len;
	}
	if(ah->dlg.len > 0) {
		memcpy(p,"\",dlg=\"",7); p += 7;
		memcpy(p,ah->dlg.data,ah->dlg.len); p += ah->dlg.len;
	}

	/* This closes the last parameter */
	memcpy(p,"\"",1); p += 1;

	*len = p-buf;

	return HAWKC_OK;
}

/*
 * Validate the HMAC of the context's header_in struct.
 * This assumes a header has been parsed and thus that the
 * header_in struct has been populated. It is also
 * required that the caller has set password and algorithm
 * on the context, as well as the reuqest parameters that
 * go into the base string (method,path,host,port)
 *
 * This function will then calculate an hmac from this data
 * and compare it to the hmac value parsed into header_in
 * struct.
 */
HawkcError hawkc_validate_hmac(HawkcContext ctx,int *is_valid) {
	HawkcError e;
	/* FIXME better names */
	size_t base_len,required_size;
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
		if( (dyn_base_buf = (unsigned char *)hawkc_calloc(ctx,1,required_size)) == NULL) {
			return hawkc_set_error(ctx,
					HAWKC_NO_MEM, "Unable to allocate %d bytes for dynamic base buffer" , required_size);
		}
		base_buf_ptr = dyn_base_buf;
	}

	/*
	 * Create base string and HMAC.
	 */
	hawkc_create_base_string(ctx,&(ctx->header_in),base_buf_ptr,&base_len);
	e = hawkc_hmac(ctx, ctx->algorithm, ctx->password.data, ctx->password.len, base_buf_ptr, base_len,ctx->hmac.data,&(ctx->hmac.len));
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
	if(ctx->header_in.mac.len == ctx->hmac.len && hawkc_fixed_time_equal(ctx->header_in.mac.data,ctx->hmac.data,ctx->hmac.len) ) {
		*is_valid = 1;
	} else {
		*is_valid = 0;
	}
	return HAWKC_OK;
}



