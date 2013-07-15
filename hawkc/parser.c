#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "hawkc.h"
#include "common.h"

static void consume_ows(HawkcContext ctx, char *s, size_t len, size_t *n);
static HawkcError parse_token(HawkcContext ctx, char *s, size_t len, HawkcString *ptoken, size_t *n);
static HawkcError parse_quoted_text(HawkcContext ctx, char *s, size_t len, HawkcString *ptoken, size_t *n);
static HawkcError parse_time(HawkcContext ctx, HawkcString ts, time_t *tp);

#define DQUOTE '"';
#define BACKSLASH '\\';

static HawkcError scheme_handler(HawkcContext ctx,HawkcString scheme,void *data) {
	if((scheme.len != 4) || strncmp(scheme.data,"Hawk",4) != 0) {
		return hawkc_set_error(ctx, __FILE__, __LINE__, NO_CRYPTO_ERROR,
					HAWKC_PARSE_ERROR, "Unsupported authentication scheme '%.*s'" , scheme.len,scheme.data);
	}
	return HAWKC_OK;
}
static HawkcError param_handler(HawkcContext ctx,HawkcString key, HawkcString value,void *data) {

	AuthorizationHeader h = (AuthorizationHeader)data;
	if(key.len == 2 && !strncmp(key.data,"id",key.len)) {
		h->id.data = value.data;
		h->id.len = value.len;
	} else if(key.len == 3 && !strncmp(key.data,"mac",key.len)) {
		h->mac.data = value.data;
		h->mac.len = value.len;
	} else if(key.len == 4 && !strncmp(key.data,"hash",key.len)) {
		h->hash.data = value.data;
		h->hash.len = value.len;
	} else if(key.len == 5 && !strncmp(key.data,"nonce",key.len)) {
		h->nonce.data = value.data;
		h->nonce.len = value.len;
	} else if(key.len == 2 && !strncmp(key.data,"ts",key.len)) {
		HawkcError e;
		if( (e = parse_time(ctx,value,&(h->ts))) != HAWKC_OK) {
			return e;
		}
	} else if(key.len == 3 && !strncmp(key.data,"ext",key.len)) {
		h->ext.data = value.data;
		h->ext.len = value.len;
	} else {
		; /* ignore unknown parameter */
	}

	return HAWKC_OK;
}

/*
 * Parse a unix time value from a string. If the string is not parsable, this function returns HAWKC_TIME_PARSE_ERROR.
 */
HawkcError parse_time(HawkcContext ctx, HawkcString ts, time_t *tp) {
	char *p = ts.data;
	time_t t = 0;
	int i = 0;
	while(i < ts.len) {
		if(!isdigit(*p)) {
			return hawkc_set_error(ctx, __FILE__, __LINE__, NO_CRYPTO_ERROR,
					HAWKC_TIME_VALUE_ERROR, "'%.*s' is not a valid integer" , ts.len,ts.data);
		}
		t = (t * 10) + digittoint(*p);

		i++;
		p++;
	}

	*tp = t;
	return HAWKC_OK;
}


HawkcError hawkc_parse_authorization_header(HawkcContext ctx, char *value, size_t len) {
	HawkcError e;

	/* FIXME: check and clear existing buffer and members */
	/* FIXME: use better approach...
	assert(ctx->header_in.buf == NULL);
	assert(ctx->header_in.buf_len == 0);
	assert(ctx->header_in.buf_pos == NULL);

	ctx->header_in.buf = hawkc_alloc(ctx,len);
	* FIXME check null *
	ctx->header_in.buf_len = len;
	ctx->header_in.buf_pos = ctx->header_in.buf;
	*/


	if( (e = hawkc_parse_auth_header(ctx,value,len,scheme_handler, param_handler,&(ctx->header_in))) != HAWKC_OK) {
		return e;
	}
	return HAWKC_OK;

}



HawkcError hawkc_parse_auth_header(HawkcContext ctx, char *value, size_t len, HawkcSchemeHandler scheme_handler, HawkcParamHandler param_handler, void *data) {

	HawkcError e;
	char *p = value;
	size_t remain = len;
	size_t n;
	HawkcString scheme;

	if( (e = parse_token(ctx,p,len,&scheme,&n)) != HAWKC_OK) {
		return e;
	}
	p += n;
	remain -= n;

	if( (e = scheme_handler(ctx,scheme,data)) != HAWKC_OK) {
			return e;
	}

	consume_ows(ctx,p,remain,&n);
	p += n;
	remain -= n;
	if(remain <= 0) {
		/* Scheme-only is ok */
		return HAWKC_OK;
	}

	while(remain > 0) {
		HawkcString key, value;
		if( (e = parse_token(ctx,p,remain,&key,&n)) != HAWKC_OK) {
			return e;
		}
		p += n;
		remain -= n;
		consume_ows(ctx,p,remain,&n);
		p += n;
		remain -= n;
		if(*p != '=') {
			return hawkc_set_error(ctx, __FILE__, __LINE__, NO_CRYPTO_ERROR,
								HAWKC_PARSE_ERROR, "Missing '=' for parameter value");
		}
		/* consume '=' */
		p++;
		remain--;

		consume_ows(ctx,p,remain,&n);
		p += n;
		remain -= n;

		if(*p == '"') {
			if( (e = parse_quoted_text(ctx,p,remain,&value,&n)) != HAWKC_OK) {
					return e;
			}
			p += n;
			remain -= n;
		} else {
			if( (e = parse_token(ctx,p,remain,&value,&n)) != HAWKC_OK) {
					return e;
			}
			p += n;
			remain -= n;
		}

		consume_ows(ctx,p,remain,&n);
		p += n;
		remain -= n;

		if( (e = param_handler(ctx,key,value,data)) != HAWKC_OK) {
					return e;
			}


		if(remain > 0) {
			if(*p == ',') {
				p++;
				remain--;
				consume_ows(ctx,p,remain,&n);
				p += n;
				remain -= n;
			} else {
				return hawkc_set_error(ctx, __FILE__, __LINE__, NO_CRYPTO_ERROR,
								HAWKC_PARSE_ERROR, "',' required after parameter value");
			}
		}
	}
	return HAWKC_OK;
}
#define IS_TOKEN(c) ( \
	   ( (c) >= '0' && (c) <= '9') \
	|| ( (c) >= 'A' && (c) <= 'Z') \
	|| ( (c) >= '^' && (c) <= 'z') \
	|| ( (c) >= '#' && (c) <= '\'') \
	|| ( (c) == '!') || ((c) == '*') || ((c) == '+') || ((c) == '-') || ((c) == '.') )

#define IS_SPACE(c) ( ((c) == ' ') || ((c) == '\t') )

/**
  * Parses a token as defined by
  * http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging#section-3.2.6
  */
HawkcError parse_token(HawkcContext ctx, char *s, size_t len, HawkcString *ptoken, size_t *n) {
	char *p = s;
	size_t i = 0;
	ptoken->data = s;
	ptoken->len = 0;

	while(i < len && IS_TOKEN(*p) ) {
		i++;
		p++;
	}
	if(i == 0) {
		return hawkc_set_error(ctx, __FILE__, __LINE__, NO_CRYPTO_ERROR,
						HAWKC_PARSE_ERROR, "Token must have at least one character");
	}
	*n = i;
	ptoken->len = i;
	return HAWKC_OK;
}

HawkcError parse_quoted_text(HawkcContext ctx, char *s, size_t len, HawkcString *ptoken, size_t *n) {
	char *p = s;
	size_t i = 0;


	if(len == 0 || *p != '"') {
		return hawkc_set_error(ctx, __FILE__, __LINE__, NO_CRYPTO_ERROR,
						HAWKC_PARSE_ERROR, "Quoted text must start with '\"'");
	}
	/* consume " */
	p++;
	i++;


	ptoken->data = p;
	ptoken->len = 0;

	while(i < len && *p != '"') {
		if(*p == '\\') {
			if(i+1 == len) {
				return hawkc_set_error(ctx, __FILE__, __LINE__, NO_CRYPTO_ERROR,
						HAWKC_PARSE_ERROR, "\\ at end of text");
			}
			p++;
			i++;
			ptoken->len++;
		}
		p++;
		i++;
		ptoken->len++;
	}
	if(i >= len) {
		return hawkc_set_error(ctx, __FILE__, __LINE__, NO_CRYPTO_ERROR,
						HAWKC_PARSE_ERROR, "Quoted text must end with '\"'");
	}

	/* consume " */
	p++;
	i++;

	*n = i;
	return HAWKC_OK;
}

void consume_ows(HawkcContext ctx, char *s, size_t len, size_t *n) {
	size_t i = 0;
	char *p = s;

	while(i < len && IS_SPACE(*p)) {
		i++;
		p++;
	}
	*n = i;
}


