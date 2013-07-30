#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "hawkc.h"
#include "common.h"

#define DQUOTE '"';
#define BACKSLASH '\\';

/*
 * Determine whether a given character is a token character according to
 * http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging#section-3.2.6
 */
#define IS_TOKEN(c) ( \
	   ( (c) >= '0' && (c) <= '9') \
	|| ( (c) >= 'A' && (c) <= 'Z') \
	|| ( (c) >= '^' && (c) <= 'z') \
	|| ( (c) >= '#' && (c) <= '\'') \
	|| ( (c) == '!') || ((c) == '*') || ((c) == '+') || ((c) == '-') || ((c) == '.') )

/*
 * Determine whether a given character is a space character according to
 * http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging#section-3.2.6
 */
#define IS_SPACE(c) ( ((c) == ' ') || ((c) == '\t') )

/*
 * Parse optional whitespace from string s with length len and store
 * number of bytes read in n;
 */
static void consume_ows(HawkcContext ctx, unsigned char *s, size_t len, size_t *n) {
	size_t i = 0;
	unsigned char *p = s;

	while(i < len && IS_SPACE(*p)) {
		i++;
		p++;
	}
	*n = i;
}
/**
  * Parses a token as defined by
  * http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging#section-3.2.6
  */
static HawkcError parse_token(HawkcContext ctx, unsigned char *s, size_t len, HawkcString *ptoken, size_t *n) {
	unsigned char *p = s;
	size_t i = 0;
	ptoken->data = s;
	ptoken->len = 0;

	while(i < len && IS_TOKEN(*p) ) {
		i++;
		p++;
	}
	if(i == 0) {
		return hawkc_set_error(ctx, HAWKC_PARSE_ERROR, "Token must have at least one character");
	}
	*n = i;
	ptoken->len = i;
	return HAWKC_OK;
}

/*
 * Parse quoted string from string s with length len and store
 * number of bytes read in n; Store the string read in
 * ptoken.
 *
 * Escape characters will not be stripped. For example, if
 * the parsed string s contains "he said: \"Wow!\"" ptoken will be set
 * to contain he said: \"Wow!\".
 *
 * Removing the quotes would make it necessary to make a copy
 * of the parsed string and we want to avoid that.
 */
static HawkcError parse_quoted_text(HawkcContext ctx, unsigned char *s, size_t len, HawkcString *ptoken, size_t *n) {
	unsigned char *p = s;
	size_t i = 0;

	if(len == 0 || *p != '"') {
		return hawkc_set_error(ctx, HAWKC_PARSE_ERROR, "Quoted text must start with '\"'");
	}
	/* consume starting " */
	p++;
	i++;

	ptoken->data = p;
	ptoken->len = 0;

	/*
	 * Consume tokens as long as we have some
	 */
	while(i < len && *p != '"') {
		/*
		 * Consume escaped token, make sure there is
		 * a token following the \ which we will blindly
		 * just consume.
		 */
		if(*p == '\\') {
			if(i+1 == len) {
				return hawkc_set_error(ctx, HAWKC_PARSE_ERROR, "\\ at end of text");
			}
			p++;
			i++;
			ptoken->len++;
		}
		p++;
		i++;
		ptoken->len++;
	}
	/*
	 * There must be a token left (which will be ", given the while condition above).
	 */
	if(i >= len) {
		return hawkc_set_error(ctx, HAWKC_PARSE_ERROR, "Quoted text must end with '\"'");
	}

	/* consume ending " */
	p++;
	i++;

	*n = i;
	return HAWKC_OK;
}




/*
 * See common.h for docs.
 */
HawkcError hawkc_parse_auth_header(HawkcContext ctx, unsigned char *value, size_t len, HawkcSchemeHandler scheme_handler, HawkcParamHandler param_handler, void *data) {
	HawkcError e;
	unsigned char *p = value;
	size_t remain = len;
	size_t n;
	HawkcString scheme;

	/*
	 * Parse scheme part.
	 */
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

	/*
	 * While we have more to parse, consume key/value pairs.
	 * token68 syntax is not supported. We always expect
	 * key=value or key="value".
	 */
	while(remain > 0) {
		HawkcString key, value;
		if( (e = parse_token(ctx,p,remain,&key,&n)) != HAWKC_OK) {
			return e;
		}
		p += n;
		remain -= n;

		/* There can be optional WS after key-token */
		consume_ows(ctx,p,remain,&n);
		p += n;
		remain -= n;

		/* There must be a = now */
		if(*p != '=') {
			return hawkc_set_error(ctx, HAWKC_PARSE_ERROR, "Missing '=' for parameter value");
		}
		/* consume '=' */
		p++;
		remain--;


		/* There can be optional WS between = and value */
		consume_ows(ctx,p,remain,&n);
		p += n;
		remain -= n;

		/*
		 *  Use first char of value to determine whether to consume
		 * quoted string or token.
		 */
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

		/* There can be optional WS after key/value pair */
		consume_ows(ctx,p,remain,&n);
		p += n;
		remain -= n;

		/* Now pass key and value to callback */
		if( (e = param_handler(ctx,key,value,data)) != HAWKC_OK) {
				return e;
		}

		/* If we have more, consume delimiter and optional WS */
		if(remain > 0) {
			if(*p == ',') {
				p++;
				remain--;
				consume_ows(ctx,p,remain,&n);
				p += n;
				remain -= n;
			} else {
				/* Delimiter must be , */
				return hawkc_set_error(ctx, HAWKC_PARSE_ERROR, "',' required after parameter value");
			}
		}
	}
	return HAWKC_OK;
}








