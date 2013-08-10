hawkc
=====

A C implementation of [hawk](https://github.com/hueniverse/hawk)

Status
======

hawkc is usable on the server side but is lacking the following features:

- payload validation
- verificatin of the WWW-Authenticate tsm parameter (timestamp signature)
- Server-Authorization header support
- SNTP support

And also see the issues list.

Usage
=====

    struct CironContext ciron_ctx;
    HawkcError e;
    int hmac_is_valid;
    time_t now;


    hawkc_context_init(&hawkc_ctx);
    hawkc_context_set_method(&hawkc_ctx,method.data, method.len);
    hawkc_context_set_path(&hawkc_ctx,path.data, path.len);
    hawkc_context_set_host(&hawkc_ctx,host.data,host.len);
    hawkc_context_set_port(&hawkc_ctx,port.data,port.len);

    hawkc_context_set_password(&hawkc_ctx,pwd.data,pwd.len);
    hawkc_context_set_algorithm(&hawkc_ctx,HAWKC_SHA_256);

    if( (e = hawkc_parse_authorization_header(&hawkc_ctx,header.data, header.len)) != HAWKC_OK) {
		    /* handle error */
    }

    if( (he = hawkc_validate_hmac(&hawkc_ctx, &hmac_is_valid)) != HAWKC_OK) {
       /* error validating */
    }
    if(!hmac_is_valid) {
       /* signature is invalid */
    }

    time(&now);
    if(hawkc_ctx.header_in.ts < now - allowed_clock_skew || hawkc_ctx.header_in.ts > now + allowed_clock_skew) {
       /* timestamp not valid, suggest our own time to client so it can set offset */
    }

    /* check nonce if desired */




