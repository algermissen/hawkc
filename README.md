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

Building hawkc
==============

hawkc depends in libcrypto of the OpenSSL distribution, so you need that to be
available on your system (configure will try to locate libcrypto for you).

Run the configure script for environment checks and Makefile generation then make:

    $ ./configure
    $ make all

This builds a static library in the hawkc directory named libhawkc.a which you
need to link to your own projects to include hawkc. Dynamic linking is not
provided at this point.

The build creates a command line utility _iron_ in the iron directory.
This can be used to seal or unseal arbitrary input. Have a look at the sources
in iron/iron.c to see how to use the hawkc library.

After the build, you should run the tests using

    $ make test


hawkc has been build and tested in the following environments:

* Linux (CentOS)
* MacOS 10.7

If you have built hawkc on a different environment, please drop me a note so I can
include that environment in the list above.


A note on building on MacOS
---------------------------
During building on MacOS 10.7 and above, you will see deprecation warnings for
all the OpenSSL (libcrypto) functions. These deprecations exist due to Apple's
recent rework of the security architecture. Background information can be
found, for example, in [this Stackoverflow answer](http://stackoverflow.com/a/7406994/267196).

Security Considerations
=======================

Make sure you read the [security considerations](https://github.com/hueniverse/hawk#security-considerations) of Hawk before using this library.


Underlying Crypto-Library
=========================

hawkc currently builds upon the cryptographic functions provided by libcrypto
of the OpenSSL distribution.

If you need to use a different underlying crypto library, you must create an
implementation of the functions declared in `hawkc/crypto.h`. Have a look at
`hawkc/crypto_openssl.c` to see how that works. The other parts of hawkc do not
depend on OpenSSL.

Usage
=====

    struct HawkcContext ctx;
    HawkcError e;
    int hmac_is_valid;
    time_t now;


    hawkc_context_init(&ctx);
    hawkc_context_set_method(&ctx,method.data, method.len);
    hawkc_context_set_path(&ctx,path.data, path.len);
    hawkc_context_set_host(&ctx,host.data,host.len);
    hawkc_context_set_port(&ctx,port.data,port.len);

    hawkc_context_set_password(&ctx,pwd.data,pwd.len);
    hawkc_context_set_algorithm(&ctx,HAWKC_SHA_256);

    if( (e = hawkc_parse_authorization_header(&ctx,header.data, header.len)) != HAWKC_OK) {
		    /* handle error */
    }

    if( (he = hawkc_validate_hmac(&ctx, &hmac_is_valid)) != HAWKC_OK) {
       /* error validating */
    }
    if(!hmac_is_valid) {
       /* signature is invalid */
    }

    time(&now);
    if(ctx.header_in.ts < now - allowed_clock_skew || ctx.header_in.ts > now + allowed_clock_skew) {
       /* timestamp not valid, suggest our own time to client so it can set offset */
    }

    /* check nonce if desired */




