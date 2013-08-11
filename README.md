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
- Incompatible with the original Hawk implementation when ext data contains double quotes (hawkc keeps the escape chars in the base string). Will be fixed.
- Support for dlg and app parameters

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

The build creates a command line utility _hawk_ in the hawk directory.

This can be used to generate Authorization header values, for example for
use with curl. Have a look at the sources in hawk/hawk.c to see how to use
the hawkc library.

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

Memory Management
=================

hawkc is designed to avoid internal memory allocation as much as possible. However,
it is impossible to estimate the size of incoming headers or data because URI
path length and extention data are both completely arbitrary. As the both go
into the base string, hawkc must support arbitrary length base string buffers.

The header file common.h defines _BASE_BUFFER_SIZE_ as a buffer size that should
be large enough to hold most base strings. This buffer size is then used to
define local buffers to avoid memory allocation for base strings of common sizes.

If the required size for a base string exceeds _BASE_BUFFER_SIZE_ memory is
allocated dynamically and freed right away, when the HMAC has been generated from
the base string.

Dynamic memory allocation is limited to _MAX_DYN_BASE_BUFFER_SIZE_ to prevent
incoming requests from taking up too much memory. An error will be returned in
such cases.




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
    
    
Using the Command Line Tool hawk
=================================

hawkc provides a commandline tool for development and testing purposes. It allows you to generate
HTTP header values, for example to be used with curl.

Suppose you have a client ID, password and algorithm to use like this:

   Client ID: 123
   Password: geheim
   Algorithm: SHA 1

And suppose you want to use these to sign an HTTP GET request  to

   http://example.org:80/api/news

Using the hawk commandline tool you can generate a header like this:

    $ hawk -i 123 -p geheim -H example.org -P /api/news -M GET -O 80 -a sha1

This will return the string (using the current system unix timestamp)    
    
    Hawk id="123",nonce="17bf5f9ca803",mac="LZess/R3c0HF3Yal3Dh/yPjkVfU=",ts="1376201564"

You can also make use of the defaults and omit GET and Port 80 and sha1:

    $ hawk -i 123 -p geheim -H example.org -P /api/news

If your intention is a curl invokation, use the -m option to generate the curl command line:

    $ hawk -i 123 -p geheim -H example.org -P /api/news -m curl
    
which produces:

    curl -v http://example.org:80/api/news \
    -H 'Authorization: Hawk id="123",nonce="eef569ba8206",\
    mac="G3tyimuqZ1Lqwv5qb56TPFn3j8Q=",ts="1376201656"'
     




Note to Implementors
====================

When you plan to add features to hawkc, please carefully note the following:

* If you add algorithms, you must check and maybe adjust several buffer size macros in hawkc.h and common.h
  These mocros are set the the maximum necessary HMAC length possibly needed by hawkc. Hence, they
  depend on the actual algorithms provided.
  In addition, you must add new algorithms to the if-cascade in common.c where algorithms are looked up by name.

