/*
 * This file implements the functions declared in crypto.h using libcrypto
 * of the OpenSSL library.
 */
#include <string.h>
#include <openssl/hmac.h>

#include "hawkc.h"
#include "common.h"
#include "crypto.h"
#include "base64.h"

HawkcError hawkc_hmac(HawkcContext ctx, HawkcAlgorithm algorithm,
		const unsigned char *password, int password_len,
		const unsigned char *data, int data_len, unsigned char *result,
		int *result_len) {

	HMAC_CTX md_ctx;
	const EVP_MD *md;
	unsigned char buf[MAX_HMAC_BYTES];
	unsigned int len;

	if (strcmp(algorithm->name, HAWKC_SHA_1->name) == 0) {
		md = EVP_sha1();
	} else if (strcmp(algorithm->name, HAWKC_SHA_256->name) == 0) {
		md = EVP_sha256();
	} else {
		return hawkc_set_error(ctx, HAWKC_ERROR_UNKNOWN_ALGORITHM,
				"Algorithm %s not recognized for HMAC calculation", algorithm->name);
	}
	HMAC_CTX_init(&md_ctx);
	HMAC_Init(&md_ctx, password, password_len, md);
	HMAC_Update(&md_ctx, data, data_len);

	HMAC_Final(&md_ctx, buf, &len);
	HMAC_CTX_cleanup(&md_ctx);

	hawkc_base64_encode(buf, len, result, result_len);

	return HAWKC_OK;
}



#if 0
FIXME: These are kept for reference, for example, how to popolate the TS-WWW-Authenticate variant
in hawk
FIXME: remove these notes
var hmac = Crypto.createHmac(credentials.algorithm, credentials.key).update(normalized);
    var digest = hmac.digest('base64');
    return digest;

    in node.js:

    exports.createHmac = exports.Hmac = Hmac;

    function Hmac(hmac, key, options) {
      if (!(this instanceof Hmac))
        return new Hmac(hmac, key, options);
      this._binding = new binding.Hmac();
      this._binding.init(hmac, toBuf(key));
      LazyTransform.call(this, options);
    }






    ---------------------------------------------------------------
    void Hmac::New(const FunctionCallbackInfo<Value>& args) {
      HandleScope scope(node_isolate);
      Hmac* hmac = new Hmac();
      hmac->Wrap(args.This());
    }



    bool Hmac::HmacUpdate(char* data, int len) {
      if (!initialised_) return false;
      HMAC_Update(&ctx_, reinterpret_cast<unsigned char*>(data), len);
      return true;
    }


    void Hmac::HmacUpdate(const FunctionCallbackInfo<Value>& args) {
      HandleScope scope(node_isolate);

      Hmac* hmac = ObjectWrap::Unwrap<Hmac>(args.This());

      ASSERT_IS_STRING_OR_BUFFER(args[0]);

      // Only copy the data if we have to, because it's a string
      bool r;
      if (args[0]->IsString()) {
        enum encoding encoding = ParseEncoding(args[1], BINARY);
        size_t buflen = StringBytes::StorageSize(args[0], encoding);
        char* buf = new char[buflen];
        size_t written = StringBytes::Write(buf, buflen, args[0], encoding);
        r = hmac->HmacUpdate(buf, written);
        delete[] buf;
      } else {
        char* buf = Buffer::Data(args[0]);
        size_t buflen = Buffer::Length(args[0]);
        r = hmac->HmacUpdate(buf, buflen);
      }

      if (!r) {
        return ThrowTypeError("HmacUpdate fail");
      }
    }


    bool Hmac::HmacDigest(unsigned char** md_value, unsigned int* md_len) {
      if (!initialised_) return false;
      *md_value = new unsigned char[EVP_MAX_MD_SIZE];
      HMAC_Final(&ctx_, *md_value, md_len);
      HMAC_CTX_cleanup(&ctx_);
      initialised_ = false;
      return true;
    }


    void Hmac::HmacDigest(const FunctionCallbackInfo<Value>& args) {
      HandleScope scope(node_isolate);

      Hmac* hmac = ObjectWrap::Unwrap<Hmac>(args.This());

      enum encoding encoding = BUFFER;
      if (args.Length() >= 1) {
        encoding = ParseEncoding(args[0]->ToString(), BUFFER);
      }

      unsigned char* md_value = NULL;
      unsigned int md_len = 0;

      bool r = hmac->HmacDigest(&md_value, &md_len);
      if (!r) {
        md_value = NULL;
        md_len = 0;
      }

      Local<Value> rc = StringBytes::Encode(
            reinterpret_cast<const char*>(md_value), md_len, encoding);
      delete[] md_value;
      args.GetReturnValue().Set(rc);
    }

    ---------------------------------------------------------------


and

exports.calculatePayloadHash = function (payload, algorithm, contentType) {

    var hash = exports.initializePayloadHash(algorithm, contentType);
    hash.update(payload || '');
    return exports.finalizePayloadHash(hash);
};


exports.initializePayloadHash = function (algorithm, contentType) {

    var hash = Crypto.createHash(algorithm);
    hash.update('hawk.' + exports.headerVersion + '.payload\n');
    hash.update(Utils.parseContentType(contentType) + '\n');
    return hash;
};


exports.finalizePayloadHash = function (hash) {

    hash.update('\n');
    return hash.digest('base64');
};

And timestamp:

exports.calculateTsMac = function (ts, credentials) {

    var hmac = Crypto.createHmac(credentials.algorithm, credentials.key);
    hmac.update('hawk.' + exports.headerVersion + '.ts\n' + ts + '\n');
    return hmac.digest('base64');
};







exports.timestampMessage = function (credentials, localtimeOffsetMsec) {

    var now = Math.floor((Utils.now() + (localtimeOffsetMsec || 0)) / 1000);
    var tsm = exports.calculateTsMac(now, credentials);
    return { ts: now, tsm: tsm };
};





#endif

