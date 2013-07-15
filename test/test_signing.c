#include "hawkc.h"
#include "common.h"
#include "test.h"

static struct HawkcContext ctx;
static HawkcError e;

static char *METHOD = "GET";
static char *PATH = "/some/path/to/foo";
static char *HOST = "example.com";
static const int PORT = 80;

int test_signing() {

	unsigned char buf[2048];
	int len,maclen,is_valid;

	char *h1 = "Hawk id=\"someId\",mac=\"t81/bBJPDw53kKCs5u5YeSmL7cs=\",ts=\"1373805459\",nonce=\"abc\", ext=\"foo\"";
	char b[] = "hawk.1.header\n1373805459\nabc\nGET\n/some/path/to/foo\nexample.com\n80\n\nfoo\n";
	char mac[] = "t81/bBJPDw53kKCs5u5YeSmL7cs=";

	ctx.method.data = METHOD;
	ctx.method.len = strlen(METHOD);

	ctx.path.data = PATH;
	ctx.path.len = strlen(PATH);

	ctx.host.data = HOST;
	ctx.host.len = strlen(HOST);

	ctx.port = PORT;


	e = hawkc_parse_authorization_header(&ctx,h1,strlen(h1));
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);

	EXPECT_BYTE_EQUAL(ctx.header_in.id.data, "someId" , ctx.header_in.id.len);
	EXPECT_INT_EQUAL(1373805459, (int)ctx.header_in.ts);

	hawkc_create_base_string(&ctx,&(ctx.header_in),buf,&len);
	EXPECT_INT_EQUAL(strlen(b),len);
	EXPECT_BYTE_EQUAL(b,buf,len);

	hawkc_hmac(&ctx, SHA_1, "test", 4, buf, len,ctx.hmac,&maclen);
	printf("[%.*s]", maclen,ctx.hmac);

	hawkc_validate_hmac(&ctx, SHA_1, "test", 4,&is_valid);
	EXPECT_TRUE(is_valid);



	return 1;
}



int main(int argc, char **argv) {

	hawkc_context_init(&ctx);

	RUNTEST(argv[0],test_signing);

	return 0;
}
