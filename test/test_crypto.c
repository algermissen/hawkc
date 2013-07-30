#include "hawkc.h"
#include "common.h"
#include "crypto.h"
#include "test.h"

static struct HawkcContext ctx;
static HawkcError e;


int test_hmac() {

	unsigned char buf[1024];
	unsigned char buf2[1024];
	size_t len;
	size_t len2;

	e = hawkc_hmac(&ctx, HAWKC_SHA_256,(unsigned char *)"test",4,(unsigned char *)"Das ist die Message",19,buf,&len);
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);

	e = hawkc_hmac(&ctx, HAWKC_SHA_256,(unsigned char *)"test",4,(unsigned char *)"Das ist die Message",19,buf2,&len2);
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);

	EXPECT_INT_EQUAL((int)len,(int)len2);
	EXPECT_BYTE_EQUAL(buf,buf2,(int)len);





	return 0;
}



int main(int argc, char **argv) {

	hawkc_context_init(&ctx);

	RUNTEST(argv[0],test_hmac);

	return 0;
}
