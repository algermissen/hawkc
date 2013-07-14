#include "hawkc.h"
#include "common.h"
#include "test.h"

static struct HawkcContext ctx;
static HawkcError e;

int test_1() {

	char *h1 = "Hawk id=\"someId\",mac=\"2D320BF8A5948601F9FA3FBA4800C8F7A1D203A317945330854D65228864468D\",ts=\"1373805459\",nonce=\"abc\"";

	e = hawkc_parse_authorization_header(&ctx,h1,strlen(h1));
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);

	EXPECT_BYTE_EQUAL(ctx.header_in.id.data, "someId" , ctx.header_in.id.len);
	EXPECT_INT_EQUAL(1373805459, (int)ctx.header_in.ts);


	/*
	e = hawkc_parse_auth_header(&ctx,"Hawk a=b",8,scheme_handler, param_handler,NULL);
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);
	EXPECT_STR_EQUAL("Hawk",scheme_buf);
	EXPECT_STR_EQUAL("<a:b>",buf);
	*/


	return 1;
}



int main(int argc, char **argv) {

	hawkc_context_init(&ctx);

	RUNTEST(argv[0],test_1);

	return 0;
}
