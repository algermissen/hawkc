#include "hawkc.h"
#include "common.h"
#include "test.h"

static struct HawkcContext ctx;
static HawkcError e;

int test_parse() {

	char *h1 = "Hawk";

	e = hawkc_parse_www_authenticate_header(&ctx,h1,strlen(h1));
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);

/*
	EXPECT_BYTE_EQUAL(ctx.header_in.id.data, "someId" , ctx.header_in.id.len);
	EXPECT_INT_EQUAL(1373805459, (int)ctx.header_in.ts);
	*/


	/*
	e = hawkc_parse_auth_header(&ctx,"Hawk a=b",8,scheme_handler, param_handler,NULL);
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);
	EXPECT_STR_EQUAL("Hawk",scheme_buf);
	EXPECT_STR_EQUAL("<a:b>",buf);
	*/


	return 0;
}

int test_parse_ts() {

	char *h1 = "Hawk ts=\"1375085388\",tsm=\"QP6wolOP0oaoxuvFhPpxcGCm\"";

	e = hawkc_parse_www_authenticate_header(&ctx,(unsigned char*)h1,strlen(h1));
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);

	EXPECT_BYTE_EQUAL(ctx.www_authenticate_header.tsm.data, "QP6wolOP0oaoxuvFhPpxcGCm" , (int)ctx.www_authenticate_header.tsm.len);
	EXPECT_INT_EQUAL(1375085388, (int)ctx.www_authenticate_header.ts);

	return 0;
}






int main(int argc, char **argv) {

	hawkc_context_init(&ctx);

	RUNTEST(argv[0],test_parse);
	RUNTEST(argv[0],test_parse_ts);

	return 0;
}
