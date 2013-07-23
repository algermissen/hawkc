#include "hawkc.h"
#include "common.h"
#include "test.h"

static struct HawkcContext ctx;
static HawkcError e;

int test_signing() {

	char *METHOD = "GET";
	char *PATH = "/some/path/to/foo";
	char *HOST = "example.com";
	char *PORT = "80";

	unsigned char buf[2048];
	int len,maclen,is_valid;

	char *h1 = "Hawk id=\"someId\",mac=\"t81/bBJPDw53kKCs5u5YeSmL7cs=\",ts=\"1373805459\",nonce=\"abc\", ext=\"foo\"";
	char b[] = "hawk.1.header\n1373805459\nabc\nGET\n/some/path/to/foo\nexample.com\n80\n\nfoo\n";
	char mac[] = "t81/bBJPDw53kKCs5u5YeSmL7cs=";

	hawkc_context_init(&ctx);


	hawkc_context_set_method(&ctx,METHOD,strlen(METHOD));
	hawkc_context_set_path(&ctx,PATH,strlen(PATH));
	hawkc_context_set_host(&ctx,HOST,strlen(HOST));
	hawkc_context_set_port(&ctx,PORT,strlen(PORT));


	e = hawkc_parse_authorization_header(&ctx,h1,strlen(h1));
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);

	EXPECT_BYTE_EQUAL(ctx.header_in.id.data, "someId" , ctx.header_in.id.len);
	EXPECT_INT_EQUAL(1373805459, (int)ctx.header_in.ts);

	hawkc_create_base_string(&ctx,&(ctx.header_in),buf,&len);
	EXPECT_INT_EQUAL(strlen(b),len);
	EXPECT_BYTE_EQUAL(b,buf,len);

	hawkc_hmac(&ctx, HAWKC_SHA_1, "test", 4, buf, len,ctx.hmac,&maclen);
	/*
	printf("[%.*s]\n", maclen,ctx.hmac);
	*/

	hawkc_validate_hmac(&ctx, HAWKC_SHA_1, "test", 4,&is_valid);
	EXPECT_TRUE(is_valid);

	return 0;
}
int test_signing_iron() {

	char *METHOD = "GET";
	char *PATH = "/product/api/test.txt";
	char *HOST = "localhost";
	char *PORT = "8080";

	unsigned char buf[2048];
	int len,maclen,is_valid;

	char *h1 = "Hawk id=\"Fe26.1**680f2ae51e93df2a18a72262f9e008f2fd6792279898de77d090143976bb9f4b*t6IP6Bqmrk1EA2ckV9XXMA*oscF7eDiBIqEv2Dp2GE3X3CzetIyNp3q_83mfBXKbBf0lnlwpz8sq_zOfC9HzRxzLenx7cYsijmvTLe9XmCNrZwY5nCewYJ85S0_FeoMa7hKe9iKjUov0iTlzEIvLJ3c4SFKX0712X5kwGrhx2XrHH758Z73W1_bQjPfUmHiWJA*c2024e696ad34852d294d694efcee46c0bef9c1a56b047b1f13d331c7707dd5b*UW8r4ys7OGlhnBtR7umBGj9GQXoEyJANZzNZL9eKW_I\",mac=\"u+elTyN6jaTLcw0F1Q1InPFwKMfv9X/85Syni2Zpih0=\",ts=\"1374147123\",nonce=\"abcdef\", ext=\"Some special data\"";
	/*
	            Hawk id=" Fe26.1**680f2ae51e93df2a18a72262f9e008f2fd6792279898de77d090143976bb9f4b*t6IP6Bqmrk1EA2ckV9XXMA*oscF7eDiBIqEv2Dp2GE3X3CzetIyNp3q_83mfBXKbBf0lnlwpz8sq_zOfC9HzRxzLenx7cYsijmvTLe9XmCNrZwY5nCewYJ85S0_FeoMa7hKe9iKjUov0iTlzEIvLJ3c4SFKX0712X5kwGrhx2XrHH758Z73W1_bQjPfUmHiWJA*c2024e696ad34852d294d694efcee46c0bef9c1a56b047b1f13d331c7707dd5b*UW8r4ys7OGlhnBtR7umBGj9GQXoEyJANZzNZL9eKW_I",mac="  u+elTyN6jaTLcw0F1Q1InPFwKMfv9X/85Syni2Zpih0=",  ts="1374147123",    nonce="abcdef",       ext="Some special data"
	            */

	char mac[] = "u+elTyN6jaTLcw0F1Q1InPFwKMfv9X/85Syni2Zpih0=";

	hawkc_context_init(&ctx);

	hawkc_context_set_method(&ctx,METHOD,strlen(METHOD));
		hawkc_context_set_path(&ctx,PATH,strlen(PATH));
		hawkc_context_set_host(&ctx,HOST,strlen(HOST));
		hawkc_context_set_port(&ctx,PORT,strlen(PORT));

	e = hawkc_parse_authorization_header(&ctx,h1,strlen(h1));
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);

	EXPECT_INT_EQUAL(1374147123, (int)ctx.header_in.ts);

	hawkc_create_base_string(&ctx,&(ctx.header_in),buf,&len);

	hawkc_hmac(&ctx, HAWKC_SHA_256, "w7*0T6C.0b4C#", 13, buf, len,ctx.hmac,&maclen);
	/*
	printf("___[%.*s]\n", maclen,ctx.hmac);
	*/

	hawkc_validate_hmac(&ctx, HAWKC_SHA_256, "w7*0T6C.0b4C#", 13,&is_valid);
	EXPECT_TRUE(is_valid);

	return 0;
}

/*
 * This test case implements 'should parse a valid authentication header (sha1)' of
 * https://github.com/hueniverse/hawk/blob/master/test/server.js
 *
 */
int test_hawk_capatibility() {

	char *METHOD = "GET";
	char *PATH = "/resource/4?filter=a";
	char *HOST = "example.com";
	char *PORT = "8080";

	unsigned char buf[2048];
	int len,maclen,is_valid;

	/*const char *pwd = "a8>7B8X@6w0P?";
	 *
	 */
	const char *pwd = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn";

	char *h1 = "Hawk id=\"1\", ts=\"1353788437\", nonce=\"k3j4h2\", mac=\"zy79QQ5/EYFmQqutVnYb73gAc/U=\", ext=\"hello\"";

	hawkc_context_init(&ctx);

	hawkc_context_set_method(&ctx,METHOD,strlen(METHOD));
		hawkc_context_set_path(&ctx,PATH,strlen(PATH));
		hawkc_context_set_host(&ctx,HOST,strlen(HOST));
		hawkc_context_set_port(&ctx,PORT,strlen(PORT));

	e = hawkc_parse_authorization_header(&ctx,h1,strlen(h1));
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);

	EXPECT_BYTE_EQUAL(ctx.header_in.id.data, "1" , ctx.header_in.id.len);
	EXPECT_INT_EQUAL(1353788437, (int)ctx.header_in.ts);

	hawkc_create_base_string(&ctx,&(ctx.header_in),buf,&len);

	hawkc_hmac(&ctx, HAWKC_SHA_1, pwd, strlen(pwd), buf, len,ctx.hmac,&maclen);
	/*
	printf("[%.*s]\n", maclen,ctx.hmac);
	*/

	hawkc_validate_hmac(&ctx, HAWKC_SHA_1, pwd, strlen(pwd),&is_valid);
	EXPECT_TRUE(is_valid);



	return 0;
}

/*
 * This test case implements 'should parse a valid authentication header (sha256)' of
 * https://github.com/hueniverse/hawk/blob/master/test/server.js
 *
 */
int test_hawk_capatibility2() {

	char *METHOD = "GET";
	char *PATH = "/resource/1?b=1&a=2";
	char *HOST = "example.com";
	char *PORT = "8000";

	unsigned char buf[2048];
	int len,maclen,is_valid;

	/*const char *pwd = "a8>7B8X@6w0P?";
	 *
	 */
	const char *pwd = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn";

	char *h1 = "Hawk id=\"dh37fgj492je\", ts=\"1353832234\", nonce=\"j4h3g2\", mac=\"m8r1rHbXN6NgO+KIIhjO7sFRyd78RNGVUwehe8Cp2dU=\", ext=\"some-app-data\"";

	hawkc_context_init(&ctx);

	hawkc_context_set_method(&ctx,METHOD,strlen(METHOD));
		hawkc_context_set_path(&ctx,PATH,strlen(PATH));
		hawkc_context_set_host(&ctx,HOST,strlen(HOST));
		hawkc_context_set_port(&ctx,PORT,strlen(PORT));


	e = hawkc_parse_authorization_header(&ctx,h1,strlen(h1));
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);

	hawkc_create_base_string(&ctx,&(ctx.header_in),buf,&len);

	hawkc_hmac(&ctx, HAWKC_SHA_256, pwd, strlen(pwd), buf, len,ctx.hmac,&maclen);
	/*
	printf("[%.*s]\n", maclen,ctx.hmac);
	*/

	hawkc_validate_hmac(&ctx, HAWKC_SHA_256, pwd, strlen(pwd),&is_valid);
	EXPECT_TRUE(is_valid);



	return 0;
}


int main(int argc, char **argv) {


	RUNTEST(argv[0],test_signing);
	RUNTEST(argv[0],test_signing_iron);
	RUNTEST(argv[0],test_hawk_capatibility);
	RUNTEST(argv[0],test_hawk_capatibility2);

	return 0;
}
