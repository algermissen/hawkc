#include <string.h>
#include "hawkc.h"
#include "common.h"
#include "test.h"

static struct HawkcContext ctx;
static HawkcError e;
static char scheme_buf[1024];
static char buf[1024];

static HawkcError scheme_handler(HawkcContext ctx,HawkcString scheme,void *data) {
	memset(scheme_buf,0,sizeof(scheme_buf));
	memset(buf,0,sizeof(buf));
	strncpy(scheme_buf,scheme.data,scheme.len);
	return HAWKC_OK;	
}
static HawkcError param_handler(HawkcContext ctx,HawkcString key, HawkcString value,void *data) {
	strcat(buf,"<");
	strncat(buf,key.data,key.len);
	strcat(buf,":");
	strncat(buf,value.data,value.len);
	strcat(buf,">");
	return HAWKC_OK;	
}

int test_scheme_only() {

	e = hawkc_parse_auth_header(&ctx,"",0,scheme_handler, param_handler,NULL);

	e = hawkc_parse_auth_header(&ctx,"Foo",3,scheme_handler, param_handler,NULL);
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);
	EXPECT_STR_EQUAL("Foo",scheme_buf);

	e = hawkc_parse_auth_header(&ctx,"Foo ",4,scheme_handler, param_handler,NULL);
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);
	EXPECT_STR_EQUAL("Foo",scheme_buf);

	e = hawkc_parse_auth_header(&ctx,"Foo  ",5,scheme_handler, param_handler,NULL);
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);
	EXPECT_STR_EQUAL("Foo",scheme_buf);

	e = hawkc_parse_auth_header(&ctx,"Foo\t  ",6,scheme_handler, param_handler,NULL);
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);
	EXPECT_STR_EQUAL("Foo",scheme_buf);

	e = hawkc_parse_auth_header(&ctx,"Hawk a=b",8,scheme_handler, param_handler,NULL);
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);
	EXPECT_STR_EQUAL("Hawk",scheme_buf);
	EXPECT_STR_EQUAL("<a:b>",buf);

	e = hawkc_parse_auth_header(&ctx,"Hawk\ta=b",8,scheme_handler, param_handler,NULL);
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);
	EXPECT_STR_EQUAL("Hawk",scheme_buf);
	EXPECT_STR_EQUAL("<a:b>",buf);

	e = hawkc_parse_auth_header(&ctx,"Hawk  a  = b    ",16,scheme_handler, param_handler,NULL);
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);
	EXPECT_STR_EQUAL("Hawk",scheme_buf);
	EXPECT_STR_EQUAL("<a:b>",buf);

	e = hawkc_parse_auth_header(&ctx,"Hawk \t a  =   b",15,scheme_handler, param_handler,NULL);
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);
	EXPECT_STR_EQUAL("Hawk",scheme_buf);
	EXPECT_STR_EQUAL("<a:b>",buf);

	e = hawkc_parse_auth_header(&ctx,"Hawk a=b,c=d",12,scheme_handler, param_handler,NULL);
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);
	EXPECT_STR_EQUAL("Hawk",scheme_buf);
	EXPECT_STR_EQUAL("<a:b><c:d>",buf);

	e = hawkc_parse_auth_header(&ctx,"Hawk a=b, c=d",13,scheme_handler, param_handler,NULL);
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);
	EXPECT_STR_EQUAL("Hawk",scheme_buf);
	EXPECT_STR_EQUAL("<a:b><c:d>",buf);

	e = hawkc_parse_auth_header(&ctx,"Hawk a=b, c=d, ",15,scheme_handler, param_handler,NULL);
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);
	EXPECT_STR_EQUAL("Hawk",scheme_buf);
	EXPECT_STR_EQUAL("<a:b><c:d>",buf);

	e = hawkc_parse_auth_header(&ctx,"Hawk a=b, c=, ",14,scheme_handler, param_handler,NULL);
	EXPECT_RETVAL(HAWKC_PARSE_ERROR,e,&ctx);

	return 0;
}

int test_quoted_string() {


	e = hawkc_parse_auth_header(&ctx,"Hawk a=\"b\"",10,scheme_handler, param_handler,NULL);
	if(e != HAWKC_OK) {
		printf("e:%s\n" , hawkc_get_error(&ctx));
	}
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);
	EXPECT_STR_EQUAL("Hawk",scheme_buf);
	EXPECT_STR_EQUAL("<a:b>",buf);

	e = hawkc_parse_auth_header(&ctx,"Hawk a=\"b\",c=\"d\"",16,scheme_handler, param_handler,NULL);
	if(e != HAWKC_OK) {
		printf("e:%s\n" , hawkc_get_error(&ctx));
	}
	/*
	printf("e:%s\n" , hawkc_get_error(&ctx));
	*/
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);
	EXPECT_STR_EQUAL("Hawk",scheme_buf);
	EXPECT_STR_EQUAL("<a:b><c:d>",buf);

	e = hawkc_parse_auth_header(&ctx,"Hawk a=\"b\",c=\"d\\\"d\"",19,scheme_handler, param_handler,NULL);
	if(e != HAWKC_OK) {
		printf("e:%s\n" , hawkc_get_error(&ctx));
	}
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);
	EXPECT_STR_EQUAL("Hawk",scheme_buf);
	EXPECT_STR_EQUAL("<a:b><c:d\\\"d>",buf);

	e = hawkc_parse_auth_header(&ctx,"Hawk a=\"b\",c=\"d\\\"\"",18,scheme_handler, param_handler,NULL);
	if(e != HAWKC_OK) {
		printf("e:%s\n" , hawkc_get_error(&ctx));
	}
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);
	EXPECT_STR_EQUAL("Hawk",scheme_buf);
	EXPECT_STR_EQUAL("<a:b><c:d\\\">",buf);

	e = hawkc_parse_auth_header(&ctx,"Hawk a=\"b\",c=\"d\\\nd\"",19,scheme_handler, param_handler,NULL);
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);
	EXPECT_STR_EQUAL("Hawk",scheme_buf);
	EXPECT_STR_EQUAL("<a:b><c:d\\\nd>",buf);

	e = hawkc_parse_auth_header(&ctx,"Hawk a=\"b\",c=\"d\\\td\"",19,scheme_handler, param_handler,NULL);
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);
	EXPECT_STR_EQUAL("Hawk",scheme_buf);
	EXPECT_STR_EQUAL("<a:b><c:d\\\td>",buf);

	e = hawkc_parse_auth_header(&ctx,"Hawk a=\"b\",c=d",14,scheme_handler, param_handler,NULL);
	EXPECT_RETVAL(HAWKC_OK,e,&ctx);
	EXPECT_STR_EQUAL("Hawk",scheme_buf);
	EXPECT_STR_EQUAL("<a:b><c:d>",buf);

	return 0;
}

int main(int argc, char **argv) {

	hawkc_context_init(&ctx);

	RUNTEST(argv[0],test_scheme_only);
	RUNTEST(argv[0],test_quoted_string);

	return 0;
}
